//! The guarded path open, the one unix-only piece of a raw stream: `O_NOFOLLOW`, `O_NONBLOCK`, and the
//! `fstat` type guard need libc, so `file:` and `fifo:` open here and nowhere else. Every other part of a
//! raw stream (the sources, the `stdin:` seat, the `+lossy` fan-out) is portable and lives once in
//! [`crate::raw_stream`]; the non-unix build swaps this module for a stand-in that refuses a path loudly.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileTypeExt as _;
use std::path::{Path, PathBuf};

use tokio::io::unix::AsyncFd;

use super::Kind;
use crate::tunnel::{BoxRead, RAW_STREAM_OPEN_TIMEOUT};

/// Serve-time type check for a raw-stream path (the twin of [`open_guarded`]'s guard 1), run before the
/// banner advertises the source as open. `lstat` (no symlink follow) the final component and refuse the
/// stable always-refused types with the SAME wording the connect-time open gives; a not-yet-existing path is
/// ALLOWED (the dial-time open is the definitive guard there, so a source created between serve and dial still
/// works). `symlink_metadata`, not `metadata`, so a symlink at the final component is seen AS a symlink and
/// refused, exactly as the `O_NOFOLLOW` open does.
pub(super) fn check_open_path(path: &Path, kind: Kind) -> eyre::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(eyre::Error::from(err).wrap_err(format!("cannot stat {}", path.display())));
        }
    };
    let file_type = metadata.file_type();
    // A symlink at the final component is refused at dial by `O_NOFOLLOW`, so it would over-claim here too.
    if file_type.is_symlink() {
        eyre::bail!(
            "{} is a symlink; a `file:`/`fifo:` target is opened with O_NOFOLLOW and will not follow a \
             symlink at the final component",
            path.display()
        );
    }
    let is_reg = file_type.is_file();
    let is_fifo = file_type.is_fifo();
    match kind {
        Kind::File if !(is_reg || is_fifo) => eyre::bail!(
            "{} is not a regular file or a FIFO ({}); a `file:` target refuses devices, directories, and \
             sockets",
            path.display(),
            describe_metadata_type(&file_type)
        ),
        Kind::Fifo if !is_fifo => eyre::bail!(
            "{} is not a FIFO ({}); a `fifo:` target opens a named pipe (make one with `mkfifo`)",
            path.display(),
            describe_metadata_type(&file_type)
        ),
        _ => Ok(()),
    }
}

/// A human name for a [`std::fs::FileType`], for the serve-time [`check_open_path`] refusal so the operator
/// sees WHAT they pointed at. Matches [`describe_type`]'s wording for the connect-time `fstat` path, but over
/// a `FileType` (not a masked `st_mode`), so the serve-time check needs no `mode_t`-width cast.
fn describe_metadata_type(file_type: &std::fs::FileType) -> &'static str {
    if file_type.is_block_device() {
        "a block device"
    } else if file_type.is_char_device() {
        "a character device"
    } else if file_type.is_dir() {
        "a directory"
    } else if file_type.is_symlink() {
        "a symlink"
    } else if file_type.is_socket() {
        "a socket"
    } else if file_type.is_fifo() {
        "a FIFO"
    } else if file_type.is_file() {
        "a regular file"
    } else {
        "an unknown type"
    }
}

/// Open a path source under the four guards and box its reader. Split out from
/// [`RawStream::open`](super::RawStream::open) so the `stdin:` arm (no path, no guards) reads cleanly
/// beside it. The guarded open is NONBLOCKING (guard 2), so it never parks a thread: for a FIFO it returns
/// a valid fd at once even with no writer, and this function then awaits a WRITER (readable readiness)
/// bounded by [`RAW_STREAM_OPEN_TIMEOUT`] before handing back the stream, so the peer gets real bytes, not
/// an instant writer-less EOF. A regular file has no writer to wait for and is handed back immediately.
pub(super) async fn open_path(path: PathBuf, kind: Kind) -> eyre::Result<BoxRead> {
    // The open is immediate and synchronous (nonblocking, no parked thread), so it runs inline; no
    // `spawn_blocking`, so nothing can leak past the timeout (that leak was the bug in issue #25).
    let opened = open_guarded(&path, kind)?;
    match opened {
        // A regular file needs no writer AND has no readiness to wait on: read it straight away, INLINE, with
        // no reactor registration. It must NOT go through `NonblockingReader`/`AsyncFd`: Linux `epoll` refuses a
        // regular fd with `EPERM` at registration (a regular file is always ready), which broke every regular
        // `file:` open on Linux while passing on macOS's kqueue.
        Opened::Regular(fd) => Ok(Box::new(RegularFileReader(fd))),
        // A FIFO reads as instant EOF with no writer, so wait for one (readable readiness) up to the timeout
        // before calling the stream open. On elapse, drop the fd (cheap, no parked thread) and refuse.
        Opened::Fifo(fd) => {
            let reader = NonblockingReader::new(fd)?;
            match tokio::time::timeout(writer_wait_timeout(), reader.readable()).await {
                Ok(Ok(())) => Ok(Box::new(reader)),
                Ok(Err(err)) => {
                    Err(eyre::Error::from(err).wrap_err(format!("waiting on {}", path.display())))
                }
                Err(_elapsed) => eyre::bail!(
                    "opening {} timed out after {}s (a FIFO with no writer?)",
                    path.display(),
                    writer_wait_timeout().as_secs()
                ),
            }
        }
    }
}

/// How long the FIFO writer-wait may run. Production always uses [`RAW_STREAM_OPEN_TIMEOUT`]; under `cfg(test)`
/// a test can shrink it (via [`set_writer_wait_timeout_for_test`]) so a no-leak test can drive many writer-less
/// opens in sequence without waiting the full production budget each time.
#[cfg(not(test))]
fn writer_wait_timeout() -> core::time::Duration {
    RAW_STREAM_OPEN_TIMEOUT
}

#[cfg(test)]
static WRITER_WAIT_MILLIS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The writer-wait duration for tests: the test override if one was set, else [`RAW_STREAM_OPEN_TIMEOUT`].
#[cfg(test)]
fn writer_wait_timeout() -> core::time::Duration {
    match WRITER_WAIT_MILLIS.load(core::sync::atomic::Ordering::Relaxed) {
        0 => RAW_STREAM_OPEN_TIMEOUT,
        millis => core::time::Duration::from_millis(millis),
    }
}

/// Serializes the tests that depend on the writer-wait duration (the one that SHRINKS it to prove no thread
/// leaks, and the flood test that needs it LONG so its opens stay parked), since [`WRITER_WAIT_MILLIS`] is
/// process-global and tests run in parallel. Async-aware so a holder can await while holding it. A test holds
/// this guard for as long as it depends on the value.
#[cfg(test)]
pub(crate) static WRITER_WAIT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Shrink the FIFO writer-wait for a test so a writer-less open refuses quickly instead of after the full
/// production budget. `RAII`-style: restores the previous value on drop so one test cannot bleed into another.
/// Serialize with [`WRITER_WAIT_TEST_LOCK`] against the flood test, which needs the wait to stay long.
#[cfg(test)]
pub(crate) fn set_writer_wait_timeout_for_test(millis: u64) -> impl Drop {
    let previous = WRITER_WAIT_MILLIS.swap(millis, core::sync::atomic::Ordering::Relaxed);
    struct Restore(u64);
    impl Drop for Restore {
        fn drop(&mut self) {
            WRITER_WAIT_MILLIS.store(self.0, core::sync::atomic::Ordering::Relaxed);
        }
    }
    Restore(previous)
}

/// A guarded, nonblocking-open fd plus which kind of object it is, so [`open_path`] knows whether to wait for a
/// writer (a FIFO) or read straight away (a regular file).
enum Opened {
    /// A regular file: no writer to wait for.
    Regular(OwnedFd),
    /// A FIFO: read-side is EOF until a writer appears, so [`open_path`] awaits readable readiness first.
    Fifo(OwnedFd),
}

/// Open the final path component under three of the four guards and return its fd. `O_NONBLOCK` (guard 2) so a
/// FIFO open returns at once with no writer present and NEVER parks a thread; `O_NOFOLLOW` (guard 3) refuses a
/// symlink at the final component; `fstat` on the opened fd enforces the type (guard 1); `O_RDONLY` fixes the
/// direction (guard 4). Synchronous and immediate: the nonblocking open cannot block, so it needs no blocking
/// thread and the [`open_path`] timeout guards only the subsequent writer-wait, not this call.
fn open_guarded(path: &Path, kind: Kind) -> eyre::Result<Opened> {
    let mut c_path = path.as_os_str().as_bytes().to_vec();
    if c_path.contains(&0) {
        eyre::bail!("path {} contains a NUL byte", path.display());
    }
    c_path.push(0);
    // TODO(#25-followup): `O_NONBLOCK` does NOT cover a regular `file:` open on a hung mount (a wedged NFS
    // server): a regular-file open ignores `O_NONBLOCK` and blocks in the kernel until the mount responds.
    // This inline (non-`spawn_blocking`) open would then park the async task itself. That variant needs pool
    // isolation (a dedicated blocking pool the open can be abandoned on), out of scope for the FIFO leak fix.
    // SAFETY: `c_path` is a NUL-terminated C string that outlives the call; the flags are valid; a failed
    // open returns -1 and is handled below, never wrapped as an fd. `O_NONBLOCK` is a no-op on a regular file
    // (local disk opens do not block); on a FIFO it is what makes the read-only open return without a writer.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        // ELOOP is `O_NOFOLLOW` refusing a symlink at the final component; name it so the operator sees the
        // guard fire rather than a bare "too many links".
        if err.raw_os_error() == Some(libc::ELOOP) {
            eyre::bail!(
                "{} is a symlink; a `file:`/`fifo:` target is opened with O_NOFOLLOW and will not follow \
                 a symlink at the final component",
                path.display()
            );
        }
        return Err(eyre::Error::from(err).wrap_err(format!("cannot open {}", path.display())));
    }
    // SAFETY: `fd` is a fresh, owned, valid descriptor (checked >= 0 above); `OwnedFd::from_raw_fd` takes
    // ownership so it is closed on drop, including every early-return error path below.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };

    // Guard 1 (regular-file-or-FIFO only): `fstat` the fd we actually hold (not the path again, which would
    // reintroduce a TOCTOU) and allow ONLY a regular file or a FIFO. A block/char device (`/dev/zero`,
    // `/dev/urandom` = infinite drain), a directory, a socket: all refused.
    // SAFETY: `fd` is a valid owned descriptor; `fstat` writes a fully-initialized `stat` into `st` and
    // returns 0, or -1 on error (handled below). `st` is zeroed first so no field is read uninitialized.
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::fstat(std::os::fd::AsRawFd::as_raw_fd(&fd), &raw mut st) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(eyre::Error::from(err).wrap_err(format!("cannot stat {}", path.display())));
    }
    // Compare entirely in `mode_t` space (`st_mode` and the `S_IF*` constants share that type: `u16` on macOS,
    // `u32` on linux), with NO widening cast. A `u32::from` here would be an IDENTITY conversion where `mode_t`
    // is already `u32` (clippy `useless_conversion`, which fails the linux gate), while an `as u32` would be an
    // `unnecessary_cast` there; staying in `mode_t` avoids BOTH and is correct on either width.
    let file_type = st.st_mode & libc::S_IFMT;
    let is_reg = file_type == libc::S_IFREG;
    let is_fifo = file_type == libc::S_IFIFO;
    match kind {
        Kind::File if !(is_reg || is_fifo) => eyre::bail!(
            "{} is not a regular file or a FIFO ({}); a `file:` target refuses devices, directories, and \
             sockets",
            path.display(),
            describe_type(file_type)
        ),
        Kind::Fifo if !is_fifo => eyre::bail!(
            "{} is not a FIFO ({}); a `fifo:` target opens a named pipe (make one with `mkfifo`)",
            path.display(),
            describe_type(file_type)
        ),
        _ => {}
    }

    Ok(if is_fifo {
        Opened::Fifo(fd)
    } else {
        Opened::Regular(fd)
    })
}

/// An [`AsyncRead`](tokio::io::AsyncRead) over a nonblocking FIFO fd (guard 2's `O_NONBLOCK` open), so the
/// guarded FIFO open never needs a blocking thread. Registers the fd with the tokio reactor via [`AsyncFd`]:
/// `EAGAIN` (would-block) yields readable readiness rather than a parked syscall, so a slow or writer-less FIFO
/// costs a poll registration, never a leaked blocking-pool thread. FIFO-ONLY: a regular file must NOT come here
/// because Linux `epoll` (which [`AsyncFd`] uses) refuses a regular fd with `EPERM` at registration; see
/// [`RegularFileReader`] for the regular-file path.
struct NonblockingReader(AsyncFd<OwnedFd>);

impl NonblockingReader {
    /// Register the nonblocking fd with the reactor. Fails only if the reactor cannot take the fd.
    fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self(AsyncFd::new(fd)?))
    }

    /// Await the fd becoming readable: for a FIFO this resolves when a WRITER connects or writes (so the peer
    /// gets real bytes, not the instant EOF a writer-less nonblocking FIFO would read as). [`open_path`] bounds
    /// this with [`RAW_STREAM_OPEN_TIMEOUT`]; on elapse the fd is dropped, no thread ever parked.
    async fn readable(&self) -> io::Result<()> {
        self.0.readable().await?.retain_ready();
        Ok(())
    }
}

impl tokio::io::AsyncRead for NonblockingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut ready = match self.0.poll_read_ready(cx) {
                Poll::Ready(Ok(ready)) => ready,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            };
            // SAFETY: a `read(2)` writes at most `len` bytes into the fd's readable region of `buf` and never
            // reads the uninitialized tail, so the count it returns is exactly how many were initialized.
            let unfilled = unsafe { buf.unfilled_mut() };
            let rc = unsafe {
                libc::read(
                    std::os::fd::AsRawFd::as_raw_fd(self.0.get_ref()),
                    unfilled.as_mut_ptr().cast::<libc::c_void>(),
                    unfilled.len(),
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    // The reactor said readable but the read would block (a spurious wakeup): clear readiness
                    // and re-poll so the next wakeup re-arms it.
                    ready.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
            let n = rc as usize;
            // SAFETY: `read` initialized exactly `n` bytes of the unfilled region (checked `rc >= 0` above).
            unsafe { buf.assume_init(n) };
            buf.advance(n);
            return Poll::Ready(Ok(()));
        }
    }
}

/// An [`AsyncRead`](tokio::io::AsyncRead) over a REGULAR-file fd that reads INLINE, with NO reactor
/// registration. A regular file cannot go through [`NonblockingReader`]/[`AsyncFd`]: Linux `epoll` (mio's
/// backend) refuses a regular fd with `EPERM` at `epoll_ctl` registration, because a regular file has no
/// readiness to wait on: it is ALWAYS ready to read. (macOS `kqueue` accepts a regular fd, which is why that
/// break only surfaced on the Linux CI.) A regular-file `read(2)` never returns `EAGAIN` on local media
/// (`O_NONBLOCK`, guard 2, is a no-op on a regular file), so each poll reads straight through and returns
/// `Ready`. This keeps the regular-file path INLINE with no `spawn_blocking`, matching the guarded open above
/// (issue #25's no-leak stance). The one caveat is the SAME one the guarded open already documents: a read from
/// a hung mount (wedged NFS) can block the calling task; pool isolation for that is out of scope (TODO(#25-followup)).
struct RegularFileReader(OwnedFd);

impl tokio::io::AsyncRead for RegularFileReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: a `read(2)` writes at most `len` bytes into the fd's readable region of `buf` and never reads
        // the uninitialized tail, so the count it returns is exactly how many were initialized.
        let unfilled = unsafe { buf.unfilled_mut() };
        let rc = unsafe {
            libc::read(
                std::os::fd::AsRawFd::as_raw_fd(&self.0),
                unfilled.as_mut_ptr().cast::<libc::c_void>(),
                unfilled.len(),
            )
        };
        if rc < 0 {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }
        let n = rc as usize;
        // SAFETY: `read` initialized exactly `n` bytes of the unfilled region (checked `rc >= 0` above).
        unsafe { buf.assume_init(n) };
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

/// Whether fd 0 is a terminal. A `stdin:` expose with no pipe would consume the operator's keystrokes, so it
/// is refused at parse (guard 7). Uses `libc::isatty`, portable across unix; the non-unix stand-in uses the
/// platform's own check. Not a guard on the byte source (there is no path), just a misuse refusal.
pub(super) fn is_stdin_a_tty() -> bool {
    // SAFETY: `isatty` reads only the fd's terminal-ness and has no preconditions; fd 0 is always valid.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// A human name for an `S_IFMT`-masked `st_mode` file type, for the "not a regular file or a FIFO (...)"
/// refusal so the operator sees WHAT they pointed at (a device, a directory) rather than only that it was
/// rejected. `file_type` is already masked with `S_IFMT` and kept in `mode_t` space (`u16` on macOS, `u32` on
/// linux) so the comparisons below need no per-platform cast (see the note at the call site in `open_guarded`).
fn describe_type(file_type: libc::mode_t) -> &'static str {
    if file_type == libc::S_IFBLK {
        "a block device"
    } else if file_type == libc::S_IFCHR {
        "a character device"
    } else if file_type == libc::S_IFDIR {
        "a directory"
    } else if file_type == libc::S_IFLNK {
        "a symlink"
    } else if file_type == libc::S_IFSOCK {
        "a socket"
    } else if file_type == libc::S_IFIFO {
        "a FIFO"
    } else if file_type == libc::S_IFREG {
        "a regular file"
    } else {
        "an unknown type"
    }
}
