//! The raw-stream forward: source an already-open byte stream and splice it toward the peer. The sources
//! share one shape, so `expose` treats them all as a read-only [`crate::tunnel::Target::RawStream`]
//! (inheriting the source-only splice and the public-gate refusal):
//!
//! - `file:<path>` / `fifo:<path>` — open an OS object the operator named on disk. Its input is an
//!   untrusted path resolved at DIAL time, so every open goes through four guards (each named at its site
//!   in [`open_guarded`]).
//! - `stdin:` — this process's own standard input (fd 0). No path, so none of the path guards apply; it is
//!   a SINGLE-CONSUMER source (fd 0 is one non-re-openable stream) taken once and never re-armed.
//! - `stdin:+lossy` / `fifo:<path>+lossy` — the operator's opt-in to FAN-OUT (delib-20 SYNTHESIS + delib-24):
//!   the source is opened ONCE and read by MANY consumers through one shared bounded ring, a consumer that
//!   falls behind having its bytes dropped rather than stalling the producer or the others. The `+lossy` claim
//!   ("this stream tolerates loss") is legal only on these live single-writer sources (a `file:` is already
//!   safe fan-out by re-open, so dropping would be corruption); the mechanism lives in
//!   [`crate::raw_stream_fanout`]. See [`Lossy`].
//!
//! The path forms mirror piping a service to the connector's stdout: where that pumps the far service to a
//! running process's stdout, `file:`/`fifo:` pump the bytes of a path the operator already made, and
//! `stdin:` pumps whatever a producer pipes into this process's standard input.
//!
//! The four path guards (`file:`/`fifo:` only; `stdin:` has no path and inherits NONE of them):
//!
//! 1. **Regular-file-or-FIFO only.** `fstat` the opened fd and allow ONLY `S_ISREG` or `S_ISFIFO`. A block
//!    or character device (`/dev/zero`, `/dev/urandom`) is an infinite drain; a directory or socket is not a
//!    byte source. All are refused, loudly at open, never as a hang.
//! 2. **Nonblocking open, bounded writer-wait.** The open uses `O_NONBLOCK`, so a read-only FIFO `open()`
//!    returns IMMEDIATELY with a valid fd even with no writer present: no thread ever parks in the syscall.
//!    But a writer-less FIFO reads as instant EOF, which is not a real byte stream, so the responder then
//!    awaits READABLE readiness on the fd (a writer connecting/writing) bounded by [`RAW_STREAM_OPEN_TIMEOUT`]
//!    via [`tokio::io::unix::AsyncFd`]. On elapse it drops the fd (cheap, no parked thread) and refuses,
//!    same message as a blocking timeout would have given. A regular file needs no writer, so it skips the
//!    wait and reads immediately.
//! 3. **No symlink / no traversal at the final component.** Open with `O_NOFOLLOW`, so a symlink AT the path
//!    the operator named is refused (a swapped final component cannot redirect the read). The path is not
//!    otherwise widened: the operator named it, and only it is opened.
//! 4. **Direction fixed at parse time.** A `file:`/`fifo:` is a SOURCE toward the peer (read the object, send
//!    its bytes). This type carries no writable direction at all, so "write peer bytes into a read-only
//!    file" is unrepresentable; the splice uses `splice_halves` with `io::sink()` upstream, never the
//!    duplex `splice`. A writable direction, if ever wanted, is a separate explicit thing, not this.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use tokio::io::unix::AsyncFd;

use crate::raw_stream_fanout::Fanout;
use crate::tunnel::{BoxRead, RAW_STREAM_OPEN_TIMEOUT, RawSource};

/// Which OS object types a path-based raw-stream forward accepts. Both fix the direction (a read-only source
/// toward the peer); they differ only in the type guard, so the scheme the operator wrote is honored:
/// `fifo:` insists on a FIFO (a regular file behind it is a mistake to surface), `file:` accepts either.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `file:<path>` — a regular file or a FIFO. The general "the bytes at this path."
    File,
    /// `fifo:<path>` — a FIFO only. A regular file at the path is refused, because the operator asked for a
    /// named pipe (whose reopen-blocks-until-writer semantics are usually the point).
    Fifo,
}

/// A resolved raw-stream forward: a read-only source of bytes toward the peer. Its direction is not a field
/// because there is only one (a writable direction is unrepresentable by construction). Either a path on disk
/// opened under the four guards, or this process's standard input taken once.
#[derive(Debug, Clone)]
pub struct RawStream(Source);

/// The sources a raw stream can splice from, sharing the read-only direction and the public-gate refusal.
#[derive(Debug, Clone)]
enum Source {
    /// A path (`file:`/`fifo:`) opened under the four guards. Cheap to clone (a path + a kind), re-opened per
    /// connection. What a re-open MEANS depends on the kind: a regular `file:` re-open is safe fan-out (each
    /// reader gets its own offset over the same static bytes, so two peers reading one file both see the whole
    /// file). A `fifo:` re-open is NOT fan-out: a FIFO is a stream, and concurrent readers of one writer SPLIT
    /// its bytes (each byte is delivered to exactly one reader), so two peers reading one live `fifo:` silently
    /// corrupt each other's stream. A `fifo:` is effectively single-consumer-at-a-time; expose one to one peer.
    Path { path: PathBuf, kind: Kind },
    /// This process's standard input (`stdin:`), a SINGLE-CONSUMER source: fd 0 is one non-re-openable
    /// stream, so it is taken once. See [`Stdin`].
    Stdin(Stdin),
    /// A `+lossy` fan-out source (`stdin:+lossy` / `fifo:...+lossy`): opened ONCE, then read by MANY consumers
    /// through one shared bounded ring with drop-for-slow. Opt-in and operator-declared (delib-20 SYNTHESIS +
    /// delib-24); the underlying source is lazy-opened on the first consumer. See [`Lossy`].
    Lossy(Lossy),
}

/// The take-once owner of a single-consumer reader (fd 0 for `stdin:`). `stdin:` names ONE non-re-openable OS
/// stream, so two concurrent readers would race and corrupt the byte order. The reader is modelled as an
/// owned resource in a shared cell: the FIRST [`RawStream::open`] that resolves `stdin:` TAKES it, and every
/// later concurrent open finds it gone and is refused. Making "two readers of one stdin" unrepresentable is
/// the whole point of the cell: once taken it is never put back, so on EOF or first-consumer disconnect it
/// does not re-arm. Holds a [`BoxRead`] so a test can arm the same take-once cell with an in-memory reader
/// and exercise the full served path without the process's real fd 0.
#[derive(Clone)]
struct Stdin(std::sync::Arc<std::sync::Mutex<Option<BoxRead>>>);

impl core::fmt::Debug for Stdin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stdin").finish_non_exhaustive()
    }
}

impl Stdin {
    /// Arm a single-consumer source over `reader`.
    fn new(reader: BoxRead) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(Some(reader))))
    }

    /// Take the reader, or refuse if a prior connection already holds it. `None` means "already in use": the
    /// caller turns it into a clean `Response::Error`, never a racing second read.
    fn take(&self) -> Option<BoxRead> {
        let Self(cell) = self;
        // A poisoned lock means a prior holder panicked mid-take; treat the source as taken (never hand out a
        // second reader) rather than unwrap. `PoisonError::into_inner` reads the guard without unwrapping.
        cell.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// A `+lossy` fan-out source: one underlying source opened ONCE, then read by MANY consumers through the
/// shared bounded ring in [`crate::raw_stream_fanout`]. The underlying source is opened lazily (on the first
/// consumer) because a `fifo:` open is async and fallible and must not run until someone actually connects;
/// the [`Opener`] is what to open. Once opened, the [`Fanout`] is memoized, so every later consumer attaches
/// to the SAME ring. The lazy-open transition is behind a `tokio::sync::Mutex` so "first consumer opens, the
/// rest attach" is a single critical section; the banner-facing [`RawSource`] is recorded ALONGSIDE it at
/// construction so a manifest read needs no async lock (and stays valid after the opener is taken).
#[derive(Clone)]
struct Lossy {
    source: RawSource,
    state: std::sync::Arc<tokio::sync::Mutex<LossyState>>,
}

/// The lazy-open state of a [`Lossy`] source: what to open on the first consumer, then the memoized fan-out.
struct LossyState {
    /// How to open the underlying source, taken once by the first consumer. `None` once opened (the fan-out
    /// owns the reader now) or once a `stdin:` session ran to completion (non-rewindable, never re-armed).
    opener: Option<Opener>,
    /// The shared fan-out, present once the source has been opened. Every consumer after the first attaches to
    /// this same ring.
    fanout: Option<Fanout>,
}

/// What a lazy [`Lossy`] source opens on its first consumer: a `fifo:` path opened under the guards, or a
/// ready `stdin:`-shaped reader taken directly (fd 0, or a test reader).
enum Opener {
    /// A `fifo:` path opened under the four guards on the first consumer.
    Fifo(PathBuf),
    /// A ready reader (fd 0 for `stdin:+lossy`, or a test reader) handed straight to the fan-out.
    Ready(BoxRead),
}

impl core::fmt::Debug for Lossy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Lossy").finish_non_exhaustive()
    }
}

impl Lossy {
    fn new(opener: Opener) -> Self {
        // Record the banner-facing source before the opener is moved into the shared state: a `fifo:+lossy`
        // names its absolute path, a `stdin:+lossy` (or a test reader) names the piped-stdin marker.
        let source = match &opener {
            Opener::Fifo(path) => RawSource::Path(absolute_display(path)),
            Opener::Ready(_) => RawSource::Stdin,
        };
        Self {
            source,
            state: std::sync::Arc::new(tokio::sync::Mutex::new(LossyState {
                opener: Some(opener),
                fanout: None,
            })),
        }
    }

    /// Attach a consumer: on the first, open the underlying source (a `fifo:` under the guards, or take the
    /// ready reader) and arm the shared fan-out; on every later consumer, attach to the same ring. A cursor is
    /// returned as a [`BoxRead`]. Refuses if the source already ran to completion and closed (a non-rewindable
    /// `stdin:+lossy` session): there is nothing left to attach to.
    async fn open(&self) -> eyre::Result<BoxRead> {
        let mut state = self.state.lock().await;
        // First consumer: open the source and arm the fan-out. The `fifo:` open is async and fallible, so a
        // failure here is returned as a clean refusal, never a half-armed fan-out.
        if let Some(opener) = state.opener.take() {
            let reader = match opener {
                Opener::Fifo(path) => open_path(path.clone(), Kind::Fifo).await?,
                Opener::Ready(reader) => reader,
            };
            state.fanout = Some(Fanout::new(reader));
        }
        let fanout = state
            .fanout
            .as_ref()
            .ok_or_else(|| eyre::eyre!("lossy source not armed"))?;
        match fanout.open() {
            Some(cursor) => Ok(Box::new(cursor)),
            None => eyre::bail!("this lossy source's live session has ended"),
        }
    }
}

impl RawStream {
    /// Parse a `file:<path>` tail into a raw-stream forward. Rejects an empty path at parse time (`file:`
    /// with no tail is a typo, not a target) so it fails loudly at expose, not at dial. `file:` is never
    /// `+lossy` (rejected upstream at parse): static bytes are already safe fan-out by re-open, so dropping
    /// bytes would be corruption, not loss-tolerance.
    pub fn file(path: &str, entry: &str) -> eyre::Result<Self> {
        Self::path(path, Kind::File, entry, "file")
    }

    /// Parse a `fifo:<path>` tail into a raw-stream forward. Same shape as [`RawStream::file`], but the type
    /// guard at open will insist the path is a FIFO. `lossy` (from a `+lossy` suffix) makes it a fan-out
    /// source: opened once, read by many consumers with drop-for-slow.
    pub fn fifo(path: &str, entry: &str, lossy: bool) -> eyre::Result<Self> {
        if path.is_empty() {
            eyre::bail!(
                "`{entry}` names a `fifo:` target with no path; write `fifo:<path>`, e.g. \
                 `pipe=fifo:/tmp/beam`"
            );
        }
        if lossy {
            return Ok(Self(Source::Lossy(Lossy::new(Opener::Fifo(
                PathBuf::from(path),
            )))));
        }
        Self::path(path, Kind::Fifo, entry, "fifo")
    }

    /// The `stdin:` source: this process's standard input. Refuses a TTY here, at parse time (loudly at
    /// expose), because a `stdin:` with no pipe would eat the operator's keystrokes, the analog of `file:`'s
    /// device refusal. Without `lossy` it is single-consumer (fd 0 is one non-re-openable stream, taken once);
    /// with `lossy` (a `+lossy` suffix) it is a fan-out source read by many consumers with drop-for-slow.
    pub fn stdin(lossy: bool) -> eyre::Result<Self> {
        if is_stdin_a_tty() {
            eyre::bail!(
                "stdin: has no pipe to read: fd 0 is a terminal, so it would consume your keystrokes. \
                 Pipe a producer in, e.g. `ffmpeg ... | tightbeam expose cam=stdin:`"
            );
        }
        let reader: BoxRead = Box::new(tokio::io::stdin());
        Ok(Self(if lossy {
            Source::Lossy(Lossy::new(Opener::Ready(reader)))
        } else {
            Source::Stdin(Stdin::new(reader))
        }))
    }

    /// A `stdin:`-shaped source over an arbitrary reader, for tests: arm the take-once cell (single-consumer)
    /// or the fan-out (`lossy`) with an in-memory reader so the full served path is exercised without the
    /// process's real fd 0. Not compiled into the binary.
    #[cfg(test)]
    pub(crate) fn from_reader(reader: BoxRead) -> Self {
        Self(Source::Stdin(Stdin::new(reader)))
    }

    /// A `stdin:+lossy`-shaped fan-out source over an arbitrary reader, for tests: arm the fan-out with an
    /// in-memory reader so the shared-ring served path is exercised without the process's real fd 0.
    #[cfg(test)]
    pub(crate) fn lossy_from_reader(reader: BoxRead) -> Self {
        Self(Source::Lossy(Lossy::new(Opener::Ready(reader))))
    }

    fn path(path: &str, kind: Kind, entry: &str, scheme: &str) -> eyre::Result<Self> {
        if path.is_empty() {
            eyre::bail!(
                "`{entry}` names a `{scheme}:` target with no path; write `{scheme}:<path>`, e.g. \
                 `pipe={scheme}:/tmp/beam`"
            );
        }
        Ok(Self(Source::Path {
            path: PathBuf::from(path),
            kind,
        }))
    }

    /// Open the source and return its bytes as an async reader (the source half of the splice). For a path,
    /// this opens the object under the four guards; errors (a device, a directory, a symlink at the final
    /// component, a FIFO with no writer within the timeout, a missing path) are returned so the caller can
    /// refuse cleanly rather than hang or reset mid-splice. For `stdin:`, this TAKES fd 0 once: a second
    /// concurrent open finds it already in use and is refused, never a racing second read. For a `+lossy`
    /// source, this attaches a fan-out cursor (opening the underlying source on the first consumer).
    pub async fn open(&self) -> eyre::Result<BoxRead> {
        let Self(source) = self;
        match source {
            Source::Path { path, kind } => open_path(path.clone(), *kind).await,
            Source::Stdin(stdin) => match stdin.take() {
                Some(reader) => Ok(reader),
                None => eyre::bail!("stdin is a single-consumer source, already in use"),
            },
            Source::Lossy(lossy) => lossy.open().await,
        }
    }

    /// The [`RawSource`] a caller's banner names in its unsafe warning: which bytes reach a stranger when this
    /// stream is served open. A path source resolves to its ABSOLUTE path (lexically, via
    /// [`std::path::absolute`]: no FS access, no symlink follow, no existence requirement, so a not-yet-created
    /// `fifo:` still renders); a `stdin:` source has no path (the risk is this process's piped input). NOT
    /// [`Path::canonicalize`], which hits the FS, follows symlinks, and fails for a `fifo:` that does not exist
    /// yet; the operator's security question is "which path did I name", made unambiguous, and the
    /// `O_NOFOLLOW` guard already refuses a symlink at open. A `+lossy` source reports its underlying kind's
    /// source, recorded at construction.
    pub fn raw_source(&self) -> RawSource {
        let Self(source) = self;
        match source {
            Source::Path { path, .. } => RawSource::Path(absolute_display(path)),
            Source::Stdin(_) => RawSource::Stdin,
            Source::Lossy(lossy) => RawSource::clone(&lossy.source),
        }
    }
}

/// Render `path` as an ABSOLUTE, lexically-resolved string for a banner's unsafe warning: [`std::path::absolute`]
/// prepends the CWD and normalizes `.`/`..` WITHOUT touching the filesystem, so it is infallible in practice,
/// works before the file exists (a not-yet-created `fifo:`), and follows no symlink. On the rare error (an
/// empty path, or a CWD that cannot be read) it falls back to the operator's path verbatim rather than failing
/// a banner. Deliberately not `canonicalize`: the security-relevant fact is which path was NAMED, not where a
/// symlink would resolve.
fn absolute_display(path: &Path) -> String {
    std::path::absolute(path)
        .map(|absolute| absolute.display().to_string())
        .unwrap_or_else(|_| path.display().to_string())
}

/// Open a path source under the four guards and box its reader. Split out from [`RawStream::open`] so the
/// `stdin:` arm (no path, no guards) reads cleanly beside it. The guarded open is NONBLOCKING (guard 2), so it
/// never parks a thread: for a FIFO it returns a valid fd at once even with no writer, and this function then
/// awaits a WRITER (readable readiness) bounded by [`RAW_STREAM_OPEN_TIMEOUT`] before handing back the stream,
/// so the peer gets real bytes, not an instant writer-less EOF. A regular file has no writer to wait for and
/// is handed back immediately.
async fn open_path(path: PathBuf, kind: Kind) -> eyre::Result<BoxRead> {
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
fn set_writer_wait_timeout_for_test(millis: u64) -> impl Drop {
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
    // Mask in `mode_t` space (`st_mode` and the `S_IF*` constants share that type, `u16` on macOS / `u32` on
    // linux), then widen the masked result ONCE to `u32` for the platform-independent `describe_type` and the
    // comparisons below. Masking first keeps this free of a per-platform `u32::from` that would be an identity
    // conversion (clippy `useless_conversion`) where `mode_t` is already `u32`.
    let file_type = u32::from(st.st_mode & libc::S_IFMT);
    let is_reg = file_type == u32::from(libc::S_IFREG);
    let is_fifo = file_type == u32::from(libc::S_IFIFO);
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
fn is_stdin_a_tty() -> bool {
    // SAFETY: `isatty` reads only the fd's terminal-ness and has no preconditions; fd 0 is always valid.
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// A human name for an `S_IFMT`-masked `st_mode` file type, for the "not a regular file or a FIFO (...)"
/// refusal so the operator sees WHAT they pointed at (a device, a directory) rather than only that it was
/// rejected. `file_type` is already masked with `S_IFMT`; the libc constants are widened to `u32` to match.
fn describe_type(file_type: u32) -> &'static str {
    if file_type == u32::from(libc::S_IFBLK) {
        "a block device"
    } else if file_type == u32::from(libc::S_IFCHR) {
        "a character device"
    } else if file_type == u32::from(libc::S_IFDIR) {
        "a directory"
    } else if file_type == u32::from(libc::S_IFLNK) {
        "a symlink"
    } else if file_type == u32::from(libc::S_IFSOCK) {
        "a socket"
    } else if file_type == u32::from(libc::S_IFIFO) {
        "a FIFO"
    } else if file_type == u32::from(libc::S_IFREG) {
        "a regular file"
    } else {
        "an unknown type"
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::io::Write as _;

    use tokio::io::AsyncReadExt as _;

    use super::RawStream;

    /// A unique scratch path under the OS temp dir (no tempfile dep), cleaned by the caller. Per-process +
    /// a counter so parallel tests never collide.
    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "tightbeam-rawstream-{}-{tag}-{}",
            std::process::id(),
            n
        ))
    }

    /// Make a fresh scratch FIFO with `mkfifo`, cleaned by the caller.
    fn scratch_fifo(tag: &str) -> std::path::PathBuf {
        let path = scratch(tag);
        let mut c_path = path.clone().into_os_string().into_encoded_bytes();
        c_path.push(0);
        // SAFETY: `c_path` is a NUL-terminated C string that outlives the call; a failed `mkfifo` returns -1
        // and the assert fails. Mode 0600: scratch, this process only.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr().cast::<libc::c_char>(), 0o600) };
        assert_eq!(rc, 0, "mkfifo {} failed", path.display());
        path
    }

    /// (a) `file:` to a regular file sources its exact bytes.
    #[tokio::test]
    async fn file_sources_a_regular_files_bytes() {
        let path = scratch("reg");
        let body = b"hello from the host\n";
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(body))
            .expect("write scratch file");

        let stream = RawStream::file(&path.to_string_lossy(), "pipe=file:x").expect("parse file:");
        let mut source = stream.open().await.expect("open regular file");
        let mut got = Vec::new();
        source.read_to_end(&mut got).await.expect("read source");
        assert_eq!(got, body, "the source half yields the file's exact bytes");

        let _ = std::fs::remove_file(&path);
    }

    /// (b) a device path (`/dev/zero`, a character device = infinite drain) is REFUSED, not streamed.
    #[tokio::test]
    async fn a_device_path_is_refused() {
        let stream = RawStream::file("/dev/zero", "drain=file:/dev/zero").expect("parse file:");
        let Err(err) = stream.open().await else {
            panic!("/dev/zero must be refused, never opened as a byte source");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("not a regular file or a FIFO") && msg.contains("character device"),
            "the refusal must name the device type: {msg}"
        );
    }

    /// (c) direction is enforced structurally: `open` yields a read-only [`super::BoxRead`], so there is no
    /// writable handle to push peer bytes back through. The splice pairs it with `io::sink()` upstream, so
    /// "write peer bytes into a read-only file" is unrepresentable rather than a runtime error. Assert the
    /// file on disk is untouched after the source is fully read and dropped.
    #[tokio::test]
    async fn direction_is_enforced_the_source_is_read_only() {
        let path = scratch("ro");
        let body = b"original contents";
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(body))
            .expect("write scratch file");

        let stream = RawStream::file(&path.to_string_lossy(), "x=file:y").expect("parse file:");
        let mut source = stream.open().await.expect("open regular file");
        let mut got = Vec::new();
        source.read_to_end(&mut got).await.expect("read source");
        drop(source);
        // The file on disk is byte-for-byte unchanged: the source is read-only, nothing could be written.
        let after = std::fs::read(&path).expect("re-read file");
        assert_eq!(
            after, body,
            "the file must be untouched by the read-only source"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A `fifo:` target refuses a regular file (the operator asked for a named pipe).
    #[tokio::test]
    async fn fifo_refuses_a_regular_file() {
        let path = scratch("notfifo");
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(b"x"))
            .expect("write scratch file");

        let stream =
            RawStream::fifo(&path.to_string_lossy(), "p=fifo:z", false).expect("parse fifo:");
        let Err(err) = stream.open().await else {
            panic!("a regular file behind fifo: must be refused");
        };
        assert!(
            err.to_string().contains("not a FIFO"),
            "the refusal must say it is not a FIFO: {err}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A symlink at the final component is refused by `O_NOFOLLOW` (guard 3): a swapped/planted symlink
    /// cannot redirect the read to another file.
    #[tokio::test]
    async fn a_symlink_at_the_final_component_is_refused() {
        let target = scratch("symtarget");
        std::fs::File::create(&target)
            .and_then(|mut f| f.write_all(b"secret"))
            .expect("write target");
        let link = scratch("symlink");
        std::os::unix::fs::symlink(&target, &link).expect("make symlink");

        let stream = RawStream::file(&link.to_string_lossy(), "s=file:l").expect("parse file:");
        let Err(err) = stream.open().await else {
            panic!("a symlink at the final component must be refused by O_NOFOLLOW");
        };
        assert!(
            err.to_string().contains("symlink"),
            "the refusal must name the symlink guard: {err}"
        );

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    /// An empty path fails at PARSE time (loudly at expose), not at dial.
    #[test]
    fn an_empty_path_is_rejected_at_parse() {
        assert!(
            RawStream::file("", "pipe=file:").is_err(),
            "`file:` with no path must be rejected at parse"
        );
        assert!(
            RawStream::fifo("", "pipe=fifo:", false).is_err(),
            "`fifo:` with no path must be rejected at parse"
        );
    }

    /// `stdin:` is a SINGLE-CONSUMER source: the first `open` takes the reader, and a second CONCURRENT open
    /// finds it already in use and is refused cleanly, never a racing second read. Uses `from_reader` so the
    /// take-once cell is exercised deterministically, independent of the runner's real fd 0. The first open
    /// also yields the source's exact bytes.
    #[tokio::test]
    async fn stdin_is_taken_once_and_the_second_open_is_refused() {
        let body = b"piped bytes into the exposer";
        let stream = RawStream::from_reader(Box::new(&body[..]));
        // Clone the resolved stream the way `Services` does: both clones share ONE take-once cell.
        let second = stream.clone();
        let mut first = stream
            .open()
            .await
            .expect("the first open takes the source");
        let mut got = Vec::new();
        first.read_to_end(&mut got).await.expect("read the source");
        assert_eq!(
            got, body,
            "the first consumer gets the source's exact bytes"
        );
        let Err(err) = second.open().await else {
            panic!("a second concurrent open must be refused, not a racing second read");
        };
        assert!(
            err.to_string()
                .contains("single-consumer source, already in use"),
            "the refusal must name the single-consumer contract: {err}"
        );
    }

    /// (a) NO-LEAK: a writer-less `fifo:` open times out cleanly and parks NO blocking-pool thread (issue #25).
    /// Proven deterministically, no thread counting: run on a runtime whose BLOCKING pool holds exactly ONE
    /// thread (`max_blocking_threads(1)`) and open many writer-less FIFOs in sequence. The OLD blocking open ran
    /// inside `spawn_blocking` and would LEAK its one parked thread on the very first writer-less open, so the
    /// second `spawn_blocking` (or any other blocking work) would starve forever and this test would hang. The
    /// nonblocking open uses NO `spawn_blocking` for the FIFO open, so all N sail through and each still refuses
    /// on the writer-wait timeout. The whole loop is itself bounded by an outer timeout, so a regression HANGS
    /// -> fails, it does not pass slowly.
    #[test]
    fn writerless_fifo_opens_do_not_park_the_blocking_pool() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("build a single-blocking-thread runtime");
        runtime.block_on(async {
            // Hold the writer-wait lock so the flood test (which needs the wait LONG) cannot run while we
            // shrink it below.
            let _lock = super::WRITER_WAIT_TEST_LOCK.lock().await;
            const N: usize = 16;
            // Shrink the writer-wait so each writer-less open refuses in ~50ms instead of the production budget.
            let _short = super::set_writer_wait_timeout_for_test(50);
            let loop_body = async {
                for _ in 0..N {
                    let fifo = scratch_fifo("noleak");
                    let stream =
                        RawStream::fifo(&fifo.to_string_lossy(), "pipe=fifo:x", false).expect("parse fifo:");
                    let opened = stream.open().await;
                    assert!(
                        opened.is_err(),
                        "a writer-less FIFO open must be REFUSED (no writer), not returned as a stream"
                    );
                    let _ = std::fs::remove_file(&fifo);
                }
            };
            // Generous outer bound: if a regression reintroduces `spawn_blocking`, the FIRST open leaks the lone
            // blocking thread and the loop stalls, tripping this timeout instead of passing.
            tokio::time::timeout(core::time::Duration::from_secs(20), loop_body)
                .await
                .expect("writer-less FIFO opens must not park the blocking pool (issue #25 regression)");
        });
    }

    /// (b) A `fifo:` WITH a writer streams its bytes end to end: the open resolves when the writer connects, and
    /// the reader yields exactly what the writer wrote (proving the writer-wait detects a real writer and the
    /// nonblocking read adapter delivers the bytes, not an empty EOF).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fifo_with_a_writer_streams_its_bytes() {
        let fifo = scratch_fifo("writer");
        let body = b"streamed through a named pipe";

        // Write from a blocking thread: opening a FIFO for write blocks until the reader's open is present,
        // which the `stream.open()` below provides.
        let writer_path = fifo.clone();
        let writer = tokio::task::spawn_blocking(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .and_then(|mut f| f.write_all(body))
                .expect("write into the FIFO");
        });

        let stream =
            RawStream::fifo(&fifo.to_string_lossy(), "pipe=fifo:x", false).expect("parse fifo:");
        let mut source = stream.open().await.expect("open the FIFO with a writer");
        writer.await.expect("writer task");
        let mut got = Vec::new();
        source.read_to_end(&mut got).await.expect("read the stream");
        assert_eq!(got, body, "a FIFO with a writer streams its exact bytes");

        let _ = std::fs::remove_file(&fifo);
    }
}
