//! The raw-stream forward: open an already-existing OS object (a file or a FIFO named by the operator) and
//! splice its bytes toward the peer. This is the expose-side mirror of `connect --stdio` (which splices the
//! connector's own stdio): where `--stdio` pumps a running process's stdin/stdout, `file:<path>` /
//! `fifo:<path>` pump the bytes of a path the operator already made.
//!
//! It owns no lifecycle beyond the file descriptor (no child, nothing to reap), which is exactly what makes
//! it a [`crate::tunnel::Target`] forward and not a handler. But its input is an untrusted path resolved at
//! DIAL time, so every open goes through four guards, each named at its site below:
//!
//! 1. **Regular-file-or-FIFO only.** `fstat` the opened fd and allow ONLY `S_ISREG` or `S_ISFIFO`. A block
//!    or character device (`/dev/zero`, `/dev/urandom`) is an infinite drain; a directory or socket is not a
//!    byte source. All are refused, loudly at open, never as a hang.
//! 2. **Blocking-open timeout.** A `fifo:` `open()` for read blocks until a writer opens the other end;
//!    bound it with [`RAW_STREAM_OPEN_TIMEOUT`] so a FIFO whose writer never appears cannot pin the task.
//! 3. **No symlink / no traversal at the final component.** Open with `O_NOFOLLOW`, so a symlink AT the path
//!    the operator named is refused (a swapped final component cannot redirect the read). The path is not
//!    otherwise widened: the operator named it, and only it is opened.
//! 4. **Direction fixed at parse time.** A `file:`/`fifo:` is a SOURCE toward the peer (read the object, send
//!    its bytes). This type carries no writable direction at all, so "write peer bytes into a read-only
//!    file" is unrepresentable; the splice uses `splice_halves` with `io::sink()` upstream, never the
//!    duplex `splice`. A writable direction, if ever wanted, is a separate explicit thing, not this.

use std::os::fd::FromRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use crate::tunnel::RAW_STREAM_OPEN_TIMEOUT;

/// Which OS object types a raw-stream forward accepts. Both fix the direction (a read-only source toward the
/// peer); they differ only in the type guard, so the scheme the operator wrote is honored: `fifo:` insists
/// on a FIFO (a regular file behind it is a mistake to surface), `file:` accepts either.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `file:<path>` — a regular file or a FIFO. The general "the bytes at this path."
    File,
    /// `fifo:<path>` — a FIFO only. A regular file at the path is refused, because the operator asked for a
    /// named pipe (whose reopen-blocks-until-writer semantics are usually the point).
    Fifo,
}

/// A resolved raw-stream forward: an owned path and the type it must resolve to. Its direction is not a
/// field because there is only one (a read-only source toward the peer); a writable direction is
/// unrepresentable by construction.
#[derive(Debug, Clone)]
pub struct RawStream {
    path: PathBuf,
    kind: Kind,
}

impl RawStream {
    /// Parse a `file:<path>` tail into a raw-stream forward. Rejects an empty path at parse time (`file:`
    /// with no tail is a typo, not a target) so it fails loudly at expose, not at dial.
    pub fn file(path: &str, entry: &str) -> eyre::Result<Self> {
        Self::parse(path, Kind::File, entry, "file")
    }

    /// Parse a `fifo:<path>` tail into a raw-stream forward. Same shape as [`RawStream::file`], but the type
    /// guard at open will insist the path is a FIFO.
    pub fn fifo(path: &str, entry: &str) -> eyre::Result<Self> {
        Self::parse(path, Kind::Fifo, entry, "fifo")
    }

    fn parse(path: &str, kind: Kind, entry: &str, scheme: &str) -> eyre::Result<Self> {
        if path.is_empty() {
            eyre::bail!(
                "`{entry}` names a `{scheme}:` target with no path; write `{scheme}:<path>`, e.g. \
                 `pipe={scheme}:/tmp/beam`"
            );
        }
        Ok(Self {
            path: PathBuf::from(path),
            kind,
        })
    }

    /// Open the object under the four guards and return its bytes as an async reader (the source half of the
    /// splice). Errors (a device, a directory, a symlink at the final component, a FIFO with no writer
    /// within the timeout, a missing path) are returned as [`eyre::Error`] so the caller can refuse the
    /// stream cleanly rather than hang or reset mid-splice.
    pub async fn open(&self) -> eyre::Result<tokio::fs::File> {
        let path = self.path.clone();
        let kind = self.kind;
        // Guard 2 (blocking-open timeout): the `open()` itself blocks for a FIFO with no writer, so it runs
        // on a blocking thread bounded by the timeout. On elapse the open is abandoned (the blocking thread
        // completes or dies with the runtime); the stream is refused rather than pinned.
        let opened = tokio::time::timeout(
            RAW_STREAM_OPEN_TIMEOUT,
            tokio::task::spawn_blocking(move || open_guarded(&path, kind)),
        )
        .await;
        match opened {
            Ok(Ok(result)) => result,
            Ok(Err(join)) => Err(eyre::eyre!("raw-stream open task failed: {join}")),
            Err(_elapsed) => eyre::bail!(
                "opening {} timed out after {}s (a FIFO with no writer?)",
                self.path.display(),
                RAW_STREAM_OPEN_TIMEOUT.as_secs()
            ),
        }
    }
}

/// The blocking body of [`RawStream::open`]: open the final path component with `O_NOFOLLOW` (guard 3),
/// `fstat` the opened fd and enforce the type (guard 1). Runs on a blocking thread because a FIFO open
/// blocks until a writer appears; the caller bounds it with a timeout (guard 2).
fn open_guarded(path: &Path, kind: Kind) -> eyre::Result<tokio::fs::File> {
    // Guard 3 (no symlink / no traversal at the final component): `O_NOFOLLOW` refuses a symlink AT the path
    // the operator named, so a swapped final component (a TOCTOU race, or a planted symlink) cannot redirect
    // the read to another file. `O_RDONLY` fixes the direction at the syscall (guard 4): the fd can only be
    // read, so peer bytes can never be written into it. Blocking (no `O_NONBLOCK`) so a FIFO read gets a
    // real writer, with the timeout above as the bound.
    let mut c_path = path.as_os_str().as_bytes().to_vec();
    if c_path.contains(&0) {
        eyre::bail!("path {} contains a NUL byte", path.display());
    }
    c_path.push(0);
    // SAFETY: `c_path` is a NUL-terminated C string that outlives the call; the flags are valid; a failed
    // open returns -1 and is handled below, never wrapped as an fd.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
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
    // SAFETY: `fd` is a fresh, owned, valid descriptor (checked >= 0 above); `File::from_raw_fd` takes
    // ownership so it is closed on drop, including every early-return error path below.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    // Guard 1 (regular-file-or-FIFO only): `fstat` the fd we actually hold (not the path again, which would
    // reintroduce a TOCTOU) and allow ONLY a regular file or a FIFO. A block/char device (`/dev/zero`,
    // `/dev/urandom` = infinite drain), a directory, a socket: all refused.
    let meta = file
        .metadata()
        .map_err(|e| eyre::Error::from(e).wrap_err(format!("cannot stat {}", path.display())))?;
    // `MetadataExt::mode` is `u32`, but `libc::S_IF*` are `mode_t`, which is `u16` on some targets (macOS)
    // and `u32` on others (linux); widen the libc constants to `u32` so the mask compares on every platform.
    let file_type = std::os::unix::fs::MetadataExt::mode(&meta) & u32::from(libc::S_IFMT);
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

    Ok(tokio::fs::File::from_std(file))
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
    use std::io::Write as _;
    use core::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::RawStream;

    /// A unique scratch path under the OS temp dir (no tempfile dep), cleaned by the caller. Per-process +
    /// a counter so parallel tests never collide.
    fn scratch(tag: &str) -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("tightbeam-rawstream-{}-{tag}-{}", std::process::id(), n))
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
        let err = stream
            .open()
            .await
            .expect_err("/dev/zero must be refused, never opened as a byte source");
        let msg = err.to_string();
        assert!(
            msg.contains("not a regular file or a FIFO") && msg.contains("character device"),
            "the refusal must name the device type: {msg}"
        );
    }

    /// (c) direction is enforced: the opened source is read-only, so peer bytes can never be written into
    /// the file. The handle the splice reads from cannot be written; the splice pairs it with `io::sink()`
    /// upstream, so "write peer bytes into a read-only file" is unrepresentable rather than a runtime error.
    #[tokio::test]
    async fn direction_is_enforced_the_source_is_read_only() {
        let path = scratch("ro");
        let body = b"original contents";
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(body))
            .expect("write scratch file");

        let stream = RawStream::file(&path.to_string_lossy(), "x=file:y").expect("parse file:");
        let mut source = stream.open().await.expect("open regular file");
        // Writing to the read-only source fails: the fd is O_RDONLY, so peer bytes have nowhere to go.
        // (`tokio::fs::File` buffers, so the EBADF surfaces on flush, not necessarily the write call.)
        let wrote = async {
            source.write_all(b"peer bytes should never land here").await?;
            source.flush().await
        }
        .await;
        assert!(
            wrote.is_err(),
            "the source is read-only; writing peer bytes into it must fail, never corrupt the file"
        );
        drop(source);
        // The file on disk is byte-for-byte unchanged: nothing was written through the source handle.
        let after = std::fs::read(&path).expect("re-read file");
        assert_eq!(after, body, "the file must be untouched by the read-only source");

        let _ = std::fs::remove_file(&path);
    }

    /// A `fifo:` target refuses a regular file (the operator asked for a named pipe).
    #[tokio::test]
    async fn fifo_refuses_a_regular_file() {
        let path = scratch("notfifo");
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(b"x"))
            .expect("write scratch file");

        let stream = RawStream::fifo(&path.to_string_lossy(), "p=fifo:z").expect("parse fifo:");
        let err = stream
            .open()
            .await
            .expect_err("a regular file behind fifo: must be refused");
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
        let err = stream
            .open()
            .await
            .expect_err("a symlink at the final component must be refused by O_NOFOLLOW");
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
            RawStream::fifo("", "pipe=fifo:").is_err(),
            "`fifo:` with no path must be rejected at parse"
        );
    }
}
