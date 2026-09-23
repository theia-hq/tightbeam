//! The raw-stream forward: source an already-open byte stream and splice it toward the peer. The sources
//! share one shape, so `expose` treats them all as a read-only `crate::tunnel::router::Target::RawStream`
//! (inheriting the source-only splice and the public-gate refusal):
//!
//! - `file:<path>` / `fifo:<path>`: open an OS object the operator named on disk. Its input is an
//!   untrusted path resolved at DIAL time, so every open goes through four guards (each named at its site
//!   in `guarded::open_guarded`).
//! - `stdin:`: this process's own standard input (fd 0). No path, so none of the path guards apply. fd 0
//!   is one non-re-openable stream, so it is a SEAT: one peer reads it at a time, and it goes back to the
//!   next peer when that one leaves, until end of input. See [`seat`].
//! - `stdin:+lossy` / `fifo:<path>+lossy`: the operator's opt-in to FAN-OUT:
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
//! Every live source (`stdin:`, `fifo:`, either `+lossy`) is attach-at-current: a peer reads from wherever
//! the stream is when it connects, never from byte 0, and a peer displaced from a `stdin:` seat sees its
//! stream end as if the input had.
//!
//! The four path guards (`file:`/`fifo:` only; `stdin:` has no path and inherits NONE of them). They are
//! the one unix-only piece of a raw stream and live in `guarded`, which a non-unix build swaps for a
//! stand-in that refuses a path loudly; everything else here is one portable definition.
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

use std::path::{Path, PathBuf};

use bifrost::NodeId;

use crate::raw_stream_fanout::{Fanout, Lifetime};
use crate::tunnel::{BoxRead, RawSource};

#[cfg_attr(not(unix), path = "raw_stream/guarded_unsupported.rs")]
mod guarded;
mod seat;
#[cfg(test)]
mod seat_tests;

#[cfg(all(test, unix))]
pub(crate) use guarded::{WRITER_WAIT_TEST_LOCK, set_writer_wait_timeout_for_test};
pub(crate) use seat::Seated;

/// Which OS object types a path-based raw-stream forward accepts. Both fix the direction (a read-only source
/// toward the peer); they differ only in the type guard, so the scheme the operator wrote is honored:
/// `fifo:` insists on a FIFO (a regular file behind it is a mistake to surface), `file:` accepts either.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `file:<path>`: a regular file or a FIFO. The general "the bytes at this path."
    File,
    /// `fifo:<path>`: a FIFO only. A regular file at the path is refused, because the operator asked for a
    /// named pipe (whose reopen-blocks-until-writer semantics are usually the point).
    Fifo,
}

/// A resolved raw-stream forward: a read-only source of bytes toward the peer. Its direction is not a field
/// because there is only one (a writable direction is unrepresentable by construction). Either a path on disk
/// opened under the four guards, or this process's standard input lent to one peer at a time.
#[derive(Debug, Clone)]
pub struct RawStream(Source);

/// An opened raw stream, as the served path splices it. A `stdin:` seat is its own arm because its splice is
/// metered and can be handed to another peer; carrying that in the type means the served path cannot open
/// a seat and splice it as a plain stream.
pub(crate) enum Opened {
    /// A path's reader or a `+lossy` cursor: splice it until it ends.
    Stream(BoxRead),
    /// The `stdin:` seat, taken: splice it through [`Seated::splice`].
    Seat(Seated),
}

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
    /// This process's standard input (`stdin:`): fd 0 is one non-re-openable stream, so one peer reads it
    /// at a time and it is handed back on release. See [`seat`].
    Stdin(seat::Seat),
    /// A `+lossy` fan-out source (`stdin:+lossy` / `fifo:...+lossy`): opened ONCE, then read by MANY consumers
    /// through one shared bounded ring with drop-for-slow. Loss is never inferred: the operator declares it
    /// on the target, and the underlying source is lazy-opened on the first consumer. See [`Lossy`].
    Lossy(Lossy),
}

/// A `+lossy` fan-out source: one underlying source opened ONCE, then read by MANY consumers through the
/// shared bounded ring in [`crate::raw_stream_fanout`]. The underlying source is opened lazily (on the first
/// consumer) because a `fifo:` open is async and fallible and must not run until someone actually connects;
/// the [`Opener`] is what to open. Once opened, the [`Fanout`] is memoized, so every later consumer attaches
/// to the SAME ring. A `fifo:` session that ends (its pump exited) re-arms for the next consumer, matching
/// plain `fifo:` re-open-per-dial. A `stdin:` session is one session, ever (fd 0 cannot rewind), and it
/// runs until end of input whether or not anyone is watching: its pump is [`Lifetime::UntilEof`], so a
/// viewer that connects and leaves never ends the feed for the viewers after it. The
/// lazy-open transition is behind a `tokio::sync::Mutex` so "first consumer opens, the rest attach" is a
/// single critical section; the banner-facing [`RawSource`] is recorded ALONGSIDE it at construction so a
/// manifest read needs no async lock (and stays valid after the opener is taken).
#[derive(Clone)]
struct Lossy {
    source: RawSource,
    state: std::sync::Arc<tokio::sync::Mutex<LossyState>>,
}

/// The lazy-open state of a [`Lossy`] source: what to open on the first consumer, then the memoized fan-out.
struct LossyState {
    /// How to open the underlying source, taken once by the first consumer. `None` once opened (the fan-out
    /// owns the reader now) or once a `stdin:` session ran to completion (non-rewindable, never re-armed). A
    /// `fifo:` session restores this when it ends, so the next consumer starts a fresh session (see `fifo`).
    opener: Option<Opener>,
    /// The `fifo:` path a new session re-opens after the last one ended (`None` for a `stdin:`/test reader,
    /// which is one session, ever). Retained beside `opener` because `opener` is cleared when a session arms;
    /// the path must survive to re-arm, exactly like the plain `fifo:` open-per-dial contract.
    fifo: Option<PathBuf>,
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
        // names its absolute path, a `stdin:+lossy` (or a test reader) names the piped-stdin marker. The
        // `fifo:` path is ALSO kept separately: the opener is cleared when a session arms, and the path must
        // survive to re-arm a new session when that one ends (A-2).
        let source = match &opener {
            Opener::Fifo(path) => RawSource::Path(absolute_display(path)),
            Opener::Ready(_) => RawSource::Stdin,
        };
        let fifo = match &opener {
            Opener::Fifo(path) => Some(path.clone()),
            Opener::Ready(_) => None,
        };
        Self {
            source,
            state: std::sync::Arc::new(tokio::sync::Mutex::new(LossyState {
                opener: Some(opener),
                fifo,
                fanout: None,
            })),
        }
    }

    /// Attach a consumer: on the first, open the underlying source (a `fifo:` under the guards, or take the
    /// ready reader) and arm the shared fan-out; on every later consumer, attach to the same ring. A cursor is
    /// returned as a [`BoxRead`]. A `fifo:` source whose session ended re-arms here (a fresh open, up to the
    /// full writer-wait); a non-rewindable `stdin:+lossy` session that ended refuses: there is nothing left
    /// to attach to.
    ///
    /// The opener is a PEEK-AND-COMMIT, never a take: a `fifo:` open is async and fallible, so the path
    /// crosses the await as a clone and the armed opener is cleared only on success. A failed (or cancelled)
    /// attempt therefore leaves the source armed for the next consumer instead of disarming it for good, and
    /// the next consumer reports its OWN attempt's outcome (the open error, never a stale "not armed").
    /// Retries serialize on this mutex, one attempt at a time: each gets the full writer-wait and a fresh
    /// raw-open permit, exactly like a first dial, so N concurrent first dials against a writer-less FIFO
    /// cost N writer-waits with N raw-open permits held for the batch (bounded by `RAW_STREAM_OPEN_TIMEOUT`
    /// and `RAW_STREAM_OPEN_PERMITS`, which are the existing bounds; no backoff, no attempt counter).
    async fn open(&self) -> eyre::Result<BoxRead> {
        let mut state = self.state.lock().await;
        loop {
            // First consumer (or the first of a re-armed `fifo:` session): open the source and arm the
            // fan-out. A `fifo:` failure returns as a clean refusal with the opener still armed; a `Ready`
            // reader cannot fail, so it is taken once and never restored.
            if state.fanout.is_none() {
                // Peek the `fifo:` path out as a CLONE; the opener itself stays armed until the open
                // returns `Ok`, so a failed or cancelled attempt never disarms the source (A-1).
                let path = if let Some(Opener::Fifo(path)) = &state.opener {
                    Some(path.clone())
                } else {
                    None
                };
                if let Some(path) = path {
                    let reader = guarded::open_path(path, Kind::Fifo).await?;
                    state.opener = None;
                    // A `fifo:` pump lets go once nobody watches, so the next session can re-open the
                    // path without two readers splitting one FIFO.
                    state.fanout = Some(Fanout::new(reader, Lifetime::WhileWatched));
                } else if let Some(Opener::Ready(reader)) = state.opener.take() {
                    // fd 0 cannot be re-opened, so letting go of it frees nothing and ends the feed for
                    // everyone after: its pump runs to end of input.
                    state.fanout = Some(Fanout::new(reader, Lifetime::UntilEof));
                }
            }
            let fanout = state
                .fanout
                .as_ref()
                .ok_or_else(|| eyre::eyre!("lossy source not armed"))?;
            match fanout.open() {
                Some(cursor) => return Ok(Box::new(cursor)),
                // The memoized fan-out's session ended (its pump exited). A `fifo:` re-arms: drop the
                // finished fan-out, restore the opener, and loop to open a fresh session. A `stdin:` (or a
                // test reader) cannot rewind: refuse, as documented.
                None => match &state.fifo {
                    Some(path) => {
                        let path = path.clone();
                        state.fanout = None;
                        state.opener = Some(Opener::Fifo(path));
                    }
                    None => eyre::bail!("this lossy source's live session has ended"),
                },
            }
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
    /// device refusal. Without `lossy` it is a seat (fd 0 is one non-re-openable stream, read by one peer at
    /// a time and handed on); with `lossy` (a `+lossy` suffix) it is a fan-out source read by many consumers
    /// with drop-for-slow.
    pub fn stdin(lossy: bool) -> eyre::Result<Self> {
        if guarded::is_stdin_a_tty() {
            eyre::bail!(
                "stdin: has no pipe to read: fd 0 is a terminal, so it would consume your keystrokes. \
                 pipe a producer in instead of serving a terminal"
            );
        }
        let reader: BoxRead = Box::new(tokio::io::stdin());
        Ok(Self(if lossy {
            Source::Lossy(Lossy::new(Opener::Ready(reader)))
        } else {
            Source::Stdin(seat::Seat::new(reader))
        }))
    }

    /// A `stdin:`-shaped source over an arbitrary reader, for tests: arm the seat
    /// or the fan-out (`lossy`) with an in-memory reader so the full served path is exercised without the
    /// process's real fd 0. Not compiled outside tests.
    #[cfg(test)]
    pub(crate) fn from_reader(reader: BoxRead) -> Self {
        Self(Source::Stdin(seat::Seat::new(reader)))
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

    /// Open the source for `peer` (the transport-attested dialer) and return its bytes: a plain reader, or a
    /// taken [`Seated`] for `stdin:`. For a path, this opens the object under the four guards; errors (a
    /// device, a directory, a symlink at the final component, a FIFO with no writer within the timeout, a
    /// missing path) are returned so the caller can refuse cleanly rather than hang or reset mid-splice. For
    /// `stdin:`, this claims the seat for `peer`: refused while another peer holds it and after end of input,
    /// never a racing second read. For a `+lossy` source, this attaches a fan-out cursor (opening the
    /// underlying source on the first consumer). Only `stdin:` reads `peer`.
    pub(crate) async fn open(&self, peer: NodeId) -> eyre::Result<Opened> {
        let Self(source) = self;
        match source {
            Source::Path { path, kind } => guarded::open_path(path.clone(), *kind)
                .await
                .map(Opened::Stream),
            Source::Stdin(seat) => Ok(Opened::Seat(seat.claim(peer).await?)),
            Source::Lossy(lossy) => lossy.open().await.map(Opened::Stream),
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

    /// Validate a PATH source at SERVE time, before the readiness banner advertises it as open to strangers
    /// (the unsafe raw-stream opt-in set). The connect-time guards (`guarded::open_guarded`) refuse a device, a
    /// directory, a socket, and a symlink at the final component, so a banner naming one as "serving the raw
    /// bytes of ..." over-claims bytes the node will ALWAYS refuse at dial. This is the serve-time twin of that
    /// type guard: `lstat` the path and refuse the STABLE always-refused types loudly HERE, word-for-word the
    /// same refusals `guarded::open_guarded` gives, so the banner and the guard agree.
    ///
    /// A path that does not exist yet is ALLOWED (a `fifo:`/`file:` source may be created before a dial,
    /// matching the lexical, no-FS rendering in [`raw_source`](Self::raw_source)); the nonblocking open at dial
    /// is the definitive guard for the missing-path case. `stdin:` (no path) is always servable.
    pub fn check_open_source(&self) -> eyre::Result<()> {
        let Self(source) = self;
        match source {
            Source::Path { path, kind } => guarded::check_open_path(path, *kind),
            Source::Stdin(_) => Ok(()),
            // A `+lossy` source is `fifo:`/`stdin:` only (`file:` is rejected upstream), so a lossy PATH is a
            // FIFO; validate its recorded absolute path the same way. A `stdin:+lossy` has no path to check.
            Source::Lossy(lossy) => match &lossy.source {
                RawSource::Path(path) => guarded::check_open_path(Path::new(path), Kind::Fifo),
                RawSource::Stdin => Ok(()),
            },
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

#[cfg(all(test, unix))]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};
    use std::io::Write as _;

    use tokio::io::AsyncReadExt as _;

    use super::{Opened, RawStream};
    use crate::tunnel::BoxRead;

    /// Open `stream` as the served path would, for one fixed dialer, and hand back its reader. Every
    /// source here is a path or a `+lossy` fan-out; the `stdin:` seat has its own tests.
    async fn open(stream: &RawStream) -> eyre::Result<BoxRead> {
        match stream
            .open(bifrost::NodeId::from_ed25519_secret(&[1u8; 32]))
            .await?
        {
            Opened::Stream(reader) => Ok(reader),
            Opened::Seat(_) => eyre::bail!("a path or fan-out source never opens as a seat"),
        }
    }

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
        mkfifo_at(&path);
        path
    }

    /// `mkfifo` at `path`, failing the test if it cannot. Mode 0600: scratch, this process only.
    fn mkfifo_at(path: &std::path::Path) {
        let mut c_path = path.to_path_buf().into_os_string().into_encoded_bytes();
        c_path.push(0);
        // SAFETY: `c_path` is a NUL-terminated C string that outlives the call; a failed `mkfifo` returns -1
        // and the assert fails.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr().cast::<libc::c_char>(), 0o600) };
        assert_eq!(rc, 0, "mkfifo {} failed", path.display());
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
        let mut source = open(&stream).await.expect("open regular file");
        let mut got = Vec::new();
        source.read_to_end(&mut got).await.expect("read source");
        assert_eq!(got, body, "the source half yields the file's exact bytes");

        let _ = std::fs::remove_file(&path);
    }

    /// (b) a device path (`/dev/zero`, a character device = infinite drain) is REFUSED, not streamed.
    #[tokio::test]
    async fn a_device_path_is_refused() {
        let stream = RawStream::file("/dev/zero", "drain=file:/dev/zero").expect("parse file:");
        let Err(err) = open(&stream).await else {
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
        let mut source = open(&stream).await.expect("open regular file");
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
        let Err(err) = open(&stream).await else {
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
        let Err(err) = open(&stream).await else {
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
                    let opened = open(&stream).await;
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
        // which the `open(&stream)` below provides.
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
        let mut source = open(&stream).await.expect("open the FIFO with a writer");
        writer.await.expect("writer task");
        let mut got = Vec::new();
        source.read_to_end(&mut got).await.expect("read the stream");
        assert_eq!(got, body, "a FIFO with a writer streams its exact bytes");

        let _ = std::fs::remove_file(&fifo);
    }

    /// A-1 (wedge pin): a failed first `fifo:` open must not consume the opener. The first open over a
    /// missing path fails with the open error, and a second open must fail with the SAME open error (the
    /// path is still absent), never the disarm message. Red on the shipped code, where the opener was taken
    /// before the fallible open, so the second open read "lossy source not armed" for the life of the node.
    #[tokio::test]
    async fn lossy_fifo_failed_first_open_leaves_the_source_retryable() {
        let path = scratch("lossy-missing");
        let stream = RawStream::fifo(&path.to_string_lossy(), "cam=fifo:x+lossy", true)
            .expect("parse fifo:+lossy");
        let Err(first) = open(&stream).await else {
            panic!("an absent path must refuse the first open");
        };
        assert!(
            first.to_string().contains("cannot open"),
            "the first refusal names the open failure: {first}"
        );
        let Err(second) = open(&stream).await else {
            panic!("the path is still absent, so the retry must refuse too");
        };
        assert!(
            second.to_string().contains("cannot open"),
            "the retry re-attempts the open rather than reading a disarmed source: {second}"
        );
        assert!(
            !second.to_string().contains("not armed"),
            "a failed open must leave the source armed for the next consumer: {second}"
        );
    }

    /// A-1 (fail-then-writer pin): after a failed first open, creating the FIFO and connecting a writer lets
    /// the NEXT consumer open the source and receive exactly the bytes written. The service is not disarmed
    /// by the failed attempt; the bytes, not only an `Ok`, are pinned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lossy_fifo_first_open_failure_then_a_writer_streams() {
        let path = scratch("lossy-then-fifo");
        let stream = RawStream::fifo(&path.to_string_lossy(), "cam=fifo:x+lossy", true)
            .expect("parse fifo:+lossy");
        let Err(first) = open(&stream).await else {
            panic!("an absent path must refuse the first open");
        };
        assert!(
            first.to_string().contains("cannot open"),
            "the first refusal names the open failure: {first}"
        );

        // The operator's benign sequence: the FIFO appears (and a writer connects) after the refusal.
        mkfifo_at(&path);
        let body = b"the writer arrives after the first refusal";
        let writer_path = path.clone();
        let writer = tokio::task::spawn_blocking(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .and_then(|mut f| f.write_all(body))
                .expect("write into the FIFO");
        });

        let mut source = open(&stream)
            .await
            .expect("the retry opens the FIFO with its writer");
        writer.await.expect("writer task");
        let mut got = Vec::new();
        source
            .read_to_end(&mut got)
            .await
            .expect("read the retried session");
        assert_eq!(
            got, body,
            "the retried session streams the writer's exact bytes"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A first open that fails on the writer-wait TIMEOUT leaves the service RETRYABLE: a writer connecting
    /// afterwards lets the next consumer open the source and deliver the post-attach bytes. The ENOENT
    /// variant is pinned next door (`lossy_fifo_first_open_failure_then_a_writer_streams`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_first_lossy_open_does_not_disarm_the_service() {
        let fifo = scratch_fifo("lossy-timeout");
        let stream = RawStream::fifo(&fifo.to_string_lossy(), "cam=fifo:x+lossy", true)
            .expect("parse fifo:+lossy");

        // Hold the shared writer-wait lock so the flood test's long wait cannot race this shrink, and
        // restore the production wait (dropping the guard) BEFORE the writer arrives below.
        let lock = super::WRITER_WAIT_TEST_LOCK.lock().await;
        let short = super::set_writer_wait_timeout_for_test(100);
        let Err(first) = open(&stream).await else {
            panic!("a writer-less FIFO must refuse the first open");
        };
        assert!(
            first.to_string().contains("timed out"),
            "the refusal names the writer-wait timeout: {first}"
        );
        drop(short);

        let body = b"post-attach bytes after a timed-out first open";
        let writer_path = fifo.clone();
        let writer = tokio::task::spawn_blocking(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .and_then(|mut f| f.write_all(body))
                .expect("write into the FIFO");
        });

        let mut source = open(&stream)
            .await
            .expect("the retry opens with the writer present");
        writer.await.expect("writer task");
        let mut got = Vec::new();
        source
            .read_to_end(&mut got)
            .await
            .expect("read the retried session");
        assert_eq!(
            got, body,
            "a timed-out first open leaves the service armed for the next consumer"
        );
        drop(lock);

        let _ = std::fs::remove_file(&fifo);
    }

    /// A-2 (served-path pin): a zero-consumer instant on a served `fifo:+lossy` source does not refuse the
    /// next consumer. Consumer 1 attaches and drains a priming byte, then drops while the FIFO writer is
    /// still connected, holding the session live (the pump parked); consumer 2 attaches to the SAME live
    /// session and receives exactly the bytes written after it attached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_zero_consumer_instant_does_not_refuse_the_served_lossy_fifo() {
        let fifo = scratch_fifo("lossy-live");
        let stream = RawStream::fifo(&fifo.to_string_lossy(), "cam=fifo:x+lossy", true)
            .expect("parse fifo:+lossy");

        // A writer that stays connected across the zero-consumer instant: it primes one byte, then waits
        // for the test's signal before writing the body, so consumer 2 attaches to a live, idle session.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let body = b"post-attach bytes on the live session";
        let writer_path = fifo.clone();
        let writer = tokio::task::spawn_blocking(move || {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .expect("open the FIFO for write");
            file.write_all(b"p").expect("prime the FIFO");
            rx.recv().expect("wait for the write signal");
            file.write_all(body).expect("write the body");
        });

        // Consumer 1: attach, drain the priming byte, leave. The pump is now parked (the writer is idle),
        // which is exactly the live zero-consumer window that used to end the session for good.
        let mut first = open(&stream).await.expect("the first consumer attaches");
        let mut prime = [0u8; 1];
        first
            .read_exact(&mut prime)
            .await
            .expect("drain the priming byte");
        assert_eq!(&prime, b"p", "the priming byte arrives first");
        drop(first);

        // Consumer 2 attaches while the session is still live, and receives the post-attach bytes.
        let mut second = open(&stream)
            .await
            .expect("a zero-consumer instant must not refuse the next consumer");
        tx.send(()).expect("signal the writer");
        let mut got = Vec::new();
        second
            .read_to_end(&mut got)
            .await
            .expect("read the live session");
        assert_eq!(
            got, body,
            "a consumer attaching to the live session receives the bytes written after it attached"
        );
        writer.await.expect("writer task");

        let _ = std::fs::remove_file(&fifo);
    }

    /// A-2 (the re-arm): after the last consumer leaves and the session has ENDED (the writer closed, the
    /// pump exited), a fresh consumer starts a NEW session: the `fifo:` is re-opened (waiting for its next
    /// writer) and streams that writer's bytes. Plain `fifo:` semantics: open per dial, not one session for
    /// the node's lifetime.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lossy_fifo_rearms_a_new_session_after_the_last_consumer_left() {
        let fifo = scratch_fifo("lossy-rearm");
        let stream = RawStream::fifo(&fifo.to_string_lossy(), "cam=fifo:x+lossy", true)
            .expect("parse fifo:+lossy");

        // Session 1: a writer connects, streams its body, and closes; the consumer drains to EOF.
        let body1 = b"first session";
        let writer_path = fifo.clone();
        let writer1 = tokio::task::spawn_blocking(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .and_then(|mut f| f.write_all(body1))
                .expect("write body 1");
        });
        let mut first = open(&stream).await.expect("the first session opens");
        writer1.await.expect("writer 1 task");
        let mut got1 = Vec::new();
        first
            .read_to_end(&mut got1)
            .await
            .expect("drain the first session");
        assert_eq!(got1, body1, "the first session streams body 1");
        drop(first);

        // Session 2: a later consumer re-arms the `fifo:` and gets the next writer's bytes.
        let body2 = b"second session";
        let writer_path = fifo.clone();
        let writer2 = tokio::task::spawn_blocking(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&writer_path)
                .and_then(|mut f| f.write_all(body2))
                .expect("write body 2");
        });
        let mut second = open(&stream)
            .await
            .expect("a `fifo:+lossy` source re-arms after its session ended");
        writer2.await.expect("writer 2 task");
        let mut got2 = Vec::new();
        second
            .read_to_end(&mut got2)
            .await
            .expect("read the re-armed session");
        assert_eq!(got2, body2, "the re-armed session streams body 2");

        let _ = std::fs::remove_file(&fifo);
    }

    /// A-2 (the one-shot side): a `stdin:+lossy` (here an in-memory reader) session is one session, ever.
    /// Draining to EOF and dropping the cursor leaves the next consumer refused ("live session has ended"):
    /// fd 0 cannot rewind.
    #[tokio::test]
    async fn lossy_stdin_does_not_rearm_after_its_session_ends() {
        let body: &'static [u8] = b"one stdin session, ever";
        let stream = RawStream::lossy_from_reader(Box::new(body));
        let mut first = open(&stream).await.expect("the first consumer attaches");
        let mut got = Vec::new();
        first.read_to_end(&mut got).await.expect("drain");
        assert_eq!(got, body, "the session streams its exact bytes");
        drop(first);

        let Err(err) = open(&stream).await else {
            panic!("a non-rewindable `stdin:+lossy` session must refuse a later consumer");
        };
        assert!(
            err.to_string().contains("live session has ended"),
            "the refusal names the ended session: {err}"
        );
    }

    /// The concurrent-first-dial serialization pin: first dials against a writer-less FIFO serialize on the
    /// per-source state mutex, and every one reports its OWN open failure (each pays the writer-wait in
    /// turn), never the disarm message. No queued dial can observe a half-armed source, and a failed attempt
    /// does not consume the opener out from under the next.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_first_lossy_dials_serialize_behind_one_open() {
        let fifo = scratch_fifo("lossy-concurrent");
        let stream = RawStream::fifo(&fifo.to_string_lossy(), "cam=fifo:x+lossy", true)
            .expect("parse fifo:+lossy");

        let _lock = super::WRITER_WAIT_TEST_LOCK.lock().await;
        let _short = super::set_writer_wait_timeout_for_test(100);
        let (first, second) = tokio::join!(open(&stream), open(&stream));
        for (dial, result) in [("first", first), ("second", second)] {
            let Err(err) = result else {
                panic!("the {dial} dial found no writer, so it must be refused");
            };
            assert!(
                err.to_string().contains("timed out"),
                "the {dial} dial reports its own open failure: {err}"
            );
        }

        let _ = std::fs::remove_file(&fifo);
    }
}
