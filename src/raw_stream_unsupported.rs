//! The non-unix stand-in for the raw-stream forward. `file:`/`fifo:` open an OS object with `O_NOFOLLOW`
//! and `fstat` its type through libc guards that are unix-only; on other platforms the target parses but any
//! open fails loudly, mirroring the `unix:` socket arm which also bails off unix. `stdin:` is NOT unix-only
//! (it reads fd 0, which every platform has), so it works here unchanged. The type keeps the same shape so
//! `tunnel.rs` compiles unchanged.

use std::path::PathBuf;

use crate::raw_stream_fanout::Fanout;
use crate::tunnel::BoxRead;

/// A resolved raw-stream forward. On non-unix a path source holds the path only to reproduce the loud open
/// failure; `stdin:` is fully supported (it needs no path guards).
#[derive(Debug, Clone)]
pub struct RawStream(Source);

#[derive(Debug, Clone)]
enum Source {
    /// A `file:`/`fifo:` path. Parses, but opening needs the unix guards, so the open fails loudly here.
    Path(PathBuf),
    /// This process's standard input (`stdin:`), a SINGLE-CONSUMER source taken once. See [`Stdin`].
    Stdin(Stdin),
    /// A `stdin:+lossy` fan-out source (a `fifo:+lossy` needs the unix open, so it fails loudly like `Path`).
    /// `stdin:` fan-out is supported here (fd 0 is portable), so the shared-ring path works unchanged.
    Lossy(Fanout),
}

/// The take-once owner of a single-consumer reader (fd 0), identical in contract to the unix build: `stdin:`
/// names one non-re-openable stream, so the first [`RawStream::open`] takes it and every later concurrent
/// open is refused. Making "two readers of one stdin" unrepresentable is the point; once taken it never
/// re-arms. Holds a [`BoxRead`] to mirror the unix build.
#[derive(Clone)]
struct Stdin(std::sync::Arc<std::sync::Mutex<Option<BoxRead>>>);

impl core::fmt::Debug for Stdin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Stdin").finish_non_exhaustive()
    }
}

impl Stdin {
    fn new(reader: BoxRead) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(Some(reader))))
    }

    fn take(&self) -> Option<BoxRead> {
        let Self(cell) = self;
        cell.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl RawStream {
    /// Parse a `file:<path>` tail. Same parse-time validation as unix; the open is what is unsupported.
    pub fn file(path: &str, entry: &str) -> eyre::Result<Self> {
        Self::path(path, entry, "file")
    }

    /// Parse a `fifo:<path>` tail. `lossy` is accepted for parse parity but a `fifo:` open needs the unix
    /// guards, so it fails loudly at open like any `Path`.
    pub fn fifo(path: &str, entry: &str, _lossy: bool) -> eyre::Result<Self> {
        Self::path(path, entry, "fifo")
    }

    /// The `stdin:` source: this process's standard input. Refuses a TTY at parse (a `stdin:` with no pipe
    /// would eat the operator's keystrokes), using a portable `isatty` check. Without `lossy` it is taken
    /// once (single-consumer); with `lossy` it is a fan-out source read by many consumers with drop-for-slow.
    pub fn stdin(lossy: bool) -> eyre::Result<Self> {
        if is_stdin_a_tty() {
            eyre::bail!(
                "stdin: has no pipe to read: fd 0 is a terminal, so it would consume your keystrokes. \
                 Pipe a producer in, e.g. `ffmpeg ... | tightbeam expose cam=stdin:`"
            );
        }
        let reader: BoxRead = Box::new(tokio::io::stdin());
        Ok(Self(if lossy {
            Source::Lossy(Fanout::new(reader))
        } else {
            Source::Stdin(Stdin::new(reader))
        }))
    }

    fn path(path: &str, entry: &str, scheme: &str) -> eyre::Result<Self> {
        if path.is_empty() {
            eyre::bail!(
                "`{entry}` names a `{scheme}:` target with no path; write `{scheme}:<path>`, e.g. \
                 `pipe={scheme}:/tmp/beam`"
            );
        }
        Ok(Self(Source::Path(PathBuf::from(path))))
    }

    /// Open the source. A `stdin:` source is taken once (a second concurrent open is refused); a `stdin:+lossy`
    /// source attaches a fan-out cursor; a `file:`/`fifo:` path needs the unix `O_NOFOLLOW` + `fstat` guards,
    /// so it is unsupported here.
    pub async fn open(&self) -> eyre::Result<BoxRead> {
        let Self(source) = self;
        match source {
            Source::Stdin(stdin) => match stdin.take() {
                Some(reader) => Ok(reader),
                None => eyre::bail!("stdin is a single-consumer source, already in use"),
            },
            Source::Lossy(fanout) => match fanout.open() {
                Some(cursor) => Ok(Box::new(cursor)),
                None => eyre::bail!("this lossy source's live session has ended"),
            },
            Source::Path(path) => eyre::bail!(
                "file:/fifo: raw-stream targets ({}) are only supported on unix",
                path.display()
            ),
        }
    }
}

/// Whether fd 0 is a terminal, via the standard library's portable `IsTerminal`. On non-unix (Windows) this
/// checks the console handle; the misuse refusal for a `stdin:` with no pipe holds the same everywhere.
fn is_stdin_a_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}
