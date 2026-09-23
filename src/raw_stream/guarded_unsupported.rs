//! The non-unix stand-in for the guarded path open. `file:` and `fifo:` open an OS object with
//! `O_NOFOLLOW` and `fstat` its type through libc guards that are unix-only, so here a path target parses
//! but refuses loudly, at serve time and at every dial, mirroring the `unix:` socket arm which also bails
//! off unix. Only the path open differs: `stdin:`, its seat, and the `+lossy` fan-out are the one portable
//! definition in [`crate::raw_stream`].

use std::path::{Path, PathBuf};

use super::Kind;
use crate::tunnel::BoxRead;

/// Refuse the serve-time check for a path source, with the same words the dial would give, so a banner
/// never advertises bytes this build can never open.
pub(super) fn check_open_path(path: &Path, _kind: Kind) -> eyre::Result<()> {
    Err(unsupported(path))
}

/// Refuse a path open: the guards that make one safe need the unix open flags.
pub(super) async fn open_path(path: PathBuf, _kind: Kind) -> eyre::Result<BoxRead> {
    Err(unsupported(&path))
}

/// Whether fd 0 is a terminal, via the standard library's portable `IsTerminal` (on Windows it checks the
/// console handle), so the misuse refusal for a `stdin:` with no pipe holds the same everywhere.
pub(super) fn is_stdin_a_tty() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stdin())
}

/// The one refusal a path target gets off unix.
fn unsupported(path: &Path) -> eyre::Report {
    eyre::eyre!(
        "file:/fifo: raw-stream targets ({}) are only supported on unix",
        path.display()
    )
}
