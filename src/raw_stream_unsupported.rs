//! The non-unix stand-in for the raw-stream forward. `file:`/`fifo:` open an OS object with `O_NOFOLLOW`
//! and `fstat` its type through libc guards that are unix-only; on other platforms the target parses but any
//! open fails loudly, mirroring the `unix:` socket arm which also bails off unix. The type keeps the same
//! shape so `tunnel.rs` compiles unchanged.

use std::path::PathBuf;

/// A resolved raw-stream forward. On non-unix it holds the path only to reproduce the loud open failure.
#[derive(Debug, Clone)]
pub struct RawStream {
    path: PathBuf,
}

impl RawStream {
    /// Parse a `file:<path>` tail. Same parse-time validation as unix; the open is what is unsupported.
    pub fn file(path: &str, entry: &str) -> eyre::Result<Self> {
        Self::parse(path, entry, "file")
    }

    /// Parse a `fifo:<path>` tail.
    pub fn fifo(path: &str, entry: &str) -> eyre::Result<Self> {
        Self::parse(path, entry, "fifo")
    }

    fn parse(path: &str, entry: &str, scheme: &str) -> eyre::Result<Self> {
        if path.is_empty() {
            eyre::bail!(
                "`{entry}` names a `{scheme}:` target with no path; write `{scheme}:<path>`, e.g. \
                 `pipe={scheme}:/tmp/beam`"
            );
        }
        Ok(Self {
            path: PathBuf::from(path),
        })
    }

    /// Opening a raw-stream target needs the unix `O_NOFOLLOW` + `fstat` guards, so it is unsupported here.
    pub async fn open(&self) -> eyre::Result<tokio::fs::File> {
        eyre::bail!(
            "file:/fifo: raw-stream targets ({}) are only supported on unix",
            self.path.display()
        )
    }
}
