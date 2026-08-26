//! nauthy: the authorization gate. Given a peer identity that the transport has already proven, decide
//! whether it may connect.
//!
//! Three policies today: `open` (any peer with the key), `strict` (a fixed allowlist), and `paired`
//! (a persisted approved set grown by consent). This is cross-cutting (any server-shaped product
//! wants it), so it is written to lift out into its own `nauthy` crate at the second consumer. It sits
//! ABOVE bifrost: reach stays policy-free; authorization is policy on proven identities.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use bifrost::NodeId;
use eyre::eyre;

/// An authorization policy over proven peer identities.
pub enum Gate {
    /// Permit any peer that reached the key.
    Open,
    /// Permit only peers on a fixed allowlist.
    Strict(HashSet<NodeId>),
    /// Permit only peers in a persisted, consent-grown approved set.
    Paired(Approvals),
}

impl Gate {
    /// Whether a proven peer identity is permitted to connect.
    pub fn permits(&self, peer: NodeId) -> bool {
        match self {
            Gate::Open => true,
            Gate::Strict(allowed) => allowed.contains(&peer),
            Gate::Paired(approvals) => approvals.keys().contains(&peer),
        }
    }
}

/// Parse node ids into an allowlist set.
pub fn parse_allowed(ids: &[String]) -> eyre::Result<HashSet<NodeId>> {
    ids.iter()
        .map(|id| id.parse::<NodeId>().map_err(Into::into))
        .collect()
}

/// A persisted set of peer keys approved to connect, for pairing mode. One node id per line, at
/// `TIGHTBEAM_APPROVED` or `~/.config/tightbeam/approved`.
pub struct Approvals {
    path: PathBuf,
    keys: HashSet<NodeId>,
}

impl Approvals {
    /// Load the approved set from the default location; an absent file is an empty set.
    pub async fn load() -> eyre::Result<Self> {
        Self::load_from(default_path()?).await
    }

    async fn load_from(path: PathBuf) -> eyre::Result<Self> {
        let keys = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(|line| line.parse::<NodeId>().map_err(Into::into))
                .collect::<eyre::Result<HashSet<NodeId>>>()?,
            Err(error) if error.kind() == ErrorKind::NotFound => HashSet::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self { path, keys })
    }

    /// The approved keys.
    pub fn keys(&self) -> &HashSet<NodeId> {
        &self.keys
    }

    /// The file backing this set.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Approve a peer and persist the set.
    pub async fn approve(&mut self, peer: NodeId) -> eyre::Result<()> {
        if self.keys.insert(peer) {
            self.persist().await?;
        }
        Ok(())
    }

    async fn persist(&self) -> eyre::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut lines = self
            .keys
            .iter()
            .map(|key| key.to_string())
            .collect::<Vec<_>>();
        lines.sort();
        tokio::fs::write(&self.path, lines.join("\n") + "\n").await?;
        Ok(())
    }
}

fn default_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_APPROVED") {
        return Ok(PathBuf::from(path));
    }
    let home =
        std::env::var_os("HOME").ok_or_else(|| eyre!("HOME not set; set TIGHTBEAM_APPROVED"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("tightbeam")
        .join("approved"))
}

#[cfg(test)]
mod tests {
    use bifrost::Transport as _;
    use bifrost_mem::MemTransport;

    use super::*;

    #[test]
    fn open_permits_any_and_strict_restricts() {
        let listed = MemTransport::bind().node_id();
        let other = MemTransport::bind().node_id();

        assert!(Gate::Open.permits(other));

        let strict = Gate::Strict(HashSet::from([listed]));
        assert!(strict.permits(listed));
        assert!(!strict.permits(other));
    }

    #[tokio::test]
    async fn approvals_persist_and_gate_pairs() {
        let path = std::env::temp_dir().join("tightbeam-nauthy-test");
        let _ = tokio::fs::remove_file(&path).await;

        let approved = MemTransport::bind().node_id();
        let other = MemTransport::bind().node_id();

        let mut approvals = Approvals::load_from(path.clone()).await.unwrap();
        approvals.approve(approved).await.unwrap();

        let reloaded = Approvals::load_from(path.clone()).await.unwrap();
        let gate = Gate::Paired(reloaded);
        assert!(gate.permits(approved));
        assert!(!gate.permits(other));

        tokio::fs::remove_file(&path).await.unwrap();
    }
}
