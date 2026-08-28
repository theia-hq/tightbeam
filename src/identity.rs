//! The node identity: the ed25519 secret tightbeam binds under and roots capabilities at.
//!
//! A capability roots at the exposer's `NodeId`, and verifying a presented cap needs the exposer to hold
//! the matching secret, so the exposer must have a *stable* identity across runs, not the fresh key a
//! throwaway dial would use. The same secret does double duty: bifrost binds the transport under it (so
//! the node is reachable at a stable `NodeId`) and [`nauthy::Identity`] roots caps at it (so a minted cap
//! verifies against the identity peers dial). It persists at `~/.config/tightbeam/identity.key`, mode
//! 0600, overridable with `--key` / `TIGHTBEAM_KEY`.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes on drop so the key does not
//! linger in freed memory, and it is unwrapped only at the two boundaries that need it raw, the transport
//! bind and the cap root.

use std::path::{Path, PathBuf};

use eyre::eyre;
use zeroize::{Zeroize as _, ZeroizeOnDrop};

/// The ed25519 secret key the node binds under and roots capabilities at. Wraps the raw bytes so they
/// zeroize on drop and never cross a boundary as a bare array.
#[derive(ZeroizeOnDrop)]
pub struct Secret([u8; 32]);

impl Secret {
    /// A fresh random secret, kept only in memory. `rand::random` draws from a CSPRNG seeded by the OS,
    /// the same source swoosh mints its keys from.
    pub fn ephemeral() -> Self {
        Self(rand::random())
    }

    /// The cap-signing identity rooted at this secret. Borrows, so the secret stays owned here and
    /// zeroizes on drop after the transport has also consumed a copy.
    pub fn cap_identity(&self) -> eyre::Result<nauthy::Identity> {
        Ok(nauthy::Identity::from_secret(&self.0)?)
    }

    /// Consume the secret into its raw bytes for the transport bind. The single boundary where the key
    /// leaves the zeroizing wrapper; the transport crate owns the key type downstream.
    pub fn into_bytes(mut self) -> [u8; 32] {
        let bytes = self.0;
        // Wipe our copy; the returned array is the caller's to own from here.
        self.0.zeroize();
        bytes
    }

    /// A stable seed for this node's SSH host key, derived from the identity secret by a domain-separated
    /// KDF (BLAKE3 `derive_key`), so the ssh host key is DISTINCT from the node key (no cross-protocol
    /// reuse) yet STABLE across runs, letting a client's `known_hosts` pin this node. The raw secret never
    /// leaves the wrapper; only this derived seed does.
    pub fn ssh_host_seed(&self) -> [u8; 32] {
        blake3::derive_key("theia sshh host key v1", &self.0)
    }
}

/// Write a provided secret as this node's persisted identity: how a machine ADOPTS a minted device seed
/// to BECOME that identity. Overwrites any key at the path (adopting replaces this node's identity),
/// mode 0600. The path is `--key` / `TIGHTBEAM_KEY` or the default; `expose` then binds under it.
pub async fn write(secret: &[u8; 32], explicit: Option<&Path>) -> eyre::Result<()> {
    let path = match explicit {
        Some(path) => path.to_owned(),
        None => default_path()?,
    };
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, secret).await?;
    restrict(&path).await?;
    Ok(())
}

/// Load the persisted secret, creating and saving a fresh one on first use.
///
/// An explicit path (`--key` / `TIGHTBEAM_KEY`) overrides the default location. tightbeam's identity is
/// always persisted (unlike swoosh's reach-outward verbs) because a cap exposer must be reachable and
/// verifiable at one stable key across runs.
pub async fn load(explicit: Option<&Path>) -> eyre::Result<Secret> {
    let path = match explicit {
        Some(path) => path.to_owned(),
        None => default_path()?,
    };
    load_or_create(&path).await
}

async fn load_or_create(path: &Path) -> eyre::Result<Secret> {
    if let Ok(mut bytes) = tokio::fs::read(path).await {
        if let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) {
            bytes.zeroize();
            return Ok(Secret(secret));
        }
        bytes.zeroize();
    }

    let secret = Secret::ephemeral();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, secret.0).await?;
    restrict(path).await?;
    Ok(secret)
}

/// The default persisted key location, `~/.config/tightbeam/identity.key`.
fn default_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_KEY") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set; pass --key"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("tightbeam")
        .join("identity.key"))
}

#[cfg(unix)]
async fn restrict(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn restrict(_path: &Path) -> eyre::Result<()> {
    Ok(())
}
