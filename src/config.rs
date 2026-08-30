//! Where tightbeam keeps its per-user files.

use std::path::PathBuf;

use bifrost::NodeId;
use eyre::eyre;

/// The persisted signet location, `~/.config/tightbeam/signet`, overridable with `TIGHTBEAM_SIGNET`.
/// Holds one thing: the public [`NodeId`] of the signet this node trusts, written once by provisioning
/// (`swoosh adopt`). Public material (a key you already share), so it sits beside the secret identity,
/// never inside it.
pub fn signet_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_SIGNET") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("signet"))
}

/// Load this node's signet: the [`NodeId`] it was provisioned to trust, or `None` if it was never
/// provisioned. The file is a single public node id; an absent file means unprovisioned, which `expose`
/// treats as "no default gate" (a loud error), never a silent open.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_signet() -> eyre::Result<Option<NodeId>> {
    match tokio::fs::read_to_string(signet_path()?).await {
        Ok(text) => Ok(Some(text.trim().parse::<NodeId>()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this node's signet: the public [`NodeId`] its default gate will trust, as `adopt` sets it from
/// an authkey. Overwrites any prior signet (re-provisioning re-trusts), creating the config dir.
pub async fn write_signet(signet: NodeId) -> eyre::Result<()> {
    let path = signet_path()?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, format!("{signet}\n")).await?;
    Ok(())
}

/// The persisted revocation-denylist location, `~/.config/tightbeam/revoked`, overridable with
/// `TIGHTBEAM_REVOKED`. Records the biscuit revocation ids of caps this node has revoked.
pub fn revoked_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_REVOKED") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("revoked"))
}

/// The tightbeam config directory, `~/.config/tightbeam`.
fn config_dir() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config").join("tightbeam"))
}
