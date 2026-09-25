//! Where tightbeam keeps its per-user files.

use std::path::PathBuf;

use bifrost::NodeId;
use eyre::eyre;

/// The persisted root location, `~/.config/tightbeam/root`, overridable with `TIGHTBEAM_ROOT`.
/// Holds one thing: the public [`NodeId`] of the root this node trusts, written once by provisioning
/// (an adopt step). Public material (a key you already share), so it sits beside the secret identity,
/// never inside it.
pub fn root_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_ROOT") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("root"))
}

/// Load this node's root: the [`NodeId`] it was provisioned to trust, or `None` if it was never
/// provisioned. The file is a single public node id; an absent file means unprovisioned, which `expose`
/// treats as "no default gate" (a loud error), never a silent open.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_root() -> eyre::Result<Option<NodeId>> {
    match tokio::fs::read_to_string(root_path()?).await {
        Ok(text) => Ok(Some(text.trim().parse::<NodeId>()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this node's root: the public [`NodeId`] its default gate will trust, as `adopt` sets it from
/// an authkey. Overwrites any prior root (re-provisioning re-trusts), creating the config dir.
pub async fn write_root(root: NodeId) -> eyre::Result<()> {
    let path = root_path()?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, format!("{root}\n")).await?;
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

/// The disabled-roots latch location, `~/.config/tightbeam/disabled_roots`: the root keys this node no
/// longer trusts, one per line, which the gate refuses every cap rooted at. A file of its own, never the
/// denylist: the denylist names grants, this names the keys that sign them, and it only ever grows. Kept
/// in the config directory, since that directory, not the file's mode, is what stands between the latch
/// and a local user who would delete it.
pub fn disabled_roots_path() -> eyre::Result<PathBuf> {
    Ok(config_dir()?.join("disabled_roots"))
}

/// The tightbeam config directory, `~/.config/tightbeam`.
fn config_dir() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config").join("tightbeam"))
}
