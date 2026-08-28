//! Where tightbeam keeps its per-user files.

use std::path::PathBuf;

use eyre::eyre;

/// The persisted approved-set location for pairing mode, `~/.config/tightbeam/approved`, overridable
/// with `TIGHTBEAM_APPROVED`. nauthy owns the load/persist logic; the location is tightbeam's to choose.
pub fn approved_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_APPROVED") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("approved"))
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
