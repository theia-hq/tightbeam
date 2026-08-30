//! Where tightbeam keeps its per-user files.

use std::path::PathBuf;

use bifrost::NodeId;
use eyre::eyre;

/// The persisted signet-anchor location, `~/.config/tightbeam/anchor`, overridable with
/// `TIGHTBEAM_ANCHOR`. Holds one thing: the public [`NodeId`] of the signet this node trusts, written
/// once by provisioning (`swoosh adopt`). Public material (a key you already share), so it sits beside
/// the secret identity, never inside it.
pub fn anchor_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_ANCHOR") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("anchor"))
}

/// Load this node's signet anchor: the [`NodeId`] of the signet it was provisioned to trust, or `None`
/// if it was never provisioned. The file is a single public node id; an absent file means unprovisioned,
/// which `expose` treats as "no default gate" (a loud error), never a silent open.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_anchor() -> eyre::Result<Option<NodeId>> {
    match tokio::fs::read_to_string(anchor_path()?).await {
        Ok(text) => Ok(Some(text.trim().parse::<NodeId>()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this node's signet anchor: the public [`NodeId`] its default gate will trust, as `adopt` sets
/// it from an authkey. Overwrites any prior anchor (re-provisioning re-anchors), creating the config dir.
pub async fn write_anchor(signet: NodeId) -> eyre::Result<()> {
    let path = anchor_path()?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, format!("{signet}\n")).await?;
    Ok(())
}

/// The persisted membership-badge location, `~/.config/tightbeam/badge`, overridable with
/// `TIGHTBEAM_BADGE`. Holds one `sheer:` link: the badge the signet signed for this device at `mint`,
/// which the device presents when it dials a family-gated node. A bearer cap, but bound to this device's
/// key, so it sits beside the anchor rather than inside the secret identity.
pub fn badge_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("TIGHTBEAM_BADGE") {
        return Ok(PathBuf::from(path));
    }
    Ok(config_dir()?.join("badge"))
}

/// Load this device's membership badge (a `sheer:` link), or `None` if it was never provisioned with one.
/// The signet holder self-signs instead of storing one, and an unprovisioned node simply has none.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_badge() -> eyre::Result<Option<String>> {
    match tokio::fs::read_to_string(badge_path()?).await {
        Ok(text) => Ok(Some(text.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this device's membership badge, as `adopt` stores it from an authkey. Overwrites any prior badge
/// (re-provisioning re-badges), creating the config dir.
pub async fn write_badge(badge: &str) -> eyre::Result<()> {
    let path = badge_path()?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, format!("{badge}\n")).await?;
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
