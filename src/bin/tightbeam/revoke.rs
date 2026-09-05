//! `tightbeam revoke`: revoke a `sheer:` capability so this node refuses it, offline and at once.

use clap::Args;
use nauthy::FileDenylist;
use tightbeam::config::revoked_path;

/// Revoke a `sheer:` capability link so this node refuses it from now on.
///
/// A cap is a bearer token verified offline, so there is no server to tell "stop honoring this". Instead
/// the node keeps a denylist of revoked ids: this records the link's id, so the gate refuses it at once
/// rather than waiting for its expiry. It revokes EXACTLY the link you pass and every narrower cap
/// delegated from it, NOT the wider grant it was attenuated from (paste the root link to kill the whole
/// tree). Local and offline; no node is bound and no identity is needed.
#[derive(Debug, Args)]
pub struct RevokeCmd {
    /// The `sheer:` link to revoke (revokes it and everything attenuated from it).
    #[arg(value_name = "link")]
    pub link: String,
}

impl RevokeCmd {
    /// Add the cap's revocation id to the persisted denylist.
    pub async fn run(self) -> eyre::Result<()> {
        // The adapter opens tightbeam's own denylist and passes it by ref to the core, which never reads
        // a config path.
        let mut denylist = FileDenylist::load(revoked_path()?).await?;
        tightbeam::tunnel::revoke_into(&mut denylist, &self.link).await?;
        println!("revoked ({})", denylist.path().display());
        Ok(())
    }
}
