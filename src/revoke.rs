//! `tightbeam revoke`: revoke a `sheer:` capability so this node refuses it, offline and at once.

use clap::Args;
use nauthy::{Cap, Denylist};

use crate::config::revoked_path;

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
        let cap = Cap::parse(&self.link)?;
        let mut denylist = Denylist::load(revoked_path()?).await?;
        denylist.revoke(&cap).await?;
        println!("revoked ({})", denylist.path().display());
        Ok(())
    }
}
