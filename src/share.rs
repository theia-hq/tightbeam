//! `tightbeam share`: mint a `sheer:` capability link for one of this node's services.

use clap::Args;
use nauthy::{Identity, Service};

use crate::duration::Lifetime;

/// Mint a share-link that IS a capability: a signed, expiring, attenuable grant to one service.
///
/// The link is rooted at this node's identity, so a connector needs no separate node id and the exposer
/// needs no allowlist to keep in sync. A holder can narrow it (`tightbeam attenuate`) and hand it off
/// entirely offline; the exposer verifies the whole chain with no server in the loop.
#[derive(Debug, Args)]
pub struct ShareCmd {
    /// The service the link grants (as named in `expose`, e.g. `ssh`).
    #[arg(value_name = "service")]
    pub service: Service,
    /// How long the link is valid, e.g. `2h`, `30m`, `90s`. Short-expiry is the v1 revocation story.
    #[arg(long, value_name = "duration", default_value = "1h")]
    pub expires: Lifetime,
    /// allow the holder to narrow and re-share the link
    #[arg(long)]
    pub delegable: bool,
}

impl ShareCmd {
    /// Mint the link and print it.
    pub fn run(self, identity: &Identity) -> eyre::Result<()> {
        let link = crate::tunnel::mint_link(
            identity,
            &self.service,
            self.expires.duration(),
            self.delegable,
        )?;
        println!("{link}");
        Ok(())
    }
}
