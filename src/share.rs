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
    pub service: Service,
    /// How long the link is valid, e.g. `2h`, `30m`, `90s`. Short-expiry is the v1 revocation story.
    #[arg(long, default_value = "1h")]
    pub expires: Lifetime,
    /// allow the holder to narrow and re-share the link
    #[arg(long)]
    pub delegable: bool,
}

impl ShareCmd {
    /// Mint the link and print it.
    pub fn run(self, identity: &Identity) -> eyre::Result<()> {
        let expiry = nauthy::expires_in(self.expires.duration());
        let cap = identity.mint(&self.service, expiry)?;
        // A non-delegable link is sealed so no holder can append a narrower block; a delegable one is
        // left open. Verification is unaffected either way.
        let cap = if self.delegable { cap } else { cap.seal()? };
        println!("{}", cap.link()?);
        Ok(())
    }
}
