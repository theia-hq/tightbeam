//! `tightbeam share`: mint a capability link for one of this node's services.

use bifrost::NodeId;
use clap::Args;
use nauthy::{Identity, Link, Service};
use tightbeam::duration::Lifetime;
use tightbeam::identity::AsNodeId as _;

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
    /// Mint the link and print it, unless this node trusts a signet other than its own key.
    ///
    /// A link roots at this node's key, and a gate on a node pinned to another signet admits only caps
    /// rooted there, so a link minted under a foreign pin is refused everywhere, this node included.
    /// Refusing here, before anything is printed, is the one place the person minting it can be told why.
    pub fn run(self, identity: &Identity, signet: Option<NodeId>) -> eyre::Result<()> {
        let own = identity.verifying_key().node_id()?;
        if let Some(signet) = signet.filter(|signet| *signet != own) {
            eyre::bail!(
                "this node trusts root {signet}. A link made here would be signed by this node's key \
                 ({own}), and no node would admit it, this one included. Make the link with `tightbeam \
                 share` on the node whose key is that root"
            );
        }
        let link = Link::mint(identity, &self.service, self.expires.duration())?;
        // A non-delegable link is sealed so no holder can append a narrower block; a delegable one is left
        // open. Verification is unaffected either way.
        let link = if self.delegable { link } else { link.seal()? };
        println!("{link}");
        Ok(())
    }
}
