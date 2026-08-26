//! `tightbeam approve`: permit a peer key to connect in pairing mode.

use bifrost::NodeId;
use clap::Args;

use crate::nauthy::Approvals;

/// Approve a peer key so it may connect in pairing mode.
#[derive(Debug, Args)]
pub struct ApproveCmd {
    /// The node id to approve.
    pub node: String,
}

impl ApproveCmd {
    /// Add a peer to the persisted approved set.
    pub async fn run(self) -> eyre::Result<()> {
        let peer: NodeId = self.node.parse()?;
        let mut approvals = Approvals::load().await?;
        approvals.approve(peer).await?;
        println!("approved {peer} ({})", approvals.path().display());
        Ok(())
    }
}
