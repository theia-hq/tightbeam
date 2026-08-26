//! `tightbeam approve`: permit a peer key to connect in pairing mode.

use bifrost::NodeId;
use clap::Args;

use crate::nauthy::Approvals;

/// Approve a peer key so it may connect in pairing mode.
#[derive(Debug, Args)]
pub struct ApproveCmd {
    /// The node id to approve.
    pub node: NodeId,
}

impl ApproveCmd {
    /// Add a peer to the persisted approved set.
    pub async fn run(self) -> eyre::Result<()> {
        let mut approvals = Approvals::load().await?;
        approvals.approve(self.node).await?;
        println!("approved {} ({})", self.node, approvals.path().display());
        Ok(())
    }
}
