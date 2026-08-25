//! tightbeam: private peer-to-peer tunnels over the bifrost overlay.
//!
//! `tightbeam expose <local-addr>` publishes a local service under this node's key;
//! `tightbeam connect <node-id> --to <port>` binds that service to a local port on another machine;
//! `tightbeam approve <node-id>` permits a peer in pairing mode.

use bifrost::{NoDiscovery, Node};
use bifrost_iroh::Endpoint;
use clap::{Parser, Subcommand};
use tightbeam::{ApproveCmd, ConnectCmd, ExposeCmd};

/// Private peer-to-peer tunnels over the bifrost overlay.
#[derive(Debug, Parser)]
#[command(name = "tightbeam", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expose a local service to peers who hold this node's key.
    Expose(ExposeCmd),
    /// Reach a peer's exposed service and bind it to a local port.
    Connect(ConnectCmd),
    /// Approve a peer key so it may connect in pairing mode.
    Approve(ApproveCmd),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Approve(cmd) => cmd.run().await,
        Command::Expose(cmd) => cmd.run(&bind_node().await?).await,
        Command::Connect(cmd) => cmd.run(&bind_node().await?).await,
    }
}

/// Bind the overlay node. The one place a concrete transport is named; everything else speaks `bifrost`.
async fn bind_node() -> eyre::Result<Node<Endpoint, NoDiscovery>> {
    Ok(Node::new(Endpoint::bind().await?, NoDiscovery))
}
