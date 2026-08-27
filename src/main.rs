//! tightbeam: private peer-to-peer tunnels over the bifrost overlay.
//!
//! `tightbeam expose <local-addr>` publishes a local service under this node's key;
//! `tightbeam connect <node-id|sheer-link> --to <port>` binds that service to a local port on another
//! machine; `tightbeam approve <node-id>` permits a peer in pairing mode; `tightbeam share <service>`
//! mints a `sheer:` capability link and `tightbeam attenuate <link>` narrows one offline.

use std::path::PathBuf;

use bifrost::{NoDiscovery, Node};
use bifrost_iroh::Endpoint;
use clap::{Parser, Subcommand};
use tightbeam::config::approved_path;
use tightbeam::identity::{self, Secret};
use tightbeam::{ApproveCmd, AttenuateCmd, ConnectCmd, ExposeCmd, ShareCmd};

/// Private peer-to-peer tunnels over the bifrost overlay.
#[derive(Debug, Parser)]
#[command(name = "tightbeam", version, about)]
struct Cli {
    /// Pin this node to a persisted identity at the given file, creating it if absent. Without it, the
    /// default `~/.config/tightbeam/identity.key` (or `TIGHTBEAM_KEY`) is used. The identity is both the
    /// address peers dial and the root a `share` link is signed under, so it is always persisted.
    #[arg(long = "key", env = "TIGHTBEAM_KEY", global = true)]
    key: Option<PathBuf>,
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
    /// Mint a `sheer:` capability link granting one service, expiring, attenuable, delegable.
    Share(ShareCmd),
    /// Narrow an existing `sheer:` link offline before handing it on.
    Attenuate(AttenuateCmd),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        // Offline verbs: no node, no network. `attenuate` needs no identity at all; `approve` grows the
        // local approved set.
        Command::Attenuate(cmd) => cmd.run(),
        Command::Approve(cmd) => cmd.run().await,
        // `share` needs the signing identity but no bound node: minting is offline.
        Command::Share(cmd) => {
            let secret = identity::load(cli.key.as_deref()).await?;
            cmd.run(&secret.cap_identity()?)
        }
        // `expose`/`connect` bind a node. The exposer also carries its cap identity so a `cap` gate can
        // verify presented tokens against the same key the node is bound under.
        Command::Expose(cmd) => {
            let secret = identity::load(cli.key.as_deref()).await?;
            let cap_identity = secret.cap_identity()?;
            let node = bind_node(secret).await?;
            cmd.run(&node, cap_identity, approved_path()?).await
        }
        Command::Connect(cmd) => {
            let secret = identity::load(cli.key.as_deref()).await?;
            let node = bind_node(secret).await?;
            cmd.run(&node).await
        }
    }
}

/// Bind the overlay node under the persisted secret. The one place a concrete transport is named;
/// everything else speaks `bifrost`. Binding under the same secret the cap identity roots at is what
/// makes a minted cap verify against the identity peers dial.
async fn bind_node(secret: Secret) -> eyre::Result<Node<Endpoint, NoDiscovery>> {
    let endpoint = Endpoint::bind_with_secret(secret.into_bytes()).await?;
    Ok(Node::new(endpoint, NoDiscovery))
}
