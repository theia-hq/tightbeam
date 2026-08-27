//! tightbeam: reach a service on a machine that has no public IP, addressed by its public key.
//!
//! `tightbeam expose <target>...` publishes local services (a `host:port` or a `unix:<path>`, named
//! `name=target` or bare for the `default` service) under this machine's key. `tightbeam connect
//! <node-id|sheer-link> --to <port> [--service <name>]` reaches an exposed service from another machine
//! and binds it to a local port. Peer to peer, with nothing in between; `ssh -L` shaped, but you address
//! the far machine by its key, not an IP.
//!
//! Who may connect is set by a gate on `expose`: `--gate open` (anyone who reaches the key), `strict`
//! with an `--allow <node-id>` allowlist, `paired` (approve peers as they arrive, `tightbeam approve
//! <node-id>`), or `cap` (a presented capability token). A capability is a signed, expiring link rooted
//! at this machine's own key: `tightbeam share <service>` mints one, `tightbeam attenuate <link>` narrows
//! one offline, and a holder connects with the link directly. The identity is always persisted (it is
//! both the address peers dial and the root a share-link is signed under): `--key` or `TIGHTBEAM_KEY`.

use std::path::PathBuf;

use bifrost::{NoDiscovery, Node};
use bifrost_iroh::Endpoint;
use clap::{CommandFactory, Parser, Subcommand};
use tightbeam::config::approved_path;
use tightbeam::identity::{self, Secret};
use tightbeam::{ApproveCmd, AttenuateCmd, ConnectCmd, ExposeCmd, ShareCmd, TreeCmd};

/// Reach a service on another machine by its public key, no public IP needed.
#[derive(Debug, Parser)]
#[command(name = "tightbeam", version, about)]
struct Cli {
    /// pin a persisted identity file [env: TIGHTBEAM_KEY]
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
    /// Print this command tree (spec vs binary).
    Tree(TreeCmd),
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        // Local verbs: no node, no network, no identity. `tree` is pure introspection over clap's own
        // model; `attenuate` narrows a link offline.
        Command::Tree(cmd) => cmd.run(&Cli::command()),
        Command::Attenuate(cmd) => cmd.run(),
        // `approve` grows the local approved set; still no node.
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
