//! The `tightbeam` binary: a thin bridge over the tunnel library, not the product.
//!
//! The library is [`tightbeam::tunnel`]; the tool built on it is
//! [swoosh](https://github.com/theia-hq/swoosh), which owns the real CLI. This binary drives the same
//! core over an EMPTY registry, so it serves only raw forwards (`host:port` / `unix:<path>` /
//! `file:` / `fifo:` / `stdin:`), never a named handler. Its one real use is as an ssh `ProxyCommand`
//! (reach an sshd over a stream, `connect --to -`) before swoosh is on a machine.
//!
//! `expose` publishes local services under this machine's key; `connect` reaches an exposed service from
//! another machine and puts it on a local port, stdout (`-`), or a unix listener. `share` / `attenuate` /
//! `revoke` mint, narrow, and revoke the `sheer:` capability links the gate honors. Each verb is a thin
//! adapter that loads the identity and denylist, resolves the gate through the shared
//! [`resolve_gate`](tightbeam::tunnel::resolve_gate) policy, prints its own banner, and drives the core.
//!
//! By default a service is gated to the machine's signet (the key it trusts, set by `swoosh adopt`),
//! admitting the owner's own devices and their delegates; `--public` is the one deliberate opt-out (never
//! a shell). The identity is always persisted, since it is both the address peers dial and the key a
//! share-link roots at: `--key` or `TIGHTBEAM_KEY`.

use core::net::SocketAddr;
use std::path::PathBuf;

use bifrost::Node;
use bifrost_iroh::Endpoint;
use clap::{CommandFactory, Parser, Subcommand};
use nauthy::Denylist;
use tightbeam::config::{load_signet, revoked_path};
use tightbeam::identity::{self, Secret};
use tightbeam::peer::{Discovery, Peer};

mod attenuate;
mod connect;
mod expose;
mod revoke;
mod share;
mod tree;

use attenuate::AttenuateCmd;
use connect::ConnectCmd;
use expose::ExposeCmd;
use revoke::RevokeCmd;
use share::ShareCmd;
use tree::TreeCmd;

/// Reach a service on another machine by its public key, no public IP needed.
#[derive(Debug, Parser)]
#[command(name = "tightbeam", version, about)]
struct Cli {
    /// pin a persisted identity file [env: TIGHTBEAM_KEY]
    #[arg(
        long = "key",
        value_name = "identity-key",
        env = "TIGHTBEAM_KEY",
        global = true
    )]
    key: Option<PathBuf>,
    /// direct address hint for a peer, `<key>=<addr>` (repeatable); reaches it directly, without n0
    #[arg(long, value_name = "key=addr", global = true)]
    peer: Vec<Peer>,
    /// bind offline: no n0 discovery, no relays; reach peers only via --peer hints (LAN, Docker, air-gap)
    #[arg(long, global = true)]
    offline: bool,
    /// fixed local bind address, e.g. `0.0.0.0:9000`; implies --offline so a peer can hardcode host:port
    #[arg(long, value_name = "addr", global = true)]
    bind_addr: Option<SocketAddr>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Expose a local service to peers who hold this node's key.
    Expose(ExposeCmd),
    /// Reach a peer's exposed service and bind it to a local port.
    Connect(ConnectCmd),
    /// Mint a `sheer:` capability link granting one service, expiring, attenuable, delegable.
    Share(ShareCmd),
    /// Narrow an existing `sheer:` link offline before handing it on.
    Attenuate(AttenuateCmd),
    /// Revoke a `sheer:` link so this node refuses it at once, without waiting for expiry.
    Revoke(RevokeCmd),
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
        // `revoke` adds to the local revocation denylist; local, no node, no identity.
        Command::Revoke(cmd) => cmd.run().await,
        // `share` needs the signing identity but no bound node: minting is offline.
        Command::Share(cmd) => {
            let secret = identity::load(cli.key.as_deref()).await?;
            cmd.run(&secret.cap_identity()?)
        }
        // `expose`/`connect` bind a node. `expose` also reads the persisted signet: the key its default
        // gate trusts (a family gate admits the owner's devices and their delegates).
        Command::Expose(cmd) => {
            let secret = identity::load(cli.key.as_deref()).await?;
            let signet = load_signet().await?;
            // Load tightbeam's own denylist here in the adapter and pass it as a value; the core takes the
            // loaded list, never a path (the same seam swoosh drives on its own store).
            let denylist = Denylist::load(revoked_path()?).await?;
            let node = bind_node(secret, cli.peer, cli.offline, cli.bind_addr).await?;
            cmd.run(&node, signet, denylist).await
        }
        Command::Connect(cmd) => {
            let secret = identity::load(cli.key.as_deref()).await?;
            let node = bind_node(secret, cli.peer, cli.offline, cli.bind_addr).await?;
            cmd.run(&node).await
        }
    }
}

/// Bind the overlay node under the persisted secret. The one place a concrete transport is named;
/// everything else speaks `bifrost`. Binding under the same secret the cap identity roots at is what
/// makes a minted cap verify against the identity peers dial.
async fn bind_node(
    secret: Secret,
    peers: Vec<Peer>,
    offline: bool,
    bind_addr: Option<SocketAddr>,
) -> eyre::Result<Node<Endpoint, Discovery>> {
    // Offline (implied by a fixed --bind-addr) binds iroh's minimal preset: no n0, no relays, reachable
    // only via the --peer hints below. Otherwise bind under n0 discovery, with hints as a direct-path
    // shortcut. A fixed bind address defaults to an ephemeral port, which suits a dial-only client.
    let endpoint = if offline || bind_addr.is_some() {
        let addr = bind_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        Endpoint::bind_offline(secret.into_bytes(), addr).await?
    } else {
        Endpoint::bind_with_secret(secret.into_bytes()).await?
    };
    // Compose local discovery (--peer hints + LAN mDNS) so a nearby peer is reached directly; under n0
    // it keeps the internet as the fallback for a remote peer with no local hint.
    let discovery = Peer::discovery(&endpoint, peers);
    Ok(Node::new(endpoint, discovery))
}
