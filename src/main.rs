//! tightbeam: reach a service on a machine that has no public IP, addressed by its public key.
//!
//! `tightbeam expose <target>...` publishes local services (a `host:port` or a `unix:<path>`, named
//! `name=target` or bare for the `default` service) under this machine's key. `tightbeam connect
//! <node-id|sheer-link> --to <port> [--service <name>]` reaches an exposed service from another machine
//! and binds it to a local port. Peer to peer, with nothing in between; `ssh -L` shaped, but you address
//! the far machine by its key, not an IP.
//!
//! Who may connect is a property of the node, not a per-expose choice: by default `expose` gates a
//! service to the machine's signet (the key it trusts, set by `swoosh adopt`), admitting the owner's own
//! devices and anyone they delegate to. `--public` is the one deliberate opt-out: it opens a service to
//! anyone (never a shell). A capability is a signed, expiring link rooted at a signet: `tightbeam share
//! <service>` mints one, `tightbeam attenuate <link>` narrows it offline, `tightbeam revoke <link>`
//! recalls it, and a holder connects with the link directly. The identity is always persisted (it is both
//! the address peers dial and the key a share-link roots at): `--key` or `TIGHTBEAM_KEY`.

use core::net::SocketAddr;
use std::path::PathBuf;

use bifrost::Node;
use bifrost_iroh::Endpoint;
use clap::{CommandFactory, Parser, Subcommand};
use tightbeam::config::load_signet;
use tightbeam::identity::{self, Secret};
use tightbeam::peer::{Discovery, Peer};
use tightbeam::{AttenuateCmd, ConnectCmd, ExposeCmd, RevokeCmd, ShareCmd, TreeCmd};

/// Reach a service on another machine by its public key, no public IP needed.
#[derive(Debug, Parser)]
#[command(name = "tightbeam", version, about)]
struct Cli {
    /// pin a persisted identity file [env: TIGHTBEAM_KEY]
    #[arg(long = "key", env = "TIGHTBEAM_KEY", global = true)]
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
            // Derive the ssh host-key seed before the secret is consumed by the bind. Only a `sshd:`
            // service uses it, but it is cheap and keeps the secret's raw bytes from leaving for it.
            let host_seed = secret.ssh_host_seed();
            let signet = load_signet().await?;
            let node = bind_node(secret, cli.peer, cli.offline, cli.bind_addr).await?;
            cmd.run(&node, host_seed, signet).await
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
