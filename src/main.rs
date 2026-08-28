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

use core::net::SocketAddr;
use std::path::PathBuf;

use bifrost::Node;
use bifrost_iroh::Endpoint;
use clap::{CommandFactory, Parser, Subcommand};
use tightbeam::config::approved_path;
use tightbeam::identity::{self, Secret};
use tightbeam::peer::{Discovery, Peer};
use tightbeam::{ApproveCmd, AttenuateCmd, ConnectCmd, ExposeCmd, ShareCmd, TreeCmd};

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
            // Derive the ssh host-key seed before the secret is consumed by the bind. Only a `sshd:`
            // service uses it, but it is cheap and keeps the secret's raw bytes from leaving for it.
            let host_seed = secret.ssh_host_seed();
            let node = bind_node(secret, cli.peer, cli.offline, cli.bind_addr).await?;
            cmd.run(&node, cap_identity, host_seed, approved_path()?)
                .await
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
