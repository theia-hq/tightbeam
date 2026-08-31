//! tightbeam: reach a service on a machine that has no public IP, addressed by its public key.
//!
//! `tightbeam expose <target>...` publishes local services (a `host:port` or a `unix:<path>`, named
//! `name=target` or bare for the `default` service) under this machine's key. `tightbeam connect
//! <node-id|sheer-link> --to <port | - | unix:PATH> [--service <name>]` reaches an exposed service from
//! another machine and puts it on a local port, stdout (`-`), or a unix listener. Peer to peer, with
//! nothing in between; `ssh -L` shaped, but you address the far machine by its key, not an IP.
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

use bifrost::{Node, NodeId, Transport};
use bifrost_iroh::Endpoint;
use clap::{CommandFactory, Parser, Subcommand};
use nauthy::Denylist;
use tightbeam::config::{load_signet, revoked_path};
use tightbeam::identity::{self, Secret};
use tightbeam::peer::{Discovery, Peer};
use tightbeam::tunnel::{self, Exposer, Registry, Services};
use tightbeam::{AttenuateCmd, ConnectCmd, ExposeCmd, RevokeCmd, ShareCmd, To, TreeCmd};

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
            expose(&node, cmd, signet, denylist).await
        }
        Command::Connect(cmd) => {
            let secret = identity::load(cli.key.as_deref()).await?;
            let node = bind_node(secret, cli.peer, cli.offline, cli.bind_addr).await?;
            connect(&node, cmd).await
        }
    }
}

/// tightbeam's `expose` adapter: a thin glue over [`tightbeam::tunnel`], symmetric with swoosh's. Parse
/// the services, resolve the gate through the shared `resolve_gate` policy (`--public` opens, else a family
/// gate on the signet, else a loud error), print tightbeam's OWN banner, and run the exposer. The core
/// prints nothing; the banner is this CLI's to own.
///
/// tightbeam's binary is a thin demo of the tunnel: it exposes only the raw-forward primitive
/// (`host:port` / `unix:<path>`), so it hands the exposer an EMPTY registry and names no service crate. A
/// handler service (`sshd:`, `fetch:`, `ping:`) lives in its own crate that swoosh injects; a bare scheme
/// here resolves to a handler no registry holds and is refused loudly at [`Exposer::new`].
async fn expose<T: Transport, D: bifrost::Discovery>(
    node: &Node<T, D>,
    cmd: ExposeCmd,
    signet: Option<NodeId>,
    denylist: Denylist,
) -> eyre::Result<()>
where
    <T::Session as bifrost::Session>::Write: Send + 'static,
    <T::Session as bifrost::Session>::Read: Send + 'static,
{
    let services = Services::parse(&cmd.services)?;
    // Build the gate before announcing readiness: an unprovisioned node with no `--public` fails HERE,
    // loudly, through the ONE shared policy point, never on a permissive default.
    let gate = tunnel::resolve_gate(cmd.public, signet, denylist)?;
    // The core assembles the exposer over an empty registry (tightbeam ships no handler of its own), so a
    // named-service scheme is refused at construction, and only raw forwards are served.
    let exposer = Exposer::new(services.clone(), Registry::new(), gate)?;
    if !cmd.quiet {
        expose_banner(
            node.node_id(),
            services.names(),
            &gate_description(&cmd, signet),
        );
    }
    exposer.run(node).await
}

/// Print tightbeam's readiness banner: the copyable node id set off by blank lines, a header, and a trailer
/// naming the exposed services, the effective gate, and how to stop. Points at `tightbeam share` (this
/// CLI's own mint verb). Only public material (the node id) is printed; the host seed and signet secret
/// never appear. Withheld under `--quiet`.
///
/// Printed to STDERR, never stdout: a `stdin:` producer pipes its bytes into this process's stdin, and stdout
/// is a data path (`connect --to -` mirrors it), so a human banner on stdout could interleave into the
/// stream. stderr is for the human; stdout/stdin carry data.
fn expose_banner<'a>(node_id: NodeId, names: impl Iterator<Item = &'a str>, gate: &str) {
    eprintln!("tightbeam ready. peers can reach these services at:\n");
    eprintln!(
        "    {node_id}                     (share this key, or mint a link with `tightbeam share`)\n"
    );
    let names: Vec<&str> = names.collect();
    eprintln!(
        "exposing {}. gate: {}. ctrl-c to stop.",
        names.join(", "),
        gate
    );
}

/// A one-line description of the effective gate, for the readiness banner: trust made visible.
fn gate_description(cmd: &ExposeCmd, signet: Option<NodeId>) -> String {
    if cmd.public {
        "public (anyone, unauthenticated)".to_owned()
    } else {
        match signet {
            Some(root) => format!("signet {}", root.short()),
            None => "unprovisioned".to_owned(),
        }
    }
}

/// tightbeam's `connect` adapter: resolve the target into a library [`Connector`], then drive the sink the
/// single `--to` selector names -- bind a local port and forward each accepted connection, stream the
/// service to stdout (`--to -`, the ssh `ProxyCommand` shape), or a reserved unix listener. `To` is one
/// closed enum, so the sink is unambiguous with no arg group and no missing-means-stdio inference.
async fn connect<T: Transport, D: bifrost::Discovery>(
    node: &Node<T, D>,
    cmd: ConnectCmd,
) -> eyre::Result<()> {
    let connector = cmd.connector()?;
    match cmd.to {
        To::Port(port) => {
            // Prove the gate admits us BEFORE announcing readiness: `preflight` reaches, probes admission,
            // and binds the port, returning an error (with the host's reason) on refusal. Only past it is
            // "forwarding …" true, so an unauthorized forward fails loudly here, never a fake success then
            // a silent reset.
            let (dial, service) = (connector.dial(), connector.service().to_owned());
            let forward = connector.preflight(node, port).await?;
            println!("forwarding 127.0.0.1:{port} to {dial} ({service})");
            forward.run().await
        }
        To::Stdout => connector.pipe_stdio(node).await,
        To::UnixListener(path) => eyre::bail!(
            "--to unix:{} is reserved, not yet built (bind a port and connect to it, or use `--to -`)",
            path.display()
        ),
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
