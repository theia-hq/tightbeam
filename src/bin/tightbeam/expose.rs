//! `tightbeam expose`: publish local services under this node's key.
//!
//! The parse -> gate -> banner -> assemble -> run body is [`ExposeCmd::run`], a thin adapter over
//! [`tightbeam::tunnel`], so this CLI drives the same library core any richer consumer does and differs only
//! in identity, banner, and surface.

use bifrost::{Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::Denylist;
use tightbeam::tunnel::{self, CancellationToken, Exposer, Registry, Services};

/// Expose a local service to peers.
///
/// tightbeam's binary is a thin demo of the tunnel: it forwards the raw primitives (`host:port` /
/// `unix:<path>`, and the raw-stream `file:<path>` / `fifo:<path>` that source a path's bytes to the peer)
/// only. A named handler service (a bare `<name>:` scheme) lives in its own crate that a richer consumer
/// injects, so it is not served here.
///
/// Authorization is a property of the node, not a per-expose choice: by default a service is gated to this
/// node's signet (set once when the node adopts an identity), admitting the owner's own devices (membership
/// badges) and
/// anyone they delegate a slip to. `--public` is the one deliberate exception: it opens a service to
/// anyone, unauthenticated.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// expose local services as `name=addr` (bare `addr` = `default`)
    #[arg(required = true, value_name = "name=addr")]
    pub services: Vec<String>,
    /// Expose to ANYONE, unauthenticated: the one deliberate opt-out from the signet.
    #[arg(long)]
    pub public: bool,
    /// Suppress the readiness banner (the node id, services, and gate). For unattended/CI use where the
    /// key must never land in a log; the tunnel still runs.
    #[arg(long)]
    pub quiet: bool,
}

impl ExposeCmd {
    /// tightbeam's `expose` adapter: a thin glue over [`tightbeam::tunnel`], symmetric with any richer
    /// consumer's. Parse the services, resolve the gate through the shared `resolve_gate` policy (`--public`
    /// opens, else a family gate on the signet, else a loud error), print tightbeam's OWN banner, and run the
    /// exposer. The core prints nothing; the banner is this CLI's to own.
    ///
    /// tightbeam's binary is a thin demo of the tunnel: it exposes only the raw-forward primitive
    /// (`host:port` / `unix:<path>`), so it hands the exposer an EMPTY registry and names no service crate. A
    /// handler service (a bare `<name>:` scheme) lives in its own crate that a richer consumer injects; a bare
    /// scheme here resolves to a handler no registry holds and is refused loudly at [`Exposer::new`].
    pub async fn run<T: Transport, D: bifrost::Discovery>(
        self,
        node: &Node<T, D>,
        signet: Option<NodeId>,
        denylist: Denylist,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let services = Services::parse(&self.services)?;
        // Build the gate before announcing readiness. This thin demo has no auto-added `control.*` services,
        // so its `--public` stays a whole-node opt-out (a deliberate `Gate::Open` BASE); a richer consumer
        // (swoosh) opens individual services per-service instead. An unprovisioned node with NO `--public`
        // fails HERE, loudly, through the shared `resolve_gate` policy, never on a permissive default.
        let gate = if self.public {
            nauthy::Gate::Open
        } else {
            tunnel::resolve_gate(signet, denylist)?
        };
        // The core assembles the exposer over an empty registry (tightbeam ships no handler of its own), so a
        // named-service scheme is refused at construction, and only raw forwards are served.
        let exposer = Exposer::new(services.clone(), Registry::new(), gate)?;
        if !self.quiet {
            expose_banner(
                node.node_id(),
                services.names(),
                &gate_description(&self, signet),
            );
        }
        // This thin demo binary has no scheduled or remote teardown surface, so it holds no teardown
        // authority to hand out: it runs until the process is signalled (SIGINT), passing a token that is
        // never cancelled. A richer consumer is where the same token is wired to a teardown surface (a local
        // timer and a gated stop handler); here it is inert.
        exposer.run(node, CancellationToken::new()).await
    }
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
