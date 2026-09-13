//! `tightbeam expose`: publish local services under this node's key.
//!
//! The parse -> gate -> banner -> assemble -> run body is [`ExposeCmd::run`], a thin adapter over
//! [`tightbeam::tunnel`], so this CLI drives the same library core any richer consumer does and differs only
//! in identity, banner, and surface.

use bifrost::{Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::{FileDenylist, Service};
use tightbeam::tunnel::{
    self, CancellationToken, ManifestEntry, Posture, RawSource, Router, TargetKind,
};

/// Expose a local service to peers.
///
/// tightbeam's binary is a thin demo of the tunnel: it forwards the raw primitives (`host:port` /
/// `unix:<path>`, and the raw-stream `file:<path>` / `fifo:<path>` that source a path's bytes to the peer)
/// only. A named handler service is bound by value in a richer consumer (swoosh, or your own embedder), so
/// it is not served here.
///
/// Authorization is a property of the node, not a per-expose choice: by default a service is gated to this
/// node's signet (set once when the node adopts an identity), admitting the owner's own devices (membership
/// badges) and
/// anyone they delegate a slip to. `--public` is the one deliberate exception: it opens a service to
/// anyone, unauthenticated.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// expose local services as `name=addr` (every entry must be `name=addr`)
    #[arg(required = true, value_name = "name=addr")]
    pub services: Vec<String>,
    /// open the WHOLE node to anyone, unauthenticated (the one opt-out from the signet)
    // CLI-Architect round-3 (Ruling 2): tightbeam's `--public` stays a whole-node BOOLEAN (the library
    // primitive, a `Gate::Open` BASE), NOT per-service like swoosh; the help states the whole-node scope so
    // the layer difference is on the surface. The bang-suffix (`--public svc!`) was REJECTED.
    #[arg(long)]
    pub public: bool,
    /// serve these raw-stream services (file:/fifo:/stdin:) to ANYONE, unauthenticated (comma-list)
    // CLI-Architect round-3 (Rulings 1 & 2): KEEP the separate `--public-unsafe <names>` name list on both
    // bins; `requires = "public"` is RULED for tightbeam ONLY (its `--public` is whole-node, so the unsafe set
    // is inert without it, a silent "I thought I opened it" footgun that this turns into a parse error).
    #[arg(
        long,
        value_name = "name",
        value_delimiter = ',',
        requires = "public",
        long_help = "Serve these raw-stream services (file:/fifo:/stdin:) to ANYONE, unauthenticated: the \
                     DISTINCT, louder opt-in for a source that has no auth of its own. Only meaningful with \
                     --public (it names which raw streams the open gate may serve). --public alone refuses a \
                     raw stream and points you here. The readiness banner names each resolved absolute path, \
                     because `--public-unsafe logs` where `logs=file:~/.ssh/id_rsa` would hand that file's \
                     bytes to anyone who reaches this node."
    )]
    pub public_unsafe: Vec<String>,
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
    /// tightbeam's binary is a thin demo of the tunnel: it exposes only the raw primitives (`host:port` /
    /// `unix:<path>` / `file:` / `fifo:` / `stdin:`), so it binds no handler of its own and names no service
    /// crate. A bare `<name>:` scheme is a teaching error: a richer consumer binds a handler by value.
    pub async fn run<T: Transport, D: bifrost::Discovery>(
        self,
        node: &Node<T, D>,
        signet: Option<NodeId>,
        denylist: FileDenylist,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // Build the gate before announcing readiness. This thin demo has no auto-added `control.*` services,
        // so its `--public` stays a whole-node opt-out (a deliberate `Gate::Open` BASE); a richer consumer
        // (swoosh) opens individual services per-service instead. An unprovisioned node with NO `--public`
        // fails HERE, loudly, through the shared `resolve_gate` policy, never on a permissive default.
        let gate = if self.public {
            nauthy::Gate::Open
        } else {
            tunnel::resolve_gate(signet, denylist)?
        };
        // Assemble the one route table: the `name=addr` grammar absorbs the raw primitives (a local forward,
        // or a `file:`/`fifo:`/`stdin:` raw-stream source; a bare `<scheme>:` is a teaching error now that
        // handlers bind by value). The bin is the ONLY place the `--public-unsafe` flag string becomes the
        // typed name set. `.expose()` is the one proof door: a raw stream under the whole-node open gate is
        // refused unless named in `--public-unsafe`, and everything else is proven open-safe.
        let router = Router::new(gate).parse(&self.services)?;
        let router = if self.public_unsafe.is_empty() {
            router
        } else {
            let names = self
                .public_unsafe
                .iter()
                .map(|name| name.parse::<Service>())
                .collect::<Result<Vec<_>, _>>()?;
            router.public_unsafe(names)
        };
        let names: Vec<String> = router.names().map(str::to_owned).collect();
        let exposer = router.expose()?;
        // Prove the transport can carry this gate BEFORE any ready output, mirroring swoosh's serve: a
        // rooted gate over a transport that does not prove the peer refuses here, never after a banner
        // the node cannot honor. The library's `run` re-checks, so the invariant holds however the
        // exposer is driven.
        exposer.prove_security::<T>()?;
        if !self.quiet {
            expose_banner(
                node.node_id(),
                names.iter().map(String::as_str),
                &gate_description(&self, signet),
            );
            // The manifest declares which raw streams read Open (proven unsafe) and their resolved absolute
            // source, so the loud warning names the exact bytes a stranger can read, not the operator's typed
            // string. Empty for a run with no --public-unsafe.
            expose_unsafe_warning(&exposer.manifest());
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

/// Print the loud UNSAFE warning for every raw-stream service the open gate serves to anyone: one line per
/// opened raw stream naming the exact bytes at risk (a resolved absolute path, or the piped stdin), sourced
/// from the manifest's declared [`RawSource`] so it names what tightbeam resolved, never the operator's typed
/// string. Nothing is printed when no raw stream is open (the common case). On STDERR with the rest of the
/// banner, never stdout (the data path).
// The per-stream gloss wording is CLI-Architect round-3 (Ratified-in-passing): `serving the raw bytes of
// {abs} to anyone, no auth` / `serving this process's piped stdin to anyone, no auth`, and the absolute path
// is NEVER truncated (the operator must SEE the exact bytes at risk). The `UNSAFE:` line prefix and one-line-
// per-stream shape are this thin bin's presentation default (the round-3 banner ruling detailed swoosh's
// grouped banner; the thin bin has no group table).
fn expose_unsafe_warning(manifest: &[ManifestEntry]) {
    for entry in manifest {
        if entry.posture != Posture::Open || entry.kind != TargetKind::RawStream {
            continue;
        }
        let risk = match &entry.raw_source {
            Some(RawSource::Path(absolute)) => {
                format!("serving the raw bytes of {absolute} to anyone, no auth")
            }
            Some(RawSource::Stdin) => {
                "serving this process's piped stdin to anyone, no auth".to_owned()
            }
            // A raw stream always declares a raw source; guard defensively rather than panic.
            None => "serving raw bytes to anyone, no auth".to_owned(),
        };
        eprintln!("UNSAFE: `{}` is {}", entry.name, risk);
    }
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
