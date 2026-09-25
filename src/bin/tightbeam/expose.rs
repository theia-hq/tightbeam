//! `tightbeam expose`: publish local services under this node's key.
//!
//! The parse -> gate -> banner -> assemble -> run body is [`ExposeCmd::run`], a thin adapter over
//! [`tightbeam::tunnel`], so this CLI drives the same library core any richer consumer does and differs only
//! in identity, banner, and surface.

use std::sync::Arc;

use bifrost::{Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::{FileDenylist, Latch, Service};
use tightbeam::tunnel::{
    self, CancellationToken, ManifestEntry, Posture, RawSource, Router, TargetKind,
};

/// Expose a local service to peers.
///
/// tightbeam's binary is a thin demo of the tunnel: it forwards the raw primitives (`tcp:<host>:<port>` /
/// `unix:<path>`, and the raw-stream `file:<path>` / `fifo:<path>` that source a path's bytes to the peer)
/// only. A named handler service is bound by value in an embedder, so it is not served here.
///
/// Authorization is a property of the node, not a per-expose choice: by default a service is gated to this
/// node's root (set once when the node adopts an identity), admitting the owner's own devices (membership
/// badges) and
/// anyone they delegate a slip to. `--public` is the one deliberate exception: it opens a service to
/// anyone, unauthenticated.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// expose local services as `name=target`
    #[arg(required = true, value_name = "name=target")]
    pub services: Vec<String>,
    /// open the WHOLE node to anyone, unauthenticated (the one opt-out from the family gate)
    // A whole-node BOOLEAN, never a per-service list: this bin exposes the library primitive directly, so
    // `--public` sets the gate's BASE posture and every service under it opens at once. The help spells the
    // whole-node scope out loud, because a layer above can offer the same word per service and an operator
    // who carries that reading over here would open far more than they meant to.
    #[arg(long)]
    pub public: bool,
    /// serve these raw-stream services (file:/fifo:/stdin:) to ANYONE, unauthenticated (comma-list)
    // A separate name list from `--public`, because opening a raw byte source to strangers is a louder
    // decision than opening a handler that authenticates for itself. It `requires = "public"`: with a
    // whole-node gate there is no open posture to serve these names through, so the set would sit inert and
    // the operator would believe they opened something they did not. A parse error says so instead.
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
    /// opens, else a family gate on the root, else a loud error), print tightbeam's OWN banner, and run the
    /// exposer. The core prints nothing; the banner is this CLI's to own.
    ///
    /// tightbeam's binary is a thin demo of the tunnel: it exposes only the raw primitives
    /// (`tcp:<host>:<port>` / `unix:<path>` / `file:` / `fifo:` / `stdin:`), so it binds no handler of its
    /// own and names no service crate. Every target carries a scheme and the set is closed, so an unknown
    /// one is a teaching error: a richer consumer binds a handler by value.
    pub async fn run<T: Transport, D: bifrost::Discovery>(
        self,
        node: &Node<T, D>,
        root: Option<NodeId>,
        revocations: Arc<Latch<FileDenylist>>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        // Build the gate before announcing readiness. This thin demo has no auto-added `control.*` services,
        // so its `--public` stays a whole-node opt-out (a deliberate `Gate::Open` BASE); an embedder opens
        // individual services per-service instead. An unprovisioned node with NO `--public`
        // fails HERE, loudly, through the shared `resolve_gate` policy, never on a permissive default.
        let gate = if self.public {
            nauthy::Gate::Open
        } else {
            tunnel::resolve_gate(root, Arc::clone(&revocations))?
        };
        // Assemble the one route table: the `name=target` grammar absorbs the raw primitives (a
        // `tcp:`/`unix:` local forward, or a `file:`/`fifo:`/`stdin:` raw-stream source; an unknown scheme
        // is a teaching error now that handlers bind by value). The bin is the ONLY place the `--public-unsafe` flag string becomes the
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
        // The live cut reads the same store the gate does, so a session admitted on a cap since revoked,
        // or rooted at a key since disabled, ends itself. Under `--public` nothing is ruled on, so
        // nothing is ever cut.
        let exposer = router.expose()?.with_live_cuts(revocations);
        // Prove the transport can carry this gate BEFORE any ready output: a
        // rooted gate over a transport that does not prove the peer refuses here, never after a banner
        // the node cannot honor. The library's `run` re-checks, so the invariant holds however the
        // exposer is driven.
        exposer.prove_security::<T>()?;
        if !self.quiet {
            expose_banner(
                node.node_id(),
                names.iter().map(String::as_str),
                &gate_description(&self, root),
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
/// CLI's own mint verb). Only public material (the node id) is printed; the host seed and root secret
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
// The absolute path is NEVER truncated or elided: the operator has to see the exact bytes at risk, and the
// middle of a path is precisely where `~/.ssh/id_rsa` would hide. One line per opened stream rather than a
// count or a summary, so a single dangerous entry cannot ride along inside a tally nobody expands.
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
fn gate_description(cmd: &ExposeCmd, root: Option<NodeId>) -> String {
    if cmd.public {
        "public (anyone, unauthenticated)".to_owned()
    } else {
        match root {
            Some(root) => format!("root {}", root.short()),
            None => "unprovisioned".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bifrost::NodeId;

    use super::{ExposeCmd, gate_description};

    fn gated() -> ExposeCmd {
        ExposeCmd {
            services: vec!["demo=echo:".to_owned()],
            public: false,
            public_unsafe: Vec::new(),
            quiet: false,
        }
    }

    /// The banner's gate line names the key the node trusts as a root, in the plain key text: the label is
    /// the word "root", and the value is the start of the key a person can match against `status` or a pin.
    #[test]
    fn the_gate_line_names_the_root_key() {
        let root = NodeId::from_ed25519_secret(&[1u8; 32]);
        let line = gate_description(&gated(), Some(root));
        assert_eq!(line, format!("root {}", root.short()));
        assert!(line.starts_with("root ed01"), "{line}");
    }
}
