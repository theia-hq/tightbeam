//! `tightbeam expose`: publish local services under this node's key and forward inbound streams.

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::{Denylist, Gate};

use crate::tunnel::{self, Exposer, Services};

/// How the readiness banner names the tool exposing the services, so the same code serves both callers
/// without hardcoding one binary. `tightbeam expose` says "tightbeam ... `tightbeam share`"; `swoosh
/// tunnel expose` says "swoosh tunnel ... `swoosh grant issue`". Two `&str`s, not one, because the
/// ready-name and the mint-verb differ (`swoosh tunnel` vs `swoosh grant issue`).
#[deprecated(
    note = "banners are a CLI concern; each CLI prints its own. Removed after swoosh cuts over."
)]
pub struct Brand {
    /// The name that leads the readiness banner, e.g. `tightbeam` or `swoosh tunnel`.
    pub ready: &'static str,
    /// The exact command that mints a link for this node, e.g. `tightbeam share` or `swoosh grant issue`.
    pub share: &'static str,
}

#[expect(
    deprecated,
    reason = "Brand's own inherent impl; deprecation is for downstream callers"
)]
impl Brand {
    /// The banner for `tightbeam` invoked directly.
    #[deprecated(
        note = "banners are a CLI concern; each CLI prints its own. Removed after swoosh cuts over."
    )]
    pub const TIGHTBEAM: Self = Self {
        ready: "tightbeam",
        share: "tightbeam share",
    };
}

/// Expose a local service to peers.
///
/// Authorization is a property of the node, not a per-expose choice: by default a service is gated to this
/// node's signet (set once by `swoosh adopt`), admitting the owner's own devices (membership badges) and
/// anyone they delegate a slip to. `--public` is the one deliberate exception: it opens a service to
/// anyone, unauthenticated.
#[derive(Debug, Args)]
pub struct ExposeCmd {
    /// expose local services as `name=addr` (bare `addr` = `default`)
    #[arg(required = true, value_name = "name=addr")]
    pub services: Vec<String>,
    /// Expose to ANYONE, unauthenticated: the one deliberate opt-out from the signet. Refused for a shell
    /// service (`sshd:`), which has no auth of its own.
    #[arg(long)]
    pub public: bool,
    /// Suppress the readiness banner (the node id, services, and gate). For unattended/CI use where the
    /// key must never land in a log; the tunnel still runs.
    #[arg(long)]
    pub quiet: bool,
}

impl ExposeCmd {
    /// Resolve the gate, print the readiness banner, and run the exposer core.
    ///
    /// A thin adapter over [`crate::tunnel`]: it loads tightbeam's own revocation denylist, builds the gate
    /// (open for `--public`, else a family gate on the node's `signet`), prints tightbeam's banner, and
    /// hands the assembled [`Exposer`] the node to run. `brand` names the calling tool in the banner so it
    /// points at the right binary's `share`; the core itself prints nothing.
    ///
    /// `signet` is this node's provisioned signet: the [`NodeId`] it trusts, or `None` if it was never
    /// provisioned. The default gate verifies presented tokens against it; `--public` overrides it.
    #[expect(
        deprecated,
        reason = "still accepts a Brand until swoosh cuts over (step 3)"
    )]
    pub async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        host_seed: [u8; 32],
        signet: Option<NodeId>,
        brand: Brand,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let services = Services::parse(&self.services)?;
        // Build the gate before announcing readiness: an unprovisioned node with no explicit override
        // fails HERE, loudly, rather than ever serving on a permissive default.
        let gate = self.gate(signet).await?;
        // The domain assembles the exposer, enforcing the sshd-cannot-be-public invariant before any
        // banner is printed, so a refused pairing never advertises a shell it will not serve.
        let exposer = Exposer::new(services.clone(), gate, host_seed)?;
        // The readiness banner names the node id AND the effective gate, so "who can reach this right now?"
        // is answerable at a glance. `--quiet` withholds it so a key never lands in an unattended log.
        if !self.quiet {
            println!(
                "{} ready. peers can reach these services at:\n",
                brand.ready
            );
            println!(
                "    {}                     (share this key, or mint a link with `{}`)\n",
                node.node_id(),
                brand.share
            );
            let names: Vec<&str> = services.names().collect();
            println!(
                "exposing {}. gate: {}. ctrl-c to stop.",
                names.join(", "),
                self.gate_description(signet)
            );
        }
        exposer.run(node).await
    }

    /// Build the authorization gate. Two modes, no policy menu: the default gates on the node's signet
    /// (admitting its members and delegates), and `--public` is the one deliberate opt-out to anyone.
    /// Unprovisioned + not public fails LOUDLY rather than falling back to anything permissive.
    async fn gate(&self, signet: Option<NodeId>) -> eyre::Result<Gate> {
        if self.public {
            return Ok(Gate::Open);
        }
        let root = signet.ok_or_else(|| {
            eyre::eyre!(
                "this node has no signet to gate on: provision it with `swoosh adopt <authkey>`, \
                 or pass --public to expose to anyone"
            )
        })?;
        // The revocation denylist is loaded once here; a `tightbeam revoke` adds to the file, which the
        // next exposer run reads. Offline, no server. The core takes the loaded denylist, never a path.
        let denylist = Denylist::load(crate::config::revoked_path()?).await?;
        Ok(tunnel::family_gate(root, denylist))
    }

    /// A one-line description of the effective gate, for the readiness banner: trust made visible.
    fn gate_description(&self, signet: Option<NodeId>) -> String {
        if self.public {
            "public (anyone, unauthenticated)".to_owned()
        } else {
            match signet {
                Some(root) => format!("signet {}", root.short()),
                None => "unprovisioned".to_owned(),
            }
        }
    }
}
