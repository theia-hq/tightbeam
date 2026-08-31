//! `tightbeam expose`: the clap surface for publishing local services under this node's key.
//!
//! A pure `Args` struct now: the parse -> gate -> banner -> assemble -> run body lives in the binary's
//! `main.rs` glue (a thin adapter over [`crate::tunnel`]), so tightbeam's CLI drives the same library core
//! swoosh does and differs only in identity, banner, and surface. See `main.rs`'s `expose` fn.

use clap::Args;

/// Expose a local service to peers.
///
/// tightbeam's binary is a thin demo of the tunnel: it forwards the raw primitives (`host:port` /
/// `unix:<path>`, and the raw-stream `file:<path>` / `fifo:<path>` that source a path's bytes to the peer)
/// only. A named handler service (`sshd:`, `fetch:`, `ping:`) lives in its own crate that a product
/// (swoosh) injects, so it is not served here.
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
    /// Expose to ANYONE, unauthenticated: the one deliberate opt-out from the signet.
    #[arg(long)]
    pub public: bool,
    /// Suppress the readiness banner (the node id, services, and gate). For unattended/CI use where the
    /// key must never land in a log; the tunnel still runs.
    #[arg(long)]
    pub quiet: bool,
}
