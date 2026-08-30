//! The service handlers tightbeam ships and registers into a [`Registry`](crate::tunnel::Registry): the
//! keyless shell (`sshd:`, behind the `ssh` feature) and the HTTP egress fetch (`fetch:`). A caller builds
//! a registry from these (plus any it injects itself, like swoosh's `diag:`) and hands it to the exposer.
//!
//! These are thin adapters: each wraps a service implementation as a [`Handler`] closure that consumes the
//! admitted witness and the boxed stream halves. Extracting `fetch` (and dropping tightbeam's `sshh`
//! dependency) into their own crates that swoosh injects, so tightbeam names no service crate, is the next
//! step; today they live here so the tunnel binary keeps working while the registry seam lands.

use std::sync::Arc;

use futures::FutureExt as _;

use crate::tunnel::{Handler, ServeFn};

/// The keyless-shell handler (`sshd:`): gated, because a shell has no auth of its own so the gate IS its
/// authentication. Captures the ssh host-key seed the caller derived from its identity.
#[cfg(feature = "ssh")]
pub fn sshd(host_seed: [u8; 32]) -> Handler {
    let serve: ServeFn = Arc::new(move |admitted, writer, reader| {
        async move {
            sshh::serve(admitted, host_seed, writer, reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::gated(serve)
}

/// The HTTP egress handler (`fetch:`): the node acts as an HTTP client and streams an origin response back.
/// It carries its own SSRF guard, so it does not require the gate (a `--public fetch:` is a deliberate
/// choice, not an accidental keyless shell).
pub fn fetch() -> Handler {
    let serve: ServeFn = Arc::new(|_admitted, mut writer, mut reader| {
        async move {
            crate::fetch::serve_fetch(&mut writer, &mut reader).await?;
            Ok(())
        }
        .boxed()
    });
    Handler::open(serve)
}
