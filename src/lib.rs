//! tightbeam: private peer-to-peer tunnels over the bifrost overlay.
//!
//! `expose` forwards inbound overlay streams to a local TCP service; `connect` binds a peer's exposed
//! service to a local port. Each proxied TCP connection rides one bifrost bidirectional stream. Who may
//! connect is decided by the [`nauthy`] crate's authorization gate: an allowlist, a paired set, or a
//! presented capability. `share` and `attenuate` mint and narrow those capabilities.
//!
//! Concurrency uses `FuturesUnordered` + `select!` (structured concurrency on one task) rather than
//! `tokio::spawn`, because the bifrost interface's futures are not `Send`-bounded. This keeps the tool
//! generic over any transport; see DECISIONS.md for the trade-off.

pub mod approve;
pub mod attenuate;
pub mod config;
pub mod connect;
pub mod duration;
pub mod expose;
pub mod identity;
pub mod share;
pub mod tree;

mod protocol;

#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod protocol_tests;

use tokio::io::{self, AsyncWriteExt as _};

pub use crate::approve::ApproveCmd;
pub use crate::attenuate::AttenuateCmd;
pub use crate::connect::ConnectCmd;
pub use crate::expose::ExposeCmd;
pub use crate::share::ShareCmd;
pub use crate::tree::TreeCmd;

/// Copy bytes both ways between a local stream and a bifrost stream until both sides close.
///
/// The shared byte pump every command funnels into once its stream is established: `connect` after a
/// service is accepted, `expose` after it dials the local target.
pub(crate) async fn splice<S, W, R>(local: S, mut writer: W, mut reader: R) -> io::Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let (mut local_reader, mut local_writer) = io::split(local);
    let upstream = async {
        io::copy(&mut local_reader, &mut writer).await?;
        writer.shutdown().await
    };
    let downstream = async {
        io::copy(&mut reader, &mut local_writer).await?;
        local_writer.shutdown().await
    };
    tokio::try_join!(upstream, downstream)?;
    Ok(())
}
