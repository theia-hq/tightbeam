//! tightbeam: private peer-to-peer tunnels over the bifrost overlay.
//!
//! `expose` forwards inbound overlay streams to a local TCP service; `connect` binds a peer's exposed
//! service to a local port. Each proxied TCP connection rides one bifrost bidirectional stream. Who may
//! connect is decided by the [`nauthy`] crate's authorization gate: by default the node's signet
//! (its own devices and their delegates), else `--public` for open. `share` and `attenuate` mint and
//! narrow the capabilities that gate honors.
//!
//! Concurrency uses `FuturesUnordered` + `select!` (structured concurrency on one task) rather than
//! `tokio::spawn`, because the bifrost interface's futures are not `Send`-bounded. This keeps the tool
//! generic over any transport; see DECISIONS.md for the trade-off.

pub mod attenuate;
pub mod config;
pub mod connect;
pub mod duration;
pub mod expose;
pub mod http;
pub mod identity;
pub mod peer;
pub mod revoke;
pub mod share;
pub mod tree;

mod fetch;
pub mod protocol;

#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod fetch_tests;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod protocol_tests;

use tokio::io::{self, AsyncWriteExt as _};

pub use crate::attenuate::AttenuateCmd;
pub use crate::connect::ConnectCmd;
pub use crate::expose::ExposeCmd;
pub use crate::revoke::RevokeCmd;
pub use crate::share::ShareCmd;
pub use crate::tree::TreeCmd;

/// Copy bytes both ways between a local duplex stream and a bifrost stream until both sides close.
///
/// The shared byte pump every command funnels into once its stream is established: `connect` after a
/// service is accepted, `expose` after it dials the local target.
pub(crate) async fn splice<S, W, R>(local: S, writer: W, reader: R) -> io::Result<()>
where
    S: io::AsyncRead + io::AsyncWrite + Unpin,
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let (local_reader, local_writer) = io::split(local);
    splice_halves(local_reader, local_writer, writer, reader).await
}

/// Copy bytes both ways between a separate local reader/writer pair and a bifrost stream until both
/// sides close. The split form of [`splice`], for locals that are not one duplex object: `connect
/// --stdio` pumps this process's stdin and stdout (two handles) against the peer stream.
pub(crate) async fn splice_halves<LR, LW, W, R>(
    mut local_reader: LR,
    mut local_writer: LW,
    mut writer: W,
    mut reader: R,
) -> io::Result<()>
where
    LR: io::AsyncRead + Unpin,
    LW: io::AsyncWrite + Unpin,
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
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
