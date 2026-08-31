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
pub mod identity;
pub mod peer;
#[cfg_attr(not(unix), path = "raw_stream_unsupported.rs")]
pub mod raw_stream;
pub mod revoke;
pub mod share;
pub mod tree;
pub mod tunnel;

pub mod protocol;

#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod protocol_tests;

use tokio::io::{self, AsyncWriteExt as _};

pub use crate::attenuate::AttenuateCmd;
pub use crate::connect::{ConnectCmd, To};
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
/// sides close. The split form of [`splice`], for locals that are not one duplex object: a `file:`/`stdin:`
/// raw-stream source pumps its reader toward the peer with a discarding sink the other way.
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

/// Pump this process's stdio against a peer service stream for an ssh-`ProxyCommand`-shaped bridge (`connect
/// --to -`), finishing as soon as the PEER closes its write half.
///
/// The asymmetry is the whole point, and the fix for the `ssh <peer> -- <cmd>` hang. The bridge's stdin is
/// the local ssh's terminal, which never reaches EOF for the life of the session, so a symmetric
/// wait-for-both pump ([`splice_halves`]) would park forever after the remote command exits (the remote
/// closes its write half, but local stdin stays open). A stdio bridge is done when the SERVICE is done:
/// when the peer half-closes (its command exited, or an interactive session ended), copy any final bytes to
/// stdout, then return, rather than waiting on a stdin that will never close. The local-to-peer copy runs
/// concurrently and is dropped on return (its writer is shut down first, so the peer sees a clean close).
pub(crate) async fn pipe_stdio_bridge<W, R>(mut writer: W, mut reader: R) -> io::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let mut local_in = io::stdin();
    let mut local_out = io::stdout();
    let upstream = async {
        io::copy(&mut local_in, &mut writer).await?;
        writer.shutdown().await
    };
    let downstream = async {
        io::copy(&mut reader, &mut local_out).await?;
        local_out.flush().await
    };
    tokio::select! {
        // The peer closed (remote command exited / session ended): the service is done, so return without
        // waiting on local stdin (which, at a terminal, never EOFs). This is what unhangs `ssh -- <cmd>`.
        result = downstream => result,
        // Local stdin closed first (a piped, finite input): half-close toward the peer, then keep draining
        // the peer's remaining output to stdout so nothing it still had to say is lost.
        result = upstream => {
            result?;
            io::copy(&mut reader, &mut local_out).await?;
            local_out.flush().await
        }
    }
}
