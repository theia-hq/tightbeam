//! tightbeam: a library for private peer-to-peer tunnels over the bifrost overlay.
//!
//! Reach a service on a machine by its public key, across any NAT, over any transport. You embed this
//! crate: an [`Exposer`](tunnel::Exposer) serves local services behind a gate and forwards each inbound
//! overlay stream to the one it names; a [`Connector`](tunnel::Connector) reaches an exposed service and
//! hands back a bidirectional stream (bound to a local port, or piped over stdio). A caller supplies the
//! services, the identity, and the output; the core prints nothing and reads no config path.
//!
//! Who may connect is decided by the [`nauthy`] crate's authorization gate: by default the node's signet
//! (its own devices and their delegates), else an open gate for anyone. A named service (a keyless shell,
//! an HTTP fetcher, diagnostics) is a [`Handler`](tunnel::Handler) a caller injects into a
//! [`Registry`](tunnel::Registry); tightbeam knows only the contract, never what a handler does, and
//! ships none of its own. [`mint_link`](tunnel::mint_link) / [`narrow_link`](tunnel::narrow_link) /
//! [`revoke_into`](tunnel::revoke_into) mint, narrow, and revoke the `sheer:` capabilities the gate
//! honors, all offline.
//!
//! The tunnel core lives in [`tunnel`]; the wire frames in [`protocol`]. The command-line tool built on
//! this library is [swoosh](https://github.com/theia-hq/swoosh). This crate also ships a `tightbeam`
//! binary (`src/bin/tightbeam/`), a thin bridge over the same core that serves only raw forwards over an
//! empty registry; its CLI command tree lives in the binary, never in this library.
//!
//! Concurrency uses `FuturesUnordered` + `select!` (structured concurrency on one task) rather than
//! `tokio::spawn`, because the bifrost interface's futures are not `Send`-bounded. This keeps the library
//! generic over any transport; see DECISIONS.md for the trade-off.

pub mod config;
pub mod duration;
pub mod identity;
pub mod open_policy;
pub mod peer;
#[cfg_attr(not(unix), path = "raw_stream_unsupported.rs")]
pub mod raw_stream;
mod raw_stream_fanout;
pub mod tunnel;

pub mod protocol;

#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod open_policy_tests;
#[cfg(test)]
mod protocol_tests;

use tokio::io::{self, AsyncWriteExt as _};

/// Copy bytes both ways between a local duplex stream and a bifrost stream until both sides close.
///
/// The shared byte pump the core funnels into once a stream is established: the exposer after it dials
/// the local target, the connector after a service is accepted.
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

/// Pump this process's stdio against a peer service stream for an ssh-`ProxyCommand`-shaped bridge (piping
/// the service to this process's stdout), finishing as soon as the PEER closes its write half.
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
