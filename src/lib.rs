//! tightbeam: a library for private peer-to-peer tunnels over the bifrost overlay.
//!
//! Reach a service on a machine by its public key, across any NAT, over any transport. You embed this
//! crate: an [`Exposer`](tunnel::Exposer) serves local services behind a gate and forwards each inbound
//! overlay stream to the one it names; a [`Connector`](tunnel::Connector) reaches an exposed service and
//! hands back a bidirectional stream (bound to a local port, or piped over stdio). A caller supplies the
//! services, the identity, and the output; the core prints nothing and reads no config path.
//!
//! Who may connect is decided by the [`nauthy`] crate's authorization gate: by default the node's root
//! (its own devices and their delegates), else an open gate for anyone. A named service is a
//! [`Handler`](tunnel::Handler) a caller binds to a name on a
//! [`Router`](tunnel::Router); tightbeam knows only the contract, never what a handler does, and
//! ships only its own built-ins (`echo:`, local forwards, raw streams). [`Link`](nauthy::Link) mints,
//! narrows, and revokes the capabilities the gate honors, all offline.
//!
//! The tunnel core lives in [`tunnel`]; the wire frames in [`protocol`]. A command-line tool can be built
//! on this library; this crate also ships a `tightbeam` binary (`src/bin/tightbeam/`), a thin bridge over
//! the same core that serves only raw forwards over an empty registry; its CLI command tree lives in the
//! binary, never in this library.
//!
//! Concurrency uses `FuturesUnordered` + `select!` (structured concurrency on one task) rather than
//! `tokio::spawn`, because the bifrost interface's futures are not `Send`-bounded. This keeps the library
//! generic over any transport; see DECISIONS.md for the trade-off.

pub mod builtins;
pub mod config;
pub mod duration;
pub mod enabled;
pub mod identity;
pub mod open_policy;
pub mod peer;
pub mod raw_stream;
mod raw_stream_fanout;
pub mod security;
pub mod tunnel;

pub mod protocol;

#[cfg(test)]
mod duration_tests;
#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod log_capture;
#[cfg(test)]
mod log_capture_tests;
#[cfg(test)]
mod peer_tests;
#[cfg(test)]
mod protocol_tests;

use std::io::Read as _;

use tokio::io::{self, AsyncWriteExt as _};
use tokio::sync::mpsc;

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

/// Pump this process's stdio against a peer service stream for a ProxyCommand-shaped bridge (piping the
/// service to this process's stdout), finishing as soon as the stream from the PEER ends or errors.
///
/// The asymmetry is the whole point. A symmetric wait-for-both pump ([`splice_halves`]) would park forever
/// after the remote command exits (the remote closes its write half, but local stdin, an interactive
/// terminal, stays open). A stdio bridge is done when the SERVICE is done: when the peer half-closes (its
/// command exited, an interactive session ended) or its session ends (the host closed it, or the path to
/// it failed), copy any final bytes to stdout, then return, whatever stdin is doing. stdin is read on its
/// own thread (see [`stdin_chunks`]), so nothing waits on a read that only returns on the next keystroke.
pub(crate) async fn pipe_stdio_bridge<W, R>(mut writer: W, mut reader: R) -> io::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let mut input = stdin_chunks()?;
    let mut local_out = io::stdout();
    let upstream = async {
        while let Some(chunk) = input.recv().await {
            writer.write_all(&chunk?).await?;
        }
        writer.shutdown().await
    };
    let downstream = async {
        io::copy(&mut reader, &mut local_out).await?;
        local_out.flush().await
    };
    tokio::select! {
        // The peer's half ended or failed: the service is done, so return. The stdin pump is dropped,
        // never awaited; its thread ends with the process.
        result = downstream => result,
        // Local stdin closed first (a piped, finite input), or the write toward the peer failed. A clean
        // end half-closes toward the peer, then the peer's remaining output still drains to stdout so
        // nothing it still had to say is lost.
        result = upstream => {
            result?;
            io::copy(&mut reader, &mut local_out).await?;
            local_out.flush().await
        }
    }
}

/// This process's stdin, read on a thread of its own and handed over in chunks; the channel closes at
/// the end of input or after a read error.
///
/// Not tokio's stdin: that reads on the runtime's blocking pool, and the runtime waits for every blocking
/// read before it shuts down, so a process whose bridge has ended would hang until the next keystroke.
/// This thread is never joined: a read it is parked in ends with the process. One bridge per process: a
/// thread left parked by an ended bridge would take the first chunk a later one was meant to read.
fn stdin_chunks() -> io::Result<mpsc::Receiver<io::Result<Vec<u8>>>> {
    // One chunk in flight: the reader waits for the stream to take a chunk before reading the next, so a
    // slow peer holds back stdin rather than this process buffering it.
    let (sender, receiver) = mpsc::channel(1);
    std::thread::Builder::new()
        .name("stdin".to_owned())
        .spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let chunk = match stdin.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(read) => Ok(buffer[..read].to_vec()),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => Err(error),
                };
                let failed = chunk.is_err();
                // A closed channel means the bridge has ended: stop reading.
                if sender.blocking_send(chunk).is_err() || failed {
                    return;
                }
            }
        })?;
    Ok(receiver)
}
