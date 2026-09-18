//! The tunnel library core: store-free, clap-free, banner-free.
//!
//! This is the domain a tunnel is made of, with no CLI around it: an [`Exposer`] that accepts overlay
//! sessions and forwards inbound streams to local services, a [`Connector`] that reaches a peer's exposed
//! service, the [`resolve_gate`] policy, and the offline credential operations on a
//! [`Link`](nauthy::Link) (mint, narrow, revoke). It prints NOTHING and reads no config path: a caller
//! loads the signet, denylist, and identity,
//! prints its own banner, and drives this core. Everything here already speaks `bifrost` and `nauthy`, never
//! clap or a store.

use core::time::Duration;

// The handler contract lives in the lean `tightbeam-handler` crate, re-exported here
// unchanged so every existing `tightbeam::tunnel::*` path keeps working, and a service implements the
// contract without taking this crate's tree. The erased bridge is imported, not re-exported: `Target` stores
// it privately and it is not part of the author-facing surface.
pub use tightbeam_handler::{
    BoxRead, BoxWrite, Handler, Metering, RootedAdmitted, ServeError, Served,
};
use tokio::io;
use tokio::net::TcpStream;

use crate::splice;

mod admit;
mod catalog;
mod connector;
mod exposer;
mod router;

#[cfg(test)]
mod fixtures;

pub use admit::resolve_gate;
pub use catalog::{Posture, ServiceCatalog, ServiceEntry};
pub use connector::{Connector, DialRefused, PortForward, PresentingConnector, ServiceSession};
pub use exposer::{CancellationToken, Exposer};
pub use router::{ManifestEntry, RawSource, Router, TARGET_SCHEMES, TargetKind};

/// How long to wait for a `fifo:` WRITER before dropping the stream. The FIFO open itself is NONBLOCKING
/// (`O_NONBLOCK`, so it returns a valid fd at once with no writer and never parks a thread), but a writer-less
/// FIFO reads as instant EOF, which is not a real byte stream. So the raw-stream open awaits readable readiness
/// (a writer connecting/writing) bounded by this timeout; on elapse the fd is dropped (cheap, no parked thread)
/// and the stream is refused, one layer deeper than the pre-gate
/// [`REQUEST_READ_TIMEOUT`](admit::REQUEST_READ_TIMEOUT) (which has already elapsed by the time a target
/// is dialed). A regular-file open has no writer to wait for and is not bounded by this.
///
/// It sits at the tunnel root because it bounds a raw-stream OPEN, which [`crate::raw_stream`] performs:
/// no one submodule here owns it.
pub(crate) const RAW_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Dial a local stream endpoint (`tcp:<host>:<port>` or `unix:<path>`) and pipe it to the bifrost stream.
/// The serve half of [`builtins::Forward`](crate::builtins::Forward), typed [`ServeError`] so a handler body
/// can `?` it directly.
///
/// The two endpoints are siblings and the splice does not care which it got; only the connect differs. The
/// scheme is matched, never guessed, so this dials exactly what the grammar admitted.
///
/// It sits at the tunnel root because it is the local-dial half [`crate::builtins`] serves a forward with,
/// neither the route table's business nor the overlay connector's.
pub(crate) async fn dial_and_splice<W, R>(
    addr: &str,
    writer: W,
    reader: R,
) -> Result<(), ServeError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match addr.split_once(':') {
        Some(("tcp", host_port)) => {
            let local = TcpStream::connect(host_port).await?;
            splice(local, writer, reader).await?;
        }
        #[cfg(unix)]
        Some(("unix", path)) => {
            let local = tokio::net::UnixStream::connect(path).await?;
            splice(local, writer, reader).await?;
        }
        #[cfg(not(unix))]
        Some(("unix", _)) => {
            return Err(ServeError::Io(io::Error::other(
                "unix sockets are not supported on this platform",
            )));
        }
        // Unreachable through the Router, whose grammar admits only the two above. It is reachable by a
        // library caller that built a `Forward` by hand, so it refuses by name rather than guessing a TCP
        // dial out of an address no one validated.
        _ => {
            return Err(ServeError::Io(io::Error::other(format!(
                "`{addr}` is not a local stream endpoint; expected `tcp:<host>:<port>` or `unix:<path>`"
            ))));
        }
    }
    Ok(())
}
