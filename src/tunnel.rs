//! The tunnel library core: store-free, clap-free, banner-free.
//!
//! This is the domain a tunnel is made of, with no CLI around it: an [`Exposer`] that accepts overlay
//! sessions and forwards inbound streams to local services, a [`Connector`] that reaches a peer's exposed
//! service, the [`resolve_gate`] policy, and the offline credential operations on a
//! [`Link`](nauthy::Link) (mint, narrow, revoke). It prints NOTHING and reads no config path: a caller
//! loads the root, denylist, and identity,
//! prints its own banner, and drives this core. Everything here already speaks `bifrost` and `nauthy`, never
//! clap or a store.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io::IoSlice;

// The handler contract lives in the lean `tightbeam-handler` crate, re-exported here
// unchanged so every existing `tightbeam::tunnel::*` path keeps working, and a service implements the
// contract without taking this crate's tree. The erased bridge is imported, not re-exported: `Target` stores
// it privately and it is not part of the author-facing surface.
pub use tightbeam_handler::{
    BoxRead, BoxWrite, Handler, Metering, RootedAdmitted, Serve, ServeError, Served,
};
use tokio::io::{self, AsyncReadExt as _};
use tokio::net::TcpStream;
use tokio::net::tcp::WriteHalf;

use crate::{splice, splice_halves};

mod admit;
mod catalog;
mod connector;
mod cut;
mod exposer;
mod router;
mod target_spec;

#[cfg(test)]
mod fixtures;

pub use admit::resolve_gate;
pub use catalog::{CatalogTooLarge, MAX_CATALOG_BLOB, Posture, ServiceCatalog, ServiceEntry};
pub use connector::{
    ConnectionLost, Connector, DialRefused, PortForward, ServiceSession, WrongPeer,
};
pub use cut::{AdmittedChains, LiveCuts};
pub use exposer::{CancellationToken, Exposer};
pub use router::{DefinitionCause, DefinitionError, ManifestEntry, RawSource, Router, TargetKind};
pub use target_spec::{TargetError, TargetSpec, TargetSyntaxError};

/// How long to wait for a `fifo:` WRITER before dropping the stream. The FIFO open itself is NONBLOCKING
/// (`O_NONBLOCK`, so it returns a valid fd at once with no writer and never parks a thread), but a writer-less
/// FIFO reads as instant EOF, which is not a real byte stream. So the raw-stream open awaits readable readiness
/// (a writer connecting/writing) bounded by this timeout; on elapse the fd is dropped (cheap, no parked thread)
/// and the stream is refused, one layer deeper than the pre-gate
/// [`REQUEST_READ_TIMEOUT`](admit::REQUEST_READ_TIMEOUT) (which has already elapsed by the time a target
/// is dialed). A regular-file open has no writer to wait for and is not bounded by this. It also bounds a
/// dialer waiting for a `stdin:` seat it has just taken from a stalled holder.
///
/// It sits at the tunnel root because it bounds a raw-stream OPEN, which [`crate::raw_stream`] performs:
/// no one submodule here owns it.
pub(crate) const RAW_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Dial a local stream endpoint (`tcp:<host>:<port>` or `unix:<path>`) and pipe it to the bifrost stream.
/// The serve half of [`builtins::Forward`](crate::builtins::Forward), typed [`ServeError`] so a handler body
/// can `?` it directly.
///
/// The two endpoints are siblings and the splice does not care which it got; only the connect differs, and
/// how a TCP service hears a splice that did not finish. The scheme is matched, never guessed, so this dials
/// exactly what the grammar admitted.
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
    dial_and_splice_within(addr, writer, reader, HANDOVER_DRAIN).await
}

/// How long, in total, a forward keeps a TCP service's socket open after the way back failed with the
/// upload already handed over. The upload's tail still queued in the forward's kernel is at most one send
/// buffer. The drain ends early when the service ends, the upload is acknowledged, or the cap below is
/// reached; a service that does not read for this long can still lose it.
const HANDOVER_DRAIN: Duration = Duration::from_secs(2);

/// How much of a service's reply a forward reads and discards while it waits for the upload to land. The
/// reply goes nowhere, so a service that streams it without end is held to this much work. Reaching it ends
/// the drain, so the upload can then be lost.
const HANDOVER_DRAIN_CAP: usize = 1024 * 1024;

/// How often the drain asks the kernel whether the upload has left the forward's send queue.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
const SEND_QUEUE_POLL: Duration = Duration::from_millis(10);

/// [`dial_and_splice`] with the handover drain's deadline as a parameter, so a test can shorten it.
async fn dial_and_splice_within<W, R>(
    addr: &str,
    writer: W,
    reader: R,
    drain: Duration,
) -> Result<(), ServeError>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    match addr.split_once(':') {
        Some(("tcp", host_port)) => {
            let mut local = TcpStream::connect(host_port).await?;
            // Zero linger from the first byte, so every way this socket closes before the peer's end was
            // handed over (an error either way, a cancel, a deadline, a cut, a killed process) resets the
            // service rather than passing it a truncated stream as a finished one. Armed here, not on the
            // way out, because a process that dies runs no code on the way out.
            local.set_zero_linger()?;
            let mut handed_over = false;
            let (local_reader, local_writer) = local.split();
            let spliced = splice_halves(
                local_reader,
                Handover {
                    half: local_writer,
                    handed_over: &mut handed_over,
                },
                writer,
                reader,
            )
            .await;
            // The peer's writer was dropped inside the splice, so the peer has already heard the failure;
            // the drain holds only the local socket. It runs in place, never spawned, so a cut, a cancel or
            // a deadline that drops this future ends it too.
            if spliced.is_err() && handed_over {
                drain_after_handover(&mut local, drain).await;
            }
            spliced?;
        }
        #[cfg(unix)]
        Some(("unix", path)) => {
            // A unix socket has no reset, so a splice that did not finish reaches this service as a clean end.
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

/// The write half toward a local TCP service, clearing the zero linger once the peer's end has been handed
/// to the forward's kernel: a `shutdown` that returned `Ok` queued every byte and the end there, and a reset
/// from this side after it would take back a finished upload because the other direction failed later. It
/// records the handover, because queued is not delivered: a close that resets before the queue drains still
/// loses the queue, which is what [`drain_after_handover`] waits out.
///
/// The borrowed split keeps the drop with the socket, which is what makes zero linger apply to it; an owned
/// half would shut down on its own drop and send a clean end ahead of the reset.
struct Handover<'a> {
    half: WriteHalf<'a>,
    handed_over: &'a mut bool,
}

impl io::AsyncWrite for Handover<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().half).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().half).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.half.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().half).poll_flush(cx)
    }

    // Cleared just before the end is sent and armed again unless it was: macOS refuses to change the
    // linger on a socket shut down both ways, which this one is when the service ended its side first. Both
    // happen in the one poll that sends the end (a TCP shutdown never waits), so nothing can cancel the
    // splice between them. A linger that cannot be set is the shutdown's error, so the splice never reports
    // a success its close could still undo.
    #[allow(deprecated)]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Deprecated for a linger that blocks the thread on drop; `None` restores the default close, which
        // never blocks, and tokio offers no other way to clear it.
        if let Err(error) = this.half.as_ref().set_linger(None) {
            return Poll::Ready(Err(error));
        }
        let polled = Pin::new(&mut this.half).poll_shutdown(cx);
        if matches!(polled, Poll::Ready(Ok(()))) {
            *this.handed_over = true;
        } else if let Err(error) = this.half.as_ref().set_zero_linger() {
            return Poll::Ready(Err(error));
        }
        polled
    }
}

/// Hold a TCP service's socket open after the way back failed with the upload handed over, reading and
/// discarding the service's reply, until the upload has had its chance to land. It stops at the first of: the
/// service's end, the forward's send queue empty (the service's kernel acknowledged every byte), the cap of
/// discarded reply, or `deadline` from the failure. The deadline is total, never idle, so a service that
/// trickles its reply cannot hold the socket past it.
///
/// Every stop is the same plain close: the linger was cleared at the handover, and this never sets it again.
/// Nothing unread and nothing more arriving, the kernel goes on sending the queued tail and the end; a reply
/// byte left unread or arriving later makes the kernel reset, and a tail still queued then is lost. A reset
/// armed here instead would hand a service that took every byte an error in place of its end.
async fn drain_after_handover(local: &mut TcpStream, deadline: Duration) {
    let (mut reply, upload) = local.split();
    let discard = async {
        let mut chunk = vec![0_u8; 64 * 1024];
        let mut discarded = 0;
        while discarded < HANDOVER_DRAIN_CAP {
            match reply.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(read) => discarded += read,
            }
        }
    };
    let landed = send_queue_empties(upload.as_ref());
    let drained = async {
        tokio::select! {
            () = discard => {}
            () = landed => {}
        }
    };
    // Elapsing is one of the stops, not a failure: the close below is the same either way.
    let _elapsed = tokio::time::timeout(deadline, drained).await;
}

/// Resolve once the forward's send queue toward the service is empty, polled on a fixed tick, so a service
/// that reads its upload while it streams a reply releases the forward in milliseconds. A query that fails
/// is skipped, never read as empty.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
async fn send_queue_empties(socket: &TcpStream) {
    let mut tick = tokio::time::interval(SEND_QUEUE_POLL);
    loop {
        tick.tick().await;
        if unsent(socket) == Some(0) {
            return;
        }
    }
}

/// No query on this target, so this stop never comes: the drain waits for the service's end, the cap or
/// the deadline.
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
async fn send_queue_empties(_socket: &TcpStream) {
    core::future::pending().await
}

/// The bytes still queued in a TCP socket's kernel toward its peer: unsent plus unacknowledged.
#[cfg(target_os = "linux")]
fn unsent(socket: &TcpStream) -> Option<usize> {
    use std::os::fd::AsRawFd as _;
    let mut queued: libc::c_int = 0;
    // SAFETY: the descriptor is borrowed from a live socket, and `TIOCOUTQ` (alias `SIOCOUTQ`) writes one
    // `c_int` through the pointer, which points at `queued` for the whole call. A failure returns -1 and
    // writes nothing.
    let rc = unsafe { libc::ioctl(socket.as_raw_fd(), libc::TIOCOUTQ, &raw mut queued) };
    if rc != 0 {
        return None;
    }
    usize::try_from(queued).ok()
}

/// The bytes still queued in a TCP socket's kernel toward its peer. Apple counts data only, not the end,
/// which the plain close that follows still sends.
#[cfg(target_vendor = "apple")]
fn unsent(socket: &TcpStream) -> Option<usize> {
    use std::os::fd::AsRawFd as _;
    let mut queued: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(size_of::<libc::c_int>()).ok()?;
    // SAFETY: the descriptor is borrowed from a live socket; `SO_NWRITE` writes at most `len` bytes (one
    // `c_int`) through the value pointer, which points at `queued`, and updates `len`. Both outlive the call.
    let rc = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            (&raw mut queued).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    usize::try_from(queued).ok()
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tunnel_tests;
