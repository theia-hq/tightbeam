//! tightbeam's first-party services: the built-in local forward and the loopback reflector, implemented
//! against the same [`Handler`] contract a caller's service implements, so the Router's
//! [`.forward`](crate::tunnel::Router::forward) and [`.echo`](crate::tunnel::Router::echo) verbs are sugar
//! over `.service`.
//!
//! Shipping these in core costs nothing (no dependency, no consumer policy) and keeps one access path: a
//! bound handler, one catalog, one posture story. The raw-stream family (`file:`/`fifo:`/`stdin:`) stays a
//! native target arm instead, because it carries the second open axis (the unsafe overlay) the
//! one-dimensional [`Exposure`](crate::open_policy::PublicUse) marker cannot express.

use tokio::io;

use crate::open_policy::OptIn;
use crate::tunnel::{BoxRead, BoxWrite, Handler, ServeError, Served, dial_and_splice};

/// The built-in local forward: connect a `host:port` or a `unix:<path>` and splice bytes to it. A socket
/// the operator deliberately stood up, so it has a legitimate public form
/// ([`Exposure = OptIn`](crate::open_policy::OptIn)); a typo in the addr is refused at bind, not at dial.
pub struct Forward {
    addr: String,
}

impl Forward {
    /// A forward to `addr` (validated by the Router's verb before it reaches here).
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    /// The resolved forwarding address (`host:port` or `unix:<path>`).
    pub fn addr(&self) -> &str {
        &self.addr
    }
}

impl Handler for Forward {
    type Exposure = OptIn;

    async fn serve(
        &self,
        _served: Served<Self>,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> Result<(), ServeError> {
        dial_and_splice(&self.addr, writer, reader).await
    }
}

/// The built-in loopback reflector: reflect the caller's OWN bytes straight back to it. It opens no host
/// resource (no file, no socket, no backend) and holds no secret, so a stranger only ever reads back what it
/// itself sent. That makes it as open-safe as a handler can be
/// ([`Exposure = OptIn`](crate::open_policy::OptIn)): the zero-setup public demo, served under a plain
/// public gate with no unsafe opt-in.
pub struct Echo;

impl Handler for Echo {
    type Exposure = OptIn;

    /// Echo is symmetric by construction: a caller must send N bytes to receive N, so it can never turn a
    /// small request into a large response the way an uncapped responder does. It therefore reports
    /// [`Metered`](crate::tunnel::Metering::Metered), and an open echo does not carry the unmetered caveat.
    fn metering(&self) -> crate::tunnel::Metering {
        crate::tunnel::Metering::Metered
    }

    async fn serve(
        &self,
        _served: Served<Self>,
        mut writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        use io::AsyncWriteExt as _;
        // `reader` carries the peer's bytes and `writer` returns to the peer, so copying `reader -> writer`
        // is the loopback; on the peer's half-close the copy hits EOF and the write half is shut down so the
        // peer sees a clean close.
        io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await?;
        Ok(())
    }
}
