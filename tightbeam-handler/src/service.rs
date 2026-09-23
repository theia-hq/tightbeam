//! The TYPED door: a service states the frame its callers open with, and receives it decoded.
//!
//! [`Handler`] is the floor and it stays raw, because half the services in this family define no bytes
//! of their own: one speaks SSH through a foreign engine, another speaks a blob wire that owns the whole
//! stream, and a framing layer in the contract would be dead weight to both. So the typed layer is a
//! LIBRARY a service opts into, never a tax the contract collects: implement [`Service`] and bind
//! [`Serve`] to get the preamble decoded for you, or implement [`Handler`] directly and pay nothing.
//! Both kinds store side by side in one erased route table, which is what makes this opt-in rather
//! than a migration.
//!
//! **The RAW halves come back BY VALUE after the preamble.** [`Service::respond`] receives the decoded
//! request AND the two stream halves, positioned at the first byte after the frame with nothing
//! buffered ahead, so a service that streams a body, counts a payload, or splices is never forced
//! through a codec. That rule is the reason this layer is safe to add: the framing touches the control
//! preamble, which is tens of bytes and happens once, and never the payload, which is the whole
//! transfer.
//!
//! [`Serve`] is a wrapper type rather than a blanket `impl<S: Service> Handler for S`, and it has to be:
//! the orphan rule forbids a downstream crate implementing a foreign trait for every type satisfying
//! its own, and `impl<S> ForeignTrait for LocalType<S>` is the shape that is allowed. The wrapper is
//! the better door anyway. It needs no change to [`Handler`], the opt-in is a visible type at the bind
//! site rather than an invisible coherence rule, and a type that tried to be both a `Service` and a
//! `Handler` fails at its own impl with a clear message instead of at a blanket it never wrote.

use core::future::Future;

use tokio::io;

use crate::contract::{BoxRead, BoxWrite, Handler, Metering, ServeError, Served};
use crate::open_policy::PublicUse;
use crate::wire::{Frame, read_frame};

/// A service whose callers open with a typed control frame: state the frame, receive it decoded, get the
/// raw stream back.
///
/// Everything [`Handler`] declares is declared here and forwarded unchanged through [`Serve`], so opting
/// in costs no authority and grants none. [`Exposure`](Service::Exposure) is the same sealed,
/// uninhabited ceiling with no default, and it reaches the dispatcher as this service's own answer: an
/// adapter that softened it would be a silent downgrade of the one compile-time property the family's
/// authority story rests on.
pub trait Service: Send + Sync + 'static {
    /// This service's open-safety CEILING, exactly as a [`Handler`] states it (no default, sealed,
    /// uninhabited), forwarded by [`Serve`] as its own [`Handler::Exposure`].
    type Exposure: PublicUse;

    /// The control frame a caller opens the stream with. [`Serve`] reads exactly one of these and hands
    /// it to [`respond`](Service::respond) decoded.
    type Request: Frame + Send;

    /// The responder-side rate limit this service enforces, forwarded to [`Handler::metering`]. Same
    /// fail-loud default: a service that states no bound is narrated as unbounded when opened.
    fn metering(&self) -> Metering {
        Metering::Unmetered
    }

    /// Serve ONE request.
    ///
    /// The stream halves arrive BY VALUE, positioned at the first byte after the request frame, so this
    /// body owns the rest of the stream outright: stream a body to EOF, count a payload, join the halves
    /// and hand them to a foreign engine. Nothing was read ahead, so nothing has to be replayed.
    ///
    /// The proof is a [`Served<Serve<Self>>`](Served), the serving proof for the handler that is
    /// actually BOUND, which is the wrapper. Naming the wrapper rather than `Self` costs nothing and
    /// keeps the proof's one property intact: `Serve<S>` is uniquely determined by `S`, so the proof is
    /// still bound to one handler type and there is no sibling wrapper to launder it through.
    fn respond(
        &self,
        served: Served<Serve<Self>>,
        request: Self::Request,
        writer: BoxWrite,
        reader: BoxRead,
    ) -> impl Future<Output = Result<(), ServeError>> + Send
    where
        Self: Sized;
}

/// The adapter that binds a [`Service`] as a [`Handler`]: read the one control frame, hand the service
/// its decoded request and the raw halves.
///
/// Bind `Serve(MyService)` where a handler is expected. The inner value stays reachable as `.0` for a
/// crate that has a reason.
///
/// **The preamble read carries no clock of its own.** The adapter reads until the frame is whole, and
/// the only bound on that is the dispatcher's uniform post-admission first-traffic deadline, which is
/// armed at handoff and DISARMED by the first byte in either direction. So a peer that opens a stream
/// and says nothing is dropped, and a peer that writes one byte and then stalls is not. A service
/// whose own profile bounds the opening read today, because it is openable and a held stream is a
/// scarce public slot, must keep reading its own preamble and stay on [`Handler`]: this door would
/// take that bound away, and a bound nobody notices leaving is the worst kind to lose. The contract
/// cannot supply one, because a bound that is the same for every service belongs to the one place
/// that dispatches them all, and a bound that varies belongs to the service that varies it.
pub struct Serve<S>(pub S);

impl<S: Service> Handler for Serve<S> {
    /// The service's own ceiling, forwarded as a TYPE. The erased bridge reads it off the wrapper and
    /// gets the service's answer, so a `Never` service behind this adapter still refuses an open witness
    /// before any success response.
    type Exposure = S::Exposure;

    fn metering(&self) -> Metering {
        self.0.metering()
    }

    async fn serve(
        &self,
        served: Served<Self>,
        writer: BoxWrite,
        mut reader: BoxRead,
    ) -> Result<(), ServeError> {
        // The ONE read this layer performs. It takes exactly the frame and stops, so `reader` goes on to
        // the service still holding the payload's first byte.
        //
        // A frame this build cannot parse arrives here as a failure and the stream ends, which is the
        // right answer for bytes that are not ours and the wrong one for a peer worth telling. A wire
        // with something true to say about an unreadable frame says it by DECODING that condition into
        // a variant of `Request` and answering from `respond`, where the writer is.
        let request = read_frame::<S::Request, _>(&mut reader)
            .await
            .map_err(|error| ServeError::Io(io::Error::other(error)))?;
        self.0.respond(served, request, writer, reader).await
    }
}
