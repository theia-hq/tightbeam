//! The `stdin:` seat: this process's one standard input, lent to one peer at a time and returned when that
//! peer leaves.
//!
//! fd 0 is one stream that cannot be re-opened or rewound, so two peers reading it at once would split its
//! bytes between them. The seat keeps it to one reader without ever throwing it away. [`Seat::claim`] lends
//! the reader to a dialing peer inside a guard, and the guard's `Drop` gives it back when the splice ends,
//! however it ends: the peer leaves, a write fails, the serve future is cancelled, or the seat is handed on.
//! The next peer then reads from about where the last one left off (up to one copy buffer plus the old
//! stream's in-flight window is lost at the change). Only end of input retires the seat.
//!
//! A holder is never timed out. It is displaced only when a DIFFERENT peer dials while the holder has been
//! refusing the bytes it is offered for a whole [`STALL_WINDOW`] (see [`Meter`]). A seat matters only to
//! someone who wants it, so a paused viewer with no contender keeps it indefinitely, and a viewer that is
//! reading keeps it against any number of dialers. The stalled holder's reader then goes straight to that
//! dialer, never back through the armed state, so no third peer can race in. There is no queue: a dialer
//! that cannot take the seat is refused and retries, because a waiting dialer would park an open permit
//! behind a holder that may read for hours.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bifrost::NodeId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::splice_halves;
use crate::tunnel::{BoxRead, RAW_STREAM_OPEN_TIMEOUT};

/// How long a holder may keep refusing its bytes before a dialing peer may take the seat.
///
/// Sized against the transport's flow control, not against a feeling for "slow". A stock QUIC receiver
/// (noq's default stream window of 1,250,000 B, which iroh does not override) grants credit in steps of an
/// eighth of that window, [`STOCK_CREDIT_STEP`], each time its application has consumed that much. So an
/// honest reader consuming `r` bytes a second against a backlog shows the sender NO accepted bytes for
/// `156_250 / r` seconds, then a burst. One step clears a window, and a window this long asks an honest
/// reader for one step per 90 s: the cutoff is about 1.7 KiB/s. A slower viewer loses the seat only to a
/// peer that dials; with no contender it keeps it.
///
/// The premise can go stale: if the transport's default stream window ever falls below eight times
/// [`STALL_MIN_BYTES`] (1 MiB), honest readers become preemptible at a higher rate. Re-check it on any
/// iroh or noq bump that moves the default window, or if bifrost ever sets a window of its own.
pub(super) const STALL_WINDOW: Duration = Duration::from_secs(90);

/// The bytes a holder must take within one [`STALL_WINDOW`] to keep its seat against a dialer. Below one
/// stock credit step, so a single honest grant restarts the window. A floor, never "any progress": an
/// 8-byte receive window grants credit a byte at a time, and "any byte resets the clock" would let a peer
/// hold the seat forever for three bytes a minute.
pub(super) const STALL_MIN_BYTES: u64 = 128 * 1024;

/// How long a holder's writer must go with every write taken before its stall window closes.
///
/// A window that closed on the first write taken without waiting could be forced shut by granting a
/// little more credit than one copy chunk, so a trickle would open a fresh, empty window forever. A whole
/// second of taking everything offered is what a caught-up viewer does, and what a trickler against a
/// backlog cannot do without reading the backlog.
pub(super) const STALL_CLEAR: Duration = Duration::from_secs(1);

/// One credit grant from a stock receiver: noq's default stream window (1,250,000 B) over eight. The
/// premise [`STALL_MIN_BYTES`] is sized under, restated here so the relationship can be asserted.
const STOCK_CREDIT_STEP: u64 = 1_250_000 / 8;

// One honest grant must clear a window, or an honest slow reader could never restart its own.
const _: () = assert!(STALL_MIN_BYTES < STOCK_CREDIT_STEP);

/// Why a dialer did not get the seat. Both reach the dialer as the open's refusal detail, so each says
/// what is true and what to do.
#[derive(thiserror::Error, Debug)]
pub(crate) enum SeatRefusal {
    /// Another peer holds the seat and is reading, idle, inside its first window, or mid hand-off. Worth
    /// a retry.
    #[error(
        "stdin: is held by another peer and serves one at a time; retry, or serve it as `stdin:+lossy` \
         to fan out"
    )]
    Held,
    /// The source reached end of input (or failed). Nothing will ever be read from it again.
    #[error("stdin: has reached end of input; restart to serve again")]
    Spent,
}

/// The seat over one single-consumer reader, shared by every clone of the route that serves it.
#[derive(Clone)]
pub(crate) struct Seat(Arc<Mutex<Cell>>);

/// Where the reader is. Every transition happens under the seat's one lock, which is what makes "at most
/// one peer reads" and "the reader is never dropped while it can still be read" hold together.
enum Cell {
    /// Nobody holds it; the next dialer takes it.
    Armed(BoxRead),
    /// A peer is reading it, through a [`SeatReader`] that gives it back on drop.
    Held(Holder),
    /// A dialer displaced a stalled holder and waits for the reader, which the holder's guard sends
    /// straight to it. Every other dialer is refused meanwhile: one hand-off at a time.
    Handing(Handoff),
    /// End of input, or a read error. Terminal.
    Spent,
}

/// The peer holding the seat, and what a dialer needs to judge and displace it.
struct Holder {
    /// Compared with each dialer's id: a peer never displaces itself, or a stalled holder could redial for
    /// a fresh window and hold the seat forever.
    peer: NodeId,
    /// Published by the holder's writer, read here at dial time.
    meter: Arc<Meter>,
    /// Fired once, when a dialer displaces this holder, to end its splice.
    preempt: oneshot::Sender<()>,
}

/// A hand-off in flight: who is waiting for the reader, and where to send it.
struct Handoff {
    dialer: NodeId,
    grant: oneshot::Sender<Grant>,
}

/// What a waiting dialer receives from the displaced holder's guard.
enum Grant {
    Seated(Seated),
    /// The holder's reader reached end of input before it could be handed on: the dialer is refused with
    /// the end, never given a dead reader or an empty stream.
    Spent,
}

/// What [`Seat::take`] decided, under the lock.
enum Take {
    Seated(Seated),
    Waiting(oneshot::Receiver<Grant>),
    Refused(SeatRefusal),
}

impl Seat {
    /// Arm a seat over `reader`.
    pub(crate) fn new(reader: BoxRead) -> Self {
        Self(Arc::new(Mutex::new(Cell::Armed(reader))))
    }

    /// Take the seat for `dialer`, or say why not.
    ///
    /// A dialer that displaces a stalled holder waits here for the reader, bounded by the raw-stream open
    /// timeout and still holding the open permit it came in with. The holder's splice is dropped
    /// synchronously, so the wait is one wake in practice; if it ever outlives the bound, the dialer takes
    /// the Held path and the reader returns to the seat when it arrives.
    pub(crate) async fn claim(&self, dialer: NodeId) -> Result<Seated, SeatRefusal> {
        let waiting = match self.take(dialer, Instant::now()) {
            Take::Seated(seated) => return Ok(seated),
            Take::Refused(refusal) => return Err(refusal),
            Take::Waiting(waiting) => waiting,
        };
        match tokio::time::timeout(RAW_STREAM_OPEN_TIMEOUT, waiting).await {
            Ok(Ok(Grant::Seated(seated))) => Ok(seated),
            Ok(Ok(Grant::Spent)) => Err(SeatRefusal::Spent),
            Ok(Err(_)) | Err(_) => Err(SeatRefusal::Held),
        }
    }

    /// Decide one dial. The only place a dialer meets the seat, so contention is detected here and
    /// nowhere else, under the lock that serializes every other transition.
    fn take(&self, dialer: NodeId, now: Instant) -> Take {
        let mut cell = self.lock();
        // Every arm puts back what the seat should hold next; `Spent` is only the placeholder.
        match core::mem::replace(&mut *cell, Cell::Spent) {
            Cell::Armed(reader) => {
                let (holder, seated) = Holder::seat(dialer, reader, self);
                *cell = Cell::Held(holder);
                Take::Seated(seated)
            }
            Cell::Spent => Take::Refused(SeatRefusal::Spent),
            // One hand-off at a time.
            handing @ Cell::Handing(_) => {
                *cell = handing;
                Take::Refused(SeatRefusal::Held)
            }
            // A peer never displaces itself (it would buy a fresh window by redialing), and nobody
            // displaces a holder that is reading, idle, or inside its first window.
            Cell::Held(holder) if holder.peer == dialer || !holder.meter.preemptible(now) => {
                *cell = Cell::Held(holder);
                Take::Refused(SeatRefusal::Held)
            }
            Cell::Held(holder) => {
                let (grant, waiting) = oneshot::channel();
                // Logged at the level a stock serving filter shows, naming both sides, so a pair of
                // identities trading the seat back and forth is visible and each can be revoked.
                tracing::error!(
                    holder = %holder.peer,
                    dialer = %dialer,
                    "stdin: seat handed to a waiting peer; its holder had stopped reading"
                );
                // The holder may already be gone (its splice ended on its own); its guard then hands
                // the reader on as it drops, which is the same outcome.
                let _ = holder.preempt.send(());
                *cell = Cell::Handing(Handoff { dialer, grant });
                Take::Waiting(waiting)
            }
        }
    }

    /// Receive the reader back from a guard: re-arm it, hand it to a waiting dialer, or retire the seat
    /// at end of input.
    fn put_back(&self, lent: Lent) {
        let mut cell = self.lock();
        let handoff = match core::mem::replace(&mut *cell, Cell::Spent) {
            Cell::Held(_) => None,
            Cell::Handing(handoff) => Some(handoff),
            // A reader coming back to a seat nobody held is a broken invariant. Never overwrite what the
            // seat holds with it: keep the seat as it is and drop the stray.
            stray @ (Cell::Armed(_) | Cell::Spent) => {
                *cell = stray;
                tracing::error!("a stdin: reader came back to a seat nobody held; dropping it");
                return;
            }
        };
        let Lent::Reading(reader) = lent else {
            // The cell is already `Spent`. This is the one transition into it, so it logs exactly once.
            tracing::error!("stdin: reached end of input; restart to serve it again");
            if let Some(handoff) = handoff {
                let _ = handoff.grant.send(Grant::Spent);
            }
            return;
        };
        let Some(handoff) = handoff else {
            *cell = Cell::Armed(reader);
            return;
        };
        let (holder, seated) = Holder::seat(handoff.dialer, reader, self);
        *cell = Cell::Held(holder);
        // The dialer gave up (timed out or was cancelled). The reader goes back to the seat rather than
        // being dropped, which would retire fd 0 for good. It is taken out of the undelivered guard first,
        // so that guard's own `Drop` does not re-enter this lock.
        if let Err(Grant::Seated(mut undelivered)) = handoff.grant.send(Grant::Seated(seated))
            && let Some(Lent::Reading(reader)) = undelivered.reader.lent.take()
        {
            *cell = Cell::Armed(reader);
        }
    }

    /// The seat's lock. A plain mutex, not an async one: every transition is a handful of moves with no
    /// await inside, and a guard's `Drop` must take it synchronously. A poisoned lock (a panic mid
    /// transition) is read through rather than unwrapped: the placeholder a transition leaves is `Spent`,
    /// so the worst outcome is a refusal, never a second reader.
    fn lock(&self) -> MutexGuard<'_, Cell> {
        let Self(cell) = self;
        cell.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl core::fmt::Debug for Seat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Seat").finish_non_exhaustive()
    }
}

impl Holder {
    /// Seat `peer` with `reader`: a fresh meter with no window open, and the preempt channel, one end
    /// kept by the cell and the other handed to the new holder beside the lent reader.
    fn seat(peer: NodeId, reader: BoxRead, seat: &Seat) -> (Self, Seated) {
        let meter = Arc::new(Meter::default());
        let (preempt, preempted) = oneshot::channel();
        let holder = Self {
            peer,
            meter: Arc::clone(&meter),
            preempt,
        };
        let seated = Seated {
            reader: SeatReader {
                lent: Some(Lent::Reading(reader)),
                seat: seat.clone(),
            },
            link: SeatLink { meter, preempted },
        };
        (holder, seated)
    }
}

/// A seat taken: the lent reader, and the link its splice needs to be judged and displaced. A seat is the
/// only source that yields one, so the served path cannot forget to meter it.
#[must_use = "dropping a seat without splicing it hands the reader straight back"]
pub(crate) struct Seated {
    pub(super) reader: SeatReader,
    link: SeatLink,
}

/// The holder's end of the seat: the meter its writer publishes to, and the signal that it was displaced.
struct SeatLink {
    meter: Arc<Meter>,
    preempted: oneshot::Receiver<()>,
}

impl Seated {
    /// Splice the lent reader toward the peer until the splice ends or the seat is handed to a dialer. The
    /// peer-facing writer is metered, which is what lets a dialer see a holder that refuses its bytes.
    /// Displaced, the splice is dropped where it stands; dropping it drops the lent reader, whose guard
    /// sends it to the dialer. The displaced peer's stream then ends as a clean close (the transport has no
    /// reset), which is why a live source's end can be false.
    pub(crate) async fn splice<W, R>(self, writer: W, reader: R) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let Self {
            reader: source,
            link: SeatLink { meter, preempted },
        } = self;
        let writer = Metered {
            inner: writer,
            meter,
        };
        tokio::select! {
            result = splice_halves(source, tokio::io::sink(), writer, reader) => result,
            // A closed channel means the seat moved on without displacing this holder: keep splicing.
            Ok(()) = preempted => Ok(()),
        }
    }
}

/// The lent reader. Reads pass straight through; `Drop` gives the reader back to its seat, or retires the
/// seat if the reader reached end of input or failed. Drop, rather than an error arm, is what covers every
/// way a splice can end: a failed `Ok` write, a splice error, a cancelled serve future, a displacement.
pub(crate) struct SeatReader {
    /// `None` once given back, so `Drop` has nothing left to do.
    lent: Option<Lent>,
    seat: Seat,
}

/// The state of a lent reader.
enum Lent {
    /// Still readable: it goes back to the seat.
    Reading(BoxRead),
    /// It returned end of input or an error, and was dropped: the seat is spent.
    Ended,
}

impl AsyncRead for SeatReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(Lent::Reading(reader)) = &mut this.lent else {
            // Ended: every later read is end of input too.
            return Poll::Ready(Ok(()));
        };
        let asked = buf.remaining();
        let before = buf.filled().len();
        let polled = Pin::new(reader).poll_read(cx, buf);
        // End of input is a ready read that filled nothing into a buffer that had room. Either it or an
        // error spends the seat: the reader has nothing more to give anyone.
        let ended = match &polled {
            Poll::Ready(Ok(())) => asked > 0 && buf.filled().len() == before,
            Poll::Ready(Err(_)) => true,
            Poll::Pending => false,
        };
        if ended {
            this.lent = Some(Lent::Ended);
        }
        polled
    }
}

impl Drop for SeatReader {
    fn drop(&mut self) {
        if let Some(lent) = self.lent.take() {
            self.seat.put_back(lent);
        }
    }
}

/// The holder's stall gauge, written by its peer-facing writer and read by the seat when another peer
/// dials. The writer publishes and the seat decides: the writer never ends a splice on its own.
///
/// It sits on the WRITER because that is where a refusal shows: a write the peer has no credit for returns
/// `Pending`. The reader side cannot see it in time, because `io::copy` keeps refilling its buffer from the
/// source while a write is pending, so on a slow producer a stalled viewer looks merely quiet until that
/// buffer fills (about 800 s at 10 B/s). A source with nothing to say never makes the writer wait, so an
/// idle holder never opens a window and is never preemptible.
///
/// The rule, in full:
/// - a window opens on a `Pending` write, unless one is already open;
/// - it restarts each time [`STALL_MIN_BYTES`] have been taken in it;
/// - it closes once the writer has gone [`STALL_CLEAR`] with every write taken;
/// - the holder is preemptible once a window has stayed open for [`STALL_WINDOW`].
#[derive(Default)]
struct Meter(Mutex<Gauge>);

/// The meter's state. Behind a plain mutex: it is written on every write and read under the seat's lock at
/// dial time, never across an await, and is contended only at a dial.
#[derive(Default)]
struct Gauge {
    writer: Writer,
    window: Option<Window>,
}

/// What the holder's writer was last doing.
#[derive(Default, Clone, Copy)]
enum Writer {
    /// Every write so far was taken at once.
    #[default]
    Unrefused,
    /// The last write was refused, and the writer is waiting on the peer.
    Refused,
    /// The last refusal ended at this instant, and every write since was taken.
    ClearSince(Instant),
}

/// One stall window: when it opened (or last restarted) and the bytes taken in it since.
#[derive(Clone, Copy)]
struct Window {
    opened: Instant,
    taken: u64,
}

impl Meter {
    /// Record one write's outcome, at `now`.
    fn record(&self, polled: &Poll<io::Result<usize>>, now: Instant) {
        let Self(gauge) = self;
        let mut gauge = gauge.lock().unwrap_or_else(PoisonError::into_inner);
        match polled {
            Poll::Pending => {
                if matches!(gauge.writer, Writer::Refused) {
                    return;
                }
                if !gauge.open(now) {
                    gauge.window = Some(Window {
                        opened: now,
                        taken: 0,
                    });
                }
                gauge.writer = Writer::Refused;
            }
            Poll::Ready(Ok(taken)) => {
                if matches!(gauge.writer, Writer::Refused) {
                    gauge.writer = Writer::ClearSince(now);
                }
                if let Some(window) = &mut gauge.window {
                    window.taken += *taken as u64;
                    if window.taken >= STALL_MIN_BYTES {
                        *window = Window {
                            opened: now,
                            taken: 0,
                        };
                    }
                }
            }
            // A failed write ends the splice; there is nothing left to judge.
            Poll::Ready(Err(_)) => {}
        }
    }

    /// Whether a dialer at `now` may displace this holder.
    fn preemptible(&self, now: Instant) -> bool {
        let Self(gauge) = self;
        let gauge = gauge.lock().unwrap_or_else(PoisonError::into_inner);
        match gauge.window {
            Some(window) if gauge.open(now) => {
                now.saturating_duration_since(window.opened) >= STALL_WINDOW
            }
            _ => false,
        }
    }
}

impl Gauge {
    /// Whether a window is open at `now`: one has opened, and the writer has not since gone a clean
    /// [`STALL_CLEAR`] with every write taken.
    fn open(&self, now: Instant) -> bool {
        match (self.window, self.writer) {
            (None, _) | (Some(_), Writer::Unrefused) => false,
            (Some(_), Writer::Refused) => true,
            (Some(_), Writer::ClearSince(clear)) => {
                now.saturating_duration_since(clear) < STALL_CLEAR
            }
        }
    }
}

/// The holder's peer-facing writer, wrapped so every write's outcome reaches its [`Meter`].
struct Metered<W> {
    inner: W,
    meter: Arc<Meter>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Metered<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.meter.record(&polled, Instant::now());
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
