//! Opt-in raw-stream fan-out: one live source, many consumers, drop-for-slow.
//!
//! A `stdin:`/`fifo:` source marked `+lossy` (operator-declared, delib-20 SYNTHESIS + delib-24) becomes a
//! fan-out: the underlying reader is opened ONCE and its bytes are copied into ONE shared ring, from which N
//! independent consumers each read through their own cursor. The design's ship-blockers (delib-20 Adversary,
//! all mandatory) are what this module IS:
//!
//! - **One shared bounded ring PER SOURCE, bounded by BYTES.** A per-consumer ring would be an
//!   aggregate-memory attack (a flooder pins `ring x N`); there is exactly one [`Ring`] per source, capped at
//!   [`RING_BYTES`], so a source's memory ceiling is independent of consumer count.
//! - **The producer NEVER blocks on a consumer.** The pump appends to the ring and, on overflow, evicts the
//!   OLDEST bytes (advancing the ring's absolute base) rather than waiting for the slowest reader. A consumer
//!   that never reads cannot stall the producer or any other consumer.
//! - **Drop-for-slow, per cursor, local.** A cursor whose position has fallen behind the ring's base (its
//!   bytes were evicted while it lagged) is force-advanced to the live edge on its next read: it silently
//!   loses the gap and continues. A lag on consumer A never gaps consumer B (each cursor is independent), and
//!   the lag is NEVER injected in-band (that would corrupt the exact-content case); it is a local operator log
//!   only.
//! - **Lazy-open on first consumer, shared while >=1, close on the last leaving.** The pump starts when the
//!   first cursor is handed out and stops when the last cursor drops (the source reader is dropped with it).
//!   A `stdin:` fan-out is one non-rewindable live session: a late joiner attaches at the live edge, it does
//!   not replay history.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};
use tokio::sync::Notify;

use crate::tunnel::BoxRead;

/// The shared ring's byte ceiling: the most live bytes buffered for the slowest consumer before older bytes
/// are dropped. One ring per source, so a source's fan-out memory is at most this regardless of how many
/// consumers attach (a per-consumer ring would let a flooder pin `RING_BYTES x N`; this is why the ring is
/// shared). 1 MiB is generous for a live media source (well over a second of most streams) and small enough
/// that a node serving several fan-out sources stays bounded.
const RING_BYTES: usize = 1 << 20;

/// How much the pump reads from the source per iteration. Independent of [`RING_BYTES`]; just the copy
/// granularity from the source reader into the ring.
const PUMP_CHUNK: usize = 64 * 1024;

/// A `+lossy` fan-out over one source: lazy-opens the source on the first consumer, shares one bounded ring
/// while at least one consumer is attached, and closes on the last leaving. Cheap to clone (an `Arc` to the
/// shared state); `RawStream` holds one and hands each `open()` a fresh [`Cursor`] reader.
#[derive(Clone)]
pub(crate) struct Fanout(Arc<Shared>);

impl core::fmt::Debug for Fanout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fanout").finish_non_exhaustive()
    }
}

/// The state shared by every consumer of one fan-out source: the ring itself, a notifier that wakes parked
/// cursors when the pump appends or the source closes, and the lifecycle bookkeeping (the take-once source
/// reader and the live consumer count) behind one mutex.
struct Shared {
    ring: Mutex<Ring>,
    /// Woken on every append and on close, so a cursor that caught up parks on [`Notify::notified`] and is
    /// resumed the instant there is more to read (or the source ends).
    wake: Notify,
    life: Mutex<Life>,
}

/// The lifecycle half of the shared state: the not-yet-taken source reader (moved out when the pump starts)
/// and the count of live cursors, which drives lazy-open (0 -> 1 starts the pump) and close-on-last (1 -> 0
/// drops the source).
struct Life {
    /// The source reader, taken by the first consumer to start the pump. `None` once the pump owns it (or the
    /// fan-out was already run once and closed: a `stdin:` session is non-rewindable, so it never re-arms).
    source: Option<BoxRead>,
    /// How many cursors are attached. The pump runs while this is >= 1 and stops when it reaches 0.
    consumers: usize,
}

/// One consumer's independent view of the ring: an absolute byte position that only ever advances (either by
/// what it read, or by a force-advance to the live edge when it lagged and its bytes were evicted). Dropping a
/// cursor decrements the live count and, if it was the last, stops the pump and closes the source.
pub(crate) struct Cursor {
    shared: Arc<Shared>,
    /// This cursor's absolute read position (bytes since the source began). Compared against the ring's `base`
    /// to detect a lag: `pos < base` means the bytes between them were dropped while this consumer was slow.
    pos: u64,
    /// The in-flight wake future when this cursor is parked at the live edge, held ACROSS polls so the waker
    /// stays registered. Dropping it on each `Pending` would deregister the waker and lose the wake that
    /// resumes the read; keeping it is what makes the park race-free (interest is registered before the ring
    /// lock is released, and retained until the notify fires). `'static` because it owns an `Arc<Shared>`.
    parked: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

/// The one shared bounded byte buffer, addressed by ABSOLUTE offsets so a lagging cursor is detectable after
/// eviction. `buf[0]` is the byte at absolute offset `base`; the pump appends at the back and, on overflow,
/// drains the front and advances `base` (dropping the oldest bytes, never blocking). `closed` is set when the
/// source hits EOF or errors, so a caught-up cursor reads EOF rather than parking forever.
struct Ring {
    buf: VecDeque<u8>,
    /// The absolute offset of `buf.front()`. A cursor whose `pos < base` lagged past the retained window.
    base: u64,
    /// The source ended (EOF or error): no more bytes will ever be appended.
    closed: bool,
}

impl Ring {
    fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            base: 0,
            closed: false,
        }
    }

    /// The absolute offset one past the last buffered byte (the live edge).
    fn head(&self) -> u64 {
        self.base + self.buf.len() as u64
    }

    /// Append `bytes` and, if the ring is now over its byte ceiling, DROP the oldest bytes to fit (advancing
    /// `base`). This never blocks and never waits on a consumer: an overflowing ring evicts history, so the
    /// producer's rate is never bounded by the slowest reader.
    fn append(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
        if self.buf.len() > RING_BYTES {
            let overflow = self.buf.len() - RING_BYTES;
            self.buf.drain(..overflow);
            self.base += overflow as u64;
        }
    }
}

impl Fanout {
    /// Arm a fan-out over `source`. The source is NOT opened here: it is held until the first [`Fanout::open`]
    /// hands out a cursor, matching the "lazy-open on the first consumer" lifecycle.
    pub(crate) fn new(source: BoxRead) -> Self {
        Self(Arc::new(Shared {
            ring: Mutex::new(Ring::new()),
            wake: Notify::new(),
            life: Mutex::new(Life {
                source: Some(source),
                consumers: 0,
            }),
        }))
    }

    /// Attach a consumer: hand back a [`Cursor`] positioned at the live edge, starting the pump if this is the
    /// first consumer. A late joiner attaches at the current head (a `stdin:` fan-out is a live session, not a
    /// replay), so it sees bytes from now on, never the history other consumers already drained.
    ///
    /// Returns `None` if the source was already consumed and closed (a non-rewindable `stdin:` session that
    /// ended): there is nothing left to attach to, so the caller refuses cleanly rather than hand out a cursor
    /// that only ever reads EOF.
    pub(crate) fn open(&self) -> Option<Cursor> {
        let Self(shared) = self;
        let mut life = shared.life.lock().unwrap_or_else(PoisonError::into_inner);
        // The first consumer starts the pump by taking the source. A later consumer finds `source` already
        // taken (the pump owns it) and simply attaches; but if the source is gone AND no consumer is live, the
        // session already ran to completion and closed, so there is nothing to attach to.
        if let Some(source) = life.source.take() {
            spawn_pump(Arc::clone(shared), source);
        } else if life.consumers == 0 {
            return None;
        }
        life.consumers += 1;
        // A late joiner starts at the live edge (the head), never replaying the bytes already streamed.
        let pos = shared
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .head();
        Some(Cursor {
            shared: Arc::clone(shared),
            pos,
            parked: None,
        })
    }
}

/// Start the pump: copy the source into the shared ring until EOF or error, waking parked cursors on every
/// append and once at close. The pump NEVER waits on a consumer, so a slow or silent consumer cannot stall
/// it; it stops the moment the source ends (or the last consumer left, checked each iteration).
fn spawn_pump(shared: Arc<Shared>, mut source: BoxRead) {
    tokio::spawn(async move {
        let mut chunk = vec![0u8; PUMP_CHUNK];
        loop {
            // Stop early if every consumer has left: close-on-last, so the source reader is dropped here.
            if shared
                .life
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .consumers
                == 0
            {
                break;
            }
            match source.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    shared
                        .ring
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .append(&chunk[..n]);
                    // Wake every parked cursor: there are new bytes to read.
                    shared.wake.notify_waiters();
                }
                // A source error ends the session for everyone: the bytes so far stay readable, then EOF.
                Err(error) => {
                    tracing::warn!(%error, "lossy fan-out source read failed; closing");
                    break;
                }
            }
        }
        shared
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed = true;
        // Wake caught-up cursors so they observe EOF rather than parking forever on a source that has ended.
        shared.wake.notify_waiters();
    });
}

impl Drop for Cursor {
    fn drop(&mut self) {
        let mut life = self
            .shared
            .life
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        life.consumers = life.consumers.saturating_sub(1);
        // Close-on-last is enforced by the pump, which re-checks this count at the top of each iteration and
        // stops at 0. No wake is needed (or possible) here: the pump is parked on the SOURCE read, not on
        // `wake`, so it observes the departure after its current read returns (the next byte, or the source's
        // own close), then drops the source. `source` is never put back: a `stdin:` session is non-rewindable.
    }
}

impl AsyncRead for Cursor {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Register interest FIRST, then inspect the ring. This is tokio's documented lost-wake-free order
            // for `Notify`: because `notify_waiters` only wakes waiters ALREADY registered (it stores no
            // permit), a check-then-register order could miss an append that lands in between and park forever.
            // Building (and polling) the `Notified` future registers the waker; only then do we look at the
            // ring, so any append/close after this point is guaranteed to wake us. The future is held in
            // `self.parked` across polls so the registration survives a `Poll::Pending` return.
            let shared = Arc::clone(&this.shared);
            let parked = this
                .parked
                .get_or_insert_with(|| Box::pin(async move { shared.wake.notified().await }));
            // Poll once to (re-)register the waker with THIS `cx`. A `Ready` here means a wake already fired; we
            // still fall through to inspect the ring (the wake's whole purpose), rebuilding a fresh future for
            // the next park. A `Pending` leaves the waker armed.
            let registered = parked.as_mut().poll(cx).is_ready();
            if registered {
                this.parked = None;
            }

            {
                let ring = this
                    .shared
                    .ring
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                // Drop-for-slow: if this cursor fell behind the retained window while it was slow, its bytes
                // were evicted. Force-advance to the live edge (the ring's base) and continue: it silently
                // loses the gap. This is LOCAL (only this cursor jumps); consumer B is untouched.
                if this.pos < ring.base {
                    this.pos = ring.base;
                }
                if this.pos < ring.head() {
                    // Bytes are available at `pos`: copy as many as fit into `buf`. Reading unparks the cursor.
                    let start = (this.pos - ring.base) as usize;
                    let available = ring.buf.len() - start;
                    let n = available.min(buf.remaining());
                    // `VecDeque` is two contiguous slices; copy across the split so a wrapped ring reads whole.
                    let (front, back) = ring.buf.as_slices();
                    copy_from_deque(front, back, start, n, buf);
                    this.pos += n as u64;
                    this.parked = None;
                    return Poll::Ready(Ok(()));
                }
                if ring.closed {
                    // Caught up and the source has ended: EOF (leave `buf` unfilled).
                    this.parked = None;
                    return Poll::Ready(Ok(()));
                }
            }
            // Caught up to the live edge, source still open. If the wake we polled had ALREADY fired (a race we
            // just absorbed), loop to re-register and re-check. Otherwise the waker is armed: yield Pending and
            // the pump's next append/close will resume us.
            if registered {
                continue;
            }
            return Poll::Pending;
        }
    }
}

/// Copy `n` bytes starting at logical offset `start` from a `VecDeque`'s two backing slices into `buf`. The
/// deque is `front` then `back`; `start`/`n` are in that logical space, so a read that spans the split copies
/// the tail of `front` and the head of `back` in order.
fn copy_from_deque(front: &[u8], back: &[u8], start: usize, n: usize, buf: &mut ReadBuf<'_>) {
    let mut remaining = n;
    let mut offset = start;
    for slice in [front, back] {
        if remaining == 0 {
            break;
        }
        if offset >= slice.len() {
            offset -= slice.len();
            continue;
        }
        let take = remaining.min(slice.len() - offset);
        buf.put_slice(&slice[offset..offset + take]);
        remaining -= take;
        offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use core::pin::Pin;
    use core::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};

    use super::Fanout;

    /// An `AsyncRead` that delivers a fixed total of bytes, pausing once per `window` bytes emitted, so a test
    /// can pace a source: a consumer that drains a window within the pause stays inside the ring, one that
    /// sleeps longer falls behind and is lapped. Each `poll_read` returns whatever fits `buf` (capped so it
    /// never overshoots the current window boundary), waiting out the pause at each boundary. Deterministic,
    /// unlike an instant in-memory source that lets the pump lap every consumer at once.
    struct PacedReader {
        window: usize,
        remaining: usize,
        emitted_in_window: usize,
        pause: core::time::Duration,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl PacedReader {
        fn new(window: usize, windows: usize, pause: core::time::Duration) -> Self {
            Self {
                window,
                remaining: window * windows,
                emitted_in_window: 0,
                pause,
                sleep: None,
            }
        }
    }

    impl AsyncRead for PacedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.remaining == 0 {
                return Poll::Ready(Ok(())); // EOF
            }
            // At a window boundary, wait out the pace before delivering the next window's bytes.
            if self.emitted_in_window == 0 {
                if self.sleep.is_none() {
                    let pause = self.pause;
                    self.sleep = Some(Box::pin(tokio::time::sleep(pause)));
                }
                let sleep = self.sleep.as_mut().expect("just set when None");
                match sleep.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => self.sleep = None,
                }
            }
            // Deliver up to the rest of this window (never across the boundary, so the next read re-paces).
            let window_left = self.window - self.emitted_in_window;
            let n = buf.remaining().min(window_left).min(self.remaining);
            buf.put_slice(&vec![7u8; n]);
            self.remaining -= n;
            self.emitted_in_window += n;
            if self.emitted_in_window == self.window {
                self.emitted_in_window = 0;
            }
            Poll::Ready(Ok(()))
        }
    }

    /// N consumers each receive the source's exact bytes from ONE shared ring (fan-out, delib-20). A small
    /// static body fits the ring, so no cursor lags: every consumer reads the whole stream, proving one source
    /// is delivered to many independent cursors.
    #[tokio::test]
    async fn fans_out_to_many_consumers_each_receiving_the_bytes() {
        let body: &'static [u8] = b"broadcast these bytes to every consumer of the lossy source";
        let fanout = Fanout::new(Box::new(body));

        // Open several cursors, then read each to EOF. The pump starts on the first open and closes on EOF.
        let mut cursors = Vec::new();
        for _ in 0..5 {
            cursors.push(fanout.open().expect("a live source hands out a cursor"));
        }
        for mut cursor in cursors {
            let mut got = Vec::new();
            cursor
                .read_to_end(&mut got)
                .await
                .expect("read the fan-out");
            assert_eq!(
                got, body,
                "every consumer receives the source's exact bytes"
            );
        }
    }

    /// DROP-ON-LAG WITHOUT STALL (the delib-20 ship-blocker): a deliberately-slow consumer has its bytes
    /// dropped while a fast consumer keeps up, and NEITHER the producer nor the fast consumer stalls. The
    /// source is PACED (a short sleep between chunks) so a consumer that drains promptly stays inside the ring
    /// window and receives every byte, while a consumer that sleeps LONGER than the pacing falls out of the
    /// window and has the evicted bytes dropped (its cursor force-advanced to the live edge). That the slow
    /// consumer finishes at all (rather than the producer stalling on it) is the no-stall proof; that the fast
    /// consumer is untouched is the "a lag on the laggard never gaps the keeper" proof.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lagging_consumer_is_dropped_without_stalling_the_producer_or_the_others() {
        // A source several ring-windows in size, delivered in ring-sized chunks with a pause between each: a
        // consumer draining at the pace keeps up (never lapped), a consumer sleeping longer than the pace is
        // lapped and drops. Chunks are `RING_BYTES` so a single missed pause evicts a whole window.
        const CHUNKS: usize = 12;
        let total = super::RING_BYTES * CHUNKS;
        let paced = PacedReader::new(
            super::RING_BYTES,
            CHUNKS,
            core::time::Duration::from_millis(15),
        );
        let fanout = Fanout::new(Box::new(paced));

        let mut fast = fanout.open().expect("fast cursor");
        let mut slow = fanout.open().expect("slow cursor");

        // The fast consumer drains continuously to EOF at (or above) the source's pace: it stays inside the
        // ring window, so nothing it needs is evicted before it reads it. Run concurrently so the producer is
        // never gated on the slow consumer.
        let fast = tokio::spawn(async move {
            let mut got = 0usize;
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let n = fast.read(&mut chunk).await.expect("fast read");
                if n == 0 {
                    break;
                }
                got += n;
            }
            got
        });

        // The slow consumer sleeps between reads far longer than the source's pace, so the pump laps it and
        // evicts the bytes it has not read. Its cursor is force-advanced past the dropped gap, so it receives
        // strictly FEWER bytes than were produced.
        let mut slow_got = 0usize;
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let n = slow.read(&mut chunk).await.expect("slow read");
            if n == 0 {
                break;
            }
            slow_got += n;
            tokio::time::sleep(core::time::Duration::from_millis(60)).await;
        }

        let fast_got = fast.await.expect("fast task");

        // The fast consumer received the WHOLE source (kept pace, never lapped): no stall, no drop for it.
        assert_eq!(
            fast_got, total,
            "the fast consumer receives every byte; a lag on the slow one never gaps it"
        );
        // The slow consumer was lapped, so it dropped bytes: it received strictly fewer than were produced.
        // (That it finished AT ALL proves the force-advance unstuck it rather than the producer stalling.)
        assert!(
            slow_got < total,
            "the lagging consumer had bytes dropped ({slow_got} of {total}), proving drop-for-slow"
        );
    }

    /// The PRODUCER NEVER BLOCKS on a consumer: a consumer that connects and NEVER reads must not stall the
    /// source. Open a cursor and never read it (a silent consumer), while a real consumer drains the source to
    /// EOF. If the producer blocked on the silent cursor, the ring would fill and the pump would stall, and the
    /// real consumer would never reach EOF (the outer timeout would trip). Its reaching EOF proves the pump
    /// evicts past the dead cursor rather than waiting on it. The source is PACED so the real consumer keeps up
    /// and receives the WHOLE stream: a byte-exact assertion, deterministically, not an instant source that
    /// would let the pump lap even the reading consumer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_producer_never_blocks_on_a_silent_consumer() {
        const WINDOWS: usize = 12;
        let total = super::RING_BYTES * WINDOWS;
        let paced = PacedReader::new(
            super::RING_BYTES,
            WINDOWS,
            core::time::Duration::from_millis(15),
        );
        let fanout = Fanout::new(Box::new(paced));

        // A silent consumer: opens, then never reads. It holds a cursor for the whole run but drains nothing.
        let _silent = fanout.open().expect("silent cursor");
        let mut reader = fanout.open().expect("reading cursor");

        let drained = tokio::time::timeout(core::time::Duration::from_secs(20), async {
            let mut got = 0usize;
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut chunk).await.expect("read");
                if n == 0 {
                    break;
                }
                got += n;
            }
            got
        })
        .await
        .expect("the producer must not block on the silent consumer");
        assert_eq!(
            drained, total,
            "the real consumer drains the whole source despite a silent cursor holding the fan-out"
        );
    }

    /// Close-on-last: after every cursor drops and the source ends, a fresh `open` on a non-rewindable session
    /// returns `None` (nothing to attach to), so the caller refuses cleanly rather than hand out an
    /// always-EOF cursor.
    #[tokio::test]
    async fn a_finished_session_hands_out_no_more_cursors() {
        let body: &'static [u8] = b"one live session";
        let fanout = Fanout::new(Box::new(body));

        let mut cursor = fanout.open().expect("first cursor");
        let mut got = Vec::new();
        cursor.read_to_end(&mut got).await.expect("drain");
        assert_eq!(got, body);
        drop(cursor);

        // Give the pump a moment to observe the last-consumer-left / EOF and finish.
        tokio::task::yield_now().await;
        assert!(
            fanout.open().is_none(),
            "a non-rewindable session that ran and closed hands out no more cursors"
        );
    }
}
