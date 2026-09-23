//! Tests for the `stdin:` seat: the cell that lends one reader at a time and takes it back, and the
//! contention-gated hand-off that moves it from a holder that stopped reading to a peer that dialed.
//!
//! The hand-off pins run on paused time against a duplex standing in for the viewer's stream: the viewer
//! "grants credit" by reading its end, so a viewer that reads nothing leaves the holder's writer refused.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};

use bifrost::NodeId;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;

use super::seat::{STALL_CLEAR, STALL_WINDOW, Seat, SeatRefusal};

/// The viewer stream's capacity: small beside the stall floor, so what the holder's writer has taken is
/// what the viewer read, give or take this much.
const VIEWER_WINDOW: usize = 1024;

/// A peer identity, one per byte.
fn node(n: u8) -> NodeId {
    NodeId::from_ed25519_secret(&[n; 32])
}

/// An endless backlog whose bytes encode their own offset (`offset % 251`), so a reader can tell a
/// continuous stream from one with a gap.
#[derive(Default)]
struct Backlog(u64);

impl AsyncRead for Backlog {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while buf.remaining() > 0 {
            buf.put_slice(&[(this.0 % 251) as u8]);
            this.0 += 1;
        }
        Poll::Ready(Ok(()))
    }
}

/// Whether `bytes` run on from one another in [`Backlog`]'s encoding.
fn continuous(bytes: &[u8]) -> bool {
    bytes
        .windows(2)
        .all(|pair| u16::from(pair[1]) == (u16::from(pair[0]) + 1) % 251)
}

/// Seat `peer` and run its splice the way the served path does, toward a viewer stream the test holds.
/// Returns the splice task and the viewer's end.
async fn hold(seat: &Seat, peer: NodeId) -> (JoinHandle<io::Result<()>>, DuplexStream) {
    let seated = seat.claim(peer).await.expect("an armed seat is taken");
    let (host, viewer) = tokio::io::duplex(VIEWER_WINDOW);
    let splice = tokio::spawn(seated.splice(host, tokio::io::empty()));
    (splice, viewer)
}

/// A producer writing `chunk` bytes every second into a source the seat reads.
fn paced_source(chunk: usize) -> (Seat, JoinHandle<()>) {
    let (mut producer, source) = tokio::io::duplex(1 << 20);
    let feed = tokio::spawn(async move {
        let mut offset = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let bytes: Vec<u8> = (offset..offset + chunk as u64)
                .map(|at| (at % 251) as u8)
                .collect();
            offset += chunk as u64;
            if producer.write_all(&bytes).await.is_err() {
                return;
            }
        }
    });
    (Seat::new(Box::new(source)), feed)
}

/// A host-log sink: every line the subscriber formats lands in one shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Self(lines) = self;
        lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    /// Install this sink as the thread's subscriber for as long as the guard lives.
    ///
    /// While only one dispatcher is registered, tracing caches a callsite's interest from whichever thread
    /// hits it first, so a parallel test thread with no subscriber can mark a line uninteresting to every
    /// thread, this one included. A second dispatcher that is never dropped keeps the cache built from all
    /// registered dispatchers instead.
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        static SECOND: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
        SECOND.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        let sink = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(move || sink.clone())
                .finish(),
        )
    }

    /// Every captured line containing `needle`.
    fn lines(&self, needle: &str) -> Vec<String> {
        let Self(lines) = self;
        let lines = lines.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&lines)
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_owned)
            .collect()
    }
}

// The cell.

/// A holder that leaves mid-stream gives the reader back, and the next peer reads on from where it
/// stopped.
#[tokio::test]
async fn a_reader_dropped_mid_stream_on_a_live_source_rearms() {
    let (mut producer, source) = tokio::io::duplex(4096);
    let seat = Seat::new(Box::new(source));
    producer
        .write_all(b"hello world")
        .await
        .expect("feed the source");

    let mut first = seat.claim(node(1)).await.expect("the armed seat is taken");
    let mut hello = [0u8; 5];
    first
        .reader
        .read_exact(&mut hello)
        .await
        .expect("the holder reads");
    assert_eq!(&hello, b"hello");
    drop(first);

    let mut second = seat
        .claim(node(2))
        .await
        .expect("a released seat re-arms for the next peer");
    let mut rest = [0u8; 6];
    second
        .reader
        .read_exact(&mut rest)
        .await
        .expect("the next peer reads");
    assert_eq!(
        &rest, b" world",
        "the next peer reads on from where the last stopped"
    );
}

/// While one peer holds the seat, another is refused as Held, never handed a racing second read.
#[tokio::test]
async fn a_held_seat_refuses_a_concurrent_second_reader() {
    let (_producer, source) = tokio::io::duplex(4096);
    let seat = Seat::new(Box::new(source));
    let _held = seat.claim(node(1)).await.expect("the armed seat is taken");
    let Err(refusal) = seat.claim(node(2)).await else {
        panic!("a second reader of a held seat must be refused");
    };
    assert!(
        matches!(refusal, SeatRefusal::Held),
        "refused as held: {refusal}"
    );
    assert!(
        refusal.to_string().contains("is held by another peer"),
        "the refusal says what is true: {refusal}"
    );
}

/// End of input spends the seat: the next peer is refused with the end, never handed an empty stream.
#[tokio::test]
async fn end_of_input_spends_the_seat_and_never_hands_out_an_empty_stream() {
    let body: &'static [u8] = b"the whole input";
    let seat = Seat::new(Box::new(body));
    let mut first = seat.claim(node(1)).await.expect("the armed seat is taken");
    let mut got = Vec::new();
    first
        .reader
        .read_to_end(&mut got)
        .await
        .expect("drain to end of input");
    assert_eq!(got, body);
    drop(first);

    for dialer in [node(2), node(1)] {
        let Err(refusal) = seat.claim(dialer).await else {
            panic!("a seat past end of input must refuse, never hand out an empty stream");
        };
        assert!(
            matches!(refusal, SeatRefusal::Spent),
            "refused as spent: {refusal}"
        );
    }
}

/// A holder whose serve future is cancelled mid-splice gives the reader back: cancellation is a drop, and
/// the drop is what returns it.
#[tokio::test]
async fn a_cancelled_splice_gives_the_reader_back() {
    let (mut producer, source) = tokio::io::duplex(4096);
    let seat = Seat::new(Box::new(source));
    let seated = seat.claim(node(1)).await.expect("the armed seat is taken");
    let (host, _viewer) = tokio::io::duplex(VIEWER_WINDOW);
    {
        let splice = seated.splice(host, tokio::io::empty());
        tokio::pin!(splice);
        assert!(
            futures::poll!(&mut splice).is_pending(),
            "the splice parks on a quiet source"
        );
    } // the serve future is dropped here, mid-splice

    let mut next = seat
        .claim(node(2))
        .await
        .expect("a cancelled holder's reader is back in the seat");
    producer.write_all(b"after").await.expect("feed the source");
    let mut got = [0u8; 5];
    next.reader.read_exact(&mut got).await.expect("read");
    assert_eq!(&got, b"after");
}

/// The end-of-input log fires once, at the transition, however many peers are refused after it.
#[tokio::test]
async fn the_end_of_input_log_fires_exactly_once() {
    let log = Captured::default();
    let _subscriber = log.install();

    let seat = Seat::new(Box::new(&b"short"[..]));
    let mut first = seat.claim(node(1)).await.expect("the armed seat is taken");
    let mut sink = Vec::new();
    first.reader.read_to_end(&mut sink).await.expect("drain");
    drop(first);
    for n in 2..6 {
        assert!(seat.claim(node(n)).await.is_err(), "spent refuses");
    }
    assert_eq!(
        log.lines("stdin: reached end of input").len(),
        1,
        "the end is logged once, not once per refused peer"
    );
}

// Contention-gated hand-off.

/// A paused `| less`: a holder that takes nothing for ten windows, with nobody else dialing,
/// keeps the seat, and later reads its bytes from where it paused.
#[tokio::test(start_paused = true)]
async fn an_uncontested_stalled_holder_keeps_the_seat() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (splice, mut viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW * 10).await;
    assert!(
        !splice.is_finished(),
        "nobody dialed, so nobody cut the holder"
    );

    let mut got = vec![0u8; 64 * 1024];
    viewer
        .read_exact(&mut got)
        .await
        .expect("the paused viewer reads on");
    assert_eq!(
        got[0], 0,
        "the paused viewer's stream starts where it paused"
    );
    assert!(continuous(&got), "and runs on without a gap");
}

/// A holder that took nothing for a whole window loses the seat to a peer that dials, and that peer
/// reads the stream on from there. The displaced viewer's stream ends.
#[tokio::test(start_paused = true)]
async fn a_contender_takes_a_stalled_seat_and_reads_on() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (splice, mut viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW + Duration::from_secs(1)).await;
    let mut next = seat
        .claim(node(2))
        .await
        .expect("a contender takes the seat from a holder that stopped reading");
    let mut got = vec![0u8; 16 * 1024];
    next.reader.read_exact(&mut got).await.expect("read on");
    assert!(continuous(&got), "the new holder reads a continuous stream");

    splice
        .await
        .expect("join")
        .expect("the displaced splice ends cleanly");
    let mut left = Vec::new();
    viewer
        .read_to_end(&mut left)
        .await
        .expect("the displaced viewer's stream ends");
}

/// A holder reading at 2 KiB/s against a backlog is above the floor, so a dialer is refused however long
/// it has held.
#[tokio::test(start_paused = true)]
async fn a_reading_holder_is_not_displaced() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (_splice, mut viewer) = hold(&seat, node(1)).await;
    let reading = tokio::spawn(async move {
        let mut chunk = vec![0u8; 2048];
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if viewer.read_exact(&mut chunk).await.is_err() {
                return;
            }
        }
    });

    for _ in 0..4 {
        tokio::time::sleep(STALL_WINDOW).await;
        let Err(refusal) = seat.claim(node(2)).await else {
            panic!("a holder reading above the floor must never be displaced");
        };
        assert!(matches!(refusal, SeatRefusal::Held));
    }
    reading.abort();
}

/// Grace: a dialer one second inside the holder's first window is refused, and one second past it takes
/// the seat.
#[tokio::test(start_paused = true)]
async fn a_dialer_inside_the_first_window_is_refused_and_past_it_takes_the_seat() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (_splice, _viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW - Duration::from_secs(1)).await;
    assert!(
        matches!(seat.claim(node(2)).await, Err(SeatRefusal::Held)),
        "inside the first window the holder keeps the seat"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        seat.claim(node(2)).await.is_ok(),
        "past the window a contender takes it"
    );
}

/// A holder on a quiet source is idle, not stalled: its writer is never refused, so no dial displaces it.
#[tokio::test(start_paused = true)]
async fn an_idle_holder_is_not_displaced() {
    let (_producer, source) = tokio::io::duplex(4096);
    let seat = Seat::new(Box::new(source));
    let (_splice, _viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW * 10).await;
    assert!(
        matches!(seat.claim(node(2)).await, Err(SeatRefusal::Held)),
        "a source with nothing to say never makes its holder preemptible"
    );
}

/// A holder never displaces itself: its own second stream is refused, and the window it was judged on is
/// untouched, so a different dialer still takes the seat.
#[tokio::test(start_paused = true)]
async fn a_holder_redialing_itself_is_refused_and_keeps_its_window() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (_splice, _viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW + Duration::from_secs(1)).await;
    assert!(
        matches!(seat.claim(node(1)).await, Err(SeatRefusal::Held)),
        "a holder's own identity never displaces it"
    );
    assert!(
        seat.claim(node(2)).await.is_ok(),
        "the redial reset nothing: the stalled holder is still preemptible"
    );
}

/// Two dialers at the same instant against a stalled holder: exactly one gets the seat.
#[tokio::test(start_paused = true)]
async fn two_simultaneous_dialers_get_one_seat() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (_splice, _viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW + Duration::from_secs(1)).await;
    let (second, third) = tokio::join!(seat.claim(node(2)), seat.claim(node(3)));
    let seated = [&second, &third]
        .iter()
        .filter(|claim| claim.is_ok())
        .count();
    assert_eq!(seated, 1, "exactly one dialer is handed the reader");
    let refused = [second, third]
        .into_iter()
        .filter_map(Result::err)
        .all(|refusal| matches!(refusal, SeatRefusal::Held));
    assert!(refused, "the other is refused as held");
}

/// A dialer that gives up mid hand-off never costs the reader: it goes back to the seat, and the next
/// dialer reads on.
#[tokio::test(start_paused = true)]
async fn a_dialer_dropped_mid_hand_off_returns_the_reader_to_the_seat() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (splice, _viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW + Duration::from_secs(1)).await;
    {
        let claim = seat.claim(node(2));
        tokio::pin!(claim);
        assert!(
            futures::poll!(&mut claim).is_pending(),
            "the dialer displaced the holder and waits for its reader"
        );
    }
    splice
        .await
        .expect("join")
        .expect("the displaced splice ends cleanly");

    let mut next = seat
        .claim(node(3))
        .await
        .expect("the undelivered reader went back to the seat");
    let mut got = vec![0u8; 4096];
    next.reader.read_exact(&mut got).await.expect("read on");
    assert!(
        continuous(&got),
        "the next dialer reads a continuous stream"
    );
}

/// A holder whose reader reached end of input while its writer was stalled: the dialer that displaces
/// it is refused with the end, never handed a dead reader.
#[tokio::test(start_paused = true)]
async fn a_hand_off_racing_end_of_input_refuses_the_dialer_with_the_end() {
    // More than the viewer stream holds, so the writer stalls after the reader has already seen the end.
    let body = vec![7u8; VIEWER_WINDOW * 2];
    let seat = Seat::new(Box::new(io::Cursor::new(body)));
    let (_splice, _viewer) = hold(&seat, node(1)).await;

    tokio::time::sleep(STALL_WINDOW + Duration::from_secs(1)).await;
    let Err(refusal) = seat.claim(node(2)).await else {
        panic!("a reader at end of input is never handed on");
    };
    assert!(
        matches!(refusal, SeatRefusal::Spent),
        "refused with the end: {refusal}"
    );
}

/// Every hand-off is one host log line naming both identities, so a pair trading the seat can be named
/// and revoked.
#[tokio::test(start_paused = true)]
async fn a_hand_off_logs_one_line_naming_both_identities() {
    let log = Captured::default();
    let _subscriber = log.install();

    let seat = Seat::new(Box::<Backlog>::default());
    let (_splice, _viewer) = hold(&seat, node(1)).await;
    tokio::time::sleep(STALL_WINDOW + Duration::from_secs(1)).await;
    let _next = seat
        .claim(node(2))
        .await
        .expect("the contender takes the seat");

    let lines = log.lines("seat handed");
    assert_eq!(lines.len(), 1, "one line per hand-off: {lines:?}");
    assert!(
        lines[0].contains(&format!("holder={}", node(1)))
            && lines[0].contains(&format!("dialer={}", node(2))),
        "the line names the displaced holder and the dialer: {}",
        lines[0]
    );
}

// The floor, judged at dial time.

/// Run a viewer that reads `chunk` bytes every `every` against a backlog, and dial at `dial_at`.
async fn dial_against_a_viewer(
    chunk: usize,
    every: Duration,
    dial_at: Duration,
) -> Result<(), SeatRefusal> {
    let seat = Seat::new(Box::<Backlog>::default());
    let (_splice, mut viewer) = hold(&seat, node(1)).await;
    let reading = tokio::spawn(async move {
        let mut bytes = vec![0u8; chunk];
        loop {
            tokio::time::sleep(every).await;
            if viewer.read_exact(&mut bytes).await.is_err() {
                return;
            }
        }
    });
    tokio::time::sleep(dial_at).await;
    let claimed = seat.claim(node(2)).await.map(drop);
    reading.abort();
    claimed
}

/// A one-byte trickle is below the floor: "any progress" would keep it forever, the floor does not.
#[tokio::test(start_paused = true)]
async fn a_one_byte_trickle_is_preemptible_at_the_window() {
    let claimed = dial_against_a_viewer(
        1,
        STALL_WINDOW - Duration::from_secs(1),
        STALL_WINDOW + Duration::from_secs(1),
    )
    .await;
    assert!(
        claimed.is_ok(),
        "a trickle does not hold the seat: {claimed:?}"
    );
}

/// A trickle a little over one copy chunk at a time would force the window shut if one taken write
/// closed it; only a clean second closes it, so the straddle is still preemptible.
#[tokio::test(start_paused = true)]
async fn a_chunk_straddling_trickle_is_preemptible_at_the_window() {
    let claimed = dial_against_a_viewer(
        16 * 1024,
        STALL_WINDOW - Duration::from_secs(1),
        STALL_WINDOW + Duration::from_secs(1),
    )
    .await;
    assert!(
        claimed.is_ok(),
        "a straddling trickle does not hold the seat: {claimed:?}"
    );
}

/// An honest stock reader at about 1.8 KiB/s: one credit grant (156,250 B) every 85 s. Each grant clears a
/// window, so it is never preemptible, however many windows pass.
#[tokio::test(start_paused = true)]
async fn an_honest_chunky_reader_is_never_preemptible() {
    let seat = Seat::new(Box::<Backlog>::default());
    let (_splice, mut viewer) = hold(&seat, node(1)).await;
    let reading = tokio::spawn(async move {
        let mut grant = vec![0u8; 156_250];
        loop {
            tokio::time::sleep(Duration::from_secs(85)).await;
            if viewer.read_exact(&mut grant).await.is_err() {
                return;
            }
        }
    });
    for _ in 0..5 {
        tokio::time::sleep(STALL_WINDOW - Duration::from_secs(1)).await;
        assert!(
            matches!(seat.claim(node(2)).await, Err(SeatRefusal::Held)),
            "an honest reader keeps its seat"
        );
    }
    reading.abort();
}

/// A holder taking nothing from a 10 B/s producer is preemptible one window after its writer is first
/// refused, not one window after a copy buffer fills from the source (about 800 s here).
#[tokio::test(start_paused = true)]
async fn a_stalled_holder_on_a_slow_producer_is_preemptible_at_the_window() {
    let (seat, feed) = paced_source(10);
    let (_splice, _viewer) = hold(&seat, node(1)).await;

    // The viewer stream fills in about VIEWER_WINDOW / 10 seconds; the window opens then.
    let filled = Duration::from_secs(VIEWER_WINDOW as u64 / 10 + 2);
    tokio::time::sleep(filled + STALL_WINDOW).await;
    assert!(
        seat.claim(node(2)).await.is_ok(),
        "the writer saw the refusal, so the window ran from it"
    );
    feed.abort();
}

/// A viewer keeping up with a 10 B/s producer, save one 5 s pause: after the pause it takes everything
/// again, so its window closes after a clean second and it is never preemptible.
#[tokio::test(start_paused = true)]
async fn a_slow_producer_with_one_hiccup_is_never_preemptible() {
    let (seat, feed) = paced_source(10);
    let (_splice, mut viewer) = hold(&seat, node(1)).await;
    let reading = tokio::spawn(async move {
        let mut bytes = vec![0u8; 4096];
        let mut paused = false;
        loop {
            if viewer.read(&mut bytes).await.map_or(true, |n| n == 0) {
                return;
            }
            // Fill the viewer's stream once, then keep up.
            if !paused {
                paused = true;
                tokio::time::sleep(Duration::from_secs(VIEWER_WINDOW as u64 / 10 + 5)).await;
            }
        }
    });

    // Long past the pause plus a whole window, so a window that never closed would be ripe.
    tokio::time::sleep(STALL_WINDOW * 3).await;
    let claimed = seat.claim(node(2)).await.map(drop);
    assert!(
        matches!(claimed, Err(SeatRefusal::Held)),
        "a viewer that caught up closed its window: {claimed:?}"
    );
    // The hiccup outlasts a clean second, or this pin would not reach the window closing.
    const { assert!(STALL_CLEAR.as_secs() < 5) };
    reading.abort();
    feed.abort();
}
