//! Tests for the local dial of a forward: how a TCP service hears a splice that did not finish.

use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::sync::Arc;

use futures::task::AtomicWaker;
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpSocket};

use super::{dial_and_splice, dial_and_splice_within};

/// How many bytes the peer uploads: more than a loopback socket buffers, so the service is still reading
/// when the forward closes its socket.
const UPLOAD: usize = 1024 * 1024;

/// The moment the peer's upload reached its end, shared by the two halves of a peer stream.
#[derive(Default)]
struct Ended {
    ended: AtomicBool,
    waker: AtomicWaker,
}

/// The peer's upload: its bytes, then its end, which it reports to [`Ended`].
struct Upload<'a> {
    body: &'a [u8],
    ended: Arc<Ended>,
}

impl io::AsyncRead for Upload<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.body).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() == before {
            this.ended.ended.store(true, Ordering::Relaxed);
            this.ended.waker.wake();
        }
        polled
    }
}

/// The way back to the peer, failing once the upload has ended: a session lost while the service replies.
struct FailsAfterUpload(Arc<Ended>);

impl io::AsyncWrite for FailsAfterUpload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.waker.register(cx.waker());
        if self.0.ended.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A loopback service whose small receive buffer, inherited by the accepted socket, keeps the forward's
/// bytes waiting in its send buffer while the service reads slowly.
fn slow_service() -> TcpListener {
    let socket = TcpSocket::new_v4().expect("a service socket");
    socket
        .set_recv_buffer_size(16 * 1024)
        .expect("shrink the service's receive buffer");
    socket
        .bind("127.0.0.1:0".parse().expect("a loopback address"))
        .expect("bind the service");
    socket.listen(1).expect("listen")
}

/// An upload the forward handed over stays whole when the way back fails after it and the service goes on
/// reading: the service reads every byte and the end, then learns from its own writes that the reply has
/// nowhere to go.
#[tokio::test]
async fn a_finished_upload_reaches_the_service_whole_when_the_download_fails() {
    let listener = slow_service();
    let addr = format!(
        "tcp:{}",
        listener.local_addr().expect("the service's address")
    );
    let body: Vec<u8> = (0..UPLOAD).map(|at| (at % 251) as u8).collect();
    let ended = Arc::new(Ended::default());
    let upload = Upload {
        body: &body,
        ended: Arc::clone(&ended),
    };
    let forward = dial_and_splice(&addr, FailsAfterUpload(ended), upload);
    let service = async {
        let (mut service, _) = listener.accept().await.expect("the forward dials");
        // One byte of reply, so the way back is written to and fails once the upload has ended.
        service.write_all(b"!").await.expect("the service replies");
        let mut got = Vec::new();
        let mut chunk = vec![0_u8; 16 * 1024];
        loop {
            let read = service.read(&mut chunk).await?;
            if read == 0 {
                return Ok::<_, io::Error>(got);
            }
            got.extend_from_slice(&chunk[..read]);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    let (forwarded, got) =
        tokio::time::timeout(ROW_TIMEOUT, async { tokio::join!(forward, service) })
            .await
            .expect("the service's reading ends the forward");
    assert!(forwarded.is_err(), "the way back failed");
    let got = got.expect("the service reads a clean end");
    assert!(got == body, "the service reads every byte the peer sent");
}

/// How many bytes the service replies with: more than a loopback socket buffers, so reply bytes still wait
/// unread in the forward's socket when the way back fails.
const REPLY: usize = 1024 * 1024;

/// How the service writes its reply: one chunk at a time.
const REPLY_CHUNK: usize = 64 * 1024;

/// The way back to the peer: it waits for the upload to end, carries `room` bytes of the reply, then fails,
/// a session lost partway through a reply.
struct FailsMidReply {
    ended: Arc<Ended>,
    room: usize,
}

impl io::AsyncWrite for FailsMidReply {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.ended.waker.register(cx.waker());
        if !this.ended.ended.load(Ordering::Relaxed) {
            return Poll::Pending;
        }
        if this.room == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)));
        }
        let carried = buf.len().min(this.room);
        this.room -= carried;
        Poll::Ready(Ok(carried))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A drain deadline short enough for a row, standing in for the forward's 2 s.
const SHORT_DRAIN: Duration = Duration::from_millis(200);

/// A drain deadline long enough for the forward to discard a [`REPLY`] it cannot send on a loaded runner,
/// still well inside [`ROW_TIMEOUT`].
const IDLE_DRAIN: Duration = Duration::from_secs(1);

/// A drain deadline no row reaches, so a row that ends in time proves another stop ended it.
const UNREACHED_DRAIN: Duration = Duration::from_secs(60);

/// How long a row waits for the forward and its service before it fails rather than hangs.
const ROW_TIMEOUT: Duration = Duration::from_secs(5);

/// An upload the forward handed over reaches an idle service whole when the way back fails partway through
/// a long reply. The service has not read all of the upload, stops reading, and leaves reply bytes unread in
/// the forward's socket; it reads on only once the forward has returned. Only the drain's deadline can end
/// the forward, and its plain close lets the queued tail and the end through.
#[tokio::test]
async fn a_finished_upload_reaches_an_idle_service_whole_after_the_drain_bound() {
    let listener = slow_service();
    let addr = format!(
        "tcp:{}",
        listener.local_addr().expect("the service's address")
    );
    let body = upload_body();
    let ended = Arc::new(Ended::default());
    let upload = Upload {
        body: &body,
        ended: Arc::clone(&ended),
    };
    let way_back = FailsMidReply {
        ended: Arc::clone(&ended),
        room: REPLY_CHUNK,
    };
    // Fired once the forward has returned, so its socket is closed before the service reads the rest.
    let closed = tokio_util::sync::CancellationToken::new();
    let forward = async {
        let forwarded = dial_and_splice_within(&addr, way_back, upload, IDLE_DRAIN).await;
        closed.cancel();
        forwarded
    };
    let service = async {
        let (mut service, _) = listener.accept().await.expect("the forward dials");
        let (mut from_forward, mut to_forward) = service.split();
        let mut got = read_until_handover(&mut from_forward, &ended).await?;
        let unread_at_failure = got.len() < body.len();
        // Stream the reply until it fails or the forward is gone: the way back carries one chunk of it.
        let reply = async {
            let part = vec![b'!'; REPLY_CHUNK];
            for _ in 0..REPLY / REPLY_CHUNK {
                if to_forward.write_all(&part).await.is_err() {
                    return;
                }
            }
        };
        tokio::select! {
            () = reply => {}
            () = closed.cancelled() => {}
        }
        closed.cancelled().await;
        from_forward.read_to_end(&mut got).await?;
        Ok::<_, io::Error>((unread_at_failure, got))
    };
    let (forwarded, got) =
        tokio::time::timeout(ROW_TIMEOUT, async { tokio::join!(forward, service) })
            .await
            .expect("the drain's deadline ends the forward");
    assert!(forwarded.is_err(), "the way back failed");
    let (unread_at_failure, got) = got.expect("the service reads a clean end");
    assert!(
        unread_at_failure,
        "part of the upload was still unread when the way back failed"
    );
    assert!(got == body, "the service reads every byte the peer sent");
}

/// A service that reads its upload while it streams a reply without end releases the forward as soon as
/// the upload has left the forward's send queue, long before the deadline or the discard cap, and the
/// upload arrives whole. Only a target that reports its send queue has this stop.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[tokio::test]
async fn a_finished_upload_stays_whole_while_the_service_streams_on() {
    let listener = slow_service();
    let addr = format!(
        "tcp:{}",
        listener.local_addr().expect("the service's address")
    );
    let body = upload_body();
    let ended = Arc::new(Ended::default());
    let upload = Upload {
        body: &body,
        ended: Arc::clone(&ended),
    };
    let way_back = FailsMidReply {
        ended: Arc::clone(&ended),
        room: 0,
    };
    let forward = dial_and_splice_within(&addr, way_back, upload, UNREACHED_DRAIN);
    let service = async {
        let (mut service, _) = listener.accept().await.expect("the forward dials");
        let (mut from_forward, mut to_forward) = service.split();
        // Read slowly to the end of the stream, however it ends: the upload is what is checked.
        let read = async {
            let mut got = Vec::new();
            let mut chunk = vec![0_u8; 16 * 1024];
            while let Ok(read @ 1..) = from_forward.read(&mut chunk).await {
                got.extend_from_slice(&chunk[..read]);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            got
        };
        // A reply trickled slowly enough that the discard cap is seconds away, never ended, and kept up
        // until the forward's close makes a write fail: a service that closed its side on reading the
        // upload's end would release the forward itself, and this row is about the send queue.
        let reply = async {
            while to_forward.write_all(&[b'!'; 1024]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::join!(read, reply).0
    };
    let (forwarded, got) =
        tokio::time::timeout(ROW_TIMEOUT, async { tokio::join!(forward, service) })
            .await
            .expect("the emptied send queue ends the forward");
    assert!(forwarded.is_err(), "the way back failed");
    assert!(got == body, "the service reads every byte the peer sent");
}

/// A service that stops reading at the handover and streams its reply as fast as it can is released at
/// the discard cap, long before the deadline. The upload's tail is the accepted loss, and the service hears
/// it as an error.
#[tokio::test]
async fn a_service_that_stops_reading_is_released_at_the_discard_cap() {
    let (forwarded, got) = stop_reading_and_stream(UNREACHED_DRAIN, Duration::ZERO).await;
    assert!(forwarded.is_err(), "the way back failed");
    assert_tail_lost(got);
}

/// A service that stops reading at the handover and trickles its reply is released at the drain's
/// deadline. The trickle is faster than the deadline, so a deadline that restarted on each byte would never
/// end the forward. The upload's tail is the accepted loss, and the service hears it as an error.
#[tokio::test]
async fn a_service_that_stops_reading_is_released_at_the_drain_deadline() {
    let started = tokio::time::Instant::now();
    let (forwarded, got) = stop_reading_and_stream(SHORT_DRAIN, Duration::from_millis(20)).await;
    // Ten deadlines of slack for a loaded runner, and still far short of the discard cap, which the trickle
    // reaches only after about 20 s.
    let took = started.elapsed();
    assert!(
        took < SHORT_DRAIN * 10,
        "the deadline, not the cap, ended the forward: {took:?}"
    );
    assert!(forwarded.is_err(), "the way back failed");
    assert_tail_lost(got);
}

/// Run a forward to a service that stops reading at the handover and writes its reply in 1 KiB pieces,
/// `period` apart, until a write fails; then it reads what reached it, however that read ends, and returns
/// how many bytes of the upload it got. The write loop ends only on a failed write, so a service that
/// returns at all heard an error: which of its calls hears the reset differs by platform, so neither the
/// read's outcome nor the error's kind is asserted.
async fn stop_reading_and_stream(
    deadline: Duration,
    period: Duration,
) -> (Result<(), super::ServeError>, usize) {
    let listener = slow_service();
    let addr = format!(
        "tcp:{}",
        listener.local_addr().expect("the service's address")
    );
    let body = upload_body();
    let ended = Arc::new(Ended::default());
    let upload = Upload {
        body: &body,
        ended: Arc::clone(&ended),
    };
    let way_back = FailsMidReply {
        ended: Arc::clone(&ended),
        room: 0,
    };
    let forward = dial_and_splice_within(&addr, way_back, upload, deadline);
    let service = async {
        let (mut service, _) = listener.accept().await.expect("the forward dials");
        let (mut from_forward, mut to_forward) = service.split();
        let mut got = read_until_handover(&mut from_forward, &ended)
            .await
            .expect("the service reads the start of the upload");
        while to_forward.write_all(&[b'!'; 1024]).await.is_ok() {
            // Even a zero sleep waits for a timer tick, which would hold a fast writer to about a KiB a
            // millisecond.
            if !period.is_zero() {
                tokio::time::sleep(period).await;
            }
        }
        // A read that ends in a reset keeps what it read before it.
        let _ended = from_forward.read_to_end(&mut got).await;
        got.len()
    };
    tokio::time::timeout(ROW_TIMEOUT, async { tokio::join!(forward, service) })
        .await
        .expect("the drain ends the forward and the service hears it")
}

/// The loss a service that stopped reading accepts: part of its upload never reached it.
fn assert_tail_lost(got: usize) {
    assert!(
        got < UPLOAD,
        "the queued tail was lost: read {got} of {UPLOAD}"
    );
}

/// The peer's upload: [`UPLOAD`] bytes in a pattern a shifted or truncated copy cannot match.
fn upload_body() -> Vec<u8> {
    (0..UPLOAD).map(|at| (at % 251) as u8).collect()
}

/// Read slowly until the forward has taken the upload's end, then stop with part of it unread.
async fn read_until_handover(
    from_forward: &mut (impl io::AsyncRead + Unpin),
    ended: &Ended,
) -> io::Result<Vec<u8>> {
    let mut got = Vec::new();
    let mut chunk = vec![0_u8; 16 * 1024];
    while !ended.ended.load(Ordering::Relaxed) {
        let read = from_forward.read(&mut chunk).await?;
        got.extend_from_slice(&chunk[..read]);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(got)
}

/// A peer stream that never yields a byte or its end.
struct Silent;

impl io::AsyncRead for Silent {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

/// The way back to the peer, failing at once.
struct Broken;

impl io::AsyncWrite for Broken {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionAborted)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A failed write toward the peer, while the peer's own stream is still open, ends the forward with the
/// upload unfinished, and the service reads a reset rather than an end the peer never sent.
#[tokio::test]
async fn a_failed_write_toward_the_peer_resets_the_tcp_service() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the service");
    let addr = format!(
        "tcp:{}",
        listener.local_addr().expect("the service's address")
    );
    let forward = dial_and_splice(&addr, Broken, Silent);
    let service = async {
        let (mut service, _) = listener.accept().await.expect("the forward dials");
        service.write_all(b"!").await.expect("the service replies");
        let mut rest = Vec::new();
        service.read_to_end(&mut rest).await
    };
    let (forwarded, ended) =
        tokio::time::timeout(ROW_TIMEOUT, async { tokio::join!(forward, service) })
            .await
            .expect("the failed write ends the forward");
    assert!(forwarded.is_err(), "the way back failed");
    assert!(
        matches!(&ended, Err(error) if error.kind() == io::ErrorKind::ConnectionReset),
        "an unfinished upload resets the service: {ended:?}"
    );
}

/// A way back that fails before the peer's upload has ended resets the service at once: the drain is for
/// an upload already handed over, and a forward that drained here would hold the service for an upload that
/// is cut short anyway, with only the reset left to tell it. The service reads nothing until the forward returns, so the
/// forward's send queue stays full and no stop but the deadline could end a drain that ran.
#[tokio::test]
async fn a_way_back_that_fails_before_the_end_resets_the_service_at_once() {
    let listener = slow_service();
    let addr = format!(
        "tcp:{}",
        listener.local_addr().expect("the service's address")
    );
    let body = upload_body();
    let closed = tokio_util::sync::CancellationToken::new();
    let forward = async {
        let upload = (&body[..]).chain(Silent);
        let forwarded = dial_and_splice_within(&addr, Broken, upload, UNREACHED_DRAIN).await;
        closed.cancel();
        forwarded
    };
    let service = async {
        let (mut service, _) = listener.accept().await.expect("the forward dials");
        // Let the upload fill the buffers before the reply fails the way back.
        service.readable().await.expect("the upload starts");
        tokio::time::sleep(Duration::from_millis(100)).await;
        service.write_all(b"!").await.expect("the service replies");
        closed.cancelled().await;
        let mut rest = Vec::new();
        service.read_to_end(&mut rest).await
    };
    let (forwarded, ended) =
        tokio::time::timeout(ROW_TIMEOUT, async { tokio::join!(forward, service) })
            .await
            .expect("the forward returns at once");
    assert!(forwarded.is_err(), "the way back failed");
    assert!(
        ended.is_err(),
        "an unfinished upload resets the service: {ended:?}"
    );
}
