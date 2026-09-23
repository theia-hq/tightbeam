//! The frame reader's two load-bearing properties, each pinned by the failure it prevents: it takes the
//! frame and STRANDS NOTHING behind it, and it refuses an over-cap claim BEFORE it allocates for it.
//! Plus the pair the cap makes symmetric (an encoder cannot emit what this decoder would refuse) and the
//! write count the one-buffer encode exists for.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use tokio::io::{self, AsyncReadExt as _};

use crate::wire::{Frame, WireError, read_frame, write_frame};

/// Drive a future to completion on this thread. Every future here moves bytes through in-memory buffers
/// that are always ready, so none of them can park; the contract crate has no runtime and needs none. A
/// future that DID park would spin here, which is the loudest available failure for a test whose whole
/// premise is that nothing waits.
fn run<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
    }
}

/// A probe frame shaped like the family's real ones: four magic bytes, a tag, then a fixed-width body
/// the tag names. The head is the magic plus the tag, because that is the least a reader must hold
/// before it knows how long the frame is.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// The tagged frame with a body.
    Ping {
        /// The caller's opaque nonce.
        nonce: u64,
    },
    /// The tagged frame whose head IS the whole frame.
    Go,
    /// A probe frame from a build on another grammar. A parse OUTCOME rather than a failure, because a
    /// peer speaking our protocol at another version is something we can answer; the service reads this
    /// variant and writes a sentence back.
    Skewed,
}

/// The probe's identity and version, split by the family's rule (capitals, then digits).
const IDENTITY: [u8; 3] = *b"PRB";
const VERSION: u8 = b'1';

mod tag {
    pub const PING: u8 = 0;
    pub const GO: u8 = 1;
}

/// A probe head this build does not speak: not our identity at all.
#[derive(Debug, thiserror::Error)]
#[error("not a probe stream")]
struct Foreign;

/// A tag this build has no frame for.
#[derive(Debug, thiserror::Error)]
#[error("unknown probe tag {0:#04x}")]
struct UnknownTag(u8);

impl Frame for Probe {
    const MAX: usize = 13;
    const HEAD: usize = 5;

    fn rest(head: &[u8]) -> usize {
        // Only a frame in THIS build's grammar has a length we can trust. Anything else stops at the
        // head, so `decode` classifies exactly what was read and the reader never guesses a length out
        // of bytes it does not understand.
        if head[..3] != IDENTITY || head[3] != VERSION {
            return 0;
        }
        match head[4] {
            tag::PING => 8,
            _ => 0,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&IDENTITY);
        out.push(VERSION);
        match self {
            Self::Ping { nonce } => {
                out.push(tag::PING);
                out.extend_from_slice(&nonce.to_be_bytes());
            }
            Self::Go => out.push(tag::GO),
            // A skewed frame is only ever READ, never written: this build has one grammar.
            Self::Skewed => out.push(tag::GO),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes[..3] != IDENTITY {
            return Err(WireError::malformed(Foreign));
        }
        if bytes[3] != VERSION {
            return Ok(Self::Skewed);
        }
        match bytes[4] {
            tag::PING => {
                let mut nonce = [0u8; 8];
                nonce.copy_from_slice(&bytes[5..13]);
                Ok(Self::Ping {
                    nonce: u64::from_be_bytes(nonce),
                })
            }
            tag::GO => Ok(Self::Go),
            other => Err(WireError::malformed(UnknownTag(other))),
        }
    }
}

/// A frame whose head is a `u32` length prefix, the other shape the length rule covers, used to drive a
/// hostile declared length.
#[derive(Debug)]
struct Declared(Vec<u8>);

impl Frame for Declared {
    const MAX: usize = 16;
    const HEAD: usize = 4;

    fn rest(head: &[u8]) -> usize {
        let mut len = [0u8; 4];
        len.copy_from_slice(&head[..4]);
        u32::from_be_bytes(len) as usize
    }

    fn encode(&self, out: &mut Vec<u8>) {
        // Deliberately caps nothing of its own: the wire's cap is what must stop an over-long frame, and
        // a writer that caps only at the width of its length field is the drift this test pins.
        let len = self.0.len() as u32;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.0);
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        Ok(Self(bytes[4..].to_vec()))
    }
}

/// A writer that counts the calls, not the bytes: the one-buffer encode exists to make this number 1,
/// because every call is an allocation, a copy, and on a sealing transport a whole frame of overhead.
#[derive(Default)]
struct Counting {
    writes: usize,
    bytes: Vec<u8>,
}

impl io::AsyncWrite for Counting {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.writes += 1;
        this.bytes.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The codec round-trips with no stream, no runtime, and no handler, which is the property that lets a
/// wire spec's byte layouts be pinned by tests a third party reads as the normative examples.
#[test]
fn a_frame_round_trips_through_its_own_codec_with_no_stream() {
    for frame in [
        Probe::Ping { nonce: 0 },
        Probe::Ping { nonce: u64::MAX },
        Probe::Go,
    ] {
        let mut bytes = Vec::new();
        frame.encode(&mut bytes);
        assert_eq!(
            Probe::decode(&bytes).expect("this build's own frame decodes"),
            frame
        );
    }
}

/// THE property the raw floor rests on: the reader takes exactly the frame and leaves the payload where
/// it is. A buffering codec over-reads by design, and after an 8-byte preamble off a stream carrying 32
/// body bytes it holds those 32 bytes inside itself, where the raw phase has to know to replay them.
/// Here the count is ZERO, byte for byte, which is what lets a service frame a preamble and then splice.
///
/// Read `rest` as a constant (or read the wire's cap instead of the declared length) and this goes red
/// with the payload eaten.
#[test]
fn the_reader_takes_the_frame_and_strands_nothing() {
    const PAYLOAD: &[u8] = &[0xab; 32];
    // Both frame sizes the wire has: one that fills the cap exactly and one well under it. The short
    // one is what catches a reader that reads the CAP instead of the declared length, which looks
    // correct on every maximal frame.
    for (frame, framed) in [(Probe::Ping { nonce: 7 }, 13), (Probe::Go, 5)] {
        let mut stream = Vec::new();
        frame.encode(&mut stream);
        assert_eq!(stream.len(), framed, "the frame's whole wire size");
        stream.extend_from_slice(PAYLOAD);

        let mut reader = stream.as_slice();
        let read: Probe = run(read_frame(&mut reader)).expect("the frame reads");
        assert_eq!(read, frame);
        assert_eq!(
            reader, PAYLOAD,
            "the payload is untouched and positioned at its first byte"
        );

        // And it is genuinely readable from the same half, which is what a service does next.
        let mut rest = Vec::new();
        run(reader.read_to_end(&mut rest)).expect("the payload drains");
        assert_eq!(rest, PAYLOAD);
    }
}

/// A short frame ends the stream rather than the head being reused as a body: an exact read that cannot
/// be satisfied is an error, never a partial frame handed to `decode`.
#[test]
fn a_truncated_frame_is_an_error_not_a_partial_decode() {
    let mut stream = Vec::new();
    Probe::Ping { nonce: 7 }.encode(&mut stream);
    stream.truncate(stream.len() - 1);

    let read: Result<Probe, _> = run(read_frame(&mut stream.as_slice()));
    let error = read.expect_err("a frame cut one byte short cannot decode");
    assert!(
        matches!(error, WireError::Io(ref io) if io.kind() == io::ErrorKind::UnexpectedEof),
        "{error}"
    );
}

/// A declared length over the wire's cap is refused BEFORE the reader allocates for it. The stream holds
/// the head and NOTHING else, so a reader that allocated first and checked second would come back with
/// an end-of-file rather than the cap, and a 4 GiB claim would try to allocate 4 GiB first.
///
/// Delete the cap check in `read_frame` and this goes red on both arms.
#[test]
fn an_over_cap_claim_is_refused_before_the_body_is_read() {
    for declared in [Declared::MAX as u32 + 1, u32::MAX] {
        let head = declared.to_be_bytes();
        let read: Result<Declared, _> = run(read_frame(&mut head.as_slice()));
        let error = read.expect_err("a claim over the cap is refused");
        assert!(
            matches!(error, WireError::TooLong { max, .. } if max == Declared::MAX),
            "a {declared} byte claim must be refused as over-cap, got {error}"
        );
    }
}

/// The cap is symmetric because it is stated once: a frame this wire's reader would refuse is a frame
/// this wire's writer does not emit, and it emits NOTHING rather than a truncated prefix. Without it an
/// encoder caps only at the width of its own length field and produces frames its own decoder rejects,
/// with the peer that sent one given no way to anticipate the refusal.
///
/// Delete the length check in `write_frame` and this goes red: the bytes reach the wire.
#[test]
fn the_encoder_cannot_emit_a_frame_its_own_decoder_would_refuse() {
    let mut writer = Counting::default();
    let over = Declared(vec![0u8; Declared::MAX]);
    let error = run(write_frame(&mut writer, &over)).expect_err("an over-cap frame is not written");
    assert!(
        matches!(error, WireError::TooLong { max, .. } if max == Declared::MAX),
        "{error}"
    );
    assert!(
        writer.bytes.is_empty() && writer.writes == 0,
        "nothing reaches the wire, not even a prefix"
    );

    // The largest frame that fits is still written, so the cap refuses the over-long and nothing else.
    let fits = Declared(vec![0u8; Declared::MAX - Declared::HEAD]);
    run(write_frame(&mut writer, &fits)).expect("a frame at the cap is written");
    assert_eq!(writer.bytes.len(), Declared::MAX);
}

/// One frame is ONE call, whatever the frame holds. The same bytes written field by field cost one call
/// per field, and every call is an allocation, a copy, and on a sealing transport a whole frame of
/// overhead: a 10-header request frame measured 46 calls against this 1.
#[test]
fn one_frame_is_one_write() {
    let mut writer = Counting::default();
    run(write_frame(&mut writer, &Probe::Ping { nonce: 7 })).expect("the frame writes");
    assert_eq!(writer.writes, 1, "a framed write is one call");
    assert_eq!(writer.bytes.len(), 13);

    run(write_frame(&mut writer, &Probe::Go)).expect("the second frame writes");
    assert_eq!(
        writer.writes, 2,
        "and the next frame is one more, never more"
    );
}

/// A head this build cannot parse stops AT THE HEAD, so the decoder classifies exactly the bytes that
/// were read. The answerable condition (our protocol, another version) comes back as a VALUE the service
/// can answer on the wire; the unanswerable one (not our protocol at all) comes back as the typed cause.
#[test]
fn a_head_this_build_cannot_parse_stops_at_the_head() {
    let mut skewed = Vec::new();
    Probe::Ping { nonce: 7 }.encode(&mut skewed);
    skewed[3] = b'2';
    let mut reader = skewed.as_slice();
    let frame: Probe =
        run(read_frame(&mut reader)).expect("a skewed frame is a value, not a failure");
    assert_eq!(frame, Probe::Skewed);
    assert_eq!(
        reader.len(),
        8,
        "the reader stopped at the head rather than trusting another grammar's length"
    );

    let foreign = b"XXX1\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let read: Result<Probe, _> = run(read_frame(&mut foreign.as_slice()));
    let error = read.expect_err("a foreign stream has nothing true to say back");
    assert!(matches!(error, WireError::Malformed(_)), "{error}");
    assert_eq!(
        error.to_string(),
        "not a probe stream",
        "the service's own typed cause survives the crossing"
    );
}
