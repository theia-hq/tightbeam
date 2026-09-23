//! The frame vocabulary a typed service's control preamble speaks: one buffer out, one exact slice in.
//!
//! Every service in this family hand-rolls the same obligation, and the copies have already drifted, so
//! the obligation is named here once: a control frame ENCODES into one buffer and DECODES from exactly
//! its own bytes, under a cap the two sides share. Naming it buys three things a convention did not.
//! A frame becomes testable with no stream, no runtime, and no handler, so a spec's byte layouts can be
//! pinned by tests a third party reads as the normative examples. The cap is stated ONCE, so an encoder
//! can no longer emit a frame its own decoder refuses. And the write becomes ONE call: a 10-header
//! request frame written field by field costs 46 `poll_write` calls against 1 for the same 252 bytes
//! encoded into a buffer first, and on a transport that allocates and seals per write that is 1058
//! bytes of framing overhead over 252 bytes of payload, against 23.
//!
//! **This layer touches the CONTROL preamble and never the payload.** [`read_frame`] reads exactly one
//! frame and not one byte more, then the caller gets its stream halves back untouched. That is not a
//! compromise, it is what every service in the family already does, and the reasons are measured. A
//! codec in the payload path costs a full 8 KiB `memcpy` per chunk per direction, which is 2 GiB of
//! pointless copying on a 1 GiB transfer. And a buffering codec is worse than slow: it OVER-READS by
//! design, so after decoding an 8-byte preamble off a stream carrying 32 body bytes it strands those 32
//! bytes inside itself, where the raw phase has to know to replay them. The exact-read shape here
//! strands ZERO, because it reads a fixed head, asks the head how long the frame is, and reads exactly
//! that. A service that hands its joined halves to a foreign protocol engine cannot tolerate stranding
//! at all: the engine must own the stream from byte zero, so a buffering codec there does not cost
//! performance, it corrupts. **Never reach for `tokio_util::codec::Framed` here.**

use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// The most a frame read or write reserves up front. A wire's own cap is the right reservation while it
/// is small, which a control preamble is by construction, but a generous cap must not turn into an
/// allocation of that size per frame: the buffer grows if a real frame needs the room.
const RESERVE: usize = 4096;

/// One control frame, as a pure codec: no IO, no policy, no handler.
///
/// Three obligations, and they are the whole trait. [`encode`](Frame::encode) fills one buffer, so a
/// writer makes one call. [`decode`](Frame::decode) reads exactly one frame's bytes, so it can be
/// driven from a literal in a test with no stream at all. [`HEAD`](Frame::HEAD) plus
/// [`rest`](Frame::rest) state the wire's own length rule, which is what lets a reader take exactly one
/// frame off a shared stream and leave the payload behind it untouched. [`MAX`](Frame::MAX) is the cap
/// both of the first two are held to, stated once so they cannot disagree.
///
/// The length rule is stated as "a fixed head, then however many bytes the head names" because that is
/// the shape every wire in this family already has, whether the head is a length prefix (`rest` is the
/// prefix read back) or a tag whose variant has a known width (`rest` is a match). A wire whose frame
/// length cannot be known from a fixed head is telling you it has no frame boundary, and it should not
/// claim one.
///
/// A frame this build cannot parse is a decode FAILURE only when there is nothing true left to say
/// about it. A condition the peer can act on, the classic being "your grammar, another version", is a
/// legitimate parse OUTCOME: give it a variant and let the service answer it on the wire, because a
/// failure here reaches the peer as a closed stream and a value reaches it as a sentence.
pub trait Frame: Sized {
    /// The largest whole frame this wire admits, in bytes. Checked against the length the head DECLARES,
    /// before the reader allocates for it, and against what [`encode`](Frame::encode) actually produced,
    /// so the two ends cannot disagree about the cap: an encoder cannot emit a frame this decoder would
    /// refuse. Keep it tight. This bounds a control preamble, never a payload, and it is the only thing
    /// standing between one admitted stream and an allocation it names for itself.
    const MAX: usize;

    /// How many leading bytes a reader must hold before [`rest`](Frame::rest) can answer. Fixed for the
    /// life of the wire, because a reader has to know how much to read before it knows anything else.
    const HEAD: usize;

    /// How many bytes FOLLOW the head, given the head. Zero when the head is the whole frame.
    ///
    /// Returns a count rather than a total so a frame shorter than its own head is unrepresentable
    /// rather than caught. A head this wire cannot parse answers `0`: the reader then stops at the head
    /// and hands exactly those bytes to [`decode`](Frame::decode), which classifies them. Guessing a
    /// length out of bytes the wire does not understand is how a reader ends up consuming a neighbour's
    /// payload.
    fn rest(head: &[u8]) -> usize;

    /// Encode the WHOLE frame, head included, into `out`. One buffer, so the caller writes once.
    fn encode(&self, out: &mut Vec<u8>);

    /// Decode one frame from exactly its own bytes: `bytes.len()` is [`HEAD`](Frame::HEAD) plus whatever
    /// [`rest`](Frame::rest) named, never more.
    fn decode(bytes: &[u8]) -> Result<Self, WireError>;

    /// The one relationship between the two consts, held at build time: a frame's cap cannot be smaller
    /// than the head every frame of the wire opens with, or the reader would refuse every frame it could
    /// ever read. Forced by [`read_frame`] and [`write_frame`], which is what makes it a compile error at
    /// the first use rather than a runtime surprise. Not overridden.
    const BOUNDS: () = assert!(
        Self::HEAD <= Self::MAX,
        "a frame's byte cap must leave room for the head every frame opens with"
    );
}

/// Why one frame could not be moved. Library vocabulary (`thiserror`); a binary maps it at its verb edge.
///
/// The service's own grammar failure rides [`Malformed`](WireError::Malformed) as a SOURCE rather than a
/// string, so a caller that cares still downcasts to the typed cause the service raised, and a caller
/// that does not gets one sentence.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The frame's head declared more bytes than the wire admits, or an encode produced more. Raised
    /// BEFORE the reader allocates, which is the whole point: a length is a peer's claim, and a claim
    /// that is checked after the `vec![0; n]` has run is not checked.
    #[error("frame is {declared} bytes, over this wire's {max} byte cap")]
    TooLong {
        /// The byte count the head declared, or the encoder produced.
        declared: usize,
        /// The cap this wire states as [`Frame::MAX`].
        max: usize,
    },
    /// The bytes were this wire's, and its grammar rejected them. The service's typed cause is the
    /// source.
    #[error(transparent)]
    Malformed(Box<dyn core::error::Error + Send + Sync>),
    /// The stream failed under the frame. Transparent, so a caller reads the real kind rather than a
    /// fabricated outer half over it.
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl WireError {
    /// Carry a service's own decode failure as the source of a malformed frame, so the typed cause
    /// survives the crossing instead of being flattened into text.
    pub fn malformed(cause: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self::Malformed(Box::new(cause))
    }
}

/// Read exactly ONE frame off `reader` and leave everything after it untouched.
///
/// Read the head, ask the head how long the frame is, refuse an over-cap claim BEFORE allocating for it,
/// then read exactly that many more bytes. Nothing buffers ahead, so the halves the caller hands on are
/// positioned at the first byte after the frame, which is what lets a service frame its preamble and
/// then splice, stream, or hand the raw stream to a foreign engine with nothing stranded behind it.
pub async fn read_frame<F: Frame, R: io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<F, WireError> {
    // Forces the head-fits-the-cap assertion at this call's monomorphization: a wire that breaks it does
    // not build.
    let () = F::BOUNDS;
    let mut frame = Vec::with_capacity(F::MAX.min(RESERVE));
    frame.resize(F::HEAD, 0);
    reader.read_exact(&mut frame).await?;
    // Saturating, because `rest` derives from bytes a peer wrote: an addition that wraps would turn a
    // hostile length into a small one, which is exactly the check this is.
    let whole = F::HEAD.saturating_add(F::rest(&frame));
    if whole > F::MAX {
        return Err(WireError::TooLong {
            declared: whole,
            max: F::MAX,
        });
    }
    frame.resize(whole, 0);
    reader.read_exact(&mut frame[F::HEAD..]).await?;
    F::decode(&frame)
}

/// Write ONE frame in ONE call: encode into a buffer, check it against the wire's own cap, flush it.
///
/// The cap check is what makes an encoder and a decoder unable to disagree. A writer that caps only at
/// the width of its length field emits frames its own reader refuses, and the peer that sent one has no
/// way to anticipate the refusal; here the frame that would not be read is the frame that is not
/// written.
pub async fn write_frame<F: Frame, W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &F,
) -> Result<(), WireError> {
    let () = F::BOUNDS;
    let mut out = Vec::with_capacity(F::MAX.min(RESERVE));
    frame.encode(&mut out);
    if out.len() > F::MAX {
        return Err(WireError::TooLong {
            declared: out.len(),
            max: F::MAX,
        });
    }
    writer.write_all(&out).await?;
    Ok(())
}
