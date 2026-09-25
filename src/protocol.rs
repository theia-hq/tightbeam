//! tightbeam's stream protocol: a small, versioned preamble on each bifrost stream that selects a
//! service, optionally presents a capability, and reports whether it was reached, before the transparent
//! byte pipe begins. Pure framing; the payload after it is raw bytes (the point of a tunnel). The one
//! guard on the write side is the checked writer: a credential frame is refused before any byte when the
//! session's declared security does not prove the peer.

use bifrost::{Refusal, RefusalDetail, SecurityProfile, Session};
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

use crate::security::{TransportInsecure, peer_proven};

/// tightbeam's protocol identity: the bytes every request preamble opens with, at every version,
/// forever. A stream whose identity is not these is not a tightbeam stream, and that is the only thing
/// an identity mismatch is allowed to mean.
const IDENTITY: [u8; 2] = *b"TB";

/// The request grammar THIS build speaks, written after [`IDENTITY`] and parsed (never compared whole)
/// on read: together they are the four magic bytes `TB04`.
///
/// `TB04` types the tag-1 response: a refusal code byte plus a bounded detail, replacing the free-form
/// string. The request layout is unchanged from `TB03` (which added the optional `membership` field
/// after `capability`), but the tag-1 meaning changed, so a `TB03` peer is not wire compatible. The two
/// ends of one tunnel are built from one rev, so a break here is correct rather than a regression; they
/// are not necessarily RUNNING one rev (a locally built end dials a released host every day), so the
/// break has to announce itself instead of dropping the stream. That is what splitting the magic buys.
const VERSION: WireVersion = WireVersion(*b"04");

/// The magic splits by RULE, not by a remembered offset: the identity is the leading run of capitals,
/// the version is the digits after it, four bytes in all. Held at build time so a magic that breaks the
/// rule fails to compile rather than splitting somewhere the next reader would not look. A digit is
/// never a capital, so "all capitals, then all digits" is exactly "the maximal leading capital run".
const _: () = assert!(
    all_between(&IDENTITY, b'A', b'Z')
        && all_between(VERSION.as_bytes(), b'0', b'9')
        && IDENTITY.len() + VERSION.as_bytes().len() == 4,
    "the magic must be four bytes: a run of capitals (the identity) then digits (the version)"
);

/// Whether `bytes` is non-empty and every byte falls in `lo..=hi`. `const` because its one caller is a
/// build-time claim about the magic.
const fn all_between(bytes: &[u8], lo: u8, hi: u8) -> bool {
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] < lo || bytes[at] > hi {
            return false;
        }
        at += 1;
    }
    !bytes.is_empty()
}

/// The version half of a request preamble: the bytes after [`IDENTITY`], naming which request grammar
/// the peer that wrote them speaks.
///
/// Parsed as a value rather than folded into one four-byte comparison, because the two halves of the
/// magic answer different questions. An IDENTITY mismatch says the stream is not ours and there is
/// nothing true we could say to whatever is on the other end. A VERSION mismatch says a tightbeam peer
/// on another rev, which is a fact both ends can act on, so it is answered on the wire
/// ([`RequestReadError::refusal`]) rather than dropped.
///
/// A value of this type has already proved that the identity run STOPPED before it, which is what makes
/// "the identity matched" a whole claim rather than a prefix test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireVersion([u8; 2]);

impl WireVersion {
    /// Read the version half, after the identity. The width of the field lives here, in the type that
    /// owns it, so the reader and the writer cannot drift apart.
    ///
    /// The identity is the MAXIMAL leading run of capitals, so matching [`IDENTITY`] against the first
    /// bytes is only half of it: the run must also END there. A capital in the first byte of this field
    /// means the peer named a LONGER identity that merely opens with ours, which is a different wire
    /// owed silence and never another version of this one. `TBH1` arriving at a `TB04` host is that
    /// case, and answering it would hand this host's wire version to a peer that does not speak this
    /// wire. The bytes after that one are not held to digits: they are whatever the peer wrote, and an
    /// unserved version is answered on its own terms whether or not it is printable.
    async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, RequestReadError> {
        let mut bytes = [0u8; 2];
        reader.read_exact(&mut bytes).await?;
        let [after_identity, ..] = bytes;
        if after_identity.is_ascii_uppercase() {
            return Err(RequestReadError::Foreign);
        }
        Ok(Self(bytes))
    }

    /// The bytes as they go on the wire.
    const fn as_bytes(&self) -> &[u8; 2] {
        &self.0
    }
}

impl core::fmt::Display for WireVersion {
    /// Renders the WHOLE four-byte tag (`TB04`), because that is the form the source, the docs and the
    /// changelog use, so a dialer handed one in a refusal can match it against what it reads. A peer's
    /// two version bytes are arbitrary and need not be printable, so they are escaped rather than
    /// trusted: this string reaches a terminal.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}{}", IDENTITY.escape_ascii(), self.0.escape_ascii())
    }
}

/// A connector's opening frame: reach the named service, optionally presenting a capability and, for an
/// authority-bound slip, a membership badge under the foreign root the slip names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The service to reach, as named in `expose`.
    pub service: String,
    /// Slot 1: a presented capability link (`<key>.<token>`), when the host gates on capabilities. Absent when
    /// the host gates on identity (open/strict/paired), where the proven `NodeId` is the whole story.
    pub capability: Option<String>,
    /// Slot 2: a membership badge under the FOREIGN root an authority-bound slip in `capability` names. The
    /// host ANDs it against the slip (the two-token authority-bound admission); absent on every other path.
    pub membership: Option<String>,
}

/// The host's reply, sent before any bytes are piped.
///
/// **This frame is FROZEN from `TB04` forward.** The tag byte, and the refusal code byte plus bounded
/// detail behind tag 1, mean the same thing at every version of the REQUEST frame and must keep meaning
/// it. It is the wire's one version-independent channel, and its whole job is to be readable by a peer
/// whose request we could not read: a version mismatch is answered with a refusal frame
/// ([`RequestReadError::refusal`]), which is only possible because a dialer on any version can parse
/// what comes back. Versioning this frame too would take that away and put every future break back to
/// the bare EOF it used to be.
///
/// So: two stability classes on one wire. The request preamble MAY break with a version bump (it
/// carries the evolving vocabulary: service, capability, membership). This one may NOT, ever. Growth
/// here is additive only, and only where an older reader still tells the truth about what it got: a new
/// refusal CODE is fine (an unknown code reads as "a class this build cannot name"), a new tag or a
/// changed field is not.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// The service was reached; the byte pipe follows.
    Ok,
    /// The host refused the stream. Typed: a consumer matches the
    /// classification; there is no free-form string to parse.
    Refused(Refusal),
}

/// Wire codes for the [`Refusal`] classes, beside the frame they select.
///
/// Additive only: a code may be ADDED (an older peer reads it as a class it cannot name, which is
/// true), and no existing code may change meaning, because the frame carrying them is frozen for every
/// version of the request (see [`Response`]).
///
/// [`Refusal`] is non-exhaustive, so a class added upstream no longer stops this file compiling. A
/// new class needs a code here, an arm in the reader, and an entry in [`refusal_code`]; miss one
/// and the host fails the response write rather than sending a code that means something else.
mod refusal_tag {
    pub const NOT_ADMITTED: u8 = 0;
    pub const BAD_REQUEST: u8 = 1;
    pub const UNAVAILABLE: u8 = 2;
}

impl Request {
    /// Write the raw request frame to the stream, unchecked. Crate-internal: every credential-bearing
    /// path goes through [`write_checked`](Self::write_checked).
    pub(crate) async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&IDENTITY).await?;
        writer.write_all(VERSION.as_bytes()).await?;
        write_str(writer, &self.service).await?;
        write_opt(writer, self.capability.as_deref()).await?;
        write_opt(writer, self.membership.as_deref()).await
    }

    /// Write the request, refusing a credential the session's declared security does not cover.
    ///
    /// The ONE checked writer every credential-bearing path goes through: a request that presents a
    /// capability or a membership badge is written only when `S`'s declared profile proves the peer
    /// ([`PeerProof::Proven`](bifrost::PeerProof::Proven) or
    /// [`InProcess`](bifrost::PeerProof::InProcess)); otherwise nothing is written and the refusal names
    /// the declared profile. A request that carries no credential takes the plain, unchecked `write` path.
    /// The profile is read from the session type the caller names (`S`), never from a value passed in:
    /// `S` is the caller's type parameter, so naming the session actually written to is the caller's
    /// obligation, and no [`Security`](bifrost::Security) value can be supplied.
    pub async fn write_checked<S, W>(&self, writer: &mut W) -> Result<(), RequestWriteError>
    where
        S: Session,
        W: io::AsyncWrite + Unpin,
    {
        let security = <S::Security as SecurityProfile>::SECURITY;
        if self.presents_credential() && !peer_proven(security) {
            return Err(TransportInsecure {
                declared: security.peer,
            }
            .into());
        }
        self.write(writer).await.map_err(Into::into)
    }

    /// Whether this request carries a credential: a capability link or a membership badge.
    fn presents_credential(&self) -> bool {
        self.capability.is_some() || self.membership.is_some()
    }

    /// Read a request from the stream.
    ///
    /// The preamble is parsed as [`IDENTITY`] plus a [`WireVersion`], never compared as four bytes, so
    /// that "not our protocol" and "our protocol, another rev" stay two facts instead of one. Only the
    /// second is something the peer can act on, and [`RequestReadError::refusal`] is where it gets
    /// answered rather than logged at the wrong end.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, RequestReadError> {
        let mut identity = [0u8; IDENTITY.len()];
        reader.read_exact(&mut identity).await?;
        if identity != IDENTITY {
            return Err(RequestReadError::Foreign);
        }
        let version = WireVersion::read(reader).await?;
        if version != VERSION {
            return Err(RequestReadError::Version { peer: version });
        }
        Ok(Request {
            service: read_str(reader).await?,
            capability: read_opt(reader).await?,
            membership: read_opt(reader).await?,
        })
    }
}

/// Why a checked request write did not finish.
///
/// Either the frame itself failed (an I/O error in the plain `write`), or the
/// request was refused before any byte because it presents a credential over a transport that does not
/// prove the peer ([`TransportInsecure`]).
#[derive(Debug, thiserror::Error)]
pub enum RequestWriteError {
    /// The request presents a credential and the session's declared profile does not prove the peer.
    /// Nothing was written.
    #[error(transparent)]
    Insecure(#[from] TransportInsecure),
    /// The frame could not be written.
    #[error("the request frame failed to write")]
    Io(#[from] io::Error),
}

/// Why a request frame could not be read.
///
/// Three failures, kept apart on purpose: only one of them is a fact the peer can act on, and only that
/// one is answered on the wire (see [`refusal`](Self::refusal)). Collapsing them is how a version-skewed
/// dialer used to get a bare EOF while the host logged a sentence nobody read.
#[derive(Debug, thiserror::Error)]
pub enum RequestReadError {
    /// The stream's identity is not [`IDENTITY`], so it is not a tightbeam stream: either the leading
    /// capitals differ, or they run ON past ours into a longer identity that merely opens with ours.
    /// The wording is exactly true and covers both: a tightbeam peer on another version is never this.
    #[error("not a tightbeam stream")]
    Foreign,
    /// A tightbeam stream from a build that speaks a different request grammar.
    ///
    /// This message goes ON THE WIRE via [`refusal`](Self::refusal), so it is FIXED text plus the two
    /// version tags and nothing else. Never interpolate host state here: this refusal is written before
    /// any gate has ruled on anything, and a detail that varied with what the host knows would put a
    /// channel on a pre-admission refusal.
    #[error(
        "tightbeam wire version mismatch: the request is {peer}, this host speaks {VERSION}; run the \
         same release at both ends"
    )]
    Version {
        /// The version the peer's preamble named.
        peer: WireVersion,
    },
    /// The frame could not be read.
    #[error("the request frame failed to read")]
    Io(#[from] io::Error),
}

impl RequestReadError {
    /// The refusal to write back, for the one unreadable frame a peer can act on.
    ///
    /// A version mismatch is answerable because the identity already proved the peer speaks tightbeam:
    /// naming both versions tells them what happened and what to do about it. A foreign identity gets
    /// nothing, since we cannot know what would even be meaningful to whatever is on the other end, and
    /// an I/O failure has no readable frame left to answer into.
    ///
    /// [`Refusal::BadRequest`] is the honest class: it means the peer rejected the request SHAPE before
    /// any policy ran, which is precisely what happened, and its payload is the dialer's own grammar,
    /// which is public by definition. It is deliberately not [`Refusal::NotAdmitted`]: no gate ran, so
    /// claiming an authorization outcome would invent a ruling nobody made.
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            // The detail is this variant's own Display, which is the whole reason that string is held
            // to fixed-text-plus-versions.
            Self::Version { .. } => Some(Refusal::BadRequest {
                detail: RefusalDetail::bounded(self.to_string()),
            }),
            Self::Foreign | Self::Io(_) => None,
        }
    }
}

impl Response {
    /// Write the response to the stream.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Response::Ok => writer.write_all(&[0]).await,
            Response::Refused(refusal) => {
                // The whole frame is settled before a byte moves, so a refusal this codec cannot
                // encode leaves the stream untouched instead of a lone `1` the peer then blocks
                // behind waiting for a code that never comes.
                let (code, detail) = refusal_code(refusal)?;
                writer.write_all(&[1, code]).await?;
                match detail {
                    Some(detail) => write_detail(writer, detail).await,
                    None => Ok(()),
                }
            }
        }
    }

    /// Read a response from the stream.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag).await?;
        match tag[0] {
            0 => Ok(Response::Ok),
            1 => {
                let mut code = [0u8; 1];
                reader.read_exact(&mut code).await?;
                match code[0] {
                    refusal_tag::NOT_ADMITTED => Ok(Response::Refused(Refusal::NotAdmitted)),
                    refusal_tag::BAD_REQUEST => Ok(Response::Refused(Refusal::BadRequest {
                        detail: read_detail(reader).await?,
                    })),
                    refusal_tag::UNAVAILABLE => Ok(Response::Refused(Refusal::Unavailable {
                        detail: read_detail(reader).await?,
                    })),
                    other => Err(io::Error::other(format!(
                        "unknown refusal code {other:#04x}"
                    ))),
                }
            }
            other => Err(io::Error::other(format!(
                "unknown response tag {other:#04x}"
            ))),
        }
    }
}

/// The wire code for a refusal class, with the detail that follows it on the wire (a payload-free
/// class carries none).
///
/// Split out of the write so the frame is decided before a byte moves, and so the arm that matters
/// is visible on its own. [`Refusal`] is non-exhaustive: a newer bifrost can name a class this
/// build has no code for, and the arm that catches one is deliberately an ERROR rather than a
/// substitution. Every code in `refusal_tag` is a claim, and a claim this build cannot read is one it
/// must not invent: quietly reusing `NOT_ADMITTED` would tell a dialer their credential was rejected
/// by a host that ruled no such thing, and reusing `UNAVAILABLE` would put arbitrary future classes
/// behind one word a reader has no way to unpick. Failing the write ends the stream instead, and a
/// dialer reporting a broken stream is telling the truth about what happened.
///
/// Reaching this arm means the bifrost pin moved and no code was added here, which is a mistake
/// made at build time; until the day a new class exists there is nothing to construct, so no test
/// can reach it and this comment is the whole of the warning.
fn refusal_code(refusal: &Refusal) -> io::Result<(u8, Option<&RefusalDetail>)> {
    match refusal {
        Refusal::NotAdmitted => Ok((refusal_tag::NOT_ADMITTED, None)),
        Refusal::BadRequest { detail } => Ok((refusal_tag::BAD_REQUEST, Some(detail))),
        Refusal::Unavailable { detail } => Ok((refusal_tag::UNAVAILABLE, Some(detail))),
        unencodable => Err(io::Error::other(format!(
            "no tightbeam refusal code for this class: {unencodable}"
        ))),
    }
}

/// Write an optional string as a presence byte followed by the string when present.
async fn write_opt<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    value: Option<&str>,
) -> io::Result<()> {
    match value {
        Some(value) => {
            writer.write_all(&[1]).await?;
            write_str(writer, value).await
        }
        None => writer.write_all(&[0]).await,
    }
}

/// Read an optional string written by [`write_opt`].
async fn read_opt<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<String>> {
    let mut present = [0u8; 1];
    reader.read_exact(&mut present).await?;
    match present[0] {
        0 => Ok(None),
        1 => Ok(Some(read_str(reader).await?)),
        other => Err(io::Error::other(format!(
            "unknown presence tag {other:#04x}"
        ))),
    }
}

/// Write a bounded refusal detail as a `u16` byte count plus UTF-8 bytes. The
/// text is already bounded by [`RefusalDetail::bounded`], so the count cannot
/// overflow the wire field; the conversion is still checked rather than
/// unwrapped, so a future unbounded caller fails the write instead of cutting a
/// codepoint.
async fn write_detail<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    detail: &RefusalDetail,
) -> io::Result<()> {
    let bytes = detail.as_str().as_bytes();
    let len =
        u16::try_from(bytes.len()).map_err(|_| io::Error::other("refusal detail too long"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(bytes).await
}

/// Read a bounded refusal detail written by [`write_detail`]. An over-cap
/// claim is rejected before the reader allocates, and the bytes must be valid
/// UTF-8: a corrupt or hostile frame is an error, never lossily repaired.
async fn read_detail<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<RefusalDetail> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let len = usize::from(u16::from_be_bytes(len));
    if len > RefusalDetail::MAX_LEN {
        return Err(io::Error::other("refusal detail too long"));
    }
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
    RefusalDetail::try_from(bytes).map_err(io::Error::other)
}

pub(crate) async fn write_str<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    value: &str,
) -> io::Result<()> {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).map_err(|_| io::Error::other("string too long"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(bytes).await
}

pub(crate) async fn read_str<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let mut bytes = vec![0u8; u16::from_be_bytes(len) as usize];
    reader.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| io::Error::other("invalid utf-8 in string"))
}
