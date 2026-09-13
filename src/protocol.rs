//! tightbeam's stream protocol: a small, versioned preamble on each bifrost stream that selects a
//! service, optionally presents a capability, and reports whether it was reached, before the transparent
//! byte pipe begins. Pure framing; the payload after it is raw bytes (the point of a tunnel). The one
//! guard on the write side is the checked writer: a credential frame is refused before any byte when the
//! session's declared security does not prove the peer.

use bifrost::{Refusal, RefusalDetail, SecurityProfile, Session};
use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

use crate::security::{TransportInsecure, peer_proven};

/// Magic + version prefixing a request; a foreign or mismatched-version stream is rejected. `TB04` types
/// the tag-1 response: a refusal code byte plus a bounded detail, replacing the free-form string. The
/// request layout is unchanged from `TB03` (which added the optional `membership` field after
/// `capability`), but the tag-1 meaning changed, so a `TB03` peer is no longer wire compatible, which is
/// correct: the two ends of one tunnel are one release.
const MAGIC: [u8; 4] = *b"TB04";

/// A connector's opening frame: reach the named service, optionally presenting a capability and, for a
/// signet-bound slip, a membership badge under the foreign fleet the slip names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The service to reach, as named in `expose`.
    pub service: String,
    /// Slot 1: a presented capability link (`sheer:…`), when the host gates on capabilities. Absent when
    /// the host gates on identity (open/strict/paired), where the proven `NodeId` is the whole story.
    pub capability: Option<String>,
    /// Slot 2: a membership badge under the FOREIGN fleet a signet-bound slip in `capability` names. The
    /// host ANDs it against the slip (the two-token signet-bound admission); absent on every other path.
    pub membership: Option<String>,
}

/// The host's reply, sent before any bytes are piped.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// The service was reached; the byte pipe follows.
    Ok,
    /// The host refused the stream. Typed: a consumer matches the
    /// classification; there is no free-form string to parse.
    Refused(Refusal),
}

/// Wire codes for the [`Refusal`] variants, beside the frame they
/// select. A new variant forces a code here and an arm in the reader.
mod refusal_tag {
    pub const NOT_ADMITTED: u8 = 0;
    pub const BAD_REQUEST: u8 = 1;
    pub const UNAVAILABLE: u8 = 2;
}

impl Request {
    /// Write the request to the stream.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&MAGIC).await?;
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
    /// the declared profile. A request that carries no credential is the plain [`write`](Self::write).
    /// The profile is read from the session TYPE, never a caller-supplied value, so no caller can assert
    /// a proof the session did not declare.
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
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).await?;
        if magic != MAGIC {
            return Err(io::Error::other("not a tightbeam stream"));
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
/// Either the frame itself failed (an I/O error, the plain [`write`](Request::write) failing), or the
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

impl Response {
    /// Write the response to the stream.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Response::Ok => writer.write_all(&[0]).await,
            Response::Refused(refusal) => {
                writer.write_all(&[1]).await?;
                match refusal {
                    Refusal::NotAdmitted => writer.write_all(&[refusal_tag::NOT_ADMITTED]).await,
                    Refusal::BadRequest { detail } => {
                        writer.write_all(&[refusal_tag::BAD_REQUEST]).await?;
                        write_detail(writer, detail).await
                    }
                    Refusal::Unavailable { detail } => {
                        writer.write_all(&[refusal_tag::UNAVAILABLE]).await?;
                        write_detail(writer, detail).await
                    }
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
