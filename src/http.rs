//! tightbeam's HTTP preamble (`TBH1`): the request/response framing for the `fetch:` egress service, a
//! sibling to [`protocol`](crate::protocol)'s `TB02`.
//!
//! It rides INSIDE a `TB02`-accepted stream: after the host replies [`Response::Ok`](crate::protocol),
//! the requester writes a [`FetchRequest`], the host performs the origin request and writes a
//! [`FetchResponse`], then streams the body until the stream closes (EOF delimits the body, as the raw
//! splice already relies on). Pure framing here; the origin fetch and the local listener live elsewhere.

use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

use crate::protocol::{read_str, write_str};

/// Magic + version prefixing every fetch frame; distinct from `TB02` so a mismatched peer is rejected.
const MAGIC: [u8; 4] = *b"TBH1";

/// A requester's fetch: the method, the absolute origin URL, and the headers to forward verbatim
/// (including `Range`, which is the whole point: the origin returns `206` and xget's resume works).
#[derive(Debug, PartialEq, Eq)]
pub struct FetchRequest {
    /// The HTTP method. v1 accepts only `GET` and `HEAD`; the field is here for forward-compat.
    pub method: String,
    /// The absolute origin URL to fetch.
    pub url: String,
    /// Request headers, forwarded verbatim (hop-by-hop headers are stripped by the caller).
    pub headers: Vec<(String, String)>,
}

/// The host's reply, sent before the body: the origin status and headers forwarded verbatim, or an
/// error (origin unreachable, method refused, policy denied) as a human-readable string.
#[derive(Debug, PartialEq, Eq)]
pub enum FetchResponse {
    /// The origin answered; its status and headers follow, then the body streams to EOF.
    Ok {
        /// The origin HTTP status, forwarded verbatim (200, 206, 301, 404, ...).
        status: u16,
        /// The origin response headers, forwarded verbatim (`Accept-Ranges`, `Content-Range`, ...).
        headers: Vec<(String, String)>,
    },
    /// The fetch could not be performed, with a reason.
    Error(String),
}

impl FetchRequest {
    /// Write the request frame.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&MAGIC).await?;
        write_str(writer, &self.method).await?;
        write_str(writer, &self.url).await?;
        write_headers(writer, &self.headers).await
    }

    /// Read a request frame.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        read_magic(reader).await?;
        Ok(Self {
            method: read_str(reader).await?,
            url: read_str(reader).await?,
            headers: read_headers(reader).await?,
        })
    }
}

impl FetchResponse {
    /// Write the response frame (the body, if any, is streamed by the caller after this).
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&MAGIC).await?;
        match self {
            Self::Ok { status, headers } => {
                writer.write_all(&[0]).await?;
                writer.write_all(&status.to_be_bytes()).await?;
                write_headers(writer, headers).await
            }
            Self::Error(message) => {
                writer.write_all(&[1]).await?;
                write_str(writer, message).await
            }
        }
    }

    /// Read a response frame.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        read_magic(reader).await?;
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag).await?;
        match tag[0] {
            0 => {
                let mut status = [0u8; 2];
                reader.read_exact(&mut status).await?;
                Ok(Self::Ok {
                    status: u16::from_be_bytes(status),
                    headers: read_headers(reader).await?,
                })
            }
            1 => Ok(Self::Error(read_str(reader).await?)),
            other => Err(io::Error::other(format!(
                "unknown fetch response tag {other:#04x}"
            ))),
        }
    }
}

/// Read and check the frame magic, rejecting a foreign or mismatched-version stream.
async fn read_magic<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<()> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).await?;
    if magic != MAGIC {
        return Err(io::Error::other("not a tightbeam fetch stream"));
    }
    Ok(())
}

/// Write a header list as a `u16` count followed by that many `(name, value)` string pairs.
async fn write_headers<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    headers: &[(String, String)],
) -> io::Result<()> {
    let count = u16::try_from(headers.len()).map_err(|_| io::Error::other("too many headers"))?;
    writer.write_all(&count.to_be_bytes()).await?;
    for (name, value) in headers {
        write_str(writer, name).await?;
        write_str(writer, value).await?;
    }
    Ok(())
}

/// Read a header list written by [`write_headers`].
async fn read_headers<R: io::AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Vec<(String, String)>> {
    let mut count = [0u8; 2];
    reader.read_exact(&mut count).await?;
    let count = u16::from_be_bytes(count);
    let mut headers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name = read_str(reader).await?;
        let value = read_str(reader).await?;
        headers.push((name, value));
    }
    Ok(headers)
}
