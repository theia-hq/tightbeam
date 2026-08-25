//! tightbeam's stream protocol: a small, versioned preamble on each bifrost stream that selects a
//! service and reports whether it was reached, before the transparent byte pipe begins. Pure framing;
//! the payload after it is raw bytes (the point of a tunnel).

use tokio::io::{self, AsyncReadExt as _, AsyncWriteExt as _};

/// Magic + version prefixing a request; a foreign or mismatched-version stream is rejected.
const MAGIC: [u8; 4] = *b"TB01";

/// A connector's opening frame: reach the named service.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// The service to reach, as named in `expose`.
    pub service: String,
}

/// The host's reply, sent before any bytes are piped.
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    /// The service was reached; the byte pipe follows.
    Ok,
    /// The service could not be reached, with a human-readable reason.
    Error(String),
}

impl Request {
    /// Write the request to the stream.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&MAGIC).await?;
        write_str(writer, &self.service).await
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
        })
    }
}

impl Response {
    /// Write the response to the stream.
    pub async fn write<W: io::AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Response::Ok => writer.write_all(&[0]).await,
            Response::Error(message) => {
                writer.write_all(&[1]).await?;
                write_str(writer, message).await
            }
        }
    }

    /// Read a response from the stream.
    pub async fn read<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag).await?;
        match tag[0] {
            0 => Ok(Response::Ok),
            1 => Ok(Response::Error(read_str(reader).await?)),
            other => Err(io::Error::other(format!(
                "unknown response tag {other:#04x}"
            ))),
        }
    }
}

async fn write_str<W: io::AsyncWrite + Unpin>(writer: &mut W, value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).map_err(|_| io::Error::other("string too long"))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(bytes).await
}

async fn read_str<R: io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let mut bytes = vec![0u8; u16::from_be_bytes(len) as usize];
    reader.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| io::Error::other("invalid utf-8 in string"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_roundtrips() {
        let mut buf = Vec::new();
        Request {
            service: "ssh".to_owned(),
        }
        .write(&mut buf)
        .await
        .unwrap();
        let decoded = Request::read(&mut buf.as_slice()).await.unwrap();
        assert_eq!(
            decoded,
            Request {
                service: "ssh".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn response_roundtrips() {
        for response in [Response::Ok, Response::Error("unknown service".to_owned())] {
            let mut buf = Vec::new();
            response.write(&mut buf).await.unwrap();
            assert_eq!(Response::read(&mut buf.as_slice()).await.unwrap(), response);
        }
    }

    #[tokio::test]
    async fn rejects_foreign_stream() {
        let mut buf = b"XXXXnonsense".as_slice();
        assert!(Request::read(&mut buf).await.is_err());
    }
}
