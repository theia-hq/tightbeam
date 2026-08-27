//! The origin-fetch handler behind a `fetch:` service: read a [`FetchRequest`] off the stream, perform
//! the HTTP GET/HEAD at the origin with a real HTTPS client (TLS terminates HERE, not at the requester),
//! and stream the response back (status + headers, then the body to stream close). This is the smallest
//! honest instance of "run this at a keyed node": a fetch, not a general proxy.

use futures::StreamExt as _;
use tokio::io::{self, AsyncWriteExt as _};

use crate::http::{FetchRequest, FetchResponse};

/// Read one [`FetchRequest`], fetch the origin, write the [`FetchResponse`] + body, then close the write
/// half so the requester sees the body's end.
pub(crate) async fn serve_fetch<W, R>(writer: &mut W, reader: &mut R) -> io::Result<()>
where
    W: io::AsyncWrite + Unpin,
    R: io::AsyncRead + Unpin,
{
    let request = FetchRequest::read(reader).await?;
    match fetch_origin(&request).await {
        Ok(response) => stream_response(writer, response).await?,
        Err(message) => FetchResponse::Error(message).write(writer).await?,
    }
    writer.shutdown().await
}

/// Perform the origin request. Redirects are forwarded to the requester verbatim (not followed here), so
/// the client decides; TLS terminates at this node.
async fn fetch_origin(request: &FetchRequest) -> Result<reqwest::Response, String> {
    let method = allowed_method(&request.method)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("http client: {error}"))?;
    let mut outgoing = client.request(method, &request.url);
    for (name, value) in forward_headers(&request.headers) {
        outgoing = outgoing.header(name, value);
    }
    outgoing
        .send()
        .await
        .map_err(|error| format!("origin request failed: {error}"))
}

/// Write the response frame (origin status + headers verbatim) then stream the body to the writer until
/// the origin body ends. Never buffers the whole body, so a large download does not grow the node's memory.
async fn stream_response<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    response: reqwest::Response,
) -> io::Result<()> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect();
    FetchResponse::Ok { status, headers }.write(writer).await?;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| io::Error::other(format!("origin body: {error}")))?;
        writer.write_all(&chunk).await?;
    }
    Ok(())
}

/// The origin method for a request method: GET and HEAD only (a fetch, not a general HTTP proxy).
pub(crate) fn allowed_method(method: &str) -> Result<reqwest::Method, String> {
    match method {
        "GET" => Ok(reqwest::Method::GET),
        "HEAD" => Ok(reqwest::Method::HEAD),
        other => Err(format!(
            "method {other} not allowed (fetch is GET/HEAD only)"
        )),
    }
}

/// The request headers to forward to the origin: everything except hop-by-hop headers and `Host` (the
/// client derives Host from the URL). `Range` and the rest pass through, so a ranged/resumable GET works.
pub(crate) fn forward_headers(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    const SKIP: [&str; 7] = [
        "host",
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
    ];
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            !SKIP.contains(&lower.as_str())
        })
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}
