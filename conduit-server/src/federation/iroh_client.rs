//! Outbound federation over iroh (E12 91r.5).
//!
//! Sends `PUT /_matrix/federation/v1/send/{txnId}` (and other requests) over
//! QUIC bi-streams instead of HTTPS.  Uses the same X-Matrix `Authorization`
//! header for event-level signing — the iroh transport does not replace
//! Matrix signing.
//!
//! Wire framing: see [`iroh_server`][super::iroh_server] for format.

#![cfg(feature = "iroh")]

use serde::{Deserialize, Serialize};
use thiserror::Error;

use conduit::transport::iroh::CONDUIT_FEDERATION_ALPN;

// ---------------------------------------------------------------------------
// Wire types (shared with iroh_server)
// ---------------------------------------------------------------------------

/// Request framing header written to the stream.
#[derive(Debug, Serialize)]
struct RequestFrame<'a> {
    method: &'a str,
    uri: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body_len: usize,
}

/// Response framing header read back from the stream.
#[derive(Debug, Deserialize)]
pub struct ResponseFrame {
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum IrohClientError {
    #[error("stream error: {0}")]
    Stream(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("framing error: {0}")]
    Frame(#[from] serde_json::Error),
    #[error("remote returned HTTP {status}: {body}")]
    RemoteError { status: u16, body: String },
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

async fn write_frame<T: Serialize>(
    send: &mut iroh::endpoint::SendStream,
    value: &T,
) -> Result<(), IrohClientError> {
    let bytes = serde_json::to_vec(value)?;
    let len = (bytes.len() as u32).to_be_bytes();
    send.write_all(&len)
        .await
        .map_err(|e| IrohClientError::Stream(Box::new(e)))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| IrohClientError::Stream(Box::new(e)))?;
    Ok(())
}

async fn read_frame<T: for<'de> Deserialize<'de>>(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<T, IrohClientError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| IrohClientError::Stream(Box::new(e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 4 * 1024 * 1024 {
        return Err(IrohClientError::Stream("response frame too large".into()));
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| IrohClientError::Stream(Box::new(e)))?;
    serde_json::from_slice(&buf).map_err(IrohClientError::Frame)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Send a signed request to `node_id` over iroh, using `endpoint`.
///
/// `method` — HTTP method (e.g. `"PUT"`)
/// `uri` — full path + query (e.g. `"/_matrix/federation/v1/send/abc123"`)
/// `auth_header` — the `X-Matrix ...` authorization header value
/// `body` — request body bytes (may be empty)
///
/// Returns `(status, response_body_bytes)`.
pub async fn send_via_iroh(
    endpoint: &iroh::Endpoint,
    node_id: iroh::PublicKey,
    method: &str,
    uri: &str,
    auth_header: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), IrohClientError> {
    let addr = iroh::EndpointAddr::new(node_id);
    let conn = endpoint
        .connect(addr, CONDUIT_FEDERATION_ALPN)
        .await
        .map_err(|e| IrohClientError::Stream(Box::new(e)))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohClientError::Stream(Box::new(e)))?;

    // Send request frame.
    let req_frame = RequestFrame {
        method,
        uri,
        headers: vec![
            ("content-type", "application/json"),
            ("authorization", auth_header),
        ],
        body_len: body.len(),
    };
    write_frame(&mut send, &req_frame).await?;

    // Send body.
    if !body.is_empty() {
        send.write_all(body)
            .await
            .map_err(|e| IrohClientError::Stream(Box::new(e)))?;
    }
    send.finish()
        .map_err(|e| IrohClientError::Stream(Box::new(e)))?;

    // Read response frame.
    let resp_frame: ResponseFrame = read_frame(&mut recv).await?;
    let status = resp_frame.status;

    // Read response body.
    let resp_body = if resp_frame.body_len > 0 {
        let mut buf = vec![0u8; resp_frame.body_len.min(16 * 1024 * 1024)];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| IrohClientError::Stream(Box::new(e)))?;
        buf
    } else {
        vec![]
    };

    conn.close(0u32.into(), b"done");

    if status < 200 || status >= 300 {
        let body_str = String::from_utf8_lossy(&resp_body).into_owned();
        return Err(IrohClientError::RemoteError {
            status,
            body: body_str,
        });
    }

    Ok((status, resp_body))
}
