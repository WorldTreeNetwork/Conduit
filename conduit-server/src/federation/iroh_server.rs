//! Inbound federation over iroh (E12 91r.6).
//!
//! Accepts QUIC bi-streams on [`CONDUIT_FEDERATION_ALPN`] and dispatches
//! them through the same axum [`Router`] that handles HTTPS-arriving
//! federation requests.  No logic is duplicated — the handler code in
//! `server.rs` is shared by both transports.
//!
//! Wire framing on each bi-directional QUIC stream:
//!
//!   → 4-byte big-endian header length
//!   → header_len bytes of UTF-8 JSON: `{ "method": "PUT", "uri": "/...",
//!       "headers": [["name","value"]], "body_len": 42 }`
//!   → body_len raw bytes (request body)
//!   ← 4-byte big-endian header length
//!   ← header_len bytes of UTF-8 JSON: `{ "status": 200, "headers": [...],
//!       "body_len": 17 }`
//!   ← body_len raw bytes (response body)

#![cfg(feature = "iroh")]

use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::Router;
use serde::{Deserialize, Serialize};
use tower::ServiceExt as _;
use tracing::{debug, warn};

use conduit::transport::iroh::CONDUIT_FEDERATION_ALPN;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Framing header sent by the connecting peer (request side).
#[derive(Debug, Deserialize)]
struct RequestFrame {
    method: String,
    uri: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    body_len: usize,
}

/// Framing header sent back to the connecting peer (response side).
#[derive(Debug, Serialize)]
struct ResponseFrame {
    status: u16,
    #[serde(default)]
    headers: Vec<(String, String)>,
    body_len: usize,
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

/// Read a length-prefixed (4-byte big-endian) JSON frame from the stream.
async fn read_frame<T: for<'de> Deserialize<'de>>(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 4 * 1024 * 1024 {
        return Err("frame header too large".into());
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Write a length-prefixed (4-byte big-endian) JSON frame to the stream.
async fn write_frame<T: Serialize>(
    send: &mut iroh::endpoint::SendStream,
    value: &T,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = serde_json::to_vec(value)?;
    let len = (bytes.len() as u32).to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Handle a single iroh connection: accept one bi-stream, route it.
async fn handle_connection(conn: iroh::endpoint::Connection, router: Router) {
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                debug!("iroh connection closed: {e}");
                return;
            }
        };

        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(&mut send, &mut recv, router).await {
                warn!("iroh stream error: {e}");
                // Send a 500 back if we can.
                let _ = write_frame(
                    &mut send,
                    &ResponseFrame {
                        status: 500,
                        headers: vec![],
                        body_len: 0,
                    },
                )
                .await;
            }
            let _ = send.finish();
        });
    }
}

async fn handle_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    router: Router,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Read request frame.
    let req_frame: RequestFrame = read_frame(recv).await?;

    // 2. Read body.
    let body_bytes = if req_frame.body_len > 0 {
        let mut buf = vec![0u8; req_frame.body_len.min(16 * 1024 * 1024)];
        recv.read_exact(&mut buf).await?;
        buf
    } else {
        vec![]
    };

    // 3. Build an http::Request from the frame.
    let mut builder = Request::builder()
        .method(req_frame.method.as_str())
        .uri(req_frame.uri.as_str());

    for (name, value) in &req_frame.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }

    let http_req = builder.body(Body::from(body_bytes))?;

    // 4. Call the axum router.
    let http_resp = router.oneshot(http_req).await?;

    // 5. Collect response.
    let status = http_resp.status().as_u16();
    let resp_headers: Vec<(String, String)> = http_resp
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|vs| (k.to_string(), vs.to_owned()))
        })
        .collect();

    let resp_body = axum::body::to_bytes(http_resp.into_body(), 16 * 1024 * 1024).await?;

    // 6. Write response frame + body.
    let resp_frame = ResponseFrame {
        status,
        headers: resp_headers,
        body_len: resp_body.len(),
    };
    write_frame(send, &resp_frame).await?;
    if !resp_body.is_empty() {
        send.write_all(&resp_body).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Accept loop (91r.6)
// ---------------------------------------------------------------------------

/// Spawn the iroh accept loop as a background tokio task.
///
/// `router` should be the fully-wired federation `Router<()>` (with all
/// middleware already applied and state injected).  The iroh inbound handler
/// simply routes requests through it, exactly as if they had arrived over HTTPS.
///
/// `endpoint` must be bound and configured to accept `CONDUIT_FEDERATION_ALPN`.
pub fn spawn_iroh_accept_loop(endpoint: iroh::Endpoint, router: Router) {
    let node_id = endpoint.id();
    tracing::info!(
        node_id = %node_id.fmt_short(),
        alpn = %std::str::from_utf8(CONDUIT_FEDERATION_ALPN).unwrap_or("?"),
        "iroh federation accept loop starting",
    );

    tokio::spawn(async move {
        loop {
            let conn = match endpoint.accept().await {
                Some(connecting) => match connecting.await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("iroh incoming connection failed: {e}");
                        continue;
                    }
                },
                None => {
                    debug!("iroh endpoint closed, stopping accept loop");
                    return;
                }
            };

            let router = router.clone();
            tokio::spawn(handle_connection(conn, router));
        }
    });
}
