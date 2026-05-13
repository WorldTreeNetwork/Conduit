//! Media repository handlers (E07).
//!
//! Implements:
//!   POST /_matrix/media/v3/upload
//!   GET  /_matrix/media/v3/config
//!   GET  /_matrix/media/v3/download/:serverName/:mediaId          (legacy unauth)
//!   GET  /_matrix/media/v3/download/:serverName/:mediaId/:fileName
//!   GET  /_matrix/media/v3/thumbnail/:serverName/:mediaId
//!   GET  /_matrix/client/v1/media/download/:serverName/:mediaId   (authenticated)
//!   GET  /_matrix/client/v1/media/download/:serverName/:mediaId/:fileName
//!   GET  /_matrix/client/v1/media/thumbnail/:serverName/:mediaId
//!   GET  /_matrix/client/v1/media/config
//!
//! Federation endpoints (in federation router):
//!   GET  /_matrix/federation/v1/media/download/:mediaId
//!   GET  /_matrix/federation/v1/media/thumbnail/:mediaId

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;

use conduit::storage::{MediaMetadata, Storage, ThumbnailMetadata};

use crate::api::client::{AuthedUser, MatrixError};
use crate::media_storage::BlobStore;

// ---------------------------------------------------------------------------
// Config (read from env)
// ---------------------------------------------------------------------------

pub fn max_upload_bytes() -> u64 {
    std::env::var("CONDUIT_MEDIA_MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(52_428_800) // 50 MiB
}

// ---------------------------------------------------------------------------
// State trait extension (so handlers can access BlobStore + server_name)
// ---------------------------------------------------------------------------

/// State required for media handlers.
pub trait MediaState: Clone + Send + Sync + 'static {
    fn storage(&self) -> &Arc<dyn Storage>;
    fn server_name(&self) -> &str;
    fn blob_store(&self) -> &BlobStore;
    fn federation_client(&self) -> &Arc<crate::federation::Client>;
    /// Maximum upload size in bytes (default: reads CONDUIT_MEDIA_MAX_UPLOAD_BYTES env var).
    fn max_upload_bytes(&self) -> u64 {
        max_upload_bytes()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a 24-character url-safe-base64 media ID.
fn generate_media_id() -> String {
    let mut bytes = [0u8; 18]; // 18 bytes → 24 base64 chars
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decide whether a MIME type should be forced to `attachment` disposition.
fn must_force_attachment(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    // Force attachment for types that could execute in browser contexts.
    matches!(
        ct.as_str(),
        "text/html"
            | "text/javascript"
            | "application/javascript"
            | "image/svg+xml"
            | "application/xhtml+xml"
    )
}

/// Build the safe response headers for a media response.
fn safe_media_headers(content_type: &str, filename: &str, force_attachment: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();

    // Content-Type
    if let Ok(v) = HeaderValue::from_str(content_type) {
        headers.insert(header::CONTENT_TYPE, v);
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
    }

    // Content-Disposition
    let disposition = if force_attachment || must_force_attachment(content_type) {
        format!("attachment; filename=\"{}\"", sanitize_filename(filename))
    } else {
        // Default to inline for images and other safe types (browsers can preview).
        format!("inline; filename=\"{}\"", sanitize_filename(filename))
    };
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }

    // Security headers
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "sandbox; default-src 'none'; style-src 'unsafe-inline'; media-src 'self'; img-src 'self'",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );

    headers
}

/// Strip path separators and null bytes from filenames.
fn sanitize_filename(name: &str) -> String {
    name.replace(['/', '\\', '\0', '"'], "_")
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ThumbnailParams {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub method: Option<String>,
    pub animated: Option<bool>,
}

// ---------------------------------------------------------------------------
// POST /_matrix/media/v3/upload
// ---------------------------------------------------------------------------

pub async fn upload<S: MediaState + crate::api::client::AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let max_bytes = MediaState::max_upload_bytes(&state);
    if body.len() as u64 > max_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "errcode": "M_TOO_LARGE", "error": "Upload exceeds size limit" })),
        )
            .into_response();
    }

    // Determine content type from Content-Type header, fallback to sniff.
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .or_else(|| {
            infer::get(&body).map(|t| t.mime_type().to_owned())
        })
        .unwrap_or_else(|| "application/octet-stream".to_owned());

    // Optional filename from Content-Disposition or query param.
    let upload_name: Option<String> = headers
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            // Parse `filename="foo.png"` or `filename*=UTF-8''foo.png`.
            s.split(';').find_map(|part| {
                let part = part.trim();
                if let Some(rest) = part.strip_prefix("filename=") {
                    Some(rest.trim_matches('"').to_owned())
                } else if let Some(rest) = part.strip_prefix("filename*=UTF-8''") {
                    percent_decode(rest)
                } else {
                    None
                }
            })
        });

    let media_id = generate_media_id();
    let server_name = MediaState::server_name(&state).to_owned();

    let (sha256, storage_path, file_size) =
        match MediaState::blob_store(&state).put(&body).await {
            Ok(v) => v,
            Err(e) => {
                return MatrixError::unknown(format!("blob store write failed: {e}")).into_response();
            }
        };

    let now = Utc::now();
    let meta = MediaMetadata {
        media_id: media_id.clone(),
        origin_server: server_name.clone(),
        uploader: Some(authed.user_id.clone()),
        content_type: Some(content_type),
        upload_name,
        file_size: file_size as i64,
        sha256,
        storage_path,
        uploaded_at: now,
        last_accessed: now,
    };

    if let Err(e) = MediaState::storage(&state).insert_media(&meta).await {
        return MatrixError::unknown(format!("failed to persist media metadata: {e}")).into_response();
    }

    let content_uri = format!("mxc://{server_name}/{media_id}");
    (StatusCode::OK, Json(json!({ "content_uri": content_uri }))).into_response()
}

// ---------------------------------------------------------------------------
// GET /_matrix/media/v3/config  /  GET /_matrix/client/v1/media/config
// ---------------------------------------------------------------------------

pub async fn media_config<S: MediaState>(
    State(state): State<S>,
) -> Json<serde_json::Value> {
    Json(json!({ "m.upload.size": state.max_upload_bytes() }))
}

// ---------------------------------------------------------------------------
// GET download endpoints (shared logic)
// ---------------------------------------------------------------------------

/// Shared download logic: look up metadata, fetch bytes, stream with safe headers.
pub async fn serve_download<S: MediaState>(
    state: &S,
    server_name: &str,
    media_id: &str,
    filename_override: Option<&str>,
    force_attachment: bool,
) -> Response {
    let meta = match state.storage().get_media(media_id, server_name).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            // Possibly a remote server — try to fetch.
            if server_name != state.server_name() {
                match fetch_remote_media(state, server_name, media_id).await {
                    Ok(m) => m,
                    Err(e) => {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(json!({ "errcode": "M_NOT_FOUND", "error": e })),
                        )
                            .into_response();
                    }
                }
            } else {
                return MatrixError::new_not_found("media not found").into_response();
            }
        }
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    let bytes = match state.blob_store().get(&meta.storage_path).await {
        Ok(b) => b,
        Err(e) => {
            return MatrixError::unknown(format!("blob read failed: {e}")).into_response();
        }
    };

    // Touch last_accessed asynchronously (best-effort).
    let _ = state.storage().touch_media_access(media_id, server_name).await;

    let content_type = meta
        .content_type
        .as_deref()
        .unwrap_or("application/octet-stream");

    let filename = filename_override
        .or(meta.upload_name.as_deref())
        .unwrap_or(&meta.media_id);

    let mut headers = safe_media_headers(content_type, filename, force_attachment);
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(bytes.len() as u64),
    );

    (headers, Body::from(bytes)).into_response()
}

// ---------------------------------------------------------------------------
// Legacy unauth download
// ---------------------------------------------------------------------------

pub async fn download_legacy<S: MediaState>(
    State(state): State<S>,
    Path((server_name, media_id)): Path<(String, String)>,
) -> Response {
    serve_download(&state, &server_name, &media_id, None, false).await
}

pub async fn download_legacy_filename<S: MediaState>(
    State(state): State<S>,
    Path((server_name, media_id, filename)): Path<(String, String, String)>,
) -> Response {
    serve_download(&state, &server_name, &media_id, Some(&filename), false).await
}

// ---------------------------------------------------------------------------
// Authenticated download
// ---------------------------------------------------------------------------

pub async fn download_authed<S: MediaState + crate::api::client::AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((server_name, media_id)): Path<(String, String)>,
) -> Response {
    serve_download(&state, &server_name, &media_id, None, false).await
}

pub async fn download_authed_filename<S: MediaState + crate::api::client::AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((server_name, media_id, filename)): Path<(String, String, String)>,
) -> Response {
    serve_download(&state, &server_name, &media_id, Some(&filename), false).await
}

// ---------------------------------------------------------------------------
// Thumbnail endpoints
// ---------------------------------------------------------------------------

/// Shared thumbnail logic.
pub async fn serve_thumbnail<S: MediaState>(
    state: &S,
    server_name: &str,
    media_id: &str,
    params: ThumbnailParams,
) -> Response {
    let req_width = params.width.unwrap_or(320) as i32;
    let req_height = params.height.unwrap_or(240) as i32;
    let method = params.method.as_deref().unwrap_or("scale").to_owned();

    // Check thumbnail cache first.
    match state
        .storage()
        .get_thumbnail(media_id, server_name, req_width, req_height, &method)
        .await
    {
        Ok(Some(t)) => {
            let bytes = match state.blob_store().get(&t.storage_path).await {
                Ok(b) => b,
                Err(e) => return MatrixError::unknown(format!("thumb read: {e}")).into_response(),
            };
            let mut headers = safe_media_headers(&t.content_type, media_id, false);
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len() as u64));
            return (headers, Body::from(bytes)).into_response();
        }
        Ok(None) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    // Need to generate thumbnail — first get the source media.
    let meta = match state.storage().get_media(media_id, server_name).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            if server_name != state.server_name() {
                match fetch_remote_media(state, server_name, media_id).await {
                    Ok(m) => m,
                    Err(e) => {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(json!({ "errcode": "M_NOT_FOUND", "error": e })),
                        )
                            .into_response();
                    }
                }
            } else {
                return MatrixError::new_not_found("media not found").into_response();
            }
        }
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };

    let source_bytes = match state.blob_store().get(&meta.storage_path).await {
        Ok(b) => b,
        Err(e) => return MatrixError::unknown(format!("source read: {e}")).into_response(),
    };

    // Generate thumbnail in a blocking thread (CPU-intensive).
    let method_clone = method.clone();
    let thumb_result = tokio::task::spawn_blocking(move || {
        generate_thumbnail(&source_bytes, req_width as u32, req_height as u32, &method_clone)
    })
    .await;

    let (thumb_bytes, thumb_ct) = match thumb_result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return MatrixError::unknown(format!("thumbnail generation failed: {e}")).into_response(),
        Err(e) => return MatrixError::unknown(format!("thumbnail task panicked: {e}")).into_response(),
    };

    // Store thumbnail.
    let (_, thumb_path, thumb_size) = match state.blob_store().put(&thumb_bytes).await {
        Ok(v) => v,
        Err(e) => return MatrixError::unknown(format!("thumb store: {e}")).into_response(),
    };

    let thumb_meta = ThumbnailMetadata {
        media_id: media_id.to_owned(),
        origin_server: server_name.to_owned(),
        width: req_width,
        height: req_height,
        method,
        content_type: thumb_ct.clone(),
        file_size: thumb_size as i64,
        storage_path: thumb_path,
    };
    // Best-effort persist (don't fail the response if this errors).
    let _ = state.storage().insert_thumbnail(&thumb_meta).await;

    let mut headers = safe_media_headers(&thumb_ct, media_id, false);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(thumb_bytes.len() as u64));
    (headers, Body::from(thumb_bytes)).into_response()
}

pub async fn thumbnail_legacy<S: MediaState>(
    State(state): State<S>,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<ThumbnailParams>,
) -> Response {
    serve_thumbnail(&state, &server_name, &media_id, params).await
}

pub async fn thumbnail_authed<S: MediaState + crate::api::client::AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<ThumbnailParams>,
) -> Response {
    serve_thumbnail(&state, &server_name, &media_id, params).await
}

// ---------------------------------------------------------------------------
// Federation media download handler
// ---------------------------------------------------------------------------

pub async fn federation_download<S: MediaState>(
    State(state): State<S>,
    Path(media_id): Path<String>,
) -> Response {
    let server_name = state.server_name().to_owned();
    match state.storage().get_media(&media_id, &server_name).await {
        Ok(Some(meta)) => {
            let bytes = match state.blob_store().get(&meta.storage_path).await {
                Ok(b) => b,
                Err(e) => return MatrixError::unknown(format!("blob read: {e}")).into_response(),
            };
            let content_type = meta
                .content_type
                .as_deref()
                .unwrap_or("application/octet-stream");
            let filename = meta.upload_name.as_deref().unwrap_or(&meta.media_id);
            let mut headers = safe_media_headers(content_type, filename, false);
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len() as u64));
            (headers, Body::from(bytes)).into_response()
        }
        Ok(None) => MatrixError::new_not_found("media not found").into_response(),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

pub async fn federation_thumbnail<S: MediaState>(
    State(state): State<S>,
    Path(media_id): Path<String>,
    Query(params): Query<ThumbnailParams>,
) -> Response {
    let server_name = state.server_name().to_owned();
    serve_thumbnail(&state, &server_name, &media_id, params).await
}

// ---------------------------------------------------------------------------
// Federation fetch path (h9n.8) — fetch remote media on demand
// ---------------------------------------------------------------------------

/// Fetch media from a remote server via the federation API, cache locally,
/// and return the metadata.
async fn fetch_remote_media<S: MediaState>(
    state: &S,
    origin_server: &str,
    media_id: &str,
) -> Result<MediaMetadata, String> {
    let fed = state.federation_client();

    // Build the federation URL.
    let path = format!("/_matrix/federation/v1/media/download/{}", media_id);

    let response = fed
        .get_raw(origin_server, &path)
        .await
        .map_err(|e| format!("federation fetch failed: {e}"))?;

    // Enforce size limit.
    let max_bytes = max_upload_bytes();
    if let Some(len) = response.content_length() {
        if len > max_bytes {
            return Err(format!("remote media too large: {len} bytes"));
        }
    }

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    let bytes = tokio::time::timeout(
        Duration::from_secs(30),
        response.bytes(),
    )
    .await
    .map_err(|_| "remote media fetch timed out".to_string())?
    .map_err(|e| format!("remote media read failed: {e}"))?;

    if bytes.len() as u64 > max_bytes {
        return Err(format!("remote media too large: {} bytes", bytes.len()));
    }

    let (sha256, storage_path, file_size) = state
        .blob_store()
        .put(&bytes)
        .await
        .map_err(|e| format!("blob store failed: {e}"))?;

    let now = Utc::now();
    let meta = MediaMetadata {
        media_id: media_id.to_owned(),
        origin_server: origin_server.to_owned(),
        uploader: None, // remote-cached
        content_type: content_type.or_else(|| {
            infer::get(&bytes).map(|t| t.mime_type().to_owned())
        }),
        upload_name: None,
        file_size: file_size as i64,
        sha256,
        storage_path,
        uploaded_at: now,
        last_accessed: now,
    };

    state
        .storage()
        .insert_media(&meta)
        .await
        .map_err(|e| format!("persist remote media metadata: {e}"))?;

    Ok(meta)
}

// ---------------------------------------------------------------------------
// Retention policy (h9n.11)
// ---------------------------------------------------------------------------

/// Delete remote-cached media that has not been accessed since `now - max_age`.
/// Returns the number of items deleted.
pub async fn cleanup_remote_media(
    storage: &dyn Storage,
    blob: &BlobStore,
    max_age: Duration,
) -> conduit::Result<usize> {
    let cutoff = Utc::now()
        - chrono::Duration::from_std(max_age).unwrap_or(chrono::Duration::days(30));

    let stale = storage.list_remote_media_older_than(cutoff).await?;
    let count = stale.len();

    for m in stale {
        // Delete blob (best-effort).
        let _ = blob.delete(&m.storage_path).await;
        // Delete DB row (cascades to thumbnails).
        storage.delete_media(&m.media_id, &m.origin_server).await?;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Thumbnail generation (h9n.6)
// ---------------------------------------------------------------------------

/// Generate a thumbnail from raw image bytes.
/// Returns `(png_bytes, "image/png")`.
fn generate_thumbnail(
    source: &[u8],
    width: u32,
    height: u32,
    method: &str,
) -> Result<(Vec<u8>, String), String> {
    use image::imageops::FilterType;
    use image::ImageFormat;
    use std::io::Cursor;

    let img = image::load_from_memory(source)
        .map_err(|e| format!("failed to decode image: {e}"))?;

    let thumb = match method {
        "crop" => img.resize_to_fill(width, height, FilterType::Lanczos3),
        _ => img.thumbnail(width, height), // "scale" + default
    };

    let mut buf = Vec::new();
    thumb
        .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
        .map_err(|e| format!("failed to encode thumbnail: {e}"))?;

    Ok((buf, "image/png".to_owned()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn percent_decode(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next()?;
            let h2 = chars.next()?;
            let byte = u8::from_str_radix(&format!("{h1}{h2}"), 16).ok()?;
            out.push(byte as char);
        } else {
            out.push(c);
        }
    }
    Some(out)
}
