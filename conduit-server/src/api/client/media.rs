//! Content repository (Matrix v1.19 client-server API, "Content repository").
//!
//! Mounted by [`router`]:
//!   POST /_matrix/media/v3/upload
//!   PUT  /_matrix/media/v3/upload/:serverName/:mediaId        (async upload, v1.7)
//!   POST /_matrix/media/v1/create                             (async upload, v1.7)
//!   GET  /_matrix/media/v3/config            GET /_matrix/client/v1/media/config
//!   GET  /_matrix/media/v3/preview_url       GET /_matrix/client/v1/media/preview_url
//!   GET  /_matrix/client/v1/media/download/:serverName/:mediaId[/:fileName]
//!   GET  /_matrix/client/v1/media/thumbnail/:serverName/:mediaId
//!   GET  /_matrix/media/v3/download/:serverName/:mediaId[/:fileName]   (deprecated, frozen)
//!   GET  /_matrix/media/v3/thumbnail/:serverName/:mediaId               (deprecated, frozen)
//!
//! Federation handlers (mounted by the federation router):
//!   GET  /_matrix/federation/v1/media/download/:mediaId
//!   GET  /_matrix/federation/v1/media/thumbnail/:mediaId
//!
//! Spec rules implemented here:
//! * `Content-Type` is stored exactly as uploaded (default
//!   `application/octet-stream`); the `filename` query parameter is kept and
//!   echoed verbatim in `Content-Disposition`, which omits `filename` when
//!   none was given.
//! * `Content-Disposition` is `inline` only for the spec's inline-safe type
//!   list, `attachment` otherwise; thumbnails are always `inline`.
//! * The recommended `Content-Security-Policy`, `nosniff` and
//!   `Cross-Origin-Resource-Policy: cross-origin` accompany every body.
//! * Deprecated unauthenticated endpoints are frozen: media stored after
//!   the freeze (uploads and remote cache fills) are `404 M_NOT_FOUND`
//!   there, while pre-freeze media keep working.
//! * Pending (created, not yet uploaded) media wait up to `timeout_ms`
//!   (default 20 s, capped at 60 s), then `504 M_NOT_YET_UPLOADED`.
//! * `413 M_TOO_LARGE` for uploads or local thumbnails over the limits,
//!   `502 M_TOO_LARGE` for oversized remote content.
//! * Remote media is `404 M_NOT_FOUND` when federation is disabled or
//!   `allow_remote=false`.

// Validation helpers return complete HTTP error responses on cold paths.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use rand::RngCore;
use serde_json::json;

use conduit::storage::{
    MediaMetadata, PendingMedia, PendingMediaCompletion, PendingMediaCreate, Storage,
    ThumbnailMetadata,
};

use crate::api::client::{AuthState, AuthedUser, MatrixError};
use crate::media_storage::BlobStore;

// ---------------------------------------------------------------------------
// Config (read from env)
// ---------------------------------------------------------------------------

pub fn max_upload_bytes() -> u64 {
    env_u64("CONDUIT_MEDIA_MAX_UPLOAD_BYTES", 52_428_800) // 50 MiB
}

pub(crate) fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_flag(name: &str, default: bool) -> bool {
    match std::env::var(name).ok().as_deref().map(str::trim) {
        Some("0") | Some("false") | Some("off") | Some("no") => false,
        Some("1") | Some("true") | Some("on") | Some("yes") => true,
        _ => default,
    }
}

/// Spec default for `timeout_ms` and our cap ("SHOULD impose a maximum").
const DEFAULT_TIMEOUT_MS: u64 = 20_000;
const MAX_TIMEOUT_MS: u64 = 60_000;

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
    /// Whether remote media may be fetched over federation
    /// (`CONDUIT_FEDERATION=0` disables).
    fn federation_enabled(&self) -> bool {
        env_flag("CONDUIT_FEDERATION", true)
    }
    /// Whether the deprecated unauthenticated endpoints are frozen
    /// (`CONDUIT_MEDIA_FREEZE_UNAUTHENTICATED=0` disables; default on).
    fn freeze_unauthenticated_media(&self) -> bool {
        env_flag("CONDUIT_MEDIA_FREEZE_UNAUTHENTICATED", true)
    }
    /// Maximum concurrent pending (`/create`d, not uploaded) media per user.
    fn max_pending_uploads(&self) -> u64 {
        env_u64("CONDUIT_MEDIA_MAX_PENDING_UPLOADS", 5)
    }
    /// Lifetime of an unused `/create` reservation (spec recommends 24h).
    fn unused_expiration(&self) -> Duration {
        Duration::from_millis(env_u64("CONDUIT_MEDIA_UNUSED_EXPIRATION_MS", 24 * 60 * 60 * 1000))
    }
    /// Images with more pixels than this are not thumbnailed (M_TOO_LARGE).
    fn max_thumbnail_pixels(&self) -> u64 {
        env_u64("CONDUIT_MEDIA_MAX_THUMBNAIL_PIXELS", 32 * 1024 * 1024)
    }
}

/// Every content-repository client route. Mount once with `.merge(...)`.
pub fn router<S: AuthState + MediaState>() -> Router<S> {
    use crate::api::client::media_preview::preview_url;
    // Upload bodies are size-checked by the handlers against
    // `max_upload_bytes`, so axum's 2 MiB default must not pre-empt them.
    let uploads = Router::new()
        .route("/_matrix/media/v3/upload", post(upload::<S>))
        .route(
            "/_matrix/media/v3/upload/:serverName/:mediaId",
            axum::routing::put(upload_to_mxc::<S>),
        )
        .layer(DefaultBodyLimit::disable());
    Router::new()
        .merge(uploads)
        .route("/_matrix/media/v1/create", post(create_mxc::<S>))
        .route("/_matrix/media/v3/config", get(media_config::<S>))
        .route("/_matrix/client/v1/media/config", get(media_config::<S>))
        .route("/_matrix/media/v3/preview_url", get(preview_url::<S>))
        .route("/_matrix/client/v1/media/preview_url", get(preview_url::<S>))
        .route("/_matrix/media/v3/download/:serverName/:mediaId", get(download_legacy::<S>))
        .route(
            "/_matrix/media/v3/download/:serverName/:mediaId/:fileName",
            get(download_legacy_filename::<S>),
        )
        .route("/_matrix/media/v3/thumbnail/:serverName/:mediaId", get(thumbnail_legacy::<S>))
        .route("/_matrix/client/v1/media/download/:serverName/:mediaId", get(download_authed::<S>))
        .route(
            "/_matrix/client/v1/media/download/:serverName/:mediaId/:fileName",
            get(download_authed_filename::<S>),
        )
        .route("/_matrix/client/v1/media/thumbnail/:serverName/:mediaId", get(thumbnail_authed::<S>))
}

// ---------------------------------------------------------------------------
// Errors and validation
// ---------------------------------------------------------------------------

/// A Matrix standard error response with an arbitrary errcode.
pub(crate) fn matrix_error(status: StatusCode, errcode: &str, error: impl Into<String>) -> Response {
    (status, Json(json!({ "errcode": errcode, "error": error.into() }))).into_response()
}

fn not_found() -> Response {
    MatrixError::new_not_found("Media not found").into_response()
}

/// Spec: media IDs consist only of `A-Za-z0-9`, `_` and `-`.
pub fn valid_media_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 255 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Appendix "Server name": `hostname [ ":" port ]` where hostname is an
/// IPv4 literal, a bracketed IPv6 literal, or a DNS name.
pub fn valid_server_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let (host, port) = if let Some(rest) = name.strip_prefix('[') {
        let Some((v6, after)) = rest.split_once(']') else { return false };
        if v6.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        match after {
            "" => return true,
            p => match p.strip_prefix(':') {
                Some(port) => (None, Some(port)),
                None => return false,
            },
        }
    } else {
        match name.rsplit_once(':') {
            Some((h, p)) => (Some(h), Some(p)),
            None => (Some(name), None),
        }
    };
    if let Some(port) = port {
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    match host {
        None => true,
        Some(h) => {
            !h.is_empty()
                && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        }
    }
}

fn validate_mxc(server_name: &str, media_id: &str) -> Result<(), Response> {
    if !valid_server_name(server_name) {
        return Err(matrix_error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "Invalid server name"));
    }
    if !valid_media_id(media_id) {
        return Err(not_found());
    }
    Ok(())
}

fn parse_bool(params: &HashMap<String, String>, name: &str) -> Result<Option<bool>, Response> {
    match params.get(name).map(String::as_str) {
        None => Ok(None),
        Some("true") => Ok(Some(true)),
        Some("false") => Ok(Some(false)),
        Some(other) => Err(matrix_error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            format!("{name} must be true or false, got {other:?}"),
        )),
    }
}

fn parse_timeout(params: &HashMap<String, String>) -> Result<Duration, Response> {
    let ms = match params.get("timeout_ms") {
        None => DEFAULT_TIMEOUT_MS,
        Some(v) => v.parse::<i64>().map_err(|_| {
            matrix_error(StatusCode::BAD_REQUEST, "M_INVALID_PARAM", "timeout_ms must be an integer")
        })?.max(0) as u64,
    };
    Ok(Duration::from_millis(ms.min(MAX_TIMEOUT_MS)))
}

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------

/// Spec "Serving inline content": the only types served `inline`.
const INLINE_SAFE_TYPES: &[&str] = &[
    "text/css", "text/plain", "text/csv", "application/json", "application/ld+json",
    "image/jpeg", "image/gif", "image/png", "image/apng", "image/webp", "image/avif",
    "video/mp4", "video/webm", "video/ogg", "video/quicktime",
    "audio/mp4", "audio/webm", "audio/aac", "audio/mpeg", "audio/ogg", "audio/wave",
    "audio/wav", "audio/x-wav", "audio/x-pn-wav", "audio/flac", "audio/x-flac",
];

/// The spec's recommended policy, verbatim.
pub const MEDIA_CSP: &str = "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; object-src 'self';";

fn base_type(content_type: &str) -> String {
    content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

pub fn is_inline_safe(content_type: &str) -> bool {
    INLINE_SAFE_TYPES.contains(&base_type(content_type).as_str())
}

/// RFC 6266 `Content-Disposition` value. The filename is reproduced
/// exactly: quoted-string escaping for printable ASCII, RFC 8187
/// `filename*` percent-encoding otherwise.
pub fn content_disposition(disposition: &str, filename: Option<&str>) -> String {
    match filename {
        None => disposition.to_owned(),
        Some(name) if name.bytes().all(|b| (0x20..0x7f).contains(&b)) => format!(
            "{disposition}; filename=\"{}\"",
            name.replace('\\', "\\\\").replace('"', "\\\"")
        ),
        Some(name) => {
            let mut encoded = String::new();
            for b in name.bytes() {
                if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
                    encoded.push(b as char);
                } else {
                    encoded.push_str(&format!("%{b:02X}"));
                }
            }
            format!("{disposition}; filename*=utf-8''{encoded}")
        }
    }
}

fn media_headers(content_type: &str, disposition: &str, length: usize) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    if let Ok(v) = HeaderValue::from_str(disposition) {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length as u64));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(MEDIA_CSP));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    headers
}

/// Headers for a download body: inline only for inline-safe types.
fn download_headers(content_type: &str, filename: Option<&str>, length: usize) -> HeaderMap {
    let kind = if is_inline_safe(content_type) { "inline" } else { "attachment" };
    media_headers(content_type, &content_disposition(kind, filename), length)
}

// ---------------------------------------------------------------------------
// Upload helpers
// ---------------------------------------------------------------------------

/// Generate a 24-character url-safe-base64 media ID.
fn generate_media_id() -> String {
    let mut bytes = [0u8; 18]; // 18 bytes → 24 base64 chars
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

enum BodyError {
    TooLarge,
    Read(String),
}

/// Read a request body, failing as soon as it exceeds `max` bytes.
async fn read_body_limited(headers: &HeaderMap, mut body: Body, max: u64) -> Result<Vec<u8>, BodyError> {
    use axum::body::HttpBody;
    if let Some(len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len > max {
            return Err(BodyError::TooLarge);
        }
    }
    let mut buf = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await {
        let frame = frame.map_err(|e| BodyError::Read(e.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if buf.len() as u64 + data.len() as u64 > max {
                return Err(BodyError::TooLarge);
            }
            buf.extend_from_slice(&data);
        }
    }
    Ok(buf)
}

fn body_error_response(e: BodyError, max: u64) -> Response {
    match e {
        BodyError::TooLarge => matrix_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "M_TOO_LARGE",
            format!("Cannot upload files larger than {max} bytes"),
        ),
        BodyError::Read(e) => matrix_error(StatusCode::BAD_REQUEST, "M_UNKNOWN", format!("Failed to read upload: {e}")),
    }
}

/// Spec: `Content-Type` is optional and defaults to `application/octet-stream`.
fn upload_content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("application/octet-stream")
        .to_owned()
}

/// Spec: the file name is the `filename` query parameter. A
/// `Content-Disposition` request header is accepted as a fallback.
fn upload_filename(params: &HashMap<String, String>, headers: &HeaderMap) -> Option<String> {
    if let Some(name) = params.get("filename") {
        return Some(name.clone()).filter(|n| !n.is_empty());
    }
    headers
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .and_then(filename_from_disposition)
}

/// Extract `filename*=` (preferred) or `filename=` from a Content-Disposition value.
pub(crate) fn filename_from_disposition(value: &str) -> Option<String> {
    let mut plain = None;
    for part in value.split(';') {
        let part = part.trim();
        let Some((key, val)) = part.split_once('=') else { continue };
        match key.trim().to_ascii_lowercase().as_str() {
            "filename*" => {
                let val = val.trim();
                let encoded = val.split_once("''").map(|(_, v)| v).unwrap_or(val);
                if let Some(decoded) = percent_decode(encoded) {
                    return Some(decoded).filter(|n| !n.is_empty());
                }
            }
            "filename" => {
                let val = val.trim();
                let unquoted = if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
                    val[1..val.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\")
                } else {
                    val.to_owned()
                };
                plain = Some(unquoted).filter(|n| !n.is_empty());
            }
            _ => {}
        }
    }
    plain
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Mark media stored while the freeze is disabled as reachable through the
/// deprecated endpoints, so enabling the freeze later keeps it reachable.
async fn record_legacy_access<S: MediaState>(state: &S, media_id: &str, origin: &str) {
    if !state.freeze_unauthenticated_media() {
        let _ = state
            .storage()
            .set_media_unauthenticated_access(media_id, origin, true)
            .await;
    }
}

/// Wakes downloads waiting on pending media whenever any upload completes.
static UPLOAD_COMPLETED: tokio::sync::Notify = tokio::sync::Notify::const_new();

// ---------------------------------------------------------------------------
// POST /_matrix/media/v3/upload
// ---------------------------------------------------------------------------

pub async fn upload<S: MediaState + AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let max_bytes = MediaState::max_upload_bytes(&state);
    let bytes = match read_body_limited(&headers, body, max_bytes).await {
        Ok(b) => b,
        Err(e) => return body_error_response(e, max_bytes),
    };
    let content_type = upload_content_type(&headers);
    let upload_name = upload_filename(&params, &headers);

    let media_id = generate_media_id();
    let server_name = MediaState::server_name(&state).to_owned();

    let (sha256, storage_path, file_size) = match MediaState::blob_store(&state).put(&bytes).await {
        Ok(v) => v,
        Err(e) => return MatrixError::unknown(format!("blob store write failed: {e}")).into_response(),
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
    record_legacy_access(&state, &media_id, &server_name).await;

    let content_uri = format!("mxc://{server_name}/{media_id}");
    (StatusCode::OK, Json(json!({ "content_uri": content_uri }))).into_response()
}

// ---------------------------------------------------------------------------
// POST /_matrix/media/v1/create
// ---------------------------------------------------------------------------

pub async fn create_mxc<S: MediaState + AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
) -> Response {
    let now = Utc::now();
    let expiry = chrono::Duration::from_std(state.unused_expiration())
        .unwrap_or_else(|_| chrono::Duration::hours(24));
    let pending = PendingMedia {
        media_id: generate_media_id(),
        origin_server: MediaState::server_name(&state).to_owned(),
        creator: authed.user_id.clone(),
        created_at: now,
        expires_at: now + expiry,
    };
    let max = state.max_pending_uploads().min(i64::MAX as u64) as i64;
    match MediaState::storage(&state).create_pending_media(&pending, max).await {
        Ok(PendingMediaCreate::Created) => (
            StatusCode::OK,
            Json(json!({
                "content_uri": format!("mxc://{}/{}", pending.origin_server, pending.media_id),
                "unused_expires_at": pending.expires_at.timestamp_millis(),
            })),
        )
            .into_response(),
        Ok(PendingMediaCreate::LimitExceeded { earliest_expiry }) => {
            let retry_after_ms = earliest_expiry
                .map(|t| (t - now).num_milliseconds().max(0))
                .unwrap_or(0);
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "errcode": "M_LIMIT_EXCEEDED",
                    "error": "Too many pending media uploads",
                    "retry_after_ms": retry_after_ms,
                })),
            )
                .into_response()
        }
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// PUT /_matrix/media/v3/upload/{serverName}/{mediaId}
// ---------------------------------------------------------------------------

fn completion_error(outcome: PendingMediaCompletion) -> Response {
    match outcome {
        PendingMediaCompletion::Completed => (StatusCode::OK, Json(json!({}))).into_response(),
        PendingMediaCompletion::NotFound => {
            MatrixError::new_not_found("Unknown or expired media ID").into_response()
        }
        PendingMediaCompletion::Forbidden => {
            MatrixError::forbidden("Media ID was created by another user").into_response()
        }
        PendingMediaCompletion::AlreadyUploaded => matrix_error(
            StatusCode::CONFLICT,
            "M_CANNOT_OVERWRITE_MEDIA",
            "Media already uploaded",
        ),
    }
}

pub async fn upload_to_mxc<S: MediaState + AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if server_name != MediaState::server_name(&state) || !valid_media_id(&media_id) {
        return MatrixError::new_not_found("Unknown media ID").into_response();
    }
    let storage = MediaState::storage(&state);
    let now = Utc::now();

    // Refuse before reading or storing the body.
    match storage.get_pending_media(&media_id, &server_name).await {
        Ok(Some(p)) if p.creator != authed.user_id => {
            return completion_error(PendingMediaCompletion::Forbidden)
        }
        Ok(Some(p)) if p.expires_at <= now => {
            return completion_error(PendingMediaCompletion::NotFound)
        }
        Ok(Some(_)) => {}
        Ok(None) => {
            return match storage.get_media(&media_id, &server_name).await {
                Ok(Some(_)) => completion_error(PendingMediaCompletion::AlreadyUploaded),
                Ok(None) => completion_error(PendingMediaCompletion::NotFound),
                Err(e) => MatrixError::unknown(e.to_string()).into_response(),
            }
        }
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let max_bytes = MediaState::max_upload_bytes(&state);
    let bytes = match read_body_limited(&headers, body, max_bytes).await {
        Ok(b) => b,
        Err(e) => return body_error_response(e, max_bytes),
    };
    let (sha256, storage_path, file_size) = match MediaState::blob_store(&state).put(&bytes).await {
        Ok(v) => v,
        Err(e) => return MatrixError::unknown(format!("blob store write failed: {e}")).into_response(),
    };
    let now = Utc::now();
    let meta = MediaMetadata {
        media_id: media_id.clone(),
        origin_server: server_name.clone(),
        uploader: Some(authed.user_id.clone()),
        content_type: Some(upload_content_type(&headers)),
        upload_name: upload_filename(&params, &headers),
        file_size: file_size as i64,
        sha256,
        storage_path,
        uploaded_at: now,
        last_accessed: now,
    };
    match storage.complete_pending_media(&meta, &authed.user_id, now).await {
        Ok(PendingMediaCompletion::Completed) => {
            record_legacy_access(&state, &media_id, &server_name).await;
            UPLOAD_COMPLETED.notify_waiters();
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Ok(other) => completion_error(other),
        Err(e) => MatrixError::unknown(e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// GET /_matrix/media/v3/config  /  GET /_matrix/client/v1/media/config
// ---------------------------------------------------------------------------

/// Both paths require authentication per spec and return the same object.
pub async fn media_config<S: MediaState + AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
) -> Json<serde_json::Value> {
    Json(json!({ "m.upload.size": MediaState::max_upload_bytes(&state) }))
}

// ---------------------------------------------------------------------------
// Media resolution (local, pending, remote)
// ---------------------------------------------------------------------------

/// How a download/thumbnail request may obtain media.
#[derive(Debug, Clone, Copy)]
pub struct FetchOptions {
    /// Deprecated unauthenticated endpoint (subject to the freeze).
    pub legacy: bool,
    pub allow_remote: bool,
    pub timeout: Duration,
}

/// Find media metadata: local row, waiting for pending uploads, or
/// fetching from the origin server. Errors are complete responses.
pub async fn resolve_media<S: MediaState>(
    state: &S,
    server_name: &str,
    media_id: &str,
    opts: FetchOptions,
) -> Result<MediaMetadata, Response> {
    validate_mxc(server_name, media_id)?;
    let storage = state.storage();
    let freeze = opts.legacy && state.freeze_unauthenticated_media();
    let local = server_name == state.server_name();
    let deadline = tokio::time::Instant::now() + opts.timeout;
    loop {
        let notified = UPLOAD_COMPLETED.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        match storage.get_media(media_id, server_name).await {
            Ok(Some(meta)) => {
                if freeze {
                    match storage.media_unauthenticated_access(media_id, server_name).await {
                        Ok(true) => {}
                        Ok(false) => return Err(not_found()),
                        Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
                    }
                }
                return Ok(meta);
            }
            Ok(None) => {}
            Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
        }

        if !local {
            // A freshly cached remote file is "new" media under the freeze.
            if freeze || !opts.allow_remote || !state.federation_enabled() {
                return Err(not_found());
            }
            return fetch_remote_media(state, server_name, media_id, opts.timeout)
                .await
                .map_err(RemoteError::into_response);
        }

        if freeze {
            // Anything not yet stored is post-freeze media.
            return Err(not_found());
        }
        let pending = match storage.get_pending_media(media_id, server_name).await {
            Ok(p) => p,
            Err(e) => return Err(MatrixError::unknown(e.to_string()).into_response()),
        };
        match pending {
            Some(p) if p.expires_at > Utc::now() => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(matrix_error(
                        StatusCode::GATEWAY_TIMEOUT,
                        "M_NOT_YET_UPLOADED",
                        "Content has not yet been uploaded",
                    ));
                }
                // Wake on any completed upload, polling as a fallback.
                let wait = (deadline - now).min(Duration::from_millis(500));
                let _ = tokio::time::timeout(wait, notified).await;
            }
            _ => return Err(not_found()),
        }
    }
}

// ---------------------------------------------------------------------------
// GET download endpoints
// ---------------------------------------------------------------------------

fn download_options(params: &HashMap<String, String>, legacy: bool) -> Result<FetchOptions, Response> {
    let allow_remote = if legacy { parse_bool(params, "allow_remote")?.unwrap_or(true) } else { true };
    // allow_redirect is accepted; this server always returns the content
    // itself, which is valid for both values.
    if legacy {
        parse_bool(params, "allow_redirect")?;
    }
    Ok(FetchOptions { legacy, allow_remote, timeout: parse_timeout(params)? })
}

/// Shared download logic: resolve, read the blob, respond with safe headers.
pub async fn serve_download<S: MediaState>(
    state: &S,
    server_name: &str,
    media_id: &str,
    filename_override: Option<&str>,
    opts: FetchOptions,
) -> Response {
    let meta = match resolve_media(state, server_name, media_id, opts).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let bytes = match state.blob_store().get(&meta.storage_path).await {
        Ok(b) => b,
        Err(e) => return MatrixError::unknown(format!("blob read failed: {e}")).into_response(),
    };
    let _ = state.storage().touch_media_access(media_id, server_name).await;

    let content_type = meta.content_type.as_deref().unwrap_or("application/octet-stream");
    let filename = filename_override.or(meta.upload_name.as_deref());
    (download_headers(content_type, filename, bytes.len()), Body::from(bytes)).into_response()
}

pub async fn download_legacy<S: MediaState>(
    State(state): State<S>,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match download_options(&params, true) {
        Ok(opts) => serve_download(&state, &server_name, &media_id, None, opts).await,
        Err(resp) => resp,
    }
}

pub async fn download_legacy_filename<S: MediaState>(
    State(state): State<S>,
    Path((server_name, media_id, filename)): Path<(String, String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match download_options(&params, true) {
        Ok(opts) => serve_download(&state, &server_name, &media_id, Some(&filename), opts).await,
        Err(resp) => resp,
    }
}

pub async fn download_authed<S: MediaState + AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match download_options(&params, false) {
        Ok(opts) => serve_download(&state, &server_name, &media_id, None, opts).await,
        Err(resp) => resp,
    }
}

pub async fn download_authed_filename<S: MediaState + AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((server_name, media_id, filename)): Path<(String, String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match download_options(&params, false) {
        Ok(opts) => serve_download(&state, &server_name, &media_id, Some(&filename), opts).await,
        Err(resp) => resp,
    }
}

// ---------------------------------------------------------------------------
// Thumbnail endpoints
// ---------------------------------------------------------------------------

/// A validated thumbnail request.
#[derive(Debug, Clone, Copy)]
pub struct ThumbnailRequest {
    pub width: u32,
    pub height: u32,
    pub crop: bool,
    pub animated: Option<bool>,
}

impl ThumbnailRequest {
    pub fn parse(params: &HashMap<String, String>) -> Result<Self, Response> {
        let dim = |name: &str| -> Result<u32, Response> {
            let raw = params.get(name).ok_or_else(|| {
                matrix_error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", format!("Missing {name}"))
            })?;
            raw.parse::<u32>().ok().filter(|v| *v > 0).ok_or_else(|| {
                matrix_error(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    format!("{name} must be a positive integer"),
                )
            })
        };
        let width = dim("width")?;
        let height = dim("height")?;
        let crop = match params.get("method").map(String::as_str) {
            None | Some("scale") => false,
            Some("crop") => true,
            Some(other) => {
                return Err(matrix_error(
                    StatusCode::BAD_REQUEST,
                    "M_INVALID_PARAM",
                    format!("method must be crop or scale, got {other:?}"),
                ))
            }
        };
        Ok(Self { width, height, crop, animated: parse_bool(params, "animated")? })
    }

    fn method(&self) -> &'static str {
        if self.crop { "crop" } else { "scale" }
    }
}

fn thumbnail_headers(content_type: &str, length: usize) -> HeaderMap {
    let ext = match base_type(content_type).as_str() {
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/apng" => "apng",
        _ => "png",
    };
    // Spec: a thumbnail's Content-Disposition MUST be inline.
    media_headers(content_type, &format!("inline; filename=\"thumbnail.{ext}\""), length)
}

/// Shared thumbnail logic.
pub async fn serve_thumbnail<S: MediaState>(
    state: &S,
    server_name: &str,
    media_id: &str,
    req: ThumbnailRequest,
    opts: FetchOptions,
) -> Response {
    let meta = match resolve_media(state, server_name, media_id, opts).await {
        Ok(m) => m,
        Err(resp) => return resp,
    };
    let local = server_name == state.server_name();
    let too_large = || {
        let status = if local { StatusCode::PAYLOAD_TOO_LARGE } else { StatusCode::BAD_GATEWAY };
        matrix_error(status, "M_TOO_LARGE", "Content is too large to thumbnail")
    };
    let width = req.width as i32;
    let height = req.height as i32;
    let width = width.max(1);
    let height = height.max(1);

    match state
        .storage()
        .get_thumbnail(media_id, server_name, width, height, req.method())
        .await
    {
        Ok(Some(t)) => match state.blob_store().get(&t.storage_path).await {
            Ok(bytes) => {
                return (thumbnail_headers(&t.content_type, bytes.len()), Body::from(bytes)).into_response()
            }
            Err(e) => tracing::warn!(error = %e, "cached thumbnail unreadable; regenerating"),
        },
        Ok(None) => {}
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    }

    let source = match state.blob_store().get(&meta.storage_path).await {
        Ok(b) => b,
        Err(e) => return MatrixError::unknown(format!("source read: {e}")).into_response(),
    };
    let source_type = meta.content_type.clone().unwrap_or_else(|| "application/octet-stream".into());
    let max_pixels = state.max_thumbnail_pixels();
    let source_for_task = source.clone();
    let source_type_for_task = source_type.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        make_thumbnail(&source_for_task, &source_type_for_task, req, max_pixels)
    })
    .await;

    match outcome {
        Ok(Ok(ThumbnailOutcome::Original)) => {
            let _ = state.storage().touch_media_access(media_id, server_name).await;
            (thumbnail_headers(&source_type, source.len()), Body::from(source)).into_response()
        }
        Ok(Ok(ThumbnailOutcome::Generated { bytes, content_type })) => {
            if let Ok((_, path, size)) = state.blob_store().put(&bytes).await {
                let thumb_meta = ThumbnailMetadata {
                    media_id: media_id.to_owned(),
                    origin_server: server_name.to_owned(),
                    width,
                    height,
                    method: req.method().to_owned(),
                    content_type: content_type.to_owned(),
                    file_size: size as i64,
                    storage_path: path,
                };
                // Best-effort cache.
                let _ = state.storage().insert_thumbnail(&thumb_meta).await;
            }
            (thumbnail_headers(content_type, bytes.len()), Body::from(bytes)).into_response()
        }
        Ok(Err(ThumbnailError::NotImage)) => matrix_error(
            StatusCode::BAD_REQUEST,
            "M_UNKNOWN",
            "Cannot generate thumbnails for the requested content",
        ),
        Ok(Err(ThumbnailError::TooLarge)) => too_large(),
        Ok(Err(ThumbnailError::Failed(e))) => {
            MatrixError::unknown(format!("thumbnail generation failed: {e}")).into_response()
        }
        Err(e) => MatrixError::unknown(format!("thumbnail task panicked: {e}")).into_response(),
    }
}

fn thumbnail_options(params: &HashMap<String, String>, legacy: bool) -> Result<(ThumbnailRequest, FetchOptions), Response> {
    let req = ThumbnailRequest::parse(params)?;
    Ok((req, download_options(params, legacy)?))
}

pub async fn thumbnail_legacy<S: MediaState>(
    State(state): State<S>,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match thumbnail_options(&params, true) {
        Ok((req, opts)) => serve_thumbnail(&state, &server_name, &media_id, req, opts).await,
        Err(resp) => resp,
    }
}

pub async fn thumbnail_authed<S: MediaState + AuthState>(
    State(state): State<S>,
    _authed: AuthedUser,
    Path((server_name, media_id)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match thumbnail_options(&params, false) {
        Ok((req, opts)) => serve_thumbnail(&state, &server_name, &media_id, req, opts).await,
        Err(resp) => resp,
    }
}

// ---------------------------------------------------------------------------
// Federation media handlers (mounted by the federation router)
// ---------------------------------------------------------------------------

/// Federation media is `multipart/mixed` with an empty JSON metadata part
/// and the bytes. <https://spec.matrix.org/v1.19/server-server-api/#content-repository>
pub fn multipart_mixed_media(content_type: &str, disposition: &str, bytes: Vec<u8>) -> Response {
    let mut boundary = generate_media_id();
    loop {
        let marker = format!("--{boundary}");
        if !bytes.windows(marker.len()).any(|window| window == marker.as_bytes()) {
            break;
        }
        boundary = generate_media_id();
    }
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/json\r\n\r\n{{}}\r\n").as_bytes());
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: {content_type}\r\nContent-Disposition: {disposition}\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(&bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!("multipart/mixed; boundary={boundary}")) {
        headers.insert(header::CONTENT_TYPE, value);
    }
    (headers, Body::from(body)).into_response()
}

async fn wrap_federation_media(response: Response) -> Response {
    if response.status() != StatusCode::OK {
        return response;
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let disposition = response
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("attachment")
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default()
        .to_vec();
    multipart_mixed_media(&content_type, &disposition, bytes)
}

pub async fn federation_download<S: MediaState>(
    State(state): State<S>,
    Path(media_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let server_name = state.server_name().to_owned();
    let mut opts = match download_options(&params, false) {
        Ok(opts) => opts,
        Err(resp) => return resp,
    };
    opts.allow_remote = false;
    let meta = match resolve_media(&state, &server_name, &media_id, opts).await {
        Ok(meta) => meta,
        Err(resp) => return resp,
    };
    let bytes = match state.blob_store().get(&meta.storage_path).await {
        Ok(bytes) => bytes,
        Err(e) => return MatrixError::unknown(format!("blob read: {e}")).into_response(),
    };
    let content_type = meta.content_type.as_deref().unwrap_or("application/octet-stream");
    let kind = if is_inline_safe(content_type) { "inline" } else { "attachment" };
    let disposition = content_disposition(kind, meta.upload_name.as_deref());
    multipart_mixed_media(content_type, &disposition, bytes)
}

pub async fn federation_thumbnail<S: MediaState>(
    State(state): State<S>,
    Path(media_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let server_name = state.server_name().to_owned();
    match thumbnail_options(&params, false) {
        Ok((req, opts)) => {
            let opts = FetchOptions { allow_remote: false, ..opts };
            wrap_federation_media(serve_thumbnail(&state, &server_name, &media_id, req, opts).await).await
        }
        Err(resp) => resp,
    }
}

// ---------------------------------------------------------------------------
// Federation fetch path (h9n.8) — fetch remote media on demand
// ---------------------------------------------------------------------------

/// Why a remote fetch failed, mapped onto the client-facing errors.
#[derive(Debug)]
pub enum RemoteError {
    NotFound(String),
    TooLarge,
    NotYetUploaded,
    Failed(String),
}

impl RemoteError {
    fn into_response(self) -> Response {
        match self {
            RemoteError::NotFound(e) => MatrixError::new_not_found(e).into_response(),
            RemoteError::TooLarge => matrix_error(
                StatusCode::BAD_GATEWAY,
                "M_TOO_LARGE",
                "Remote content is too large to serve",
            ),
            RemoteError::NotYetUploaded => matrix_error(
                StatusCode::GATEWAY_TIMEOUT,
                "M_NOT_YET_UPLOADED",
                "Content has not yet been uploaded",
            ),
            RemoteError::Failed(e) => matrix_error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", e),
        }
    }
}

fn remote_errcode(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("errcode").and_then(|c| c.as_str()).map(str::to_owned))
}

fn map_federation_error(e: crate::federation::client::FederationError) -> RemoteError {
    use crate::federation::client::FederationError;
    match e {
        FederationError::RemoteError { status, body } => {
            let code = remote_errcode(&body);
            match (status, code.as_deref()) {
                (504, Some("M_NOT_YET_UPLOADED")) => RemoteError::NotYetUploaded,
                (_, Some("M_TOO_LARGE")) => RemoteError::TooLarge,
                (404, _) => RemoteError::NotFound("Remote media not found".into()),
                _ => RemoteError::Failed(format!("remote returned {status}")),
            }
        }
        other => RemoteError::Failed(format!("federation fetch failed: {other}")),
    }
}

/// Read a response body, failing once it exceeds `max` bytes.
async fn read_limited(mut response: reqwest::Response, max: u64) -> Result<Vec<u8>, RemoteError> {
    if response.content_length().is_some_and(|len| len > max) {
        return Err(RemoteError::TooLarge);
    }
    let mut buf = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| RemoteError::Failed(format!("remote media read failed: {e}")))?
    {
        if buf.len() as u64 + chunk.len() as u64 > max {
            return Err(RemoteError::TooLarge);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// One part of a `multipart/mixed` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartPart {
    /// Lower-cased header names.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MultipartPart {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn find_bytes(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Parse an RFC 2046 `multipart/mixed` body (federation media responses).
pub fn parse_multipart_mixed(content_type: &str, body: &[u8]) -> Result<Vec<MultipartPart>, String> {
    let boundary = content_type
        .split(';')
        .skip(1)
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("boundary"))
        .map(|(_, v)| v.trim().trim_matches('"').to_owned())
        .filter(|b| !b.is_empty())
        .ok_or("multipart response without boundary")?;
    let delimiter = format!("--{boundary}");
    let mut pos = find_bytes(body, delimiter.as_bytes(), 0).ok_or("missing first boundary")? + delimiter.len();
    let mut parts = Vec::new();
    loop {
        if body[pos..].starts_with(b"--") {
            break; // close delimiter
        }
        // Skip transport padding and the line break after the delimiter.
        while pos < body.len() && (body[pos] == b' ' || body[pos] == b'\t') {
            pos += 1;
        }
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        } else if body[pos..].starts_with(b"\n") {
            pos += 1;
        } else {
            return Err("malformed boundary line".into());
        }
        let (header_block, content_start) = if body[pos..].starts_with(b"\r\n") {
            (&body[pos..pos], pos + 2)
        } else if body[pos..].starts_with(b"\n") {
            (&body[pos..pos], pos + 1)
        } else if let Some(end) = find_bytes(body, b"\r\n\r\n", pos) {
            (&body[pos..end], end + 4)
        } else if let Some(end) = find_bytes(body, b"\n\n", pos) {
            (&body[pos..end], end + 2)
        } else {
            return Err("unterminated part headers".into());
        };
        let headers = String::from_utf8_lossy(header_block)
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let crlf_delim = format!("\r\n{delimiter}");
        let lf_delim = format!("\n{delimiter}");
        let (content_end, next) = match find_bytes(body, crlf_delim.as_bytes(), content_start) {
            Some(i) => (i, i + crlf_delim.len()),
            None => match find_bytes(body, lf_delim.as_bytes(), content_start) {
                Some(i) => (i, i + lf_delim.len()),
                None => return Err("missing closing boundary".into()),
            },
        };
        parts.push(MultipartPart { headers, body: body[content_start..content_end].to_vec() });
        pos = next;
        if pos >= body.len() {
            break;
        }
    }
    Ok(parts)
}

/// Content of a remote media download.
struct RemoteContent {
    content_type: Option<String>,
    filename: Option<String>,
    bytes: Vec<u8>,
}

/// Fetch media from a remote server via the federation API, cache locally,
/// and return the metadata.
async fn fetch_remote_media<S: MediaState>(
    state: &S,
    origin_server: &str,
    media_id: &str,
    timeout: Duration,
) -> Result<MediaMetadata, RemoteError> {
    let max_bytes = state.max_upload_bytes();
    // A generous fetch deadline: the remote may itself wait timeout_ms for
    // an asynchronous upload before it starts sending bytes.
    let deadline = timeout + Duration::from_secs(30);
    let content = tokio::time::timeout(deadline, download_remote(state, origin_server, media_id, timeout, max_bytes))
        .await
        .map_err(|_| RemoteError::Failed("remote media fetch timed out".into()))??;

    let (sha256, storage_path, file_size) = state
        .blob_store()
        .put(&content.bytes)
        .await
        .map_err(|e| RemoteError::Failed(format!("blob store failed: {e}")))?;

    let now = Utc::now();
    let meta = MediaMetadata {
        media_id: media_id.to_owned(),
        origin_server: origin_server.to_owned(),
        uploader: None, // remote-cached
        content_type: Some(content.content_type.unwrap_or_else(|| "application/octet-stream".into())),
        upload_name: content.filename,
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
        .map_err(|e| RemoteError::Failed(format!("persist remote media metadata: {e}")))?;
    record_legacy_access(state, media_id, origin_server).await;
    Ok(meta)
}

async fn download_remote<S: MediaState>(
    state: &S,
    origin_server: &str,
    media_id: &str,
    timeout: Duration,
    max_bytes: u64,
) -> Result<RemoteContent, RemoteError> {
    let fed = state.federation_client();
    let ms = timeout.as_millis();
    let path = format!("/_matrix/federation/v1/media/download/{media_id}?timeout_ms={ms}");
    let response = match fed.get_raw(origin_server, &path).await {
        Ok(r) => r,
        Err(crate::federation::client::FederationError::RemoteError { status, body })
            if matches!(status, 400 | 404 | 405)
                && remote_errcode(&body).as_deref().map_or(status != 404, |c| c == "M_UNRECOGNIZED") =>
        {
            // Pre-v1.11 origin: fall back to the deprecated media endpoint.
            let legacy = format!(
                "/_matrix/media/v3/download/{origin_server}/{media_id}?allow_remote=false&allow_redirect=false&timeout_ms={ms}"
            );
            let response = fed.get_raw(origin_server, &legacy).await.map_err(map_federation_error)?;
            return raw_content(response, max_bytes).await;
        }
        Err(e) => return Err(map_federation_error(e)),
    };
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    if !base_type(&content_type).starts_with("multipart/") {
        // Tolerate servers that answer with the bare bytes.
        return raw_content(response, max_bytes).await;
    }
    // Allow room for the JSON part and part headers.
    let body = read_limited(response, max_bytes + 64 * 1024).await?;
    let parts = parse_multipart_mixed(&content_type, &body).map_err(RemoteError::Failed)?;
    let [_metadata, media] = parts.as_slice() else {
        return Err(RemoteError::Failed(format!("expected 2 multipart parts, got {}", parts.len())));
    };
    if let Some(location) = media.header("location") {
        // The origin redirected us; fetch it like any untrusted URL.
        let policy = Arc::new(crate::api::client::safe_fetch::FetchPolicy {
            allow: crate::api::client::media_preview::allowlist_from_env(),
            max_bytes: max_bytes as usize,
            timeout: Duration::from_secs(30),
            max_redirects: 5,
        });
        let fetched = crate::api::client::safe_fetch::fetch(policy, location)
            .await
            .map_err(|e| match e {
                crate::api::client::safe_fetch::FetchError::TooLarge => RemoteError::TooLarge,
                other => RemoteError::Failed(other.to_string()),
            })?;
        return Ok(RemoteContent {
            content_type: fetched.content_type,
            filename: fetched.content_disposition.as_deref().and_then(filename_from_disposition),
            bytes: fetched.body,
        });
    }
    if media.body.len() as u64 > max_bytes {
        return Err(RemoteError::TooLarge);
    }
    Ok(RemoteContent {
        content_type: media.header("content-type").map(str::to_owned),
        filename: media.header("content-disposition").and_then(filename_from_disposition),
        bytes: media.body.clone(),
    })
}

async fn raw_content(response: reqwest::Response, max_bytes: u64) -> Result<RemoteContent, RemoteError> {
    let header_value = |name: header::HeaderName| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let content_type = header_value(header::CONTENT_TYPE);
    let filename = header_value(header::CONTENT_DISPOSITION)
        .as_deref()
        .and_then(filename_from_disposition);
    let bytes = read_limited(response, max_bytes).await?;
    Ok(RemoteContent { content_type, filename, bytes })
}

// ---------------------------------------------------------------------------
// Retention policy (h9n.11)
// ---------------------------------------------------------------------------

/// Delete remote-cached media that has not been accessed since `now - max_age`.
/// Returns the number of items deleted. Blobs are content-addressed and
/// may be shared, so a blob is removed only once nothing references it.
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
        // Delete DB row (cascades to thumbnails), then the unreferenced blob.
        storage.delete_media(&m.media_id, &m.origin_server).await?;
        if !storage.media_storage_path_in_use(&m.storage_path).await? {
            let _ = blob.delete(&m.storage_path).await;
        }
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Thumbnail generation
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ThumbnailOutcome {
    /// Serve the original bytes (content no larger than requested).
    Original,
    Generated { bytes: Vec<u8>, content_type: &'static str },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ThumbnailError {
    NotImage,
    TooLarge,
    Failed(String),
}

fn is_animated(source: &[u8], format: image::ImageFormat) -> bool {
    use image::AnimationDecoder as _;
    use std::io::Cursor;
    match format {
        image::ImageFormat::Gif => image::codecs::gif::GifDecoder::new(Cursor::new(source))
            .map(|d| d.into_frames().take(2).count() > 1)
            .unwrap_or(false),
        image::ImageFormat::WebP => image::codecs::webp::WebPDecoder::new(Cursor::new(source))
            .map(|d| d.has_animation())
            .unwrap_or(false),
        image::ImageFormat::Png => image::codecs::png::PngDecoder::new(Cursor::new(source))
            .and_then(|d| d.is_apng())
            .unwrap_or(false),
        _ => false,
    }
}

/// Produce a thumbnail per the spec's sizing rules:
/// * never upscale; content no larger than requested is returned as-is
///   (when its type is inline-safe and animation rules allow);
/// * `scale` keeps the aspect ratio and is never smaller than requested
///   in either dimension unless the source is;
/// * `crop` returns exactly the requested size (or, for a smaller source,
///   the largest region with the requested aspect ratio);
/// * animated output only when `animated=true` (and then only by passing
///   through an already-small animated original).
pub fn make_thumbnail(
    source: &[u8],
    source_type: &str,
    req: ThumbnailRequest,
    max_pixels: u64,
) -> Result<ThumbnailOutcome, ThumbnailError> {
    use image::imageops::FilterType;
    use image::{ImageFormat, ImageReader};
    use std::io::Cursor;

    let reader = ImageReader::new(Cursor::new(source))
        .with_guessed_format()
        .map_err(|e| ThumbnailError::Failed(e.to_string()))?;
    let format = reader.format().ok_or(ThumbnailError::NotImage)?;
    let (sw, sh) = reader.into_dimensions().map_err(|_| ThumbnailError::NotImage)?;
    if sw == 0 || sh == 0 {
        return Err(ThumbnailError::NotImage);
    }
    if sw as u64 * sh as u64 > max_pixels {
        return Err(ThumbnailError::TooLarge);
    }
    let (w, h) = (req.width, req.height);

    let animated = is_animated(source, format);
    let passthrough_ok = matches!(
        base_type(source_type).as_str(),
        "image/jpeg" | "image/png" | "image/gif" | "image/webp" | "image/apng"
    ) && (!animated || req.animated == Some(true));
    if sw <= w && sh <= h && passthrough_ok {
        return Ok(ThumbnailOutcome::Original);
    }

    let mut decoder = ImageReader::with_format(Cursor::new(source), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(sw);
    limits.max_image_height = Some(sh);
    decoder.limits(limits);
    let img = decoder.decode().map_err(|_| ThumbnailError::NotImage)?;

    let thumb = if req.crop {
        if sw >= w && sh >= h {
            img.resize_to_fill(w, h, FilterType::Lanczos3)
        } else {
            // Largest centred region with the requested aspect, no scaling.
            let (cw, ch) = if (sw as u64) * (h as u64) > (sh as u64) * (w as u64) {
                (((sh as u64 * w as u64) / h as u64).max(1) as u32, sh)
            } else {
                (sw, ((sw as u64 * h as u64) / w as u64).max(1) as u32)
            };
            img.crop_imm((sw - cw) / 2, (sh - ch) / 2, cw, ch)
        }
    } else {
        // Smallest aspect-preserving size covering the request, capped at
        // the source size.
        let factor = (w as f64 / sw as f64).max(h as f64 / sh as f64);
        if factor >= 1.0 {
            img
        } else {
            let nw = ((sw as f64 * factor).ceil() as u32).clamp(1, sw);
            let nh = ((sh as f64 * factor).ceil() as u32).clamp(1, sh);
            img.resize_exact(nw, nh, FilterType::Lanczos3)
        }
    };

    let mut buf = Vec::new();
    let content_type = if format == ImageFormat::Jpeg {
        image::DynamicImage::ImageRgb8(thumb.to_rgb8())
            .write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)
            .map_err(|e| ThumbnailError::Failed(e.to_string()))?;
        "image/jpeg"
    } else {
        thumb
            .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
            .map_err(|e| ThumbnailError::Failed(e.to_string()))?;
        "image/png"
    };
    Ok(ThumbnailOutcome::Generated { bytes: buf, content_type })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(w, h, image::Rgba([10, 20, 30, 255]));
        let mut buf = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .unwrap();
        buf
    }

    fn animated_gif(w: u32, h: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut enc = image::codecs::gif::GifEncoder::new(&mut buf);
            let frames = (0..2).map(|i| {
                image::Frame::new(image::RgbaImage::from_pixel(w, h, image::Rgba([i * 100, 0, 0, 255])))
            });
            enc.encode_frames(frames).unwrap();
        }
        buf
    }

    fn dims(bytes: &[u8]) -> (u32, u32) {
        image::load_from_memory(bytes).unwrap().into_rgba8().dimensions()
    }

    fn req(w: u32, h: u32, crop: bool, animated: Option<bool>) -> ThumbnailRequest {
        ThumbnailRequest { width: w, height: h, crop, animated }
    }

    fn generated(o: ThumbnailOutcome) -> (Vec<u8>, &'static str) {
        match o {
            ThumbnailOutcome::Generated { bytes, content_type } => (bytes, content_type),
            ThumbnailOutcome::Original => panic!("expected a generated thumbnail"),
        }
    }

    #[test]
    fn inline_allowlist_matches_spec() {
        for t in ["image/png", "IMAGE/JPEG", "text/plain; charset=utf-8", "video/mp4", "audio/x-flac", "application/ld+json"] {
            assert!(is_inline_safe(t), "{t}");
        }
        for t in ["text/html", "image/svg+xml", "application/javascript", "application/pdf", "application/octet-stream", "text/xml", "application/xhtml+xml"] {
            assert!(!is_inline_safe(t), "{t}");
        }
    }

    #[test]
    fn content_disposition_preserves_filename() {
        assert_eq!(content_disposition("inline", None), "inline");
        assert_eq!(content_disposition("attachment", Some("War and Peace.pdf")), "attachment; filename=\"War and Peace.pdf\"");
        assert_eq!(content_disposition("inline", Some("a\"b\\c.txt")), "inline; filename=\"a\\\"b\\\\c.txt\"");
        assert_eq!(content_disposition("inline", Some("café.png")), "inline; filename*=utf-8''caf%C3%A9.png");
        assert_eq!(content_disposition("inline", Some("a\r\nb")), "inline; filename*=utf-8''a%0D%0Ab");
        // Round trip through our own parser.
        for name in ["War and Peace.pdf", "café.png", "a\"b\\c.txt", "../../etc/passwd"] {
            assert_eq!(filename_from_disposition(&content_disposition("inline", Some(name))).as_deref(), Some(name));
        }
    }

    #[test]
    fn server_name_and_media_id_validation() {
        for ok in ["example.org", "example.org:8448", "1.2.3.4", "1.2.3.4:80", "[::1]", "[1234:5678::abcd]:5678", "localhost"] {
            assert!(valid_server_name(ok), "{ok}");
        }
        for bad in ["", "exa mple.org", "example.org:", "example.org:123456", "[::1", "[nope]", "a/b", "..%2f", "example.org:80a"] {
            assert!(!valid_server_name(bad), "{bad}");
        }
        assert!(valid_media_id("AQwafuaFswefuhsfAFAgsw_-09"));
        for bad in ["", "../etc", "a.b", "a%2fb", "a b", "ä"] {
            assert!(!valid_media_id(bad), "{bad}");
        }
    }

    #[test]
    fn scale_never_returns_smaller_than_requested() {
        let src = png(400, 200);
        let (bytes, ct) = generated(make_thumbnail(&src, "image/png", req(100, 100, false, None), u64::MAX).unwrap());
        assert_eq!(ct, "image/png");
        let (w, h) = dims(&bytes);
        assert!(w >= 100 && h >= 100, "{w}x{h}");
        assert_eq!((w, h), (200, 100), "aspect ratio preserved");
    }

    #[test]
    fn scale_does_not_upscale() {
        let src = png(400, 50);
        let (bytes, _) = generated(make_thumbnail(&src, "image/png", req(100, 100, false, None), u64::MAX).unwrap());
        assert_eq!(dims(&bytes), (400, 50));
    }

    #[test]
    fn crop_matches_requested_size_and_aspect() {
        let src = png(300, 100);
        let (bytes, _) = generated(make_thumbnail(&src, "image/png", req(32, 32, true, None), u64::MAX).unwrap());
        assert_eq!(dims(&bytes), (32, 32));
        // Source narrower than requested: requested aspect, no upscale.
        let src = png(50, 400);
        let (bytes, _) = generated(make_thumbnail(&src, "image/png", req(96, 96, true, None), u64::MAX).unwrap());
        assert_eq!(dims(&bytes), (50, 50));
    }

    #[test]
    fn small_content_returns_original() {
        let src = png(20, 20);
        assert!(matches!(
            make_thumbnail(&src, "image/png", req(32, 32, true, None), u64::MAX).unwrap(),
            ThumbnailOutcome::Original
        ));
    }

    #[test]
    fn animated_only_when_requested() {
        let gif = animated_gif(10, 10);
        // animated=true: the small animated original may be returned.
        assert!(matches!(
            make_thumbnail(&gif, "image/gif", req(32, 32, false, Some(true)), u64::MAX).unwrap(),
            ThumbnailOutcome::Original
        ));
        // animated=false or absent: a static PNG.
        for animated in [Some(false), None] {
            let (bytes, ct) = generated(make_thumbnail(&gif, "image/gif", req(32, 32, false, animated), u64::MAX).unwrap());
            assert_eq!(ct, "image/png");
            assert!(bytes.starts_with(b"\x89PNG"));
        }
    }

    #[test]
    fn not_image_and_too_large() {
        assert_eq!(
            make_thumbnail(b"%PDF-1.4 not an image", "application/pdf", req(32, 32, false, None), u64::MAX).unwrap_err(),
            ThumbnailError::NotImage
        );
        let src = png(100, 100);
        assert_eq!(
            make_thumbnail(&src, "image/png", req(32, 32, false, None), 9_999).unwrap_err(),
            ThumbnailError::TooLarge
        );
    }

    #[test]
    fn multipart_parses_spec_layout() {
        let body = b"--abc\r\nContent-Type: application/json\r\n\r\n{}\r\n--abc\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=\"x.png\"\r\n\r\n\x89PNG\r\n--ab\x00\r\n--abc--\r\n";
        let parts = parse_multipart_mixed("multipart/mixed; boundary=abc", body).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].header("content-type"), Some("application/json"));
        assert_eq!(parts[0].body, b"{}");
        assert_eq!(parts[1].header("content-type"), Some("image/png"));
        assert_eq!(parts[1].body, b"\x89PNG\r\n--ab\x00");
        assert_eq!(
            parts[1].header("content-disposition").and_then(filename_from_disposition).as_deref(),
            Some("x.png")
        );
        let redirect = b"--b\r\nContent-Type: application/json\r\n\r\n{}\r\n--b\r\nLocation: https://cdn.example/x\r\n\r\n\r\n--b--";
        let parts = parse_multipart_mixed("multipart/mixed; boundary=\"b\"", redirect).unwrap();
        assert_eq!(parts[1].header("location"), Some("https://cdn.example/x"));
        assert!(parse_multipart_mixed("multipart/mixed", body).is_err());
    }
}
