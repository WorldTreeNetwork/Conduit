//! Integration tests for the E07 Media Repository endpoints.
//!
//! Each test spins up an ephemeral Postgres DB via `TempDb`, runs migrations,
//! and exercises the full media handler stack via `tower::ServiceExt::oneshot`.
//!
//! # Running
//! ```
//! DATABASE_URL=postgresql://postgres@localhost/conduit \
//!     cargo test --workspace --tests -- media
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tempfile::TempDir;
use tokio::sync::{RwLock, broadcast};
use tower::util::ServiceExt as _;

use conduit::keys::ServerKey;
use conduit::storage::Storage;
use conduit_server::{
    BlobStore, PostgresStorage,
    api::client::{self as auth, AuthState, TxnCacheKey, TypingStore, PresenceStore},
    api::client::media::{self as media_api, MediaState},
    federation,
};

// ---------------------------------------------------------------------------
// TempDb fixture
// ---------------------------------------------------------------------------

struct TempDb {
    admin_url: String,
    db_name: String,
    pool: PgPool,
}

impl TempDb {
    async fn new() -> Self {
        let admin_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres@localhost/postgres".to_owned());

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let tid = format!("{:?}", std::thread::current().id())
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();
        let db_name = format!("conduit_test_media_{}_{}", tid, nanos).to_lowercase();

        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&admin_url)
            .await
            .expect("connect to admin postgres");

        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin_pool)
            .await
            .unwrap_or_else(|e| panic!("CREATE DATABASE {db_name}: {e}"));
        admin_pool.close().await;

        let test_url = replace_db_in_url(&admin_url, &db_name);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&test_url)
            .await
            .unwrap_or_else(|e| panic!("connect to {db_name}: {e}"));

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap_or_else(|e| panic!("migrations on {db_name}: {e}"));

        TempDb { admin_url, db_name, pool }
    }

    fn storage(&self) -> Arc<dyn Storage> {
        PostgresStorage::new(self.pool.clone()).into_arc()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::process::Command::new("psql")
            .args([
                &self.admin_url,
                "-c",
                &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db_name),
            ])
            .output();
    }
}

fn replace_db_in_url(url: &str, new_db: &str) -> String {
    let url = url.trim_end_matches('/');
    if let Some(pos) = url.rfind('/') {
        format!("{}/{}", &url[..pos], new_db)
    } else {
        format!("{}/{}", url, new_db)
    }
}

// ---------------------------------------------------------------------------
// Minimal AppState for tests
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TestState {
    storage: Arc<dyn Storage>,
    server_name: Arc<str>,
    server_key: Arc<ServerKey>,
    txn_cache: Arc<RwLock<HashMap<TxnCacheKey, String>>>,
    events_tx: broadcast::Sender<i64>,
    typing_store: Arc<TypingStore>,
    typing_tx: broadcast::Sender<String>,
    presence_store: Arc<PresenceStore>,
    blob_store: BlobStore,
    fed_client: Arc<federation::Client>,
    max_upload_bytes: u64,
}

impl AuthState for TestState {
    fn storage(&self) -> &Arc<dyn Storage> { &self.storage }
    fn server_name(&self) -> &str { &self.server_name }
    fn server_key(&self) -> Arc<ServerKey> { Arc::clone(&self.server_key) }
    fn txn_cache(&self) -> &Arc<RwLock<HashMap<TxnCacheKey, String>>> { &self.txn_cache }
    fn events_tx(&self) -> &broadcast::Sender<i64> { &self.events_tx }
    fn typing_store(&self) -> &Arc<TypingStore> { &self.typing_store }
    fn typing_tx(&self) -> &broadcast::Sender<String> { &self.typing_tx }
    fn presence_store(&self) -> &Arc<PresenceStore> { &self.presence_store }
}

impl MediaState for TestState {
    fn storage(&self) -> &Arc<dyn Storage> { &self.storage }
    fn server_name(&self) -> &str { &self.server_name }
    fn blob_store(&self) -> &BlobStore { &self.blob_store }
    fn federation_client(&self) -> &Arc<federation::Client> { &self.fed_client }
    fn max_upload_bytes(&self) -> u64 { self.max_upload_bytes }
}

async fn make_test_state(db: &TempDb, blob_dir: &TempDir) -> TestState {
    let storage = db.storage();
    let server_key = Arc::new(conduit_server::keys::load_or_generate(&*storage).await.unwrap());
    let (events_tx, _) = broadcast::channel(16);
    let (typing_store, typing_tx) = TypingStore::new();
    let presence_store = PresenceStore::new();
    let blob_store = BlobStore::new(blob_dir.path().to_path_buf()).unwrap();

    // Build a dummy federation client for tests (no real HTTP).
    let http = reqwest::Client::new();
    let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap();
    let remote_keys = Arc::new(conduit_server::RemoteKeyCache::new());
    let server_key_arc = Arc::clone(&server_key);
    let server_name: Arc<str> = "localhost".into();
    let fed_client = Arc::new(federation::Client::new(
        http,
        resolver,
        remote_keys,
        server_key_arc,
        Arc::clone(&server_name),
    ));

    TestState {
        storage,
        server_name,
        server_key,
        txn_cache: Arc::new(RwLock::new(HashMap::new())),
        events_tx,
        typing_store,
        typing_tx,
        presence_store,
        blob_store,
        fed_client,
        max_upload_bytes: 52_428_800, // 50 MiB default
    }
}

fn build_router(state: TestState) -> Router {
    Router::new()
        .route("/_matrix/client/v3/register", post(auth::register::<TestState>))
        .route("/_matrix/client/v3/login",
            get(auth::get_login_flows::<TestState>).post(auth::login::<TestState>))
        .merge(media_api::router::<TestState>())
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn raw_body(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap().to_vec()
}

/// Register a test user and return the access token.
async fn register_user(app: &Router, username: &str) -> String {
    let body = json!({
        "username": username,
        "password": "testpass123",
        "auth": { "type": "m.login.dummy" }
    });
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/register")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let v = json_body(resp).await;
    v["access_token"].as_str().unwrap().to_owned()
}

/// POST raw bytes to /upload, returns the response.
async fn do_upload(app: &Router, token: &str, bytes: &[u8], content_type: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/media/v3/upload")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", content_type)
        .body(Body::from(bytes.to_vec()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

/// Upload and assert 200, panicking with the body if not.
async fn upload_ok(app: &Router, token: &str, bytes: &[u8], content_type: &str) -> Value {
    let resp = do_upload(app, token, bytes, content_type).await;
    let status = resp.status();
    let body = json_body(resp).await;
    assert_eq!(status, StatusCode::OK, "upload failed: {body}");
    body
}

// ---------------------------------------------------------------------------
// Test 1: upload_returns_content_uri
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_returns_content_uri() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);

    let token = register_user(&app, "uploader1").await;
    let png = minimal_png();
    let resp = do_upload(&app, &token, &png, "image/png").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let uri = body["content_uri"].as_str().expect("content_uri must be present");
    assert!(uri.starts_with("mxc://localhost/"), "got: {uri}");
}

// ---------------------------------------------------------------------------
// Test 2: download_round_trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_round_trip() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);

    let token = register_user(&app, "uploader2").await;
    let data = b"round trip test data";
    let resp = do_upload(&app, &token, data, "application/octet-stream").await;
    let body = json_body(resp).await;
    let uri = body["content_uri"].as_str().unwrap();
    // mxc://localhost/<mediaId>
    let media_id = uri.strip_prefix("mxc://localhost/").unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v1/media/download/localhost/{media_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let got = raw_body(resp).await;
    assert_eq!(got, data);
}

#[tokio::test]
async fn federation_media_download_and_thumbnail_are_multipart_mixed() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state.clone());
    let token = register_user(&app, "fedmedia").await;
    let png = minimal_png();
    let body = upload_ok(&app, &token, &png, "image/png").await;
    let media_id = body["content_uri"]
        .as_str()
        .unwrap()
        .strip_prefix("mxc://localhost/")
        .unwrap()
        .to_owned();

    let download = media_api::federation_download(
        State(state.clone()),
        Path(media_id.clone()),
        Query(HashMap::new()),
    )
    .await;
    assert_eq!(download.status(), StatusCode::OK);
    let content_type = download.headers()[header::CONTENT_TYPE].to_str().unwrap().to_owned();
    assert!(content_type.starts_with("multipart/mixed;"), "{content_type}");
    let bytes = raw_body(download).await;
    let parts = media_api::parse_multipart_mixed(&content_type, &bytes).expect("download multipart");
    assert_eq!(parts.len(), 2, "federation download has a metadata part and a media part");
    assert_eq!(parts[0].header("content-type"), Some("application/json"));
    assert_eq!(parts[0].body, b"{}");
    assert_eq!(parts[1].header("content-type"), Some("image/png"));
    assert!(parts[1].header("content-disposition").is_some());
    assert_eq!(parts[1].body, png);

    let thumbnail = media_api::federation_thumbnail(
        State(state),
        Path(media_id),
        Query(HashMap::from([
            ("width".into(), "8".into()),
            ("height".into(), "8".into()),
            ("method".into(), "scale".into()),
        ])),
    )
    .await;
    assert_eq!(thumbnail.status(), StatusCode::OK);
    let content_type = thumbnail.headers()[header::CONTENT_TYPE].to_str().unwrap().to_owned();
    assert!(content_type.starts_with("multipart/mixed;"), "{content_type}");
    let bytes = raw_body(thumbnail).await;
    let parts = media_api::parse_multipart_mixed(&content_type, &bytes).expect("thumbnail multipart");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].body, b"{}");
    assert!(parts[1].header("content-type").unwrap().starts_with("image/"));
    assert!(parts[1].header("content-disposition").unwrap().starts_with("inline;"));
    assert!(!parts[1].body.is_empty());
}

#[tokio::test]
async fn federation_pending_media_waits_for_timeout_ms() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let now = chrono::Utc::now();
    let pending = conduit::storage::PendingMedia {
        media_id: "pendingMedia1".into(),
        origin_server: "localhost".into(),
        creator: "@alice:localhost".into(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
    };
    assert_eq!(
        state.storage.create_pending_media(&pending, 10).await.unwrap(),
        conduit::storage::PendingMediaCreate::Created
    );

    let started = std::time::Instant::now();
    let download = media_api::federation_download(
        State(state.clone()),
        Path(pending.media_id.clone()),
        Query(HashMap::from([("timeout_ms".into(), "200".into())])),
    )
    .await;
    assert_eq!(download.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(200),
        "federation download must wait timeout_ms, elapsed {:?}",
        started.elapsed()
    );
    let body = json_body(download).await;
    assert_eq!(body["errcode"], "M_NOT_YET_UPLOADED");

    let started = std::time::Instant::now();
    let thumbnail = media_api::federation_thumbnail(
        State(state),
        Path(pending.media_id),
        Query(HashMap::from([
            ("width".into(), "8".into()),
            ("height".into(), "8".into()),
            ("method".into(), "scale".into()),
            ("timeout_ms".into(), "0".into()),
        ])),
    )
    .await;
    assert_eq!(thumbnail.status(), StatusCode::GATEWAY_TIMEOUT);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "timeout_ms=0 must not wait the default"
    );
    let body = json_body(thumbnail).await;
    assert_eq!(body["errcode"], "M_NOT_YET_UPLOADED");
}

// ---------------------------------------------------------------------------
// Test 3: download_with_filename_includes_disposition
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_with_filename_includes_disposition() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);

    let token = register_user(&app, "uploader3").await;
    let png = minimal_png();
    let body = upload_ok(&app, &token, &png, "image/png").await;
    let media_id = body["content_uri"].as_str().unwrap()
        .strip_prefix("mxc://localhost/").unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v1/media/download/localhost/{media_id}/myphoto.png"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let disposition = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        disposition.contains("myphoto.png"),
        "Content-Disposition should contain filename, got: {disposition}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: download_html_forced_attachment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_html_forced_attachment() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);

    let token = register_user(&app, "uploader4").await;
    let html = b"<html><body>xss test</body></html>";
    let resp = do_upload(&app, &token, html, "text/html").await;
    let body = json_body(resp).await;
    let media_id = body["content_uri"].as_str().unwrap()
        .strip_prefix("mxc://localhost/").unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v1/media/download/localhost/{media_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let disposition = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        disposition.starts_with("attachment"),
        "text/html must use attachment disposition, got: {disposition}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: download_unknown_media_404
// ---------------------------------------------------------------------------

#[tokio::test]
async fn download_unknown_media_404() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);
    let token = register_user(&app, "uploader5").await;

    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v1/media/download/localhost/doesnotexist999")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 6: thumbnail_scale_smaller_than_source
// ---------------------------------------------------------------------------

#[tokio::test]
async fn thumbnail_scale_smaller_than_source() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);

    let token = register_user(&app, "uploader6").await;
    // Create a 100x100 PNG.
    let png = make_png(100, 100);
    let resp = do_upload(&app, &token, &png, "image/png").await;
    let body = json_body(resp).await;
    let media_id = body["content_uri"].as_str().unwrap()
        .strip_prefix("mxc://localhost/").unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "/_matrix/client/v1/media/thumbnail/localhost/{media_id}?width=50&height=50&method=scale"
        ))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "thumbnail request failed");
    let thumb_bytes = raw_body(resp).await;
    // Scaled down to exactly the requested size (square source, square box).
    let thumb = image::load_from_memory(&thumb_bytes).unwrap();
    assert_eq!((thumb.width(), thumb.height()), (50, 50));
    // Verify it's a valid PNG.
    assert!(thumb_bytes.starts_with(b"\x89PNG"), "thumbnail must be PNG");
}

// ---------------------------------------------------------------------------
// Test 7: thumbnail_cached_on_second_call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn thumbnail_cached_on_second_call() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state.clone());

    let token = register_user(&app, "uploader7").await;
    let png = make_png(80, 80);
    let body = upload_ok(&app, &token, &png, "image/png").await;
    let media_id = body["content_uri"].as_str().unwrap()
        .strip_prefix("mxc://localhost/").unwrap();

    // First thumbnail request — generates + caches.
    let thumb_uri = format!(
        "/_matrix/client/v1/media/thumbnail/localhost/{media_id}?width=40&height=40&method=scale"
    );
    let resp1 = app.clone().oneshot(
        Request::builder().method("GET").uri(&thumb_uri).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let bytes1 = raw_body(resp1).await;

    // Second request — should come from cache (same bytes).
    let resp2 = app.clone().oneshot(
        Request::builder().method("GET").uri(&thumb_uri).header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let bytes2 = raw_body(resp2).await;

    assert_eq!(bytes1, bytes2, "cached thumbnail must be identical to original");

    // Verify the thumbnail is in the DB.
    let thumb = MediaState::storage(&state)
        .get_thumbnail(media_id, "localhost", 40, 40, "scale")
        .await
        .unwrap();
    assert!(thumb.is_some(), "thumbnail must be cached in DB after second call");
}

// ---------------------------------------------------------------------------
// Test 8: media_config_returns_upload_limit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn media_config_returns_upload_limit() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);

    let token = register_user(&app, "configreader").await;
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/media/v3/config")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let size = body["m.upload.size"].as_u64().expect("m.upload.size must be a number");
    assert!(size > 0, "upload size limit must be positive");
}

// ---------------------------------------------------------------------------
// Test 9: upload_too_large_rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn upload_too_large_rejected() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    // Build state with a tiny upload limit (10 bytes) to avoid env-var races.
    let mut state = make_test_state(&db, &tmp).await;
    state.max_upload_bytes = 10;
    let app = build_router(state);

    let token = register_user(&app, "uploader9").await;
    // Upload 100 bytes — over the 10-byte limit.
    let big_data = vec![0u8; 100];
    let resp = do_upload(&app, &token, &big_data, "application/octet-stream").await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = json_body(resp).await;
    assert_eq!(body["errcode"], "M_TOO_LARGE");
}

// ---------------------------------------------------------------------------
// Test 10: safe_headers_present
// ---------------------------------------------------------------------------

#[tokio::test]
async fn safe_headers_present() {
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let app = build_router(state);

    let token = register_user(&app, "uploader10").await;
    let png = minimal_png();
    let resp = do_upload(&app, &token, &png, "image/png").await;
    let body = json_body(resp).await;
    let media_id = body["content_uri"].as_str().unwrap()
        .strip_prefix("mxc://localhost/").unwrap();

    let req = Request::builder()
        .method("GET")
        .uri(format!("/_matrix/client/v1/media/download/localhost/{media_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let headers = resp.headers();

    let csp = headers
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(csp.contains("sandbox"), "CSP must contain sandbox, got: {csp}");

    let xcto = headers
        .get("x-content-type-options")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(xcto, "nosniff", "X-Content-Type-Options must be nosniff");
}

// ---------------------------------------------------------------------------
// PNG helpers
// ---------------------------------------------------------------------------

/// Minimal valid 1×1 white PNG.
fn minimal_png() -> Vec<u8> {
    // Pre-computed 1x1 white PNG bytes (valid according to the PNG spec).
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR length + type
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, // bit depth, color type, ...
        0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, // IHDR CRC + IDAT length
        0x54, 0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0x3F, // IDAT type + data
        0x00, 0x05, 0xFE, 0x02, 0xFE, 0xA7, 0x35, 0x81, // IDAT data
        0x84, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, // IDAT CRC + IEND length
        0x44, 0xAE, 0x42, 0x60, 0x82,                   // IEND type + CRC
    ]
}

/// Generate an N×N solid-color PNG using the `image` crate.
fn make_png(width: u32, height: u32) -> Vec<u8> {
    use image::{ImageFormat, RgbImage};
    use std::io::Cursor;

    let mut img = RgbImage::new(width, height);
    for pixel in img.pixels_mut() {
        *pixel = image::Rgb([100u8, 149u8, 237u8]); // cornflower blue
    }
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png).unwrap();
    buf
}

// RoomEventSender for the test harness (conduit-29w). Mirrors the AppState impl
// in main.rs: delegate to the generic event pipeline, then wake any /sync waiters.
#[async_trait::async_trait]
impl conduit::room::RoomEventSender for TestState {
    async fn send_event(
        &self,
        sender: &str,
        room_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
    ) -> conduit::Result<String> {
        match conduit_server::api::client::event_pipeline::build_sign_and_persist(
            self, sender, room_id, event_type, state_key, content,
        )
        .await
        {
            Ok(event_id) => {
                let _ = self.events_tx.send(0);
                Ok(event_id)
            }
            Err((_code, err)) => {
                Err(conduit::Error::InvalidEvent(err.0.errcode.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// conduit-aef: remote media over federation (mock origin server)
// ---------------------------------------------------------------------------

/// A mock origin homeserver. `/_matrix/federation/v1/media/download/:id`
/// answers in the spec's multipart/mixed format for `blob`, 404s for
/// `missing`, and serves a body larger than any test limit for `huge`.
async fn spawn_mock_origin(
    hits: Arc<std::sync::atomic::AtomicUsize>,
    png: Vec<u8>,
) -> String {
    use axum::extract::Path as AxPath;
    use axum::response::IntoResponse;
    let app = Router::new().route(
        "/_matrix/federation/v1/media/download/:mediaId",
        get(move |AxPath(media_id): AxPath<String>| {
            let hits = Arc::clone(&hits);
            let png = png.clone();
            async move {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                match media_id.as_str() {
                    "blob" => {
                        let mut body = Vec::new();
                        body.extend_from_slice(b"--fedboundary\r\nContent-Type: application/json\r\n\r\n{}\r\n--fedboundary\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=\"remote cat.png\"\r\n\r\n");
                        body.extend_from_slice(&png);
                        body.extend_from_slice(b"\r\n--fedboundary--\r\n");
                        (
                            StatusCode::OK,
                            [(header::CONTENT_TYPE, "multipart/mixed; boundary=fedboundary")],
                            body,
                        )
                            .into_response()
                    }
                    "huge" => (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/octet-stream")],
                        vec![0u8; 4096],
                    )
                        .into_response(),
                    _ => (
                        StatusCode::NOT_FOUND,
                        axum::Json(json!({"errcode": "M_NOT_FOUND", "error": "nope"})),
                    )
                        .into_response(),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn authed_get(app: &Router, token: &str, uri: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn remote_media_is_fetched_over_federation_cached_and_served() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let png = make_png(64, 32);
    let origin = spawn_mock_origin(Arc::clone(&hits), png.clone()).await;
    let mut state = make_test_state(&db, &tmp).await;
    state.fed_client = Arc::new(
        federation::Client::new(
            reqwest::Client::new(),
            hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap(),
            Arc::new(conduit_server::RemoteKeyCache::new()),
            Arc::clone(&state.server_key),
            Arc::clone(&state.server_name),
        )
        .with_test_base_url(origin),
    );
    state.max_upload_bytes = 1024 * 1024;
    let app = build_router(state.clone());
    let token = register_user(&app, "remotefan").await;

    // First request fetches from the origin (multipart/mixed) and caches.
    let resp = authed_get(&app, &token, "/_matrix/client/v1/media/download/remote.example/blob").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/png");
    assert_eq!(
        resp.headers()[header::CONTENT_DISPOSITION],
        "inline; filename=\"remote cat.png\"",
        "remote filename must be reused"
    );
    assert_eq!(raw_body(resp).await, png);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Second request is served from the local cache.
    let resp = authed_get(&app, &token, "/_matrix/client/v1/media/download/remote.example/blob").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(raw_body(resp).await, png);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "cached media must not be refetched");
    let cached = MediaState::storage(&state).get_media("blob", "remote.example").await.unwrap().unwrap();
    assert_eq!(cached.uploader, None);
    assert_eq!(cached.upload_name.as_deref(), Some("remote cat.png"));

    // Thumbnails of cached remote media come from the cache too.
    let resp = authed_get(&app, &token, "/_matrix/client/v1/media/thumbnail/remote.example/blob?width=16&height=16&method=crop").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Newly cached remote media is frozen on the deprecated endpoint, which
    // also never triggers a fetch for uncached remote media.
    let resp = app.clone().oneshot(
        Request::builder().uri("/_matrix/media/v3/download/remote.example/blob").body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app.clone().oneshot(
        Request::builder().uri("/_matrix/media/v3/download/remote.example/other").body(Body::empty()).unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Remote 404 maps to M_NOT_FOUND.
    let resp = authed_get(&app, &token, "/_matrix/client/v1/media/download/remote.example/missing").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(json_body(resp).await["errcode"], "M_NOT_FOUND");
}

#[tokio::test]
async fn oversized_remote_media_is_502_too_large() {
    use std::sync::atomic::AtomicUsize;
    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let origin = spawn_mock_origin(Arc::new(AtomicUsize::new(0)), make_png(4, 4)).await;
    let mut state = make_test_state(&db, &tmp).await;
    state.fed_client = Arc::new(
        federation::Client::new(
            reqwest::Client::new(),
            hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap(),
            Arc::new(conduit_server::RemoteKeyCache::new()),
            Arc::clone(&state.server_key),
            Arc::clone(&state.server_name),
        )
        .with_test_base_url(origin),
    );
    state.max_upload_bytes = 1000;
    let app = build_router(state.clone());
    let token = register_user(&app, "bigremote").await;
    let resp = authed_get(&app, &token, "/_matrix/client/v1/media/download/remote.example/huge").await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(json_body(resp).await["errcode"], "M_TOO_LARGE");
    assert!(MediaState::storage(&state).get_media("huge", "remote.example").await.unwrap().is_none());
}

/// Remote cache and URL-preview images share a null uploader. Preview images
/// stay while a live preview names them, then follow the same idle window.
/// Deleting media removes thumbnail blobs that nothing else references, and
/// leaves a content-addressed blob that another row still uses.
#[tokio::test]
async fn preview_retention_and_admin_delete_drop_unreferenced_blobs() {
    use std::path::Path;
    use axum::routing::delete;
    use chrono::{Duration as ChronoDuration, Utc};
    use conduit::storage::{MediaMetadata, ThumbnailMetadata, UrlPreview};
    use conduit_server::api::admin as admin_api;
    use conduit_server::api::client::media::{cleanup_preview_media, cleanup_remote_media};

    let db = TempDb::new().await;
    let tmp = TempDir::new().unwrap();
    let state = make_test_state(&db, &tmp).await;
    let storage = Arc::clone(&state.storage);
    let blob = state.blob_store.clone();
    let old = Utc::now() - ChronoDuration::days(40);
    let fresh = Utc::now();

    async fn store(
        storage: &Arc<dyn Storage>,
        blob: &conduit_server::BlobStore,
        id: &str,
        bytes: &[u8],
        purpose: &str,
        uploader: Option<&str>,
        accessed: chrono::DateTime<Utc>,
    ) -> String {
        let (_sha, path, size) = blob.put(bytes).await.unwrap();
        storage
            .insert_media(&MediaMetadata {
                media_id: id.to_owned(),
                origin_server: "localhost".into(),
                uploader: uploader.map(str::to_owned),
                content_type: Some("image/png".into()),
                upload_name: None,
                file_size: size as i64,
                sha256: _sha,
                storage_path: path.clone(),
                uploaded_at: accessed,
                last_accessed: accessed,
            })
            .await
            .unwrap();
        storage.set_media_purpose(id, "localhost", purpose).await.unwrap();
        path
    }

    let remote_bytes = b"remote-cache-bytes-9f3a".as_slice();
    let remote_path = store(&storage, &blob, "remote1", remote_bytes, "remote", None, old).await;
    let (_sha, thumb_path, thumb_size) = blob.put(b"remote-thumb-bytes-9f3a").await.unwrap();
    storage
        .insert_thumbnail(&ThumbnailMetadata {
            media_id: "remote1".into(),
            origin_server: "localhost".into(),
            width: 8,
            height: 8,
            method: "scale".into(),
            content_type: "image/png".into(),
            file_size: thumb_size as i64,
            storage_path: thumb_path.clone(),
        })
        .await
        .unwrap();
    let kept_preview = store(&storage, &blob, "previewkeep", b"preview-kept", "preview", None, old).await;
    let dropped_preview = store(&storage, &blob, "previewdrop", b"preview-dropped", "preview", None, old).await;
    let _fresh_preview = store(&storage, &blob, "previewfresh", b"preview-fresh", "preview", None, fresh).await;
    let upload_path = store(&storage, &blob, "userupload", b"user-upload", "upload", Some("@alice:localhost"), old).await;
    storage
        .insert_url_preview(&UrlPreview {
            url: "https://example.org/kept".into(),
            fetched_at: fresh,
            expires_at: fresh + ChronoDuration::hours(2),
            og: json!({ "og:image": "mxc://localhost/previewkeep" }),
        })
        .await
        .unwrap();

    let removed = cleanup_remote_media(storage.as_ref(), &blob, std::time::Duration::from_secs(30 * 24 * 3600))
        .await
        .unwrap();
    assert_eq!(removed, 1, "only the stale remote cache row is swept");
    assert!(storage.get_media("remote1", "localhost").await.unwrap().is_none());
    assert!(!tmp.path().join(&remote_path).exists(), "remote blob removed");
    assert!(!tmp.path().join(&thumb_path).exists(), "thumbnail blob removed with its media");
    for id in ["previewkeep", "previewdrop", "previewfresh", "userupload"] {
        assert!(storage.get_media(id, "localhost").await.unwrap().is_some(), "{id} must survive the remote sweep");
    }
    assert!(tmp.path().join(&kept_preview).exists());
    assert!(tmp.path().join(&dropped_preview).exists());

    let removed = cleanup_preview_media(storage.as_ref(), &blob, std::time::Duration::from_secs(30 * 24 * 3600))
        .await
        .unwrap();
    assert_eq!(removed, 1, "only the idle unreferenced preview is removed");
    assert!(storage.get_media("previewdrop", "localhost").await.unwrap().is_none());
    assert!(!tmp.path().join(&dropped_preview).exists());
    assert!(storage.get_media("previewkeep", "localhost").await.unwrap().is_some());
    assert!(storage.get_media("previewfresh", "localhost").await.unwrap().is_some());
    assert!(tmp.path().join(&upload_path).exists());

    sqlx::query("UPDATE url_previews SET expires_at = $1")
        .bind(old)
        .execute(&db.pool)
        .await
        .unwrap();
    let removed = cleanup_preview_media(storage.as_ref(), &blob, std::time::Duration::from_secs(30 * 24 * 3600))
        .await
        .unwrap();
    assert_eq!(removed, 1);
    assert!(storage.get_media("previewkeep", "localhost").await.unwrap().is_none());
    assert!(!Path::new(&tmp.path().join(&kept_preview)).exists());
    assert!(storage.get_media("previewfresh", "localhost").await.unwrap().is_some(), "a recent preview image waits out the idle window");
    assert!(storage.get_media("userupload", "localhost").await.unwrap().is_some());

    // Admin delete of a duplicated upload removes the row and its thumbnail
    // blob, and removes the content-addressed original only when the other
    // copy is gone too.
    let app = build_router(state.clone()).merge(
        Router::new()
            .route(
                "/_matrix/conduit/admin/v1/media/:mediaId",
                delete(admin_api::delete_media::<TestState>),
            )
            .with_state(state.clone()),
    );
    let body = json!({ "username": "admin", "password": "testpass123", "auth": { "type": "m.login.dummy" } });
    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/_matrix/client/v3/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap(),
    ).await.unwrap();
    let registered = json_body(resp).await;
    let token = registered["access_token"].as_str().unwrap().to_owned();
    let user_id = registered["user_id"].as_str().unwrap().to_owned();
    storage.set_admin(&user_id, true).await.unwrap();

    let png = make_png(40, 20);
    let first: Value = upload_ok(&app, &token, &png, "image/png").await;
    let second: Value = upload_ok(&app, &token, &png, "image/png").await;
    let mut unique_png = Vec::new();
    image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(40, 20, image::Rgb([200, 30, 30])))
        .write_to(&mut std::io::Cursor::new(&mut unique_png), image::ImageFormat::Png)
        .unwrap();
    let unique: Value = upload_ok(&app, &token, &unique_png, "image/png").await;
    let id_of = |v: &Value| v["content_uri"].as_str().unwrap().rsplit('/').next().unwrap().to_owned();
    let first_id = id_of(&first);
    let second_id = id_of(&second);
    let unique_id = id_of(&unique);
    for id in [&first_id, &second_id, &unique_id] {
        let resp = authed_get(&app, &token, &format!("/_matrix/client/v1/media/thumbnail/localhost/{id}?width=8&height=8")).await;
        assert_eq!(resp.status(), StatusCode::OK, "{id}");
        let _ = raw_body(resp).await;
    }
    let paths = |id: &str| {
        let pool = db.pool.clone();
        let id = id.to_owned();
        async move {
            let original: String = sqlx::query_scalar("SELECT storage_path FROM media WHERE media_id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .unwrap();
            let thumbs: Vec<String> = sqlx::query_scalar("SELECT storage_path FROM media_thumbnails WHERE media_id = $1")
                .bind(&id)
                .fetch_all(&pool)
                .await
                .unwrap();
            (original, thumbs)
        }
    };
    let (shared_blob, first_thumbs) = paths(&first_id).await;
    let (shared_again, _) = paths(&second_id).await;
    let (unique_blob, unique_thumbs) = paths(&unique_id).await;
    assert_eq!(shared_blob, shared_again);
    assert_ne!(unique_blob, shared_blob);
    assert!(!unique_thumbs.is_empty() && !first_thumbs.is_empty());

    let del = |id: &str| {
        let app = app.clone();
        let token = token.clone();
        let id = id.to_owned();
        async move {
            app.oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/_matrix/conduit/admin/v1/media/{id}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        }
    };
    assert_eq!(del(&unique_id).await.status(), StatusCode::OK);
    assert!(storage.get_media(&unique_id, "localhost").await.unwrap().is_none());
    assert!(!tmp.path().join(&unique_blob).exists());
    for thumb in &unique_thumbs {
        assert!(!tmp.path().join(thumb).exists(), "unreferenced thumbnail blob {thumb}");
    }
    assert!(tmp.path().join(&shared_blob).exists(), "the other copy still references the blob");

    assert_eq!(del(&first_id).await.status(), StatusCode::OK);
    assert!(tmp.path().join(&shared_blob).exists());
    for thumb in &first_thumbs {
        assert!(tmp.path().join(thumb).exists(), "second thumbnail still references {thumb}");
    }
    assert_eq!(del(&second_id).await.status(), StatusCode::OK);
    assert!(!tmp.path().join(&shared_blob).exists());
    for thumb in &first_thumbs {
        assert!(!tmp.path().join(thumb).exists(), "thumbnail blob {thumb} outlived both rows");
    }
}
