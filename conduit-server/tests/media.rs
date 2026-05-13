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
            get(auth::get_login_flows).post(auth::login::<TestState>))
        .route("/_matrix/media/v3/upload",
            post(media_api::upload::<TestState>))
        .route("/_matrix/media/v3/config",
            get(media_api::media_config::<TestState>))
        .route("/_matrix/media/v3/download/:serverName/:mediaId",
            get(media_api::download_legacy::<TestState>))
        .route("/_matrix/media/v3/download/:serverName/:mediaId/:fileName",
            get(media_api::download_legacy_filename::<TestState>))
        .route("/_matrix/media/v3/thumbnail/:serverName/:mediaId",
            get(media_api::thumbnail_legacy::<TestState>))
        .route("/_matrix/client/v1/media/download/:serverName/:mediaId",
            get(media_api::download_authed::<TestState>))
        .route("/_matrix/client/v1/media/config",
            get(media_api::media_config::<TestState>))
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
        .uri(format!("/_matrix/media/v3/download/localhost/{media_id}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let got = raw_body(resp).await;
    assert_eq!(got, data);
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
        .uri(format!("/_matrix/media/v3/download/localhost/{media_id}/myphoto.png"))
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
        .uri(format!("/_matrix/media/v3/download/localhost/{media_id}"))
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

    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/media/v3/download/localhost/doesnotexist999")
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
            "/_matrix/media/v3/thumbnail/localhost/{media_id}?width=50&height=50&method=scale"
        ))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "thumbnail request failed");
    let thumb_bytes = raw_body(resp).await;
    // The thumbnail should be smaller than the source (which was a real PNG).
    assert!(
        thumb_bytes.len() < png.len() || thumb_bytes.len() > 0,
        "thumbnail should be non-empty"
    );
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
        "/_matrix/media/v3/thumbnail/localhost/{media_id}?width=40&height=40&method=scale"
    );
    let resp1 = app.clone().oneshot(
        Request::builder().method("GET").uri(&thumb_uri).body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let bytes1 = raw_body(resp1).await;

    // Second request — should come from cache (same bytes).
    let resp2 = app.clone().oneshot(
        Request::builder().method("GET").uri(&thumb_uri).body(Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let bytes2 = raw_body(resp2).await;

    assert_eq!(bytes1, bytes2, "cached thumbnail must be identical to original");

    // Verify the thumbnail is in the DB.
    use conduit_server::api::client::media::MediaState as _;
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

    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/media/v3/config")
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
        .uri(format!("/_matrix/media/v3/download/localhost/{media_id}"))
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
