//! Content repository journeys through the shipped binary and PostgreSQL
//! (Matrix v1.19 "Content repository"): upload/download headers, the
//! unauthenticated-media freeze, asynchronous uploads, thumbnails, config
//! parity, and SSRF-safe URL previews against a local origin server.

mod common;

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Harness helpers
// ---------------------------------------------------------------------------

/// Relaunch the production binary with extra environment.
async fn server_with_env(env: &[(&str, &str)]) -> Server {
    let mut server = Server::new().await;
    server.stop();
    let ready = server.files.path().join("ready-media.json");
    let log = std::fs::File::create(server.files.path().join("server.log")).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_conduit-server"));
    command
        .current_dir(server.files.path())
        .env_remove("CONDUIT_TLS_CA")
        .env("DATABASE_URL", &server.database_url)
        .env("CONDUIT_SERVER_NAME", "production.test")
        .env("CONDUIT_LISTEN_ADDR", "127.0.0.1:0")
        .env("CONDUIT_READY_FILE", &ready)
        .env("CONDUIT_MEDIA_ROOT", server.files.path().join("media"))
        .env("CONDUIT_OIDC_ISSUER", "off")
        .env("CONDUIT_FEDERATION", "0")
        .env_remove("CONDUIT_REMOTE_KEYS_OVERRIDE")
        .env("CONDUIT_AS_REGISTRATIONS_DIR", server.files.path().join("app-services"))
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stderr(log.try_clone().unwrap())
        .stdout(log);
    for (k, v) in env {
        command.env(k, v);
    }
    server.child = Some(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = server.child.as_mut().unwrap().try_wait().unwrap() {
            panic!("production server exited {status}: {}", server.logs());
        }
        if let Some(address) = std::fs::read(&ready)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v["address"].as_str().map(str::to_owned))
        {
            server.base_url = format!("http://{address}");
            if server
                .http
                .get(format!("{}/health", server.base_url))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return server;
            }
        }
        assert!(Instant::now() < deadline, "startup timed out: {}", server.logs());
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn token(server: &Server, name: &str) -> String {
    server.register(name).await["access_token"].as_str().unwrap().to_owned()
}

async fn upload(server: &Server, token: &str, query: &str, content_type: Option<&str>, body: Vec<u8>) -> reqwest::Response {
    let mut req = server
        .http
        .post(format!("{}/_matrix/media/v3/upload{query}", server.base_url))
        .bearer_auth(token)
        .body(body);
    if let Some(ct) = content_type {
        req = req.header("content-type", ct);
    }
    req.send().await.unwrap()
}

async fn upload_ok(server: &Server, token: &str, query: &str, content_type: Option<&str>, body: Vec<u8>) -> String {
    let resp = upload(server, token, query, content_type, body).await;
    assert_eq!(resp.status(), 200, "upload: {}", resp.text().await.unwrap());
    let v: Value = resp.json().await.unwrap();
    v["content_uri"].as_str().unwrap().strip_prefix("mxc://production.test/").unwrap().to_owned()
}

async fn get(server: &Server, path: &str, token: Option<&str>) -> reqwest::Response {
    let mut req = server.http.get(format!("{}{path}", server.base_url));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap()
}

async fn expect_error(resp: reqwest::Response, status: u16, errcode: &str) -> Value {
    let actual = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    assert_eq!(actual, status, "{text}");
    let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"));
    assert_eq!(v["errcode"], errcode, "{text}");
    v
}

fn header(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn png(w: u32, h: u32) -> Vec<u8> {
    let img = image::RgbImage::from_pixel(w, h, image::Rgb([40, 90, 200]));
    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png).unwrap();
    buf
}

fn dims(bytes: &[u8]) -> (u32, u32) {
    image::load_from_memory(bytes).unwrap().into_rgb8().dimensions()
}

const CSP: &str = "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; object-src 'self';";

// ---------------------------------------------------------------------------
// Minimal origin HTTP server for preview tests
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    delay: Duration,
    /// Send the body with chunked transfer encoding (no Content-Length).
    chunked: bool,
}

impl Reply {
    fn ok(content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self { status: 200, headers: vec![("Content-Type".into(), content_type.into())], body: body.into(), ..Default::default() }
    }
    fn redirect(location: &str) -> Self {
        Self { status: 302, headers: vec![("Location".into(), location.into())], ..Default::default() }
    }
}

type Routes = Arc<Mutex<HashMap<String, Reply>>>;

struct Origin {
    port: u16,
    routes: Routes,
    log: Arc<Mutex<Vec<String>>>,
}

impl Origin {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes: Routes = Arc::default();
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        let (r, l) = (Arc::clone(&routes), Arc::clone(&log));
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let (routes, log) = (Arc::clone(&r), Arc::clone(&l));
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&buf);
                    let path = request.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    log.lock().unwrap().push(path.clone());
                    let reply = routes.lock().unwrap().get(&path).cloned().unwrap_or(Reply {
                        status: 404,
                        body: b"not found".to_vec(),
                        ..Default::default()
                    });
                    tokio::time::sleep(reply.delay).await;
                    let mut head = format!("HTTP/1.1 {} X\r\nConnection: close\r\n", reply.status);
                    for (k, v) in &reply.headers {
                        head.push_str(&format!("{k}: {v}\r\n"));
                    }
                    if reply.chunked {
                        head.push_str("Transfer-Encoding: chunked\r\n\r\n");
                        let _ = socket.write_all(head.as_bytes()).await;
                        for part in reply.body.chunks(512) {
                            let _ = socket.write_all(format!("{:x}\r\n", part.len()).as_bytes()).await;
                            let _ = socket.write_all(part).await;
                            let _ = socket.write_all(b"\r\n").await;
                        }
                        let _ = socket.write_all(b"0\r\n\r\n").await;
                    } else {
                        head.push_str(&format!("Content-Length: {}\r\n\r\n", reply.body.len()));
                        let _ = socket.write_all(head.as_bytes()).await;
                        let _ = socket.write_all(&reply.body).await;
                    }
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, routes, log }
    }

    fn route(&self, path: &str, reply: Reply) {
        self.routes.lock().unwrap().insert(path.into(), reply);
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn hits(&self, path: &str) -> usize {
        self.log.lock().unwrap().iter().filter(|p| *p == path).count()
    }

    fn total_hits(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

async fn preview(server: &Server, token: &str, url: &str, ts: Option<i64>) -> reqwest::Response {
    let mut query = vec![("url", url.to_owned())];
    if let Some(ts) = ts {
        query.push(("ts", ts.to_string()));
    }
    server
        .http
        .get(format!("{}/_matrix/client/v1/media/preview_url", server.base_url))
        .query(&query)
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Upload / download semantics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_media_download_headers_follow_spec() {
    let server = Server::new().await;
    let alice = token(&server, "alice").await;

    // filename query parameter + non-inline type => attachment with the exact name.
    let id = upload_ok(&server, &alice, "?filename=War%20and%20Peace.pdf", Some("application/pdf"), b"%PDF-1.4".to_vec()).await;
    let resp = get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}"), Some(&alice)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "content-type"), "application/pdf");
    assert_eq!(header(&resp, "content-disposition"), "attachment; filename=\"War and Peace.pdf\"");
    assert_eq!(header(&resp, "content-security-policy"), CSP);
    assert_eq!(header(&resp, "x-content-type-options"), "nosniff");
    assert_eq!(header(&resp, "cross-origin-resource-policy"), "cross-origin");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), b"%PDF-1.4");

    // Inline-safe type without a filename: inline, and no filename parameter.
    let image = png(4, 4);
    let id = upload_ok(&server, &alice, "", Some("image/png"), image.clone()).await;
    let resp = get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}"), Some(&alice)).await;
    assert_eq!(header(&resp, "content-type"), "image/png");
    assert_eq!(header(&resp, "content-disposition"), "inline");
    // The path filename overrides, reproduced exactly (RFC 8187 for non-ASCII).
    let resp = get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}/caf%C3%A9.png"), Some(&alice)).await;
    assert_eq!(header(&resp, "content-disposition"), "inline; filename*=utf-8''caf%C3%A9.png");

    // HTML and SVG are attachments even though the upload claimed them.
    for ct in ["text/html", "image/svg+xml", "application/javascript"] {
        let id = upload_ok(&server, &alice, "?filename=x", Some(ct), b"<script>alert(1)</script>".to_vec()).await;
        let resp = get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}"), Some(&alice)).await;
        assert_eq!(header(&resp, "content-type"), ct);
        assert_eq!(header(&resp, "content-disposition"), "attachment; filename=\"x\"", "{ct}");
    }

    // Missing Content-Type defaults to application/octet-stream (no sniffing).
    let id = upload_ok(&server, &alice, "", None, image).await;
    let resp = get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}"), Some(&alice)).await;
    assert_eq!(header(&resp, "content-type"), "application/octet-stream");
    assert_eq!(header(&resp, "content-disposition"), "attachment");

    // Authenticated endpoints require a token; unknown/invalid IDs are 404.
    expect_error(get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}"), None).await, 401, "M_MISSING_TOKEN").await;
    expect_error(get(&server, "/_matrix/client/v1/media/download/production.test/doesNotExist", Some(&alice)).await, 404, "M_NOT_FOUND").await;
    expect_error(get(&server, "/_matrix/client/v1/media/download/production.test/bad.id", Some(&alice)).await, 404, "M_NOT_FOUND").await;
    expect_error(get(&server, "/_matrix/client/v1/media/download/bad%20server/abc", Some(&alice)).await, 400, "M_INVALID_PARAM").await;
    // Uploads require a token.
    let resp = server.http.post(format!("{}/_matrix/media/v3/upload", server.base_url)).body("x").send().await.unwrap();
    expect_error(resp, 401, "M_MISSING_TOKEN").await;
}

#[tokio::test]
async fn production_media_config_parity_and_upload_limit() {
    // Above axum's 2 MiB default body limit, to prove the handler owns the limit.
    let server = server_with_env(&[("CONDUIT_MEDIA_MAX_UPLOAD_BYTES", "3000000")]).await;
    let alice = token(&server, "alice").await;
    let v1 = server.request(Method::GET, "/_matrix/client/v1/media/config", Some(&alice), None, 200).await;
    let v3 = server.request(Method::GET, "/_matrix/media/v3/config", Some(&alice), None, 200).await;
    assert_eq!(v1, json!({"m.upload.size": 3000000}));
    assert_eq!(v1, v3, "v1 and v3 config must agree");
    server.request(Method::GET, "/_matrix/client/v1/media/config", None, None, 401).await;
    server.request(Method::GET, "/_matrix/media/v3/config", None, None, 401).await;

    let id = upload_ok(&server, &alice, "", Some("application/octet-stream"), vec![7u8; 2_500_000]).await;
    let resp = get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}"), Some(&alice)).await;
    assert_eq!(resp.bytes().await.unwrap().len(), 2_500_000);
    let resp = upload(&server, &alice, "", Some("application/octet-stream"), vec![0u8; 3_000_001]).await;
    expect_error(resp, 413, "M_TOO_LARGE").await;
}

#[tokio::test]
async fn production_media_unauthenticated_endpoints_are_frozen() {
    let server = Server::new().await;
    let alice = token(&server, "alice").await;
    let image = png(64, 64);
    let id = upload_ok(&server, &alice, "?filename=a.png", Some("image/png"), image.clone()).await;

    // Newly uploaded media: deprecated endpoints 404, authenticated ones work.
    for path in [
        format!("/_matrix/media/v3/download/production.test/{id}"),
        format!("/_matrix/media/v3/download/production.test/{id}/a.png"),
        format!("/_matrix/media/v3/thumbnail/production.test/{id}?width=32&height=32"),
    ] {
        expect_error(get(&server, &path, None).await, 404, "M_NOT_FOUND").await;
    }
    let resp = get(&server, &format!("/_matrix/client/v1/media/thumbnail/production.test/{id}?width=32&height=32"), Some(&alice)).await;
    assert_eq!(resp.status(), 200);

    // Media stored before the freeze stays reachable without authentication.
    let output = Command::new("psql")
        .args([
            "--no-psqlrc", &server.database_url, "-v", "ON_ERROR_STOP=1", "-c",
            &format!("UPDATE media SET unauthenticated_access = true WHERE media_id = '{id}'"),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let resp = get(&server, &format!("/_matrix/media/v3/download/production.test/{id}?allow_redirect=true&allow_remote=false"), None).await;
    assert_eq!(resp.status(), 200, "allow_redirect=true still returns the content itself");
    assert_eq!(header(&resp, "content-disposition"), "inline; filename=\"a.png\"");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), image.as_slice());
}

#[tokio::test]
async fn production_media_freeze_can_be_disabled() {
    let server = server_with_env(&[("CONDUIT_MEDIA_FREEZE_UNAUTHENTICATED", "0")]).await;
    let alice = token(&server, "alice").await;
    let id = upload_ok(&server, &alice, "", Some("text/plain"), b"hello".to_vec()).await;
    let resp = get(&server, &format!("/_matrix/media/v3/download/production.test/{id}"), None).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "hello");
}

#[tokio::test]
async fn production_media_remote_is_not_found_when_federation_disabled() {
    let server = Server::new().await; // harness runs with CONDUIT_FEDERATION=0
    let alice = token(&server, "alice").await;
    let started = Instant::now();
    expect_error(get(&server, "/_matrix/client/v1/media/download/matrix.org/abcDEF123", Some(&alice)).await, 404, "M_NOT_FOUND").await;
    expect_error(get(&server, "/_matrix/client/v1/media/thumbnail/matrix.org/abcDEF123?width=32&height=32", Some(&alice)).await, 404, "M_NOT_FOUND").await;
    assert!(started.elapsed() < Duration::from_secs(2), "must not attempt a federation fetch");
}

// ---------------------------------------------------------------------------
// Asynchronous uploads
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_media_async_upload_lifecycle() {
    let server = Server::new().await;
    let alice = token(&server, "alice").await;
    let bob = token(&server, "bob").await;

    let before = chrono::Utc::now().timestamp_millis();
    let created = server.request(Method::POST, "/_matrix/media/v1/create", Some(&alice), Some(json!({})), 200).await;
    let uri = created["content_uri"].as_str().unwrap();
    let id = uri.strip_prefix("mxc://production.test/").unwrap().to_owned();
    assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    let expires = created["unused_expires_at"].as_i64().unwrap();
    let day = 24 * 60 * 60 * 1000;
    assert!(expires >= before + day - 5_000 && expires <= chrono::Utc::now().timestamp_millis() + day + 5_000);
    server.request(Method::POST, "/_matrix/media/v1/create", None, Some(json!({})), 401).await;

    // Not yet uploaded: waits for timeout_ms, then 504 M_NOT_YET_UPLOADED.
    let started = Instant::now();
    let path = format!("/_matrix/client/v1/media/download/production.test/{id}");
    expect_error(get(&server, &format!("{path}?timeout_ms=400"), Some(&alice)).await, 504, "M_NOT_YET_UPLOADED").await;
    assert!(started.elapsed() >= Duration::from_millis(400));
    expect_error(
        get(&server, &format!("/_matrix/client/v1/media/thumbnail/production.test/{id}?width=8&height=8&timeout_ms=0"), Some(&alice)).await,
        504,
        "M_NOT_YET_UPLOADED",
    )
    .await;

    // Only the creator may upload.
    let put = |tok: String, body: Vec<u8>, query: &'static str| {
        let req = server
            .http
            .put(format!("{}/_matrix/media/v3/upload/production.test/{id}{query}", server.base_url))
            .bearer_auth(tok)
            .header("content-type", "text/plain")
            .body(body);
        async move { req.send().await.unwrap() }
    };
    expect_error(put(bob.clone(), b"mallory".to_vec(), "").await, 403, "M_FORBIDDEN").await;

    // A waiting download completes as soon as the content arrives.
    let waiter = {
        let http = server.http.clone();
        let url = format!("{}{path}?timeout_ms=4000", server.base_url);
        let alice = alice.clone();
        tokio::spawn(async move { http.get(url).bearer_auth(alice).send().await.unwrap() })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let resp = put(alice.clone(), b"async hello".to_vec(), "?filename=hello.txt").await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap(), json!({}));
    let waited = waiter.await.unwrap();
    assert_eq!(waited.status(), 200);
    assert_eq!(header(&waited, "content-disposition"), "inline; filename=\"hello.txt\"");
    assert_eq!(waited.text().await.unwrap(), "async hello");

    // The content cannot be overwritten, by anyone.
    expect_error(put(alice.clone(), b"again".to_vec(), "").await, 409, "M_CANNOT_OVERWRITE_MEDIA").await;
    expect_error(put(bob.clone(), b"again".to_vec(), "").await, 409, "M_CANNOT_OVERWRITE_MEDIA").await;

    // Unknown IDs and foreign server names are 404.
    let resp = server
        .http
        .put(format!("{}/_matrix/media/v3/upload/production.test/neverCreated", server.base_url))
        .bearer_auth(&alice)
        .body("x")
        .send()
        .await
        .unwrap();
    expect_error(resp, 404, "M_NOT_FOUND").await;
    let resp = server
        .http
        .put(format!("{}/_matrix/media/v3/upload/elsewhere.example/{id}", server.base_url))
        .bearer_auth(&alice)
        .body("x")
        .send()
        .await
        .unwrap();
    expect_error(resp, 404, "M_NOT_FOUND").await;
}

#[tokio::test]
async fn production_media_pending_limit_and_expiry() {
    let server = server_with_env(&[
        ("CONDUIT_MEDIA_MAX_PENDING_UPLOADS", "2"),
        ("CONDUIT_MEDIA_UNUSED_EXPIRATION_MS", "1500"),
        ("CONDUIT_MEDIA_MAX_UPLOAD_BYTES", "16"),
    ])
    .await;
    let alice = token(&server, "alice").await;
    let bob = token(&server, "bob").await;
    let first = server.request(Method::POST, "/_matrix/media/v1/create", Some(&alice), Some(json!({})), 200).await;
    server.request(Method::POST, "/_matrix/media/v1/create", Some(&alice), Some(json!({})), 200).await;
    let limited = server.request(Method::POST, "/_matrix/media/v1/create", Some(&alice), Some(json!({})), 429).await;
    assert_eq!(limited["errcode"], "M_LIMIT_EXCEEDED");
    let retry = limited["retry_after_ms"].as_i64().unwrap();
    assert!(retry > 0 && retry <= 1500, "retry_after_ms {retry}");
    // The quota is per user.
    server.request(Method::POST, "/_matrix/media/v1/create", Some(&bob), Some(json!({})), 200).await;

    // An oversized async upload is 413 and leaves the reservation usable.
    let id = first["content_uri"].as_str().unwrap().rsplit('/').next().unwrap().to_owned();
    let resp = server
        .http
        .put(format!("{}/_matrix/media/v3/upload/production.test/{id}", server.base_url))
        .bearer_auth(&alice)
        .body(vec![1u8; 17])
        .send()
        .await
        .unwrap();
    expect_error(resp, 413, "M_TOO_LARGE").await;

    tokio::time::sleep(Duration::from_millis(1700)).await;
    // Expired reservations no longer count, cannot be uploaded to, and 404.
    server.request(Method::POST, "/_matrix/media/v1/create", Some(&alice), Some(json!({})), 200).await;
    let resp = server
        .http
        .put(format!("{}/_matrix/media/v3/upload/production.test/{id}", server.base_url))
        .bearer_auth(&alice)
        .body("late")
        .send()
        .await
        .unwrap();
    expect_error(resp, 404, "M_NOT_FOUND").await;
    expect_error(
        get(&server, &format!("/_matrix/client/v1/media/download/production.test/{id}?timeout_ms=0"), Some(&alice)).await,
        404,
        "M_NOT_FOUND",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Thumbnails
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_media_thumbnails() {
    let server = server_with_env(&[("CONDUIT_MEDIA_MAX_THUMBNAIL_PIXELS", "1000000")]).await;
    let alice = token(&server, "alice").await;
    let id = upload_ok(&server, &alice, "", Some("image/png"), png(400, 200)).await;
    let base = format!("/_matrix/client/v1/media/thumbnail/production.test/{id}");

    expect_error(get(&server, &format!("{base}?height=32"), Some(&alice)).await, 400, "M_MISSING_PARAM").await;
    expect_error(get(&server, &format!("{base}?width=abc&height=32"), Some(&alice)).await, 400, "M_INVALID_PARAM").await;
    expect_error(get(&server, &format!("{base}?width=-5&height=32"), Some(&alice)).await, 400, "M_INVALID_PARAM").await;
    expect_error(get(&server, &format!("{base}?width=32&height=32&method=zoom"), Some(&alice)).await, 400, "M_INVALID_PARAM").await;
    expect_error(get(&server, &format!("{base}?width=32&height=32&animated=maybe"), Some(&alice)).await, 400, "M_INVALID_PARAM").await;
    expect_error(get(&server, &format!("{base}?width=32&height=32"), None).await, 401, "M_MISSING_TOKEN").await;

    // scale: aspect preserved, never smaller than requested.
    let resp = get(&server, &format!("{base}?width=100&height=100&method=scale"), Some(&alice)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "content-type"), "image/png");
    assert_eq!(header(&resp, "content-disposition"), "inline; filename=\"thumbnail.png\"");
    assert_eq!(header(&resp, "content-security-policy"), CSP);
    assert_eq!(dims(&resp.bytes().await.unwrap()), (200, 100));
    // crop: exactly the requested size.
    let resp = get(&server, &format!("{base}?width=32&height=32&method=crop&animated=false"), Some(&alice)).await;
    assert_eq!(dims(&resp.bytes().await.unwrap()), (32, 32));
    // Larger than the content: the original, never upscaled.
    let resp = get(&server, &format!("{base}?width=800&height=600"), Some(&alice)).await;
    assert_eq!(dims(&resp.bytes().await.unwrap()), (400, 200));

    // Not an image: 400 M_UNKNOWN. Too many pixels: 413 M_TOO_LARGE.
    let doc = upload_ok(&server, &alice, "", Some("application/pdf"), b"%PDF-1.4 nope".to_vec()).await;
    expect_error(
        get(&server, &format!("/_matrix/client/v1/media/thumbnail/production.test/{doc}?width=32&height=32"), Some(&alice)).await,
        400,
        "M_UNKNOWN",
    )
    .await;
    let huge = upload_ok(&server, &alice, "", Some("image/png"), png(1100, 1000)).await;
    expect_error(
        get(&server, &format!("/_matrix/client/v1/media/thumbnail/production.test/{huge}?width=32&height=32"), Some(&alice)).await,
        413,
        "M_TOO_LARGE",
    )
    .await;
}

// ---------------------------------------------------------------------------
// URL previews
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_media_preview_url_refuses_internal_destinations() {
    let origin = Origin::start().await;
    origin.route("/", Reply::ok("text/html", "<title>internal secret</title>"));
    let server = Server::new().await;
    let alice = token(&server, "alice").await;
    let port = origin.port;
    for url in [
        format!("http://127.0.0.1:{port}/"),
        format!("http://localhost:{port}/"),
        format!("http://[::1]:{port}/"),
        format!("http://[::ffff:127.0.0.1]:{port}/"),
        format!("http://[::ffff:7f00:1]:{port}/"),
        format!("http://0.0.0.0:{port}/"),
        format!("http://2130706433:{port}/"),
        format!("http://0x7f.0.0.1:{port}/"),
        "http://169.254.169.254/latest/meta-data/".to_owned(),
        "http://10.0.0.1/".to_owned(),
        "http://172.16.5.4/".to_owned(),
        "http://192.168.1.1/".to_owned(),
        "http://100.64.0.1/".to_owned(),
        "http://224.0.0.1/".to_owned(),
        "http://[fd00::1]/".to_owned(),
        "http://[fe80::1]/".to_owned(),
        "http://[64:ff9b::a9fe:a9fe]/".to_owned(),
    ] {
        let started = Instant::now();
        expect_error(preview(&server, &alice, &url, None).await, 403, "M_FORBIDDEN").await;
        assert!(started.elapsed() < Duration::from_secs(2), "{url} must be refused without connecting");
    }
    assert_eq!(origin.total_hits(), 0, "no request may reach the internal origin");

    expect_error(preview(&server, &alice, "file:///etc/passwd", None).await, 400, "M_INVALID_PARAM").await;
    expect_error(preview(&server, &alice, "not a url", None).await, 400, "M_INVALID_PARAM").await;
    let resp = server
        .http
        .get(format!("{}/_matrix/client/v1/media/preview_url", server.base_url))
        .query(&[("url", "https://example.org/"), ("ts", "yesterday")])
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    expect_error(resp, 400, "M_INVALID_PARAM").await;
    let resp = server.http.get(format!("{}/_matrix/client/v1/media/preview_url", server.base_url)).bearer_auth(&alice).send().await.unwrap();
    expect_error(resp, 400, "M_MISSING_PARAM").await;
    let resp = server
        .http
        .get(format!("{}/_matrix/client/v1/media/preview_url", server.base_url))
        .query(&[("url", "https://example.org/")])
        .send()
        .await
        .unwrap();
    expect_error(resp, 401, "M_MISSING_TOKEN").await;
    // The deprecated path is the same endpoint, also authenticated.
    let resp = server
        .http
        .get(format!("{}/_matrix/media/v3/preview_url", server.base_url))
        .query(&[("url", origin.url("/"))])
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap();
    expect_error(resp, 403, "M_FORBIDDEN").await;
}

#[tokio::test]
async fn production_media_preview_url_opengraph_rehost_cache_and_ts() {
    let origin = Origin::start().await;
    let image = png(48, 24);
    let page = |title: &str| {
        Reply::ok(
            "text/html; charset=utf-8",
            format!(
                r#"<html><head><title>fallback</title>
                <meta property="og:title" content="{title}">
                <meta property="og:description" content="A &amp; B">
                <meta property="og:image" content="/logo.png">
                <meta property="og:image:width" content="999">
                </head><body></body></html>"#
            ),
        )
    };
    origin.route("/page", page("Version one"));
    origin.route("/logo.png", Reply::ok("image/png", image.clone()));
    origin.route("/direct.png", Reply::ok("image/png", image.clone()));
    origin.route("/plain", Reply::ok("application/octet-stream", vec![1, 2, 3]));
    let server = server_with_env(&[
        ("CONDUIT_URL_PREVIEW_IP_ALLOWLIST", "127.0.0.1/32"),
        ("CONDUIT_URL_PREVIEW_CACHE_MS", "800"),
    ])
    .await;
    let alice = token(&server, "alice").await;
    let page_url = origin.url("/page");

    let resp = preview(&server, &alice, &format!("{page_url}#fragment"), None).await;
    assert_eq!(resp.status(), 200);
    let og: Value = resp.json().await.unwrap();
    assert_eq!(og["og:title"], "Version one");
    assert_eq!(og["og:description"], "A & B");
    assert_eq!(og["og:image:type"], "image/png");
    assert_eq!(og["og:image:width"], 48, "dimensions come from the re-hosted image");
    assert_eq!(og["og:image:height"], 24);
    assert_eq!(og["matrix:image:size"], image.len());
    let mxc = og["og:image"].as_str().unwrap();
    let image_id = mxc.strip_prefix("mxc://production.test/").expect("og:image must be re-hosted as mxc");
    let resp = get(&server, &format!("/_matrix/client/v1/media/download/production.test/{image_id}"), Some(&alice)).await;
    assert_eq!(resp.bytes().await.unwrap().as_ref(), image.as_slice());
    let first_fetch_done = chrono::Utc::now().timestamp_millis();

    // Cached: the origin is not contacted again within the cache lifetime.
    origin.route("/page", page("Version two"));
    let og: Value = preview(&server, &alice, &page_url, None).await.json().await.unwrap();
    assert_eq!(og["og:title"], "Version one");
    assert_eq!(origin.hits("/page"), 1);

    // After expiry a fresh preview is generated...
    tokio::time::sleep(Duration::from_millis(900)).await;
    let og: Value = preview(&server, &alice, &page_url, None).await.json().await.unwrap();
    assert_eq!(og["og:title"], "Version two");
    assert_eq!(origin.hits("/page"), 2);
    // ...while ts selects the preview generated at or before that time.
    let og: Value = preview(&server, &alice, &page_url, Some(first_fetch_done)).await.json().await.unwrap();
    assert_eq!(og["og:title"], "Version one");
    // No preview that old: a newer one is acceptable.
    let og: Value = preview(&server, &alice, &page_url, Some(1)).await.json().await.unwrap();
    assert_eq!(og["og:title"], "Version two");
    assert_eq!(origin.hits("/page"), 2);

    // A URL that is itself an image previews as that image.
    let og: Value = preview(&server, &alice, &origin.url("/direct.png"), None).await.json().await.unwrap();
    assert!(og["og:image"].as_str().unwrap().starts_with("mxc://production.test/"));
    assert_eq!(og["matrix:image:size"], image.len());
    // Other content types yield an empty object.
    let og: Value = preview(&server, &alice, &origin.url("/plain"), None).await.json().await.unwrap();
    assert_eq!(og, json!({}));
    // Upstream errors are 502.
    expect_error(preview(&server, &alice, &origin.url("/missing"), None).await, 502, "M_UNKNOWN").await;
}

#[tokio::test]
async fn production_media_preview_url_revalidates_redirects_and_images() {
    let origin = Origin::start().await;
    let port = origin.port;
    origin.route("/to-metadata", Reply::redirect("http://169.254.169.254/latest/meta-data/"));
    origin.route("/to-v6-loopback", Reply::redirect(&format!("http://[::1]:{port}/page")));
    origin.route("/to-mapped", Reply::redirect(&format!("http://[::ffff:127.0.0.1]:{port}/page")));
    origin.route("/hop", Reply::redirect("/page"));
    origin.route(
        "/page",
        Reply::ok(
            "text/html",
            r#"<meta property="og:title" content="Redirected"><meta property="og:image" content="http://10.1.2.3/secret.png"><meta property="og:image:alt" content="alt">"#,
        ),
    );
    let server = server_with_env(&[("CONDUIT_URL_PREVIEW_IP_ALLOWLIST", "127.0.0.1/32")]).await;
    let alice = token(&server, "alice").await;

    for path in ["/to-metadata", "/to-v6-loopback", "/to-mapped"] {
        expect_error(preview(&server, &alice, &origin.url(path), None).await, 403, "M_FORBIDDEN").await;
    }
    assert_eq!(origin.hits("/page"), 0, "redirect targets outside the allowlist are never contacted");

    // A permitted redirect is followed; an internal og:image is dropped.
    let og: Value = preview(&server, &alice, &origin.url("/hop"), None).await.json().await.unwrap();
    assert_eq!(og["og:title"], "Redirected");
    assert!(og.get("og:image").is_none() && og.get("og:image:alt").is_none(), "{og}");
    assert_eq!(origin.hits("/page"), 1);
}

#[tokio::test]
async fn production_media_preview_url_size_and_time_limits() {
    let origin = Origin::start().await;
    let big = format!("<title>{}</title>", "x".repeat(10_000));
    origin.route("/big", Reply::ok("text/html", big.clone()));
    origin.route("/big-chunked", Reply { chunked: true, ..Reply::ok("text/html", big) });
    origin.route("/slow", Reply { delay: Duration::from_secs(4), ..Reply::ok("text/html", "<title>late</title>") });
    let server = server_with_env(&[
        ("CONDUIT_URL_PREVIEW_IP_ALLOWLIST", "127.0.0.1/32"),
        ("CONDUIT_URL_PREVIEW_MAX_BYTES", "2048"),
        ("CONDUIT_URL_PREVIEW_TIMEOUT_MS", "700"),
    ])
    .await;
    let alice = token(&server, "alice").await;
    expect_error(preview(&server, &alice, &origin.url("/big"), None).await, 502, "M_TOO_LARGE").await;
    expect_error(preview(&server, &alice, &origin.url("/big-chunked"), None).await, 502, "M_TOO_LARGE").await;
    let started = Instant::now();
    expect_error(preview(&server, &alice, &origin.url("/slow"), None).await, 504, "M_UNKNOWN").await;
    assert!(started.elapsed() < Duration::from_millis(2500), "deadline enforced: {:?}", started.elapsed());
}
