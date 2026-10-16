//! Notary key query through the shipped binary: this server signs documents it
//! fetches for other servers, and a failed direct key fetch is retried through
//! a trusted notary.

mod common;

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use common::production::Server;
use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
use reqwest::Method;
use serde_json::{json, Value};

use conduit::keys::{generate_server_key, public_bytes, ServerKey};
use conduit_server::federation::auth::sign_request;

const LOCAL: &str = "production.test";

fn sign_unsigned(unsigned: &Value, key: &ServerKey, server_name: &str) -> Value {
    let bytes = conduit::canonical_json::to_canonical_bytes(unsigned).unwrap();
    let signature = key.signing_key.sign(&bytes);
    let mut document = unsigned.clone();
    document["signatures"] = json!({
        server_name: { key.key_id.clone(): STANDARD_NO_PAD.encode(signature.to_bytes()) }
    });
    document
}

fn key_document(server_name: &str, key: &ServerKey, valid_until_ts: i64) -> Value {
    let unsigned = json!({
        "server_name": server_name,
        "verify_keys": { key.key_id.clone(): { "key": STANDARD_NO_PAD.encode(public_bytes(key)) } },
        "old_verify_keys": {},
        "valid_until_ts": valid_until_ts,
    });
    sign_unsigned(&unsigned, key, server_name)
}

fn add_signature(mut document: Value, key: &ServerKey, server_name: &str) -> Value {
    let mut unsigned = document.clone();
    unsigned.as_object_mut().unwrap().remove("signatures");
    unsigned.as_object_mut().unwrap().remove("unsigned");
    let bytes = conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap();
    let signature = key.signing_key.sign(&bytes);
    document["signatures"][server_name][&key.key_id] = json!(STANDARD_NO_PAD.encode(signature.to_bytes()));
    document
}

/// Recompute the signing bytes in this test and check `server_name`'s signature
/// with the public key published at `GET /_matrix/key/v2/server` (or carried in
/// the document when the signer is the origin under test).
fn assert_signature(document: &Value, server_name: &str, verify_key_b64: &str, key_id: &str) {
    let signature_b64 = document["signatures"][server_name][key_id]
        .as_str()
        .unwrap_or_else(|| panic!("{server_name} did not sign with {key_id}: {document}"));
    let mut unsigned = document.clone();
    unsigned.as_object_mut().unwrap().remove("signatures");
    unsigned.as_object_mut().unwrap().remove("unsigned");
    let bytes = conduit::canonical_json::to_canonical_bytes(&unsigned).unwrap();
    let public = STANDARD_NO_PAD.decode(verify_key_b64).unwrap();
    let signature = STANDARD_NO_PAD.decode(signature_b64).unwrap();
    let verifying = VerifyingKey::from_bytes(public.as_slice().try_into().unwrap()).unwrap();
    let signature = Signature::from_bytes(signature.as_slice().try_into().unwrap());
    verifying
        .verify_strict(&bytes, &signature)
        .unwrap_or_else(|error| panic!("{server_name} signature did not verify: {error}; {document}"));
}

#[derive(Clone)]
struct OriginState {
    document: Value,
    hits: Arc<AtomicU32>,
    fail: Arc<AtomicBool>,
}

async fn origin_handler(State(state): State<OriginState>, request: Request<axum::body::Body>) -> impl IntoResponse {
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !host.starts_with("remote.test") || state.fail.load(Ordering::SeqCst) {
        return (StatusCode::INTERNAL_SERVER_ERROR, "down").into_response();
    }
    state.hits.fetch_add(1, Ordering::SeqCst);
    axum::Json(state.document).into_response()
}

async fn spawn_origin(document: Value) -> (String, Arc<AtomicU32>, Arc<AtomicBool>) {
    let hits = Arc::new(AtomicU32::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    let state = OriginState {
        document,
        hits: Arc::clone(&hits),
        fail: Arc::clone(&fail),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().fallback(origin_handler).with_state(state);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    (format!("http://{address}"), hits, fail)
}

#[derive(Clone)]
struct NotaryMock {
    notary_document: Value,
    queried: Value,
    hits: Arc<std::sync::Mutex<Vec<String>>>,
}

async fn notary_handler(State(state): State<NotaryMock>, request: Request<axum::body::Body>) -> impl IntoResponse {
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or("").to_owned();
    state.hits.lock().unwrap().push(format!("{path}?{query}"));
    if path == "/_matrix/key/v2/server" && query.contains("server_name=notary.test") {
        return axum::Json(state.notary_document).into_response();
    }
    if path.starts_with("/_matrix/key/v2/query/") {
        return axum::Json(json!({ "server_keys": [state.queried.clone()] })).into_response();
    }
    (StatusCode::INTERNAL_SERVER_ERROR, "direct fetch failed").into_response()
}

async fn spawn_notary_mock(notary_document: Value, queried: Value) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    let hits = Arc::new(std::sync::Mutex::new(Vec::new()));
    let state = NotaryMock {
        notary_document,
        queried,
        hits: Arc::clone(&hits),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new().fallback(notary_handler).with_state(state);
    tokio::spawn(async move { axum::serve(listener, app).await.ok() });
    (format!("http://{address}"), hits)
}

async fn json_status(server: &Server, method: Method, path: &str, body: Option<Value>) -> (u16, Value) {
    let mut request = server.http.request(method, format!("{}{path}", server.base_url));
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    let value = serde_json::from_str(&text).unwrap_or(Value::Null);
    assert!(
        status == 200 || status == 400 || status == 401,
        "{path}: {status} {text}; log {}",
        server.logs()
    );
    (status, value)
}

#[tokio::test]
async fn notary_signs_remote_keys_and_fetches_through_a_notary() {
    let remote_key = generate_server_key();
    let valid_until = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let origin = key_document("remote.test", &remote_key, valid_until);
    let origin_key_id = remote_key.key_id.clone();
    let origin_public = origin["verify_keys"][&origin_key_id]["key"].as_str().unwrap().to_owned();
    let (origin_url, hits, fail) = spawn_origin(origin).await;

    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", &origin_url),
    ])
    .await;
    let published = server.request(Method::GET, "/_matrix/key/v2/server", None, None, 200).await;
    let local_key_id = published["verify_keys"].as_object().unwrap().keys().next().unwrap().clone();
    let local_public = published["verify_keys"][&local_key_id]["key"].as_str().unwrap().to_owned();

    let (status, queried) = json_status(&server, Method::GET, "/_matrix/key/v2/query/remote.test", None).await;
    assert_eq!(status, 200, "unauthenticated notary query: {queried}");
    let document = &queried["server_keys"][0];
    assert_eq!(document["server_name"], "remote.test");
    assert_signature(document, "remote.test", &origin_public, &origin_key_id);
    assert_signature(document, LOCAL, &local_public, &local_key_id);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the origin is fetched once");

    let (status, again) = json_status(&server, Method::GET, "/_matrix/key/v2/query/remote.test", None).await;
    assert_eq!(status, 200);
    assert_signature(&again["server_keys"][0], LOCAL, &local_public, &local_key_id);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a fresh cache entry is not refetched");

    let future = valid_until + 86_400_000;
    let (status, refreshed) = json_status(
        &server,
        Method::GET,
        &format!("/_matrix/key/v2/query/remote.test?minimum_valid_until_ts={future}"),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_signature(&refreshed["server_keys"][0], LOCAL, &local_public, &local_key_id);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "minimum_valid_until_ts beyond the cached key refetches");

    fail.store(true, Ordering::SeqCst);
    let (status, stale) = json_status(
        &server,
        Method::GET,
        &format!("/_matrix/key/v2/query/remote.test?minimum_valid_until_ts={}", future + 1),
        None,
    )
    .await;
    assert_eq!(status, 200, "{stale}");
    assert_eq!(stale["server_keys"][0]["server_name"], "remote.test");
    assert_signature(&stale["server_keys"][0], LOCAL, &local_public, &local_key_id);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "a failed refetch keeps the last document");

    let (status, missing) = json_status(&server, Method::GET, "/_matrix/key/v2/query/down.test", None).await;
    assert_eq!(status, 200, "{missing}");
    assert_eq!(missing["server_keys"].as_array().unwrap().len(), 0);

    let (status, empty) = json_status(&server, Method::POST, "/_matrix/key/v2/query", Some(json!({"server_keys": {}}))).await;
    assert_eq!(status, 200, "{empty}");
    assert_eq!(empty["server_keys"].as_array().unwrap().len(), 0);

    let (status, batch) = json_status(
        &server,
        Method::POST,
        "/_matrix/key/v2/query",
        Some(json!({ "server_keys": { "down.test": {}, "remote.test": {} } })),
    )
    .await;
    assert_eq!(status, 200, "{batch}");
    let names: Vec<_> = batch["server_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|doc| doc["server_name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, vec!["remote.test".to_owned()]);
    assert_signature(&batch["server_keys"][0], LOCAL, &local_public, &local_key_id);

    // Outbound: direct fetch of signer.test fails. A notary signature is required.
    let notary_key = generate_server_key();
    let signer_key = Arc::new(generate_server_key());
    let notary_doc = key_document("notary.test", &notary_key, valid_until);
    let signer_doc = key_document("signer.test", &signer_key, valid_until);
    let mut forged = signer_doc.clone();
    forged["signatures"]["notary.test"][&notary_key.key_id] = json!(STANDARD_NO_PAD.encode([9u8; 64]));
    let (bad_url, bad_hits) = spawn_notary_mock(notary_doc.clone(), forged).await;
    let bad = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &bad_url),
        ("CONDUIT_TRUSTED_KEY_SERVERS", "notary.test"),
    ])
    .await;
    let path = "/_matrix/federation/v1/publicRooms";
    let auth = sign_request::<Value>("GET", path, "signer.test", LOCAL, None, &signer_key);
    let response = bad
        .http
        .get(format!("{}{path}", bad.base_url))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    assert_eq!(status, 401, "a notary document without a valid notary signature is rejected: {text}; {}", bad.logs());
    let seen = bad_hits.lock().unwrap().clone();
    assert!(
        seen.iter().any(|hit| hit.contains("/_matrix/key/v2/query/signer.test")),
        "direct failure must query the notary: {seen:?}"
    );

    let signed = add_signature(signer_doc, &notary_key, "notary.test");
    let (good_url, good_hits) = spawn_notary_mock(notary_doc, signed).await;
    let good = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_REMOTE_KEYS_OVERRIDE", &good_url),
        ("CONDUIT_TRUSTED_KEY_SERVERS", "notary.test"),
    ])
    .await;
    let auth = sign_request::<Value>("GET", path, "signer.test", LOCAL, None, &signer_key);
    let response = good
        .http
        .get(format!("{}{path}", good.base_url))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    assert_eq!(status, 200, "notary-signed keys authenticate the caller: {text}; {}", good.logs());
    let seen = good_hits.lock().unwrap().clone();
    assert!(
        seen.iter().any(|hit| hit.contains("/_matrix/key/v2/query/signer.test")),
        "the notary query is the path that supplied the key: {seen:?}"
    );
}
