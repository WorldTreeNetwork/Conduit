//! Client-Server API standards and room-membership basics through the
//! shipped binary and real PostgreSQL (conduit-y99.28, conduit-y99.29).

mod common;

use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

struct User {
    id: String,
    token: String,
}

async fn user(server: &Server, name: &str) -> User {
    let registered = server.register(name).await;
    User {
        id: registered["user_id"].as_str().unwrap().to_owned(),
        token: registered["access_token"].as_str().unwrap().to_owned(),
    }
}

fn encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Raw request returning status, headers and parsed JSON body.
async fn raw(
    server: &Server,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (u16, reqwest::header::HeaderMap, Value) {
    let mut request = server.http.request(method, format!("{}{path}", server.base_url));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let text = response.text().await.unwrap();
    let value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{path}: non-JSON body ({e}): {text:?}"));
    (status, headers, value)
}

// ---------------------------------------------------------------------------
// conduit-y99.28: API standards and discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn versions_advertise_v1_19_and_unstable_features() {
    let server = Server::new().await;
    let versions = server
        .request(Method::GET, "/_matrix/client/versions", None, None, 200)
        .await;
    let list: Vec<&str> = versions["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(list.contains(&"v1.19"), "{versions}");
    assert!(list.contains(&"v1.11"), "{versions}");
    assert!(list.iter().all(|v| v.starts_with("v1.")), "{versions}");
    assert!(versions["unstable_features"].is_object(), "{versions}");
    // Authentication is optional; an authenticated call answers the same.
    let alice = user(&server, "alice").await;
    let authed = server
        .request(Method::GET, "/_matrix/client/versions", Some(&alice.token), None, 200)
        .await;
    assert_eq!(authed["versions"], versions["versions"]);
}

#[tokio::test]
async fn unknown_endpoints_and_methods_answer_m_unrecognized() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;

    let (status, _, body) =
        raw(&server, Method::GET, "/_matrix/client/v3/definitely_not_an_endpoint", None, None).await;
    assert_eq!(status, 404);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED");

    let (status, _, body) = raw(
        &server,
        Method::GET,
        "/_matrix/client/v3/definitely_not_an_endpoint",
        Some(&alice.token),
        None,
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED");

    // Known endpoint, wrong method.
    let (status, headers, body) =
        raw(&server, Method::DELETE, "/_matrix/client/v3/sync", Some(&alice.token), None).await;
    assert_eq!(status, 405);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED");
    assert!(headers.get("allow").is_some(), "405 keeps the Allow header");

    let (status, _, body) = raw(
        &server,
        Method::PUT,
        "/_matrix/client/v3/createRoom",
        Some(&alice.token),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 405);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED");

    // Handler-produced 404s keep their own errcode.
    let (status, _, body) = raw(
        &server,
        Method::GET,
        &format!("/_matrix/client/v3/user/{}/account_data/org.example.absent", encode(&alice.id)),
        Some(&alice.token),
        None,
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}

#[tokio::test]
async fn auth_metadata_reports_oauth_unsupported() {
    let server = Server::new().await;
    let (status, _, body) =
        raw(&server, Method::GET, "/_matrix/client/v1/auth_metadata", None, None).await;
    assert_eq!(status, 404);
    assert_eq!(body["errcode"], "M_UNRECOGNIZED");
    // The legacy API is advertised instead.
    let flows = server
        .request(Method::GET, "/_matrix/client/v3/login", None, None, 200)
        .await;
    assert!(flows["flows"].as_array().is_some_and(|f| !f.is_empty()));
}

#[tokio::test]
async fn capabilities_advertise_only_supported_room_versions() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let caps = server
        .request(Method::GET, "/_matrix/client/v3/capabilities", Some(&alice.token), None, 200)
        .await;
    let versions = &caps["capabilities"]["m.room_versions"];
    assert_eq!(versions["default"], "11");
    assert_eq!(versions["available"], json!({"11": "stable"}));
    // Every advertised version can actually be created.
    for version in versions["available"].as_object().unwrap().keys() {
        server
            .request(
                Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(&alice.token),
                Some(json!({"room_version": version})),
                200,
            )
            .await;
    }
    let (status, _, body) = raw(
        &server,
        Method::POST,
        "/_matrix/client/v3/createRoom",
        Some(&alice.token),
        Some(json!({"room_version": "10"})),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["errcode"], "M_UNSUPPORTED_ROOM_VERSION");
}

#[tokio::test]
async fn server_managed_account_data_is_rejected_with_405() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(&alice.token),
            Some(json!({})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let user_path = encode(&alice.id);
    for kind in ["m.fully_read", "m.push_rules"] {
        let global = format!("/_matrix/client/v3/user/{user_path}/account_data/{kind}");
        let (status, _, body) =
            raw(&server, Method::PUT, &global, Some(&alice.token), Some(json!({"event_id": "$x"}))).await;
        assert_eq!(status, 405, "{kind}: {body}");
        assert_eq!(body["errcode"], "M_BAD_JSON");

        let scoped = format!(
            "/_matrix/client/v3/user/{user_path}/rooms/{}/account_data/{kind}",
            encode(&room)
        );
        let (status, _, body) =
            raw(&server, Method::PUT, &scoped, Some(&alice.token), Some(json!({"event_id": "$x"}))).await;
        assert_eq!(status, 405, "{kind}: {body}");
        assert_eq!(body["errcode"], "M_BAD_JSON");
    }
    // Ordinary types are unaffected.
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/user/{user_path}/account_data/org.example.theme"),
            Some(&alice.token),
            Some(json!({"dark": true})),
            200,
        )
        .await;
}

#[tokio::test]
async fn rate_limited_responses_carry_retry_after() {
    let server = Server::new().await;
    // Unauthenticated callers share a per-IP bucket of burst 20.
    let mut limited = None;
    for _ in 0..60 {
        let response = server
            .http
            .get(format!("{}/_matrix/client/v3/login", server.base_url))
            .send()
            .await
            .unwrap();
        if response.status().as_u16() == 429 {
            limited = Some(response);
            break;
        }
    }
    let response = limited.expect("anonymous burst must be rate limited");
    let retry_after: u64 = response.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry_after >= 1);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["errcode"], "M_LIMIT_EXCEEDED");
}
