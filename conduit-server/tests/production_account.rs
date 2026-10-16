//! Account & device management journeys (conduit-y99.18) through the
//! shipped binary and real PostgreSQL.  Every test owns its process,
//! database, port, logs and media directory.

mod common;

use std::time::Duration;

use axum::extract::State;
use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};
use tokio::sync::mpsc;

const PASSWORD: &str = "test-password";

fn token(v: &Value) -> &str {
    v["access_token"].as_str().unwrap()
}

async fn login(server: &Server, user: &str, password: &str, extra: Value) -> Value {
    let mut body = json!({
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": user},
        "password": password,
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    server
        .request(Method::POST, "/_matrix/client/v3/login", None, Some(body), 200)
        .await
}

fn password_auth(user: &str, password: &str, session: &Value) -> Value {
    json!({
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": user},
        "password": password,
        "session": session,
    })
}

async fn devices(server: &Server, access: &str) -> Vec<Value> {
    server
        .request(Method::GET, "/_matrix/client/v3/devices", Some(access), None, 200)
        .await["devices"]
        .as_array()
        .unwrap()
        .clone()
}

fn device_ids(list: &[Value]) -> Vec<String> {
    let mut ids: Vec<String> = list
        .iter()
        .map(|d| d["device_id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

async fn set_admin(server: &Server, user_id: &str) {
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    sqlx::query("UPDATE accounts SET is_admin = true WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn raw(
    server: &Server,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> reqwest::Response {
    let mut req = server.http.request(method, format!("{}{path}", server.base_url));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send().await.unwrap()
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_device_lifecycle_with_uia_keys_and_device_lists() {
    let server = Server::new().await;
    let (alice, bob, _room, _event) = server.chat_pair().await;
    let alice_token = token(&alice);
    let bob_token = token(&bob);
    let alice_id = alice["user_id"].as_str().unwrap();

    let phone = login(
        &server,
        "alice",
        PASSWORD,
        json!({"device_id": "PHONE", "initial_device_display_name": "Phone"}),
    )
    .await;
    assert_eq!(phone["device_id"], "PHONE");
    let phone_token = token(&phone);

    // Listing, single lookup, rename.
    let list = devices(&server, alice_token).await;
    let mut want = vec!["PHONE".to_owned(), alice["device_id"].as_str().unwrap().to_owned()];
    want.sort();
    assert_eq!(device_ids(&list), want);
    let got = server
        .request(Method::GET, "/_matrix/client/v3/devices/PHONE", Some(alice_token), None, 200)
        .await;
    assert_eq!(got["display_name"], "Phone");
    let missing = server
        .request(Method::GET, "/_matrix/client/v3/devices/NOPE", Some(alice_token), None, 404)
        .await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND");
    server
        .request(
            Method::PUT,
            "/_matrix/client/v3/devices/PHONE",
            Some(alice_token),
            Some(json!({"display_name": "Work phone"})),
            200,
        )
        .await;
    // Omitting display_name leaves it unchanged.
    server
        .request(Method::PUT, "/_matrix/client/v3/devices/PHONE", Some(alice_token), Some(json!({})), 200)
        .await;
    let got = server
        .request(Method::GET, "/_matrix/client/v3/devices/PHONE", Some(alice_token), None, 200)
        .await;
    assert_eq!(got["display_name"], "Work phone");
    let missing = server
        .request(
            Method::PUT,
            "/_matrix/client/v3/devices/NOPE",
            Some(alice_token),
            Some(json!({"display_name": "x"})),
            404,
        )
        .await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND");
    // A re-login with a known device ID ignores initial_device_display_name.
    let phone = login(
        &server,
        "alice",
        PASSWORD,
        json!({"device_id": "PHONE", "initial_device_display_name": "Ignored"}),
    )
    .await;
    let old_phone_token = phone_token.to_owned();
    let phone_token = token(&phone);
    let rejected = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(&old_phone_token), None, 401)
        .await;
    assert_eq!(rejected["errcode"], "M_UNKNOWN_TOKEN", "re-login invalidates the device's old token");
    let got = server
        .request(Method::GET, "/_matrix/client/v3/devices/PHONE", Some(alice_token), None, 200)
        .await;
    assert_eq!(got["display_name"], "Work phone");

    // The phone publishes self-signed E2EE keys; bob sees them.
    let phone_keys = common::keys::Device::new(alice_id, "PHONE");
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/upload",
            Some(phone_token),
            Some(json!({
                "device_keys": phone_keys.keys,
                "one_time_keys": {"signed_curve25519:AAAA": phone_keys.signed_key("b3Rr", false)}
            })),
            200,
        )
        .await;
    let query = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(bob_token),
            Some(json!({"device_keys": {alice_id: []}})),
            200,
        )
        .await;
    assert!(query["device_keys"][alice_id]["PHONE"].is_object());
    let bob_sync = server
        .request(Method::GET, "/_matrix/client/v3/sync?timeout=0", Some(bob_token), None, 200)
        .await;
    let since = bob_sync["next_batch"].as_str().unwrap().to_owned();

    // DELETE requires UIA: first a challenge, then a wrong password, then success.
    let challenge = server
        .request(Method::DELETE, "/_matrix/client/v3/devices/PHONE", Some(alice_token), Some(json!({})), 401)
        .await;
    assert_eq!(challenge["flows"], json!([{"stages": ["m.login.password"]}]));
    let session = challenge["session"].clone();
    assert!(session.is_string());
    let wrong = server
        .request(
            Method::DELETE,
            "/_matrix/client/v3/devices/PHONE",
            Some(alice_token),
            Some(json!({"auth": password_auth("alice", "wrong", &session)})),
            401,
        )
        .await;
    assert_eq!(wrong["errcode"], "M_FORBIDDEN");
    assert_eq!(wrong["session"], session);
    // A session cannot be replayed against a different operation.
    let replay = server
        .request(
            Method::POST,
            "/_matrix/client/v3/delete_devices",
            Some(alice_token),
            Some(json!({"devices": ["PHONE"], "auth": password_auth("alice", PASSWORD, &session)})),
            403,
        )
        .await;
    assert_eq!(replay["errcode"], "M_FORBIDDEN");
    // Bob cannot complete Alice's session with his own password.
    let other_user = server
        .request(
            Method::DELETE,
            "/_matrix/client/v3/devices/PHONE",
            Some(alice_token),
            Some(json!({"auth": password_auth("bob", PASSWORD, &session)})),
            401,
        )
        .await;
    assert_eq!(other_user["errcode"], "M_FORBIDDEN");
    server
        .request(
            Method::DELETE,
            "/_matrix/client/v3/devices/PHONE",
            Some(alice_token),
            Some(json!({"auth": password_auth("alice", PASSWORD, &session)})),
            200,
        )
        .await;

    // Token, keys and device are gone; the deletion is a hard logout.
    let gone = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(phone_token), None, 401)
        .await;
    assert_eq!(gone["errcode"], "M_UNKNOWN_TOKEN");
    assert_eq!(gone["soft_logout"], false);
    assert_eq!(device_ids(&devices(&server, alice_token).await).len(), 1);
    let query = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(bob_token),
            Some(json!({"device_keys": {alice_id: []}})),
            200,
        )
        .await;
    assert!(query["device_keys"][alice_id].get("PHONE").is_none());
    let claim = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/claim",
            Some(bob_token),
            Some(json!({"one_time_keys": {alice_id: {"PHONE": "signed_curve25519"}}})),
            200,
        )
        .await;
    assert!(claim["one_time_keys"][alice_id]["PHONE"]
        .as_object()
        .map(|m| m.is_empty())
        .unwrap_or(true));
    let bob_sync = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            Some(bob_token),
            None,
            200,
        )
        .await;
    assert!(bob_sync["device_lists"]["changed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u == alice_id), "{bob_sync}");

    // Deleting an already-deleted device succeeds (after UIA).
    let challenge = server
        .request(Method::DELETE, "/_matrix/client/v3/devices/PHONE", Some(alice_token), None, 401)
        .await;
    server
        .request(
            Method::DELETE,
            "/_matrix/client/v3/devices/PHONE",
            Some(alice_token),
            Some(json!({"auth": password_auth("alice", PASSWORD, &challenge["session"])})),
            200,
        )
        .await;

    // Recreating the device ID never resurrects the old token.
    let again = login(&server, "alice", PASSWORD, json!({"device_id": "PHONE"})).await;
    server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(phone_token), None, 401)
        .await;
    server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&again)), None, 200)
        .await;

    // Bulk deletion.
    let second = login(&server, "alice", PASSWORD, json!({})).await;
    let missing = server
        .request(Method::POST, "/_matrix/client/v3/delete_devices", Some(alice_token), Some(json!({})), 400)
        .await;
    assert_eq!(missing["errcode"], "M_MISSING_PARAM");
    let challenge = server
        .request(
            Method::POST,
            "/_matrix/client/v3/delete_devices",
            Some(alice_token),
            Some(json!({"devices": ["PHONE", second["device_id"]]})),
            401,
        )
        .await;
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/delete_devices",
            Some(alice_token),
            Some(json!({
                "devices": ["PHONE", second["device_id"], "NEVER_EXISTED"],
                "auth": password_auth("@alice:production.test", PASSWORD, &challenge["session"]),
            })),
            200,
        )
        .await;
    assert_eq!(
        device_ids(&devices(&server, alice_token).await),
        vec![alice["device_id"].as_str().unwrap().to_owned()]
    );
    server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&second)), None, 401)
        .await;
}

#[tokio::test]
async fn production_logout_deletes_devices() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let second = login(&server, "alice", PASSWORD, json!({})).await;
    let third = login(&server, "alice", PASSWORD, json!({})).await;

    server
        .request(Method::POST, "/_matrix/client/v3/logout", Some(token(&second)), Some(json!({})), 200)
        .await;
    let ids = device_ids(&devices(&server, token(&alice)).await);
    assert_eq!(ids.len(), 2);
    assert!(!ids.contains(&second["device_id"].as_str().unwrap().to_owned()));

    server
        .request(Method::POST, "/_matrix/client/v3/logout/all", Some(token(&third)), Some(json!({})), 200)
        .await;
    for t in [token(&alice), token(&third)] {
        let r = server
            .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(t), None, 401)
            .await;
        assert_eq!(r["errcode"], "M_UNKNOWN_TOKEN");
    }
    let fresh = login(&server, "alice", PASSWORD, json!({})).await;
    assert_eq!(devices(&server, token(&fresh)).await.len(), 1);
}

#[tokio::test]
async fn production_access_token_query_parameter_is_accepted() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let who = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/account/whoami?access_token={}", token(&alice)),
            None,
            None,
            200,
        )
        .await;
    assert_eq!(who["user_id"], alice["user_id"]);
    let bad = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami?access_token=nope", None, None, 401)
        .await;
    assert_eq!(bad["errcode"], "M_UNKNOWN_TOKEN");
}

// ---------------------------------------------------------------------------
// Password and deactivation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_password_change_revokes_other_devices() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let other = login(&server, "alice", PASSWORD, json!({})).await;

    let caps = server
        .request(Method::GET, "/_matrix/client/v3/capabilities", Some(token(&alice)), None, 200)
        .await;
    assert_eq!(caps["capabilities"]["m.change_password"]["enabled"], true);

    let missing = server
        .request(Method::POST, "/_matrix/client/v3/account/password", Some(token(&alice)), Some(json!({})), 400)
        .await;
    assert_eq!(missing["errcode"], "M_MISSING_PARAM");
    let challenge = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            Some(token(&alice)),
            Some(json!({"new_password": "second-password"})),
            401,
        )
        .await;
    assert_eq!(challenge["flows"], json!([{"stages": ["m.login.password"]}]));
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            Some(token(&alice)),
            Some(json!({
                "new_password": "second-password",
                "auth": password_auth("alice", PASSWORD, &challenge["session"]),
            })),
            200,
        )
        .await;
    // The requesting session survives; the other device is gone.
    server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&alice)), None, 200)
        .await;
    let r = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&other)), None, 401)
        .await;
    assert_eq!(r["errcode"], "M_UNKNOWN_TOKEN");
    assert_eq!(devices(&server, token(&alice)).await.len(), 1);
    let old = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "alice"}, "password": PASSWORD})),
            403,
        )
        .await;
    assert_eq!(old["errcode"], "M_FORBIDDEN");
    let kept = login(&server, "alice", "second-password", json!({})).await;

    // logout_devices: false keeps every session.
    let challenge = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            Some(token(&alice)),
            Some(json!({"new_password": "third-password", "logout_devices": false})),
            401,
        )
        .await;
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            Some(token(&alice)),
            Some(json!({
                "new_password": "third-password",
                "logout_devices": false,
                "auth": password_auth("alice", "second-password", &challenge["session"]),
            })),
            200,
        )
        .await;
    server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&kept)), None, 200)
        .await;

    // Without an access token the password stage identifies the user,
    // and every device is revoked.
    let challenge = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            None,
            Some(json!({"new_password": "fourth-password"})),
            401,
        )
        .await;
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            None,
            Some(json!({
                "new_password": "fourth-password",
                "auth": password_auth("alice", "third-password", &challenge["session"]),
            })),
            200,
        )
        .await;
    for t in [token(&alice), token(&kept)] {
        server
            .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(t), None, 401)
            .await;
    }
    login(&server, "alice", "fourth-password", json!({})).await;
}

#[tokio::test]
async fn production_deactivation_leaves_rooms_and_blocks_login() {
    let server = Server::new().await;
    let (alice, bob, room_id, _) = server.chat_pair().await;
    let alice_id = alice["user_id"].as_str().unwrap();
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/profile/{alice_id}/displayname"),
            Some(token(&alice)),
            Some(json!({"displayname": "Alice"})),
            200,
        )
        .await;

    let challenge = server
        .request(Method::POST, "/_matrix/client/v3/account/deactivate", Some(token(&alice)), Some(json!({})), 401)
        .await;
    assert_eq!(challenge["flows"], json!([{"stages": ["m.login.password"]}]));
    let done = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/deactivate",
            Some(token(&alice)),
            Some(json!({
                "erase": true,
                "auth": password_auth("alice", PASSWORD, &challenge["session"]),
            })),
            200,
        )
        .await;
    assert_eq!(done["id_server_unbind_result"], "success");

    let r = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&alice)), None, 401)
        .await;
    assert_eq!(r["errcode"], "M_UNKNOWN_TOKEN");
    let r = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "alice"}, "password": PASSWORD})),
            403,
        )
        .await;
    assert_eq!(r["errcode"], "M_USER_DEACTIVATED");
    let member = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.member/{alice_id}"),
            Some(token(&bob)),
            None,
            200,
        )
        .await;
    assert_eq!(member["membership"], "leave");
    // The user ID stays taken.
    let r = server
        .request(Method::GET, "/_matrix/client/v3/register/available?username=alice", None, None, 400)
        .await;
    assert_eq!(r["errcode"], "M_USER_IN_USE");
    // Erasure cleared the profile.
    let profile = raw(
        &server,
        Method::GET,
        &format!("/_matrix/client/v3/profile/{alice_id}"),
        &[("authorization", &format!("Bearer {}", token(&bob)))],
    )
    .await;
    let profile: Value = profile.json().await.unwrap_or(Value::Null);
    assert_ne!(profile["displayname"], "Alice", "{profile}");
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_registration_validates_usernames_before_uia() {
    let mut server = Server::new().await;
    server.register("alice").await;

    let ok = server
        .request(Method::GET, "/_matrix/client/v3/register/available?username=carol", None, None, 200)
        .await;
    assert_eq!(ok, json!({"available": true}));
    for (name, code) in [
        ("alice", "M_USER_IN_USE"),
        ("ALICE", "M_USER_IN_USE"),
        ("bad%20name", "M_INVALID_USERNAME"),
        ("12345", "M_INVALID_USERNAME"),
        ("caf%C3%A9", "M_INVALID_USERNAME"),
    ] {
        let r = server
            .request(
                Method::GET,
                &format!("/_matrix/client/v3/register/available?username={name}"),
                None,
                None,
                400,
            )
            .await;
        assert_eq!(r["errcode"], code, "{name}");
    }
    let r = server
        .request(Method::GET, "/_matrix/client/v3/register/available", None, None, 400)
        .await;
    assert_eq!(r["errcode"], "M_MISSING_PARAM");

    // Username errors come before the UIA challenge.
    let r = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "alice", "password": "x"})), 400)
        .await;
    assert_eq!(r["errcode"], "M_USER_IN_USE");
    let r = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "no spaces"})), 400)
        .await;
    assert_eq!(r["errcode"], "M_INVALID_USERNAME");
    let r = server
        .request(Method::POST, "/_matrix/client/v3/register?kind=robot", None, Some(json!({})), 400)
        .await;
    assert_eq!(r["errcode"], "M_INVALID_PARAM");

    // Usernames map to lowercase localparts.
    let challenge = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "Dave"})), 401)
        .await;
    let dave = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "Dave", "password": PASSWORD,
                "auth": {"type": "m.login.dummy", "session": challenge["session"]}})),
            200,
        )
        .await;
    assert_eq!(dave["user_id"], "@dave:production.test");
    assert!(dave["expires_in_ms"].as_i64().unwrap() > 0);
    assert!(dave.get("refresh_token").is_none());

    // No username: the server picks a valid one.
    let challenge = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({})), 401)
        .await;
    let picked = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"auth": {"type": "m.login.dummy", "session": challenge["session"]}})),
            200,
        )
        .await;
    assert!(picked["user_id"].as_str().unwrap().ends_with(":production.test"));

    // inhibit_login returns only the user ID.
    let challenge = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "erin"})), 401)
        .await;
    let erin = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "erin", "password": PASSWORD, "inhibit_login": true,
                "auth": {"type": "m.login.dummy", "session": challenge["session"]}})),
            200,
        )
        .await;
    assert_eq!(erin, json!({"user_id": "@erin:production.test"}));
    login(&server, "erin", PASSWORD, json!({})).await;

    // No registration tokens configured: none is valid.
    let v = server
        .request(
            Method::GET,
            "/_matrix/client/v1/register/m.login.registration_token/validity?token=abc",
            None,
            None,
            200,
        )
        .await;
    assert_eq!(v, json!({"valid": false}));
    // Guests are disabled by default.
    let g = server
        .request(Method::POST, "/_matrix/client/v3/register?kind=guest", None, Some(json!({})), 403)
        .await;
    assert_eq!(g["errcode"], "M_GUEST_ACCESS_FORBIDDEN");

    // An application service's exclusive namespace is M_EXCLUSIVE for
    // everyone else, and registrable by the service itself.
    server.stop();
    let dir = server.files.path().join("app-services");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("bridge.yaml"),
        "id: bridge\nurl: http://127.0.0.1:9\nas_token: as-secret\nhs_token: hs-secret\n\
sender_localpart: bridgebot\nnamespaces:\n  users:\n    - exclusive: true\n      regex: \"@bridge_.*:production.test\"\n  aliases: []\n  rooms: []\n",
    )
    .unwrap();
    server.start().await;
    let r = server
        .request(Method::GET, "/_matrix/client/v3/register/available?username=bridge_x", None, None, 400)
        .await;
    assert_eq!(r["errcode"], "M_EXCLUSIVE");
    let r = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "bridge_x"})), 400)
        .await;
    assert_eq!(r["errcode"], "M_EXCLUSIVE");
    let ghost = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            Some("as-secret"),
            Some(json!({"username": "bridge_x", "type": "m.login.application_service",
                "inhibit_login": true})),
            200,
        )
        .await;
    assert_eq!(ghost["user_id"], "@bridge_x:production.test");
    let r = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            Some("as-secret"),
            Some(json!({"username": "outside", "inhibit_login": true})),
            400,
        )
        .await;
    assert_eq!(r["errcode"], "M_EXCLUSIVE");
}

#[tokio::test]
async fn production_registration_tokens_gate_registration() {
    let server = Server::with_env(&[("CONDUIT_REGISTRATION_TOKENS", "letmein,second")]).await;
    let v = server
        .request(
            Method::GET,
            "/_matrix/client/v1/register/m.login.registration_token/validity?token=letmein",
            None,
            None,
            200,
        )
        .await;
    assert_eq!(v, json!({"valid": true}));
    let v = server
        .request(
            Method::GET,
            "/_matrix/client/v1/register/m.login.registration_token/validity?token=wrong",
            None,
            None,
            200,
        )
        .await;
    assert_eq!(v, json!({"valid": false}));

    let challenge = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "alice"})), 401)
        .await;
    assert_eq!(challenge["flows"], json!([{"stages": ["m.login.registration_token"]}]));
    let session = challenge["session"].clone();
    // Dummy is not an offered stage.
    let r = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "alice", "auth": {"type": "m.login.dummy", "session": session}})),
            401,
        )
        .await;
    assert_eq!(r["errcode"], "M_FORBIDDEN");
    let r = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "alice", "auth": {"type": "m.login.registration_token", "token": "wrong", "session": session}})),
            401,
        )
        .await;
    assert_eq!(r["errcode"], "M_FORBIDDEN");
    assert_eq!(r["session"], session);
    let ok = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "alice", "password": PASSWORD,
                "auth": {"type": "m.login.registration_token", "token": "letmein", "session": session}})),
            200,
        )
        .await;
    assert_eq!(ok["user_id"], "@alice:production.test");

    // The fallback page completes the token stage out of band.
    let challenge = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "bob"})), 401)
        .await;
    let session = challenge["session"].as_str().unwrap().to_owned();
    let page = raw(
        &server,
        Method::GET,
        &format!("/_matrix/client/v3/auth/m.login.registration_token/fallback/web?session={session}"),
        &[],
    )
    .await;
    assert_eq!(page.status(), 200);
    assert!(page.headers()["content-type"].to_str().unwrap().starts_with("text/html"));
    assert!(page.text().await.unwrap().contains("name=\"token\""));
    let done = server
        .http
        .post(format!(
            "{}/_matrix/client/v3/auth/m.login.registration_token/fallback/web",
            server.base_url
        ))
        .form(&[("session", session.as_str()), ("token", "second")])
        .send()
        .await
        .unwrap();
    assert_eq!(done.status(), 200);
    assert!(done.text().await.unwrap().contains("authDone"));
    let bob = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "bob", "password": PASSWORD, "auth": {"session": session}})),
            200,
        )
        .await;
    assert_eq!(bob["user_id"], "@bob:production.test");
}

#[tokio::test]
async fn production_registration_can_be_disabled() {
    let server = Server::with_env(&[("CONDUIT_ALLOW_REGISTRATION", "false")]).await;
    let r = server
        .request(Method::POST, "/_matrix/client/v3/register", None, Some(json!({"username": "alice"})), 403)
        .await;
    assert_eq!(r["errcode"], "M_FORBIDDEN");
    let r = server
        .request(
            Method::GET,
            "/_matrix/client/v1/register/m.login.registration_token/validity?token=x",
            None,
            None,
            403,
        )
        .await;
    assert_eq!(r["errcode"], "M_FORBIDDEN");
    let r = server
        .request(Method::GET, "/_matrix/client/v3/register/available?username=alice", None, None, 403)
        .await;
    assert_eq!(r["errcode"], "M_FORBIDDEN");
}

// ---------------------------------------------------------------------------
// Refresh tokens and soft logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_refresh_tokens_rotate_and_soft_logout() {
    let server = Server::with_env(&[("CONDUIT_REFRESH_TOKEN_ACCESS_LIFETIME_MS", "2000")]).await;
    server.register("alice").await;

    let session = login(&server, "alice", PASSWORD, json!({"refresh_token": true, "device_id": "LAPTOP"})).await;
    assert_eq!(session["expires_in_ms"], 2000);
    let r1 = session["refresh_token"].as_str().unwrap().to_owned();
    let alice_id = session["user_id"].as_str().unwrap().to_owned();
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/upload",
            Some(token(&session)),
            Some(json!({"device_keys": common::keys::Device::new(&alice_id, "LAPTOP").keys})),
            200,
        )
        .await;

    // Expiry is a soft logout.
    tokio::time::sleep(Duration::from_millis(3100)).await;
    let expired = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&session)), None, 401)
        .await;
    assert_eq!(expired["errcode"], "M_UNKNOWN_TOKEN");
    assert_eq!(expired["soft_logout"], true);

    // Refresh: R1 -> (A2, R2).  R1 stays usable until R2 is used.
    let second = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": r1})), 200)
        .await;
    assert_eq!(second["expires_in_ms"], 2000);
    let r2 = second["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(r2, r1);
    let who = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&second)), None, 200)
        .await;
    assert_eq!(who["device_id"], "LAPTOP");
    // The client "lost" R2 and retries with R1: R2 is revoked.
    let third = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": r1})), 200)
        .await;
    let r3 = third["refresh_token"].as_str().unwrap().to_owned();
    let r = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": r2})), 401)
        .await;
    assert_eq!(r["errcode"], "M_UNKNOWN_TOKEN");
    // Using R3 revokes R1.
    let fourth = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": r3})), 200)
        .await;
    let r = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": r1})), 401)
        .await;
    assert_eq!(r["errcode"], "M_UNKNOWN_TOKEN");
    assert_eq!(r["soft_logout"], false);

    let r = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": "nope"})), 401)
        .await;
    assert_eq!(r["errcode"], "M_UNKNOWN_TOKEN");
    let r = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({})), 400)
        .await;
    assert_eq!(r["errcode"], "M_MISSING_PARAM");

    // Soft-logout recovery by re-login with the same device keeps its keys
    // and invalidates the device's previous access and refresh tokens.
    let r4 = fourth["refresh_token"].as_str().unwrap().to_owned();
    let relogin = login(&server, "alice", PASSWORD, json!({"device_id": "LAPTOP", "refresh_token": true})).await;
    assert_eq!(relogin["device_id"], "LAPTOP");
    let r = server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": r4})), 401)
        .await;
    assert_eq!(r["errcode"], "M_UNKNOWN_TOKEN");
    let r = server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&fourth)), None, 401)
        .await;
    assert_eq!(r["soft_logout"], false, "re-login revoked the old session");
    let observer = login(&server, "alice", PASSWORD, json!({})).await;
    let query = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(token(&observer)),
            Some(json!({"device_keys": {alice_id.clone(): ["LAPTOP"]}})),
            200,
        )
        .await;
    assert!(query["device_keys"][&alice_id]["LAPTOP"].is_object());

    // Logout revokes the refresh token too.
    let r5 = relogin["refresh_token"].as_str().unwrap().to_owned();
    server
        .request(Method::POST, "/_matrix/client/v3/logout", Some(token(&relogin)), Some(json!({})), 200)
        .await;
    server
        .request(Method::POST, "/_matrix/client/v3/refresh", None, Some(json!({"refresh_token": r5})), 401)
        .await;

    // Without refresh_token the access token is long-lived and says so.
    let plain = login(&server, "alice", PASSWORD, json!({})).await;
    assert!(plain.get("refresh_token").is_none());
    assert_eq!(plain["expires_in_ms"], 30 * 24 * 60 * 60 * 1000i64);
}

// ---------------------------------------------------------------------------
// Guests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_guest_access_is_restricted_and_upgradable() {
    let server = Server::with_env(&[("CONDUIT_ALLOW_GUEST_ACCESS", "true")]).await;
    let alice = server.register("alice").await;

    let guest = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register?kind=guest",
            None,
            Some(json!({"username": "ignored", "device_id": "IGNORED", "initial_device_display_name": "Guest tablet"})),
            200,
        )
        .await;
    let guest_id = guest["user_id"].as_str().unwrap().to_owned();
    let localpart = guest_id.trim_start_matches('@').split(':').next().unwrap().to_owned();
    assert!(localpart.bytes().all(|b| b.is_ascii_digit()), "{guest_id}");
    assert_ne!(guest["device_id"], "IGNORED");
    let gt = token(&guest).to_owned();

    // Allowed: whoami, devices, capabilities (which reflect the limits).
    server.request(Method::GET, "/_matrix/client/v3/account/whoami", Some(&gt), None, 200).await;
    let list = devices(&server, &gt).await;
    assert_eq!(list[0]["display_name"], "Guest tablet");
    let caps = server.request(Method::GET, "/_matrix/client/v3/capabilities", Some(&gt), None, 200).await;
    assert_eq!(caps["capabilities"]["m.change_password"]["enabled"], false);
    assert_eq!(caps["capabilities"]["m.get_login_token"]["enabled"], false);
    assert_eq!(caps["capabilities"]["m.set_avatar_url"]["enabled"], false);

    // Forbidden: anything outside the guest subset.
    for (method, path, body) in [
        (Method::POST, "/_matrix/client/v3/createRoom".to_owned(), json!({})),
        (Method::POST, "/_matrix/client/v1/login/get_token".to_owned(), json!({})),
        (Method::POST, "/_matrix/client/v3/account/password".to_owned(), json!({"new_password": "x"})),
        (Method::PUT, format!("/_matrix/client/v3/profile/{guest_id}/avatar_url"), json!({"avatar_url": "mxc://x/y"})),
    ] {
        let r = server.request(method, &path, Some(&gt), Some(body), 403).await;
        assert_eq!(r["errcode"], "M_GUEST_ACCESS_FORBIDDEN", "{path}");
    }

    // Joining needs m.room.guest_access = can_join.
    let room = server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token(&alice)), Some(json!({"preset": "public_chat"})), 200)
        .await;
    let room_id = room["room_id"].as_str().unwrap().to_owned();
    let r = server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{room_id}"), Some(&gt), Some(json!({})), 403)
        .await;
    assert_eq!(r["errcode"], "M_GUEST_ACCESS_FORBIDDEN");
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room_id}/state/m.room.guest_access"),
            Some(token(&alice)),
            Some(json!({"guest_access": "can_join"})),
            200,
        )
        .await;
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{room_id}"), Some(&gt), Some(json!({})), 200)
        .await;
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/g1"),
            Some(&gt),
            Some(json!({"msgtype": "m.text", "body": "hello from a guest"})),
            200,
        )
        .await;
    server.request(Method::GET, "/_matrix/client/v3/sync?timeout=0", Some(&gt), None, 200).await;

    // Upgrade keeps the user ID and lifts the restrictions.
    let r = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": "someoneelse", "guest_access_token": gt, "password": PASSWORD})),
            400,
        )
        .await;
    assert_eq!(r["errcode"], "M_INVALID_USERNAME");
    let challenge = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": localpart, "guest_access_token": gt, "password": PASSWORD})),
            401,
        )
        .await;
    let upgraded = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({"username": localpart, "guest_access_token": gt, "password": PASSWORD,
                "auth": {"type": "m.login.dummy", "session": challenge["session"]}})),
            200,
        )
        .await;
    assert_eq!(upgraded["user_id"], guest_id);
    server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token(&upgraded)), Some(json!({})), 200)
        .await;
    login(&server, &localpart, PASSWORD, json!({})).await;
}

// ---------------------------------------------------------------------------
// Login tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_get_login_token_reprompts_and_logs_in_once() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let flows = server.request(Method::GET, "/_matrix/client/v3/login", None, None, 200).await;
    assert!(flows["flows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["type"] == "m.login.token" && f["get_login_token"] == true));
    let caps = server
        .request(Method::GET, "/_matrix/client/v3/capabilities", Some(token(&alice)), None, 200)
        .await;
    assert_eq!(caps["capabilities"]["m.get_login_token"]["enabled"], true);

    for _ in 0..2 {
        // Every call re-prompts.
        let challenge = server
            .request(Method::POST, "/_matrix/client/v1/login/get_token", Some(token(&alice)), Some(json!({})), 401)
            .await;
        let issued = server
            .request(
                Method::POST,
                "/_matrix/client/v1/login/get_token",
                Some(token(&alice)),
                Some(json!({"auth": password_auth("alice", PASSWORD, &challenge["session"])})),
                200,
            )
            .await;
        assert_eq!(issued["expires_in_ms"], 120000);
        let login_token = issued["login_token"].as_str().unwrap();
        let session = server
            .request(
                Method::POST,
                "/_matrix/client/v3/login",
                None,
                Some(json!({"type": "m.login.token", "token": login_token, "device_id": "QR",
                    "initial_device_display_name": "Scanned"})),
                200,
            )
            .await;
        assert_eq!(session["user_id"], alice["user_id"]);
        assert_eq!(session["device_id"], "QR");
        let reuse = server
            .request(
                Method::POST,
                "/_matrix/client/v3/login",
                None,
                Some(json!({"type": "m.login.token", "token": login_token})),
                403,
            )
            .await;
        assert_eq!(reuse["errcode"], "M_FORBIDDEN");
    }
}

// ---------------------------------------------------------------------------
// Discovery, whois, 3PIDs, fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn production_well_known_defaults_and_cors() {
    let server = Server::new().await;
    let resp = raw(
        &server,
        Method::GET,
        "/.well-known/matrix/client",
        &[("origin", "https://app.example.org")],
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["m.homeserver"]["base_url"], server.base_url.as_str());
    assert!(body.get("m.identity_server").is_none());
    let r = server.request(Method::GET, "/.well-known/matrix/server", None, None, 404).await;
    assert_eq!(r["errcode"], "M_NOT_FOUND");
    server.request(Method::GET, "/.well-known/matrix/support", None, None, 404).await;

    // A local admin becomes the default support contact.
    let alice = server.register("alice").await;
    set_admin(&server, alice["user_id"].as_str().unwrap()).await;
    let support = server.request(Method::GET, "/.well-known/matrix/support", None, None, 200).await;
    assert_eq!(
        support["contacts"],
        json!([{"matrix_id": "@alice:production.test", "role": "m.role.admin"}])
    );
}

#[tokio::test]
async fn production_well_known_configured() {
    let server = Server::with_env(&[
        ("CONDUIT_WELL_KNOWN_CLIENT_BASE_URL", "https://matrix.example.org"),
        ("CONDUIT_WELL_KNOWN_IDENTITY_SERVER", "https://id.example.org"),
        ("CONDUIT_WELL_KNOWN_SERVER", "matrix.example.org:443"),
        ("CONDUIT_SUPPORT_PAGE", "https://example.org/help"),
        (
            "CONDUIT_SUPPORT_CONTACTS",
            r#"[{"email_address":"security@example.org","role":"m.role.security"}]"#,
        ),
    ])
    .await;
    let client = server.request(Method::GET, "/.well-known/matrix/client", None, None, 200).await;
    assert_eq!(
        client,
        json!({
            "m.homeserver": {"base_url": "https://matrix.example.org"},
            "m.identity_server": {"base_url": "https://id.example.org"},
        })
    );
    let s = server.request(Method::GET, "/.well-known/matrix/server", None, None, 200).await;
    assert_eq!(s, json!({"m.server": "matrix.example.org:443"}));
    let support = server.request(Method::GET, "/.well-known/matrix/support", None, None, 200).await;
    assert_eq!(
        support,
        json!({
            "contacts": [{"email_address": "security@example.org", "role": "m.role.security"}],
            "support_page": "https://example.org/help",
        })
    );
}

#[tokio::test]
async fn production_whois_reports_sessions_to_self_and_admins() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let alice_id = alice["user_id"].as_str().unwrap();

    // The first authenticated request records last-seen data.
    let r = raw(
        &server,
        Method::GET,
        "/_matrix/client/v3/account/whoami",
        &[("authorization", &format!("Bearer {}", token(&alice))), ("user-agent", "conduit-account-test/1.0")],
    )
    .await;
    assert_eq!(r.status(), 200);
    let mut whois = Value::Null;
    for _ in 0..50 {
        whois = server
            .request(Method::GET, &format!("/_matrix/client/v3/admin/whois/{alice_id}"), Some(token(&alice)), None, 200)
            .await;
        if !whois["devices"][alice["device_id"].as_str().unwrap()]["sessions"][0]["connections"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(whois["user_id"], alice_id);
    let conn = &whois["devices"][alice["device_id"].as_str().unwrap()]["sessions"][0]["connections"][0];
    assert_eq!(conn["ip"], "127.0.0.1");
    assert_eq!(conn["user_agent"], "conduit-account-test/1.0");
    assert!(conn["last_seen"].as_i64().unwrap() > 0);
    let list = devices(&server, token(&alice)).await;
    assert_eq!(list[0]["last_seen_ip"], "127.0.0.1");
    assert!(list[0]["last_seen_ts"].as_i64().is_some());

    let r = server
        .request(Method::GET, &format!("/_matrix/client/v3/admin/whois/{alice_id}"), Some(token(&bob)), None, 403)
        .await;
    assert_eq!(r["errcode"], "M_FORBIDDEN");
    set_admin(&server, bob["user_id"].as_str().unwrap()).await;
    server
        .request(Method::GET, &format!("/_matrix/client/v3/admin/whois/{alice_id}"), Some(token(&bob)), None, 200)
        .await;
    let r = server
        .request(Method::GET, "/_matrix/client/v3/admin/whois/@nobody:production.test", Some(token(&bob)), None, 404)
        .await;
    assert_eq!(r["errcode"], "M_NOT_FOUND");
}

#[tokio::test]
async fn production_threepid_endpoints_answer_honestly() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let t = token(&alice);
    let caps = server.request(Method::GET, "/_matrix/client/v3/capabilities", Some(t), None, 200).await;
    assert_eq!(caps["capabilities"]["m.3pid_changes"]["enabled"], false);

    let list = server.request(Method::GET, "/_matrix/client/v3/account/3pid", Some(t), None, 200).await;
    assert_eq!(list, json!({"threepids": []}));
    // Binding goes through an identity server (conduit-y99.36): it needs
    // id_server and id_access_token.
    let r = server
        .request(Method::POST, "/_matrix/client/v3/account/3pid/bind", Some(t), Some(json!({"client_secret": "s", "sid": "1"})), 400)
        .await;
    assert_eq!(r["errcode"], "M_MISSING_PARAM");
    for path in ["/_matrix/client/v3/account/3pid/add", "/_matrix/client/v3/account/3pid"] {
        let r = server
            .request(Method::POST, path, Some(t), Some(json!({"client_secret": "s", "sid": "1"})), 403)
            .await;
        assert_eq!(r["errcode"], "M_FORBIDDEN", "{path}");
    }
    for path in ["/_matrix/client/v3/account/3pid/delete", "/_matrix/client/v3/account/3pid/unbind"] {
        let r = server
            .request(Method::POST, path, Some(t), Some(json!({"medium": "email", "address": "a@b.c"})), 200)
            .await;
        assert_eq!(r, json!({"id_server_unbind_result": "no-support"}), "{path}");
        let r = server.request(Method::POST, path, Some(t), Some(json!({"medium": "email"})), 400).await;
        assert_eq!(r["errcode"], "M_MISSING_PARAM");
    }
    for path in [
        "/_matrix/client/v3/register/email/requestToken",
        "/_matrix/client/v3/register/msisdn/requestToken",
        "/_matrix/client/v3/account/password/email/requestToken",
        "/_matrix/client/v3/account/3pid/msisdn/requestToken",
    ] {
        let r = server
            .request(Method::POST, path, None, Some(json!({"client_secret": "s", "email": "a@b.c", "send_attempt": 1})), 403)
            .await;
        assert_eq!(r["errcode"], "M_THREEPID_DENIED", "{path}");
    }
    server.request(Method::GET, "/_matrix/client/v3/account/3pid", None, None, 401).await;
}

async fn token_sink() -> (String, mpsc::UnboundedReceiver<Value>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::post(
                    |State(tx): State<mpsc::UnboundedSender<Value>>, axum::Json(body): axum::Json<Value>| async move {
                        let _ = tx.send(body);
                        axum::http::StatusCode::OK
                    },
                ),
            )
            .with_state(tx);
        axum::serve(listener, app).await.ok();
    });
    (url, rx)
}

async fn delivered(rx: &mut mpsc::UnboundedReceiver<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("validation sink timed out")
        .expect("validation sink closed")
}

async fn nothing_delivered(rx: &mut mpsc::UnboundedReceiver<Value>) {
    let arrived = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
    assert!(arrived.is_err(), "sink received a token that should not have been sent: {arrived:?}");
}

async fn submit_token(server: &Server, submit_url: &str, sid: &str, secret: &str, token: &str) -> (u16, Value) {
    let response = server
        .http
        .post(submit_url)
        .json(&json!({"sid": sid, "client_secret": secret, "token": token}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(json!({"raw": text})))
}

fn addresses(list: &Value) -> Vec<(String, String)> {
    list["threepids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["medium"].as_str().unwrap().to_owned(),
                row["address"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[tokio::test]
async fn homeserver_validated_threepids_require_the_delivered_token() {
    let (sink, mut rx) = token_sink().await;
    let server = Server::with_env(&[("CONDUIT_THREEPID_SINK", &sink)]).await;
    let alice = server.register("alice").await;
    let alice_token = token(&alice);
    let caps = server
        .request(Method::GET, "/_matrix/client/v3/capabilities", Some(alice_token), None, 200)
        .await;
    assert_eq!(caps["capabilities"]["m.3pid_changes"]["enabled"], true);

    // Adding an email: a repeated send_attempt does not send again, a
    // wrong token does not validate, and only the sink's token does.
    let secret = "add-email-secret";
    let requested = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/email/requestToken",
            None,
            Some(json!({"client_secret": secret, "email": "Alice@Example.com", "send_attempt": 1})),
            200,
        )
        .await;
    let sid = requested["sid"].as_str().unwrap().to_owned();
    let submit_url = requested["submit_url"].as_str().unwrap().to_owned();
    assert!(submit_url.starts_with(&server.base_url), "{submit_url}");
    assert!(submit_url.ends_with("/_matrix/client/v3/validate/email/submitToken"), "{submit_url}");
    let first = delivered(&mut rx).await;
    assert_eq!(first["address"], "alice@example.com");
    assert_eq!(first["sid"], sid);
    assert_eq!(first["purpose"], "add");
    let token1 = first["token"].as_str().unwrap().to_owned();
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/email/requestToken",
            None,
            Some(json!({"client_secret": secret, "email": "alice@example.com", "send_attempt": 1})),
            200,
        )
        .await;
    nothing_delivered(&mut rx).await;

    let (status, body) = submit_token(&server, &submit_url, &sid, secret, "WRONG-TOKEN-DISTINCTIVE").await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errcode"], "M_INVALID_PARAM");
    let rejected = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/add",
            Some(alice_token),
            Some(json!({
                "sid": sid,
                "client_secret": secret,
                "auth": password_auth("alice", PASSWORD, &Value::Null),
            })),
            403,
        )
        .await;
    assert_eq!(rejected["errcode"], "M_THREEPID_AUTH_FAILED");
    assert_eq!(
        server.request(Method::GET, "/_matrix/client/v3/account/3pid", Some(alice_token), None, 200).await["threepids"],
        json!([])
    );

    let resent = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/email/requestToken",
            None,
            Some(json!({"client_secret": secret, "email": "alice@example.com", "send_attempt": 2})),
            200,
        )
        .await;
    assert_eq!(resent["sid"], sid);
    let second = delivered(&mut rx).await;
    let token2 = second["token"].as_str().unwrap().to_owned();
    assert_ne!(token2, token1);
    let (status, _) = submit_token(&server, &submit_url, &sid, secret, &token1).await;
    assert_eq!(status, 400, "the replaced token must no longer validate");
    let (status, body) = submit_token(&server, &submit_url, &sid, secret, &token2).await;
    assert_eq!((status, body["success"].as_bool()), (200, Some(true)));

    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/add",
            Some(alice_token),
            Some(json!({
                "sid": sid,
                "client_secret": secret,
                "auth": password_auth("alice", PASSWORD, &Value::Null),
            })),
            200,
        )
        .await;
    let listed = server
        .request(Method::GET, "/_matrix/client/v3/account/3pid", Some(alice_token), None, 200)
        .await;
    assert_eq!(addresses(&listed), vec![("email".into(), "alice@example.com".into())]);
    assert!(listed["threepids"][0]["added_at"].as_i64().unwrap() > 0);
    assert!(listed["threepids"][0]["validated_at"].as_i64().unwrap() > 0);

    let bob = server.register("bob").await;
    let in_use = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/email/requestToken",
            Some(token(&bob)),
            Some(json!({"client_secret": "bob-secret", "email": "alice@example.com", "send_attempt": 1})),
            400,
        )
        .await;
    assert_eq!(in_use["errcode"], "M_THREEPID_IN_USE");
    nothing_delivered(&mut rx).await;

    // Deprecated POST /account/3pid accepts the same homeserver session.
    let legacy_secret = "legacy-email-secret";
    let legacy = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/email/requestToken",
            None,
            Some(json!({"client_secret": legacy_secret, "email": "legacy@example.com", "send_attempt": 1})),
            200,
        )
        .await;
    let legacy_mail = delivered(&mut rx).await;
    let (status, _) = submit_token(
        &server,
        legacy["submit_url"].as_str().unwrap(),
        legacy["sid"].as_str().unwrap(),
        legacy_secret,
        "WRONG-TOKEN-DISTINCTIVE",
    )
    .await;
    assert_eq!(status, 400);
    let failed = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid",
            Some(alice_token),
            Some(json!({"three_pid_creds": {"sid": legacy["sid"], "client_secret": legacy_secret}})),
            403,
        )
        .await;
    assert_eq!(failed["errcode"], "M_THREEPID_AUTH_FAILED");
    let (status, _) = submit_token(
        &server,
        legacy["submit_url"].as_str().unwrap(),
        legacy["sid"].as_str().unwrap(),
        legacy_secret,
        legacy_mail["token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid",
            Some(alice_token),
            Some(json!({"three_pid_creds": {"sid": legacy["sid"], "client_secret": legacy_secret}})),
            200,
        )
        .await;

    // Password reset proves the email only after the delivered token is submitted.
    let unknown = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password/email/requestToken",
            None,
            Some(json!({"client_secret": "pw-missing", "email": "nobody@example.com", "send_attempt": 1})),
            400,
        )
        .await;
    assert_eq!(unknown["errcode"], "M_THREEPID_NOT_FOUND");
    nothing_delivered(&mut rx).await;
    let pw_secret = "pw-email-secret";
    let pw = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password/email/requestToken",
            None,
            Some(json!({"client_secret": pw_secret, "email": "alice@example.com", "send_attempt": 1})),
            200,
        )
        .await;
    let pw_mail = delivered(&mut rx).await;
    let early = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            None,
            Some(json!({
                "new_password": "should-not-stick",
                "logout_devices": false,
                "auth": {"type": "m.login.email.identity", "threepid_creds": {"sid": pw["sid"], "client_secret": pw_secret}},
            })),
            401,
        )
        .await;
    assert_eq!(early["errcode"], "M_FORBIDDEN");
    login(&server, "alice", PASSWORD, json!({})).await;
    let (status, _) = submit_token(
        &server,
        pw["submit_url"].as_str().unwrap(),
        pw["sid"].as_str().unwrap(),
        pw_secret,
        pw_mail["token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            None,
            Some(json!({
                "new_password": "reset-password",
                "logout_devices": false,
                "auth": {"type": "m.login.email.identity", "threepid_creds": {"sid": pw["sid"], "client_secret": pw_secret}},
            })),
            200,
        )
        .await;
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": PASSWORD,
            })),
            403,
        )
        .await;
    login(&server, "alice", "reset-password", json!({})).await;

    // Registration binds the validated email and refuses one already in use.
    let taken = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register/email/requestToken",
            None,
            Some(json!({"client_secret": "reg-taken", "email": "alice@example.com", "send_attempt": 1})),
            400,
        )
        .await;
    assert_eq!(taken["errcode"], "M_THREEPID_IN_USE");
    nothing_delivered(&mut rx).await;
    let reg_secret = "reg-email-secret";
    let reg = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register/email/requestToken",
            None,
            Some(json!({"client_secret": reg_secret, "email": "carol@example.com", "send_attempt": 1})),
            200,
        )
        .await;
    let reg_mail = delivered(&mut rx).await;
    let (status, _) = submit_token(
        &server,
        reg["submit_url"].as_str().unwrap(),
        reg["sid"].as_str().unwrap(),
        reg_secret,
        reg_mail["token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    let carol = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({
                "username": "carol",
                "password": PASSWORD,
                "auth": {"type": "m.login.email.identity", "threepid_creds": {"sid": reg["sid"], "client_secret": reg_secret}},
            })),
            200,
        )
        .await;
    let carol_list = server
        .request(Method::GET, "/_matrix/client/v3/account/3pid", Some(token(&carol)), None, 200)
        .await;
    assert_eq!(addresses(&carol_list), vec![("email".into(), "carol@example.com".into())]);

    // Phone numbers follow the same session, including m.login.msisdn.
    let phone_secret = "add-msisdn-secret";
    let phone = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/msisdn/requestToken",
            None,
            Some(json!({"client_secret": phone_secret, "country": "GB", "phone_number": "07700900001", "send_attempt": 1})),
            200,
        )
        .await;
    let sms = delivered(&mut rx).await;
    assert_eq!(sms["address"], "447700900001");
    assert_eq!(sms["medium"], "msisdn");
    let (status, _) = submit_token(
        &server,
        phone["submit_url"].as_str().unwrap(),
        phone["sid"].as_str().unwrap(),
        phone_secret,
        "WRONG-TOKEN-DISTINCTIVE",
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = submit_token(
        &server,
        phone["submit_url"].as_str().unwrap(),
        phone["sid"].as_str().unwrap(),
        phone_secret,
        sms["token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/add",
            Some(alice_token),
            Some(json!({
                "sid": phone["sid"],
                "client_secret": phone_secret,
                "auth": password_auth("alice", "reset-password", &Value::Null),
            })),
            200,
        )
        .await;
    let taken_phone = server
        .request(
            Method::POST,
            "/_matrix/client/v3/register/msisdn/requestToken",
            None,
            Some(json!({"client_secret": "reg-phone", "country": "GB", "phone_number": "07700900001", "send_attempt": 1})),
            400,
        )
        .await;
    assert_eq!(taken_phone["errcode"], "M_THREEPID_IN_USE");
    let missing_phone = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password/msisdn/requestToken",
            None,
            Some(json!({"client_secret": "pw-phone-missing", "country": "GB", "phone_number": "07700900002", "send_attempt": 1})),
            400,
        )
        .await;
    assert_eq!(missing_phone["errcode"], "M_THREEPID_NOT_FOUND");
    nothing_delivered(&mut rx).await;
    let pw_phone_secret = "pw-phone-secret";
    let pw_phone = server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password/msisdn/requestToken",
            None,
            Some(json!({"client_secret": pw_phone_secret, "country": "GB", "phone_number": "07700900001", "send_attempt": 1})),
            200,
        )
        .await;
    let pw_sms = delivered(&mut rx).await;
    let (status, _) = submit_token(
        &server,
        pw_phone["submit_url"].as_str().unwrap(),
        pw_phone["sid"].as_str().unwrap(),
        pw_phone_secret,
        pw_sms["token"].as_str().unwrap(),
    )
    .await;
    assert_eq!(status, 200);
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/password",
            None,
            Some(json!({
                "new_password": "phone-password",
                "logout_devices": false,
                "auth": {"type": "m.login.msisdn", "threepid_creds": {"sid": pw_phone["sid"], "client_secret": pw_phone_secret}},
            })),
            200,
        )
        .await;
    login(&server, "alice", "phone-password", json!({})).await;

    server
        .request(
            Method::POST,
            "/_matrix/client/v3/account/3pid/delete",
            Some(alice_token),
            Some(json!({"medium": "msisdn", "address": "447700900001"})),
            200,
        )
        .await;
    let after_delete = server
        .request(Method::GET, "/_matrix/client/v3/account/3pid", Some(alice_token), None, 200)
        .await;
    assert!(!addresses(&after_delete).iter().any(|(medium, _)| medium == "msisdn"));
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/register/msisdn/requestToken",
            None,
            Some(json!({"client_secret": "reg-phone-free", "country": "GB", "phone_number": "07700900001", "send_attempt": 1})),
            200,
        )
        .await;
    let freed = delivered(&mut rx).await;
    assert_eq!(freed["purpose"], "register");
}

#[tokio::test]
async fn production_password_fallback_page_completes_uia() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let second = login(&server, "alice", PASSWORD, json!({})).await;
    let path = format!("/_matrix/client/v3/devices/{}", second["device_id"].as_str().unwrap());
    let challenge = server.request(Method::DELETE, &path, Some(token(&alice)), None, 401).await;
    let session = challenge["session"].as_str().unwrap().to_owned();

    let page = raw(
        &server,
        Method::GET,
        &format!("/_matrix/client/v3/auth/m.login.password/fallback/web?session={session}"),
        &[],
    )
    .await;
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("type=\"password\""));
    assert!(html.contains("action=\"web\""));

    let url = format!("{}/_matrix/client/v3/auth/m.login.password/fallback/web", server.base_url);
    let bad = server.http.post(&url).form(&[("session", session.as_str()), ("password", "wrong")]).send().await.unwrap();
    assert_eq!(bad.status(), 401);
    assert!(bad.text().await.unwrap().contains("role=\"alert\""));
    let good = server.http.post(&url).form(&[("session", session.as_str()), ("password", PASSWORD)]).send().await.unwrap();
    assert_eq!(good.status(), 200);
    let html = good.text().await.unwrap();
    assert!(html.contains("window.onAuthDone"));
    assert!(html.contains("postMessage(\"authDone\""));

    // The client resubmits with only the session.
    server
        .request(Method::DELETE, &path, Some(token(&alice)), Some(json!({"auth": {"session": session}})), 200)
        .await;
    server
        .request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&second)), None, 401)
        .await;

    let unknown = raw(&server, Method::GET, "/_matrix/client/v3/auth/m.login.recaptcha/fallback/web?session=x", &[]).await;
    assert_eq!(unknown.status(), 404);
    let expired = raw(&server, Method::GET, "/_matrix/client/v3/auth/m.login.password/fallback/web?session=gone", &[]).await;
    assert_eq!(expired.status(), 400);
    // An unknown session in the JSON API is an error, not a fresh challenge.
    let r = server
        .request(Method::DELETE, &path, Some(token(&alice)), Some(json!({"auth": {"session": "gone"}})), 400)
        .await;
    assert_eq!(r["errcode"], "M_UNKNOWN");
}
