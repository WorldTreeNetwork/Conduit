//! CS-API module journeys (modules lane): extended profiles and profile
//! propagation, server-side key backup, account locking and suspension,
//! server notices, deprecated legacy endpoints and previously untested
//! surfaces — through the shipped binary and real PostgreSQL.

mod common;

use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

fn token(v: &Value) -> &str {
    v["access_token"].as_str().unwrap()
}

fn uid(v: &Value) -> &str {
    v["user_id"].as_str().unwrap()
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
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

/// A request whose status and headers the test inspects itself.
async fn raw(
    server: &Server,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> reqwest::Response {
    let mut request = server.http.request(method, format!("{}{path}", server.base_url));
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    if let Some(b) = body {
        request = request.json(&b);
    }
    request.send().await.unwrap()
}

async fn create_room(server: &Server, access: &str, body: Value) -> String {
    server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(access), Some(body), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn member_content(server: &Server, access: &str, room: &str, user: &str) -> Value {
    server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{}/state/m.room.member/{}", enc(room), enc(user)),
            Some(access),
            None,
            200,
        )
        .await
}

// ---------------------------------------------------------------------------
// Profiles (conduit-y99.38, conduit-y99.25)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn profile_extended_fields_round_trip_and_limits() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let me = uid(&alice).to_owned();
    let t = token(&alice);
    let field = |k: &str| format!("/_matrix/client/v3/profile/{}/{}", enc(&me), k);

    // m.tz and a namespaced custom key of any JSON type.
    server.request(Method::PUT, &field("m.tz"), Some(t), Some(json!({"m.tz": "Europe/London"})), 200).await;
    let custom = json!({"pronouns": ["they"], "n": 3});
    server
        .request(Method::PUT, &field("com.example.info"), Some(t), Some(json!({"com.example.info": custom})), 200)
        .await;
    // Null is stored, not treated as deletion.
    server
        .request(Method::PUT, &field("com.example.nothing"), Some(t), Some(json!({"com.example.nothing": null})), 200)
        .await;
    let got = server.request(Method::GET, &field("m.tz"), None, None, 200).await;
    assert_eq!(got, json!({"m.tz": "Europe/London"}));
    let got = server.request(Method::GET, &field("com.example.nothing"), None, None, 200).await;
    assert_eq!(got, json!({"com.example.nothing": null}));
    let full = server
        .request(Method::GET, &format!("/_matrix/client/v3/profile/{}", enc(&me)), None, None, 200)
        .await;
    assert_eq!(full["m.tz"], "Europe/London");
    assert_eq!(full["com.example.info"], custom);

    // DELETE removes the key; deleting again still succeeds.
    server.request(Method::DELETE, &field("m.tz"), Some(t), None, 200).await;
    server.request(Method::DELETE, &field("m.tz"), Some(t), None, 200).await;
    let missing = server.request(Method::GET, &field("m.tz"), None, None, 404).await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND");

    // Errors: invalid key, key too long, missing property, bad JSON,
    // wrong types, another user's profile.
    let bad = server.request(Method::PUT, &field("Tz"), Some(t), Some(json!({"Tz": "x"})), 400).await;
    assert_eq!(bad["errcode"], "M_INVALID_PARAM");
    let long_key = format!("com.{}", "a".repeat(260));
    let bad = server
        .request(Method::PUT, &field(&long_key), Some(t), Some(json!({ long_key.clone(): 1 })), 400)
        .await;
    assert_eq!(bad["errcode"], "M_KEY_TOO_LARGE");
    let bad = server.request(Method::PUT, &field("m.tz"), Some(t), Some(json!({"other": 1})), 400).await;
    assert_eq!(bad["errcode"], "M_MISSING_PARAM");
    let response = raw(&server, Method::PUT, &field("m.tz"), Some(t), None, &[("content-type", "application/json")]).await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.json::<Value>().await.unwrap()["errcode"], "M_BAD_JSON");
    let bad = server.request(Method::PUT, &field("m.tz"), Some(t), Some(json!({"m.tz": 5})), 400).await;
    assert_eq!(bad["errcode"], "M_BAD_JSON");
    let bad = server
        .request(Method::PUT, &field("avatar_url"), Some(t), Some(json!({"avatar_url": "https://x/y.png"})), 400)
        .await;
    assert_eq!(bad["errcode"], "M_BAD_JSON");
    let bob = server.register("bob").await;
    let denied = server.request(Method::PUT, &field("m.tz"), Some(token(&bob)), Some(json!({"m.tz": "UTC"})), 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
    let denied = server.request(Method::DELETE, &field("com.example.info"), Some(token(&bob)), None, 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");

    // 64 KiB whole-profile limit.
    let big = "x".repeat(40 * 1024);
    server.request(Method::PUT, &field("com.example.a"), Some(t), Some(json!({"com.example.a": big})), 200).await;
    let too_big = server
        .request(Method::PUT, &field("com.example.b"), Some(t), Some(json!({"com.example.b": big})), 400)
        .await;
    assert_eq!(too_big["errcode"], "M_PROFILE_TOO_LARGE");
    // Replacing an existing field is measured after the replacement.
    server.request(Method::PUT, &field("com.example.a"), Some(t), Some(json!({"com.example.a": "small"})), 200).await;
    server.request(Method::PUT, &field("com.example.b"), Some(t), Some(json!({"com.example.b": big})), 200).await;

    // Unknown users are 404 when lookups are open.
    let none = server
        .request(Method::GET, "/_matrix/client/v3/profile/%40ghost%3Aproduction.test", None, None, 404)
        .await;
    assert_eq!(none["errcode"], "M_NOT_FOUND");

    // m.profile_fields capability.
    let caps = server.request(Method::GET, "/_matrix/client/v3/capabilities", Some(t), None, 200).await;
    assert_eq!(caps["capabilities"]["m.profile_fields"], json!({"enabled": true}));
    assert_eq!(caps["capabilities"]["m.set_displayname"]["enabled"], true);
}

#[tokio::test]
async fn profile_changes_propagate_to_member_events_and_presence() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let other_room = create_room(&server, token(&alice), json!({"preset": "private_chat"})).await;
    let me = uid(&alice).to_owned();

    // Bob starts syncing so the presence update is observable.
    let initial = server
        .request(Method::GET, "/_matrix/client/v3/sync?timeout=0", Some(token(&bob)), None, 200)
        .await;
    let since = initial["next_batch"].as_str().unwrap().to_owned();

    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/profile/{}/displayname", enc(&me)),
            Some(token(&alice)),
            Some(json!({"displayname": "Alice Liddell"})),
            200,
        )
        .await;
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/profile/{}/avatar_url", enc(&me)),
            Some(token(&alice)),
            Some(json!({"avatar_url": "mxc://production.test/alice"})),
            200,
        )
        .await;

    for r in [&room, &other_room] {
        let content = member_content(&server, token(&alice), r, &me).await;
        assert_eq!(content["membership"], "join");
        assert_eq!(content["displayname"], "Alice Liddell");
        assert_eq!(content["avatar_url"], "mxc://production.test/alice");
    }

    let delta = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
            Some(token(&bob)),
            None,
            200,
        )
        .await;
    let timeline = delta["rooms"]["join"][&room]["timeline"]["events"].as_array().unwrap();
    assert!(timeline.iter().any(|e| e["type"] == "m.room.member"
        && e["state_key"] == me
        && e["content"]["displayname"] == "Alice Liddell"));
    let presence = delta["presence"]["events"].as_array().unwrap();
    let mine = presence.iter().find(|e| e["sender"] == me).expect("presence update for alice");
    assert_eq!(mine["content"]["displayname"], "Alice Liddell");
    assert_eq!(mine["content"]["avatar_url"], "mxc://production.test/alice");
    assert!(mine["content"]["presence"].is_string());

    // DELETE displayname propagates its removal.
    server
        .request(
            Method::DELETE,
            &format!("/_matrix/client/v3/profile/{}/displayname", enc(&me)),
            Some(token(&alice)),
            None,
            200,
        )
        .await;
    let content = member_content(&server, token(&alice), &room, &me).await;
    assert!(content.get("displayname").is_none(), "{content}");
    assert_eq!(content["avatar_url"], "mxc://production.test/alice");

    // A fresh join carries the joiner's profile without the client
    // sending it.
    let carol = server.register("carol").await;
    let carol_id = uid(&carol).to_owned();
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/profile/{}/displayname", enc(&carol_id)),
            Some(token(&carol)),
            Some(json!({"displayname": "Carol"})),
            200,
        )
        .await;
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{}", enc(&room)), Some(token(&carol)), Some(json!({})), 200)
        .await;
    let content = member_content(&server, token(&alice), &room, &carol_id).await;
    assert_eq!(content["displayname"], "Carol");
}

#[tokio::test]
async fn restricted_profile_lookup_allows_only_the_spec_minimum() {
    let server = Server::with_env(&[("CONDUIT_PROFILE_LOOKUP", "restricted")]).await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let carol = server.register("carol").await;
    let profile = |u: &str| format!("/_matrix/client/v3/profile/{}", enc(u));

    // Strangers: 403, unknown users included (no enumeration).
    let denied = server.request(Method::GET, &profile(uid(&bob)), Some(token(&alice)), None, 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
    let denied = server
        .request(Method::GET, &profile("@ghost:production.test"), Some(token(&alice)), None, 403)
        .await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
    // Self is always allowed.
    server.request(Method::GET, &profile(uid(&alice)), Some(token(&alice)), None, 200).await;

    // Sharing a private room allows the lookup.
    let private = create_room(&server, token(&alice), json!({"preset": "private_chat", "invite": [uid(&bob)]})).await;
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{}", enc(&private)), Some(token(&bob)), Some(json!({})), 200)
        .await;
    server.request(Method::GET, &profile(uid(&bob)), Some(token(&alice)), None, 200).await;
    server
        .request(Method::GET, &format!("{}/displayname", profile(uid(&bob))), Some(token(&alice)), None, 404)
        .await;
    // Carol shares nothing with bob yet.
    server.request(Method::GET, &profile(uid(&bob)), Some(token(&carol)), None, 403).await;

    // A user joined to a public room is visible to anyone, even without
    // a token.
    create_room(&server, token(&bob), json!({"preset": "public_chat"})).await;
    server.request(Method::GET, &profile(uid(&bob)), Some(token(&carol)), None, 200).await;
    server.request(Method::GET, &profile(uid(&bob)), None, None, 200).await;

    // World-readable history counts too.
    let dave = server.register("dave").await;
    create_room(
        &server,
        token(&dave),
        json!({"preset": "private_chat", "initial_state": [{
            "type": "m.room.history_visibility", "state_key": "",
            "content": {"history_visibility": "world_readable"}
        }]}),
    )
    .await;
    server.request(Method::GET, &profile(uid(&dave)), Some(token(&carol)), None, 200).await;
}

// ---------------------------------------------------------------------------
// Server-side key backup (conduit-y99.39)
// ---------------------------------------------------------------------------

fn key(verified: bool, index: u64, forwarded: u64, tag: &str) -> Value {
    json!({
        "first_message_index": index,
        "forwarded_count": forwarded,
        "is_verified": verified,
        "session_data": {"ciphertext": tag},
    })
}

#[tokio::test]
async fn key_backup_versions_keys_etags_and_errors() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let t = token(&alice);
    let alg = "m.megolm_backup.v1.curve25519-aes-sha2";

    let none = server.request(Method::GET, "/_matrix/client/v3/room_keys/version", Some(t), None, 404).await;
    assert_eq!(none["errcode"], "M_NOT_FOUND");
    // Writing without any backup: 404.
    let none = server
        .request(Method::PUT, "/_matrix/client/v3/room_keys/keys/!r:hs/s?version=1", Some(t), Some(key(false, 0, 0, "a")), 404)
        .await;
    assert_eq!(none["errcode"], "M_NOT_FOUND");

    let v1 = server
        .request(Method::POST, "/_matrix/client/v3/room_keys/version", Some(t), Some(json!({"algorithm": alg, "auth_data": {"public_key": "one"}})), 200)
        .await["version"]
        .as_str()
        .unwrap()
        .to_owned();
    let info = server
        .request(Method::GET, &format!("/_matrix/client/v3/room_keys/version/{v1}"), Some(t), None, 200)
        .await;
    assert_eq!(info["count"], 0);
    assert_eq!(info["algorithm"], alg);
    let etag0 = info["etag"].as_str().unwrap().to_owned();

    let room = "!room:production.test";
    let session_path = |r: &str, s: &str, v: &str| format!("/_matrix/client/v3/room_keys/keys/{}/{}?version={v}", enc(r), enc(s));

    // Per-session put: count and a new etag.
    let r1 = server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(false, 5, 1, "first")), 200).await;
    assert_eq!(r1["count"], 1);
    assert_ne!(r1["etag"], etag0);
    // Replacement rules: a worse key (higher index) is ignored...
    let r2 = server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(false, 9, 0, "worse")), 200).await;
    assert_eq!(r2["etag"], r1["etag"], "ignored upload must not change the etag");
    let got = server.request(Method::GET, &session_path(room, "s1", &v1), Some(t), None, 200).await;
    assert_eq!(got["session_data"]["ciphertext"], "first");
    // ...a lower first_message_index replaces...
    server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(false, 2, 3, "lower-index")), 200).await;
    let got = server.request(Method::GET, &session_path(room, "s1", &v1), Some(t), None, 200).await;
    assert_eq!(got["session_data"]["ciphertext"], "lower-index");
    // ...a verified key wins over any unverified one...
    server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(true, 7, 7, "verified")), 200).await;
    server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(false, 0, 0, "unverified")), 200).await;
    let got = server.request(Method::GET, &session_path(room, "s1", &v1), Some(t), None, 200).await;
    assert_eq!(got["session_data"]["ciphertext"], "verified");
    // ...and on equal verification and index the lower forwarded_count wins.
    server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(true, 7, 2, "fewer-forwards")), 200).await;
    let got = server.request(Method::GET, &session_path(room, "s1", &v1), Some(t), None, 200).await;
    assert_eq!(got["session_data"]["ciphertext"], "fewer-forwards");

    // Malformed key data.
    let bad = server
        .request(Method::PUT, &session_path(room, "s9", &v1), Some(t), Some(json!({"session_data": {}})), 400)
        .await;
    assert_eq!(bad["errcode"], "M_BAD_JSON");

    // Per-room and whole-backup puts.
    let room2 = "!other:production.test";
    let r = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/room_keys/keys/{}?version={v1}", enc(room)),
            Some(t),
            Some(json!({"sessions": {"s2": key(false, 0, 0, "s2")}})),
            200,
        )
        .await;
    assert_eq!(r["count"], 2);
    let r = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/room_keys/keys?version={v1}"),
            Some(t),
            Some(json!({"rooms": {room2: {"sessions": {"s3": key(false, 0, 0, "s3"), "s4": key(false, 0, 0, "s4")}}}})),
            200,
        )
        .await;
    assert_eq!(r["count"], 4);
    let all = server.request(Method::GET, &format!("/_matrix/client/v3/room_keys/keys?version={v1}"), Some(t), None, 200).await;
    assert_eq!(all["rooms"][room]["sessions"].as_object().unwrap().len(), 2);
    assert_eq!(all["rooms"][room2]["sessions"].as_object().unwrap().len(), 2);
    let one_room = server
        .request(Method::GET, &format!("/_matrix/client/v3/room_keys/keys/{}?version={v1}", enc(room2)), Some(t), None, 200)
        .await;
    assert_eq!(one_room["sessions"].as_object().unwrap().len(), 2);
    let empty = server
        .request(Method::GET, &format!("/_matrix/client/v3/room_keys/keys/{}?version={v1}", enc("!none:hs")), Some(t), None, 200)
        .await;
    assert_eq!(empty, json!({"sessions": {}}));
    let gone = server.request(Method::GET, &session_path(room, "nope", &v1), Some(t), None, 404).await;
    assert_eq!(gone["errcode"], "M_NOT_FOUND");

    // DELETE session, room and all, each answering etag + count.
    let before = server.request(Method::GET, &format!("/_matrix/client/v3/room_keys/version/{v1}"), Some(t), None, 200).await;
    let d = server.request(Method::DELETE, &session_path(room, "s2", &v1), Some(t), None, 200).await;
    assert_eq!(d["count"], 3);
    assert_ne!(d["etag"], before["etag"]);
    server.request(Method::GET, &session_path(room, "s2", &v1), Some(t), None, 404).await;
    let d = server
        .request(Method::DELETE, &format!("/_matrix/client/v3/room_keys/keys/{}?version={v1}", enc(room2)), Some(t), None, 200)
        .await;
    assert_eq!(d["count"], 1);
    let d = server.request(Method::DELETE, &format!("/_matrix/client/v3/room_keys/keys?version={v1}"), Some(t), None, 200).await;
    assert_eq!(d["count"], 0);
    // Unknown version on read/delete: 404.
    for (m, p) in [
        (Method::GET, "/_matrix/client/v3/room_keys/keys?version=999".to_owned()),
        (Method::DELETE, format!("/_matrix/client/v3/room_keys/keys/{}?version=999", enc(room))),
        (Method::GET, "/_matrix/client/v3/room_keys/version/999".to_owned()),
    ] {
        let e = server.request(m, &p, Some(t), None, 404).await;
        assert_eq!(e["errcode"], "M_NOT_FOUND");
    }

    // Update: only auth_data changes; algorithm and version must match.
    server
        .request(Method::PUT, &format!("/_matrix/client/v3/room_keys/version/{v1}"), Some(t), Some(json!({"algorithm": alg, "auth_data": {"public_key": "two"}, "version": v1})), 200)
        .await;
    let info = server.request(Method::GET, "/_matrix/client/v3/room_keys/version", Some(t), None, 200).await;
    assert_eq!(info["auth_data"]["public_key"], "two");
    let e = server
        .request(Method::PUT, &format!("/_matrix/client/v3/room_keys/version/{v1}"), Some(t), Some(json!({"algorithm": "m.other", "auth_data": {}})), 400)
        .await;
    assert_eq!(e["errcode"], "M_INVALID_PARAM");
    let e = server
        .request(Method::PUT, &format!("/_matrix/client/v3/room_keys/version/{v1}"), Some(t), Some(json!({"algorithm": alg, "auth_data": {}, "version": "1"})), 400)
        .await;
    assert_eq!(e["errcode"], "M_INVALID_PARAM");
    let e = server
        .request(Method::PUT, "/_matrix/client/v3/room_keys/version/999", Some(t), Some(json!({"algorithm": alg, "auth_data": {}})), 404)
        .await;
    assert_eq!(e["errcode"], "M_NOT_FOUND");

    // A newer backup makes v1 stale for writes.
    server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(false, 0, 0, "x")), 200).await;
    let v2 = server
        .request(Method::POST, "/_matrix/client/v3/room_keys/version", Some(t), Some(json!({"algorithm": alg, "auth_data": {"public_key": "three"}})), 200)
        .await["version"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(v1, v2);
    let wrong = server.request(Method::PUT, &session_path(room, "s1", &v1), Some(t), Some(key(false, 0, 0, "x")), 403).await;
    assert_eq!(wrong["errcode"], "M_WRONG_ROOM_KEYS_VERSION");
    assert_eq!(wrong["current_version"], v2);
    // The old version is still readable.
    server.request(Method::GET, &session_path(room, "s1", &v1), Some(t), None, 200).await;

    // Deleting a version removes its keys; deleting again succeeds; a
    // version that never existed is 404.
    server.request(Method::PUT, &session_path(room, "k", &v2), Some(t), Some(key(false, 0, 0, "k")), 200).await;
    server.request(Method::DELETE, &format!("/_matrix/client/v3/room_keys/version/{v2}"), Some(t), None, 200).await;
    server.request(Method::DELETE, &format!("/_matrix/client/v3/room_keys/version/{v2}"), Some(t), None, 200).await;
    let e = server.request(Method::DELETE, "/_matrix/client/v3/room_keys/version/424242", Some(t), None, 404).await;
    assert_eq!(e["errcode"], "M_NOT_FOUND");
    let e = server.request(Method::GET, &session_path(room, "k", &v2), Some(t), None, 404).await;
    assert_eq!(e["errcode"], "M_NOT_FOUND");
    let latest = server.request(Method::GET, "/_matrix/client/v3/room_keys/version", Some(t), None, 200).await;
    assert_eq!(latest["version"], v1);
}

// ---------------------------------------------------------------------------
// Account locking and suspension (conduit-y99.43)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_lock_endpoints_and_locked_account_enforcement() {
    let server = Server::new().await;
    let admin = server.register("admin").await;
    let other_admin = server.register("otheradmin").await;
    let alice = server.register("alice").await;
    let alice_id = uid(&alice).to_owned();
    set_admin(&server, uid(&admin)).await;
    set_admin(&server, uid(&other_admin)).await;
    let lock = |u: &str| format!("/_matrix/client/v1/admin/lock/{}", enc(u));

    // Non-admins are refused before any lookup (no enumeration).
    let e = server.request(Method::GET, &lock(&alice_id), Some(token(&alice)), None, 403).await;
    assert_eq!(e["errcode"], "M_FORBIDDEN");
    let e = server.request(Method::GET, &lock("@ghost:production.test"), Some(token(&alice)), None, 403).await;
    assert_eq!(e["errcode"], "M_FORBIDDEN");
    // Admin errors: remote user, unknown user, another admin, self.
    let e = server.request(Method::GET, &lock("@x:elsewhere.test"), Some(token(&admin)), None, 400).await;
    assert_eq!(e["errcode"], "M_INVALID_PARAM");
    let e = server.request(Method::GET, &lock("@ghost:production.test"), Some(token(&admin)), None, 404).await;
    assert_eq!(e["errcode"], "M_NOT_FOUND");
    let e = server.request(Method::PUT, &lock(uid(&other_admin)), Some(token(&admin)), Some(json!({"locked": true})), 403).await;
    assert_eq!(e["errcode"], "M_FORBIDDEN");
    let e = server.request(Method::PUT, &lock(uid(&admin)), Some(token(&admin)), Some(json!({"locked": true})), 403).await;
    assert_eq!(e["errcode"], "M_FORBIDDEN");

    let s = server.request(Method::GET, &lock(&alice_id), Some(token(&admin)), None, 200).await;
    assert_eq!(s, json!({"locked": false}));
    let s = server.request(Method::PUT, &lock(&alice_id), Some(token(&admin)), Some(json!({"locked": true})), 200).await;
    assert_eq!(s, json!({"locked": true}));
    let s = server.request(Method::GET, &lock(&alice_id), Some(token(&admin)), None, 200).await;
    assert_eq!(s, json!({"locked": true}));

    // Locked: 401 M_USER_LOCKED + soft_logout everywhere but logout.
    for (m, p) in [
        (Method::GET, "/_matrix/client/v3/account/whoami"),
        (Method::GET, "/_matrix/client/v3/sync?timeout=0"),
        (Method::GET, "/_matrix/client/v3/capabilities"),
    ] {
        let e = server.request(m, p, Some(token(&alice)), None, 401).await;
        assert_eq!(e["errcode"], "M_USER_LOCKED", "{p}");
        assert_eq!(e["soft_logout"], true);
    }
    // Login is refused the same way (no new tokens while locked).
    let e = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "alice"}, "password": "test-password"})),
            401,
        )
        .await;
    assert_eq!(e["errcode"], "M_USER_LOCKED");

    // Unlocking restores the very same token (tokens are not invalidated).
    server.request(Method::PUT, &lock(&alice_id), Some(token(&admin)), Some(json!({"locked": false})), 200).await;
    let who = server.request(Method::GET, "/_matrix/client/v3/account/whoami", Some(token(&alice)), None, 200).await;
    assert_eq!(who["user_id"], alice_id);

    // Logout works while locked.
    server.request(Method::PUT, &lock(&alice_id), Some(token(&admin)), Some(json!({"locked": true})), 200).await;
    server.request(Method::POST, "/_matrix/client/v3/logout", Some(token(&alice)), Some(json!({})), 200).await;

    // The body must carry a boolean.
    let bad = server.request(Method::PUT, &lock(&alice_id), Some(token(&admin)), Some(json!({"locked": "yes"})), 400).await;
    assert_eq!(bad["errcode"], "M_BAD_JSON");
}

#[tokio::test]
async fn suspended_accounts_keep_reading_but_cannot_add_activity() {
    let server = Server::new().await;
    let admin = server.register("admin").await;
    set_admin(&server, uid(&admin)).await;
    let (alice, bob, room, event_id) = server.chat_pair().await;
    let bob_id = uid(&bob).to_owned();
    let bob_t = token(&bob).to_owned();
    // Bob's own message, to redact later.
    let own = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/own", enc(&room)),
            Some(&bob_t),
            Some(json!({"msgtype": "m.text", "body": "mine"})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let other_room = create_room(&server, token(&alice), json!({"preset": "public_chat"})).await;
    let suspend = format!("/_matrix/client/v1/admin/suspend/{}", enc(&bob_id));
    let s = server.request(Method::GET, &suspend, Some(token(&admin)), None, 200).await;
    assert_eq!(s, json!({"suspended": false}));
    let e = server.request(Method::GET, &suspend, Some(token(&alice)), None, 403).await;
    assert_eq!(e["errcode"], "M_FORBIDDEN");
    let s = server.request(Method::PUT, &suspend, Some(token(&admin)), Some(json!({"suspended": true})), 200).await;
    assert_eq!(s, json!({"suspended": true}));
    assert_eq!(server.request(Method::GET, &suspend, Some(token(&admin)), None, 200).await, json!({"suspended": true}));

    let forbidden: Vec<(Method, String, Value)> = vec![
        (Method::PUT, format!("/_matrix/client/v3/rooms/{}/send/m.room.message/t1", enc(&room)), json!({"msgtype": "m.text", "body": "hi"})),
        (Method::PUT, format!("/_matrix/client/v3/rooms/{}/state/m.room.topic", enc(&room)), json!({"topic": "x"})),
        (Method::POST, format!("/_matrix/client/v3/join/{}", enc(&other_room)), json!({})),
        (Method::POST, format!("/_matrix/client/v3/rooms/{}/invite", enc(&room)), json!({"user_id": uid(&admin)})),
        (Method::POST, "/_matrix/client/v3/createRoom".to_owned(), json!({})),
        (Method::PUT, format!("/_matrix/client/v3/profile/{}/displayname", enc(&bob_id)), json!({"displayname": "B"})),
        (Method::PUT, format!("/_matrix/client/v3/rooms/{}/redact/{}/r1", enc(&room), enc(&event_id)), json!({})),
    ];
    for (m, p, b) in forbidden {
        let e = server.request(m, &p, Some(&bob_t), Some(b), 403).await;
        assert_eq!(e["errcode"], "M_USER_SUSPENDED", "{p}");
    }
    // Still allowed: reading, syncing, own redactions, leaving, logging in.
    server.request(Method::GET, "/_matrix/client/v3/sync?timeout=0", Some(&bob_t), None, 200).await;
    server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/messages?dir=b", enc(&room)), Some(&bob_t), None, 200)
        .await;
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/redact/{}/r2", enc(&room), enc(&own)),
            Some(&bob_t),
            Some(json!({})),
            200,
        )
        .await;
    let second = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "bob"}, "password": "test-password"})),
            200,
        )
        .await;
    // New sessions are suspended too.
    let e = server.request(Method::POST, "/_matrix/client/v3/createRoom", Some(token(&second)), Some(json!({})), 403).await;
    assert_eq!(e["errcode"], "M_USER_SUSPENDED");
    server
        .request(Method::POST, &format!("/_matrix/client/v3/rooms/{}/leave", enc(&room)), Some(&bob_t), Some(json!({})), 200)
        .await;

    // Unsuspending restores activity.
    server.request(Method::PUT, &suspend, Some(token(&admin)), Some(json!({"suspended": false})), 200).await;
    server.request(Method::POST, "/_matrix/client/v3/createRoom", Some(&bob_t), Some(json!({})), 200).await;
}

// ---------------------------------------------------------------------------
// Server notices (conduit-y99.41)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_notices_room_is_tagged_invite_only_and_reused() {
    let server = Server::new().await;
    let admin = server.register("admin").await;
    set_admin(&server, uid(&admin)).await;
    let alice = server.register("alice").await;
    let alice_id = uid(&alice).to_owned();
    let send = "/_matrix/conduit/admin/v1/server_notices";

    // Admin only.
    let e = server
        .request(Method::POST, send, Some(token(&alice)), Some(json!({"user_id": alice_id, "content": {"body": "x"}})), 403)
        .await;
    assert_eq!(e["errcode"], "M_FORBIDDEN");
    let e = server
        .request(Method::POST, send, Some(token(&admin)), Some(json!({"user_id": "@ghost:production.test", "content": {"body": "x"}})), 404)
        .await;
    assert_eq!(e["errcode"], "M_NOT_FOUND");

    let first = server
        .request(
            Method::POST,
            send,
            Some(token(&admin)),
            Some(json!({"user_id": alice_id, "content": {"msgtype": "m.text", "body": "Scheduled maintenance tonight"}})),
            200,
        )
        .await;
    assert!(first["event_id"].as_str().unwrap().starts_with('$'));

    // The user is invited (not joined) to a room tagged m.server_notice.
    let sync = server.request(Method::GET, "/_matrix/client/v3/sync?timeout=0", Some(token(&alice)), None, 200).await;
    let invites = sync["rooms"]["invite"].as_object().expect("invite section");
    assert_eq!(invites.len(), 1);
    let room_id = invites.keys().next().unwrap().clone();
    assert!(sync["rooms"]["join"].get(&room_id).is_none());

    // Rejecting the invite is refused.
    let e = server
        .request(Method::POST, &format!("/_matrix/client/v3/rooms/{}/leave", enc(&room_id)), Some(token(&alice)), Some(json!({})), 403)
        .await;
    assert_eq!(e["errcode"], "M_CANNOT_LEAVE_SERVER_NOTICE_ROOM");

    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{}", enc(&room_id)), Some(token(&alice)), Some(json!({})), 200)
        .await;
    let tags = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/user/{}/rooms/{}/tags", enc(&alice_id), enc(&room_id)),
            Some(token(&alice)),
            None,
            200,
        )
        .await;
    assert!(tags["tags"].get("m.server_notice").is_some(), "{tags}");
    let messages = server
        .request(Method::GET, &format!("/_matrix/client/v3/rooms/{}/messages?dir=b&limit=50", enc(&room_id)), Some(token(&alice)), None, 200)
        .await;
    let notice = messages["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "m.room.message")
        .expect("notice event");
    assert_eq!(notice["content"]["msgtype"], "m.server_notice");
    assert_eq!(notice["content"]["body"], "Scheduled maintenance tonight");
    assert_eq!(notice["sender"], "@server-notices:production.test");

    // The user cannot post in the notices room.
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/t", enc(&room_id)),
            Some(token(&alice)),
            Some(json!({"msgtype": "m.text", "body": "hi"})),
            403,
        )
        .await;

    // After joining the user may leave; the next notice re-invites them
    // into the same room (exactly one notices room per user).
    server
        .request(Method::POST, &format!("/_matrix/client/v3/rooms/{}/leave", enc(&room_id)), Some(token(&alice)), Some(json!({})), 200)
        .await;
    server
        .request(
            Method::POST,
            send,
            Some(token(&admin)),
            Some(json!({"user_id": alice_id, "content": {
                "body": "Limit reached", "server_notice_type": "m.server_notice.usage_limit_reached",
                "limit_type": "monthly_active_user", "admin_contact": "mailto:ops@production.test"
            }})),
            200,
        )
        .await;
    let sync = server.request(Method::GET, "/_matrix/client/v3/sync?timeout=0", Some(token(&alice)), None, 200).await;
    assert_eq!(sync["rooms"]["invite"].as_object().unwrap().keys().collect::<Vec<_>>(), vec![&room_id]);
}
