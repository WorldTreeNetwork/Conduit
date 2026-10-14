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

// ---------------------------------------------------------------------------
// conduit-y99.29: membership, summaries, mutual rooms, invite permission
// ---------------------------------------------------------------------------

async fn create_room(server: &Server, who: &User, body: Value) -> String {
    server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(&who.token), Some(body), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn member_content(server: &Server, who: &User, room: &str, target: &str) -> Value {
    server
        .request(
            Method::GET,
            &format!(
                "/_matrix/client/v3/rooms/{}/state/m.room.member/{}",
                encode(room),
                encode(target)
            ),
            Some(&who.token),
            None,
            200,
        )
        .await
}

#[tokio::test]
async fn join_by_room_id_and_membership_reasons_reach_member_events() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;

    let joined = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/join", encode(&room)),
            Some(&bob.token),
            Some(json!({"reason": "Looking for support"})),
            200,
        )
        .await;
    assert_eq!(joined["room_id"], room.as_str());
    let content = member_content(&server, &alice, &room, &bob.id).await;
    assert_eq!(content["membership"], "join");
    assert_eq!(content["reason"], "Looking for support");

    // An alias is not a room ID on this endpoint.
    let (status, _, body) = raw(
        &server,
        Method::POST,
        &format!("/_matrix/client/v3/rooms/{}/join", encode("#nope:production.test")),
        Some(&bob.token),
        Some(json!({})),
    )
    .await;
    assert_eq!((status, body["errcode"].as_str()), (400, Some("M_INVALID_PARAM")), "{body}");

    let base = format!("/_matrix/client/v3/rooms/{}", encode(&room));
    for (path, reason, membership) in [
        ("kick", "kick reason", "leave"),
        ("invite", "invite reason", "invite"),
        ("ban", "ban reason", "ban"),
        ("unban", "unban reason", "leave"),
    ] {
        server
            .request(
                Method::POST,
                &format!("{base}/{path}"),
                Some(&alice.token),
                Some(json!({"user_id": bob.id, "reason": reason})),
                200,
            )
            .await;
        let content = member_content(&server, &alice, &room, &bob.id).await;
        assert_eq!(content["membership"], membership, "{path}");
        assert_eq!(content["reason"], reason, "{path}");
    }
    // /join/{roomIdOrAlias} keeps the reason too, then leave with a reason.
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{}", encode(&room)),
            Some(&bob.token),
            Some(json!({"reason": "back again"})),
            200,
        )
        .await;
    assert_eq!(member_content(&server, &alice, &room, &bob.id).await["reason"], "back again");
    server
        .request(Method::POST, &format!("{base}/leave"), Some(&bob.token), Some(json!({"reason": "bye"})), 200)
        .await;
    let content = member_content(&server, &alice, &room, &bob.id).await;
    assert_eq!(content["membership"], "leave");
    assert_eq!(content["reason"], "bye");

    // Joining an invite-only room uninvited is 403.
    let private = create_room(&server, &alice, json!({"preset": "private_chat"})).await;
    let (status, _, body) = raw(
        &server,
        Method::POST,
        &format!("/_matrix/client/v3/rooms/{}/join", encode(&private)),
        Some(&bob.token),
        Some(json!({})),
    )
    .await;
    assert_eq!((status, body["errcode"].as_str()), (403, Some("M_FORBIDDEN")), "{body}");
}

#[tokio::test]
async fn room_summary_respects_visibility_and_reports_state() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let public = create_room(
        &server,
        &alice,
        json!({
            "preset": "public_chat", "name": "Cheese", "topic": "Tasty",
            "room_alias_name": "cheese",
            "creation_content": {"type": "m.space"},
            "initial_state": [
                {"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "m.megolm.v1.aes-sha2"}},
                {"type": "m.room.avatar", "state_key": "", "content": {"url": "mxc://production.test/avatar"}}
            ]
        }),
    )
    .await;
    // By alias, anonymously: public rooms are summarised without membership.
    let anon = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v1/room_summary/{}", encode("#cheese:production.test")),
            None,
            None,
            200,
        )
        .await;
    assert_eq!(anon["room_id"], public.as_str());
    assert_eq!(anon["name"], "Cheese");
    assert_eq!(anon["topic"], "Tasty");
    assert_eq!(anon["canonical_alias"], "#cheese:production.test");
    assert_eq!(anon["avatar_url"], "mxc://production.test/avatar");
    assert_eq!(anon["encryption"], "m.megolm.v1.aes-sha2");
    assert_eq!(anon["room_type"], "m.space");
    assert_eq!(anon["room_version"], "11");
    assert_eq!(anon["join_rule"], "public");
    assert_eq!(anon["num_joined_members"], 1);
    assert_eq!(anon["world_readable"], false);
    assert_eq!(anon["guest_can_join"], false);
    assert!(anon.get("membership").is_none(), "{anon}");

    let mine = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v1/room_summary/{}", encode(&public)),
            Some(&alice.token),
            None,
            200,
        )
        .await;
    assert_eq!(mine["membership"], "join");
    let theirs = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v1/room_summary/{}", encode(&public)),
            Some(&bob.token),
            None,
            200,
        )
        .await;
    assert_eq!(theirs["membership"], "leave");

    // Private rooms: hidden from strangers and anonymous callers, visible
    // to invitees.
    let private = create_room(&server, &alice, json!({"preset": "private_chat", "name": "Secret"})).await;
    let path = format!("/_matrix/client/v1/room_summary/{}", encode(&private));
    let (status, _, body) = raw(&server, Method::GET, &path, None, None).await;
    assert_eq!((status, body["errcode"].as_str()), (404, Some("M_NOT_FOUND")));
    let (status, _, body) = raw(&server, Method::GET, &path, Some(&bob.token), None).await;
    assert_eq!((status, body["errcode"].as_str()), (404, Some("M_NOT_FOUND")));
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", encode(&private)),
            Some(&alice.token),
            Some(json!({"user_id": bob.id})),
            200,
        )
        .await;
    let invited = server.request(Method::GET, &path, Some(&bob.token), None, 200).await;
    assert_eq!(invited["membership"], "invite");
    assert_eq!(invited["join_rule"], "invite");
    assert_eq!(invited["name"], "Secret");

    // Unknown rooms are 404.
    let (status, _, body) = raw(
        &server,
        Method::GET,
        &format!("/_matrix/client/v1/room_summary/{}", encode("!missing:production.test")),
        Some(&bob.token),
        None,
    )
    .await;
    assert_eq!((status, body["errcode"].as_str()), (404, Some("M_NOT_FOUND")));
}

#[tokio::test]
async fn mutual_rooms_lists_shared_joins_in_batches() {
    let server = Server::with_env(&[("CONDUIT_MUTUAL_ROOMS_BATCH", "2")]).await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let mut shared = Vec::new();
    for _ in 0..3 {
        let room = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
        server
            .request(Method::POST, &format!("/_matrix/client/v3/join/{}", encode(&room)), Some(&bob.token), Some(json!({})), 200)
            .await;
        shared.push(room);
    }
    // Alice alone, and a room bob left: neither is mutual.
    create_room(&server, &alice, json!({})).await;
    let departed = create_room(&server, &alice, json!({"preset": "public_chat"})).await;
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{}", encode(&departed)), Some(&bob.token), Some(json!({})), 200)
        .await;
    server
        .request(Method::POST, &format!("/_matrix/client/v3/rooms/{}/leave", encode(&departed)), Some(&bob.token), Some(json!({})), 200)
        .await;

    let path = format!("/_matrix/client/v1/mutual_rooms?user_id={}", encode(&bob.id));
    let first = server.request(Method::GET, &path, Some(&alice.token), None, 200).await;
    assert_eq!(first["count"], 3);
    assert_eq!(first["joined"].as_array().unwrap().len(), 2);
    let token = first["next_batch"].as_str().expect("more results").to_owned();
    let second = server
        .request(Method::GET, &format!("{path}&from={}", encode(&token)), Some(&alice.token), None, 200)
        .await;
    assert_eq!(second["count"], 3);
    assert!(second.get("next_batch").is_none(), "{second}");
    let mut seen: Vec<String> = first["joined"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["joined"].as_array().unwrap())
        .map(|r| r.as_str().unwrap().to_owned())
        .collect();
    seen.sort();
    shared.sort();
    assert_eq!(seen, shared);

    // Unknown users share nothing.
    let none = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v1/mutual_rooms?user_id={}", encode("@ghost:production.test")),
            Some(&alice.token),
            None,
            200,
        )
        .await;
    assert_eq!(none, json!({"count": 0, "joined": []}));

    for (query, errcode) in [
        (String::new(), "M_MISSING_PARAM"),
        (format!("?user_id={}", encode(&alice.id)), "M_INVALID_PARAM"),
        ("?user_id=not-a-user".to_owned(), "M_INVALID_PARAM"),
        (format!("?user_id={}&from=garbage", encode(&bob.id)), "M_INVALID_PARAM"),
        // A token minted for bob is not valid for another user.
        (format!("?user_id={}&from={}", encode("@ghost:production.test"), encode(&token)), "M_INVALID_PARAM"),
    ] {
        let (status, _, body) = raw(
            &server,
            Method::GET,
            &format!("/_matrix/client/v1/mutual_rooms{query}"),
            Some(&alice.token),
            None,
        )
        .await;
        assert_eq!((status, body["errcode"].as_str()), (400, Some(errcode)), "{query}: {body}");
    }
}

#[tokio::test]
async fn invite_blocking_rejects_invites_and_hides_pending_ones() {
    let server = Server::new().await;
    let alice = user(&server, "alice").await;
    let bob = user(&server, "bob").await;
    let room = create_room(&server, &alice, json!({"preset": "private_chat"})).await;
    let pending = create_room(&server, &alice, json!({"preset": "private_chat"})).await;
    // An invite that predates blocking.
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", encode(&pending)),
            Some(&alice.token),
            Some(json!({"user_id": bob.id})),
            200,
        )
        .await;
    let sync = server
        .request(Method::GET, "/_matrix/client/v3/sync", Some(&bob.token), None, 200)
        .await;
    assert!(sync["rooms"]["invite"].get(&pending).is_some(), "{sync}");

    let config_path = format!(
        "/_matrix/client/v3/user/{}/account_data/m.invite_permission_config",
        encode(&bob.id)
    );
    server
        .request(Method::PUT, &config_path, Some(&bob.token), Some(json!({"default_action": "block"})), 200)
        .await;

    // POST /invite
    let (status, _, body) = raw(
        &server,
        Method::POST,
        &format!("/_matrix/client/v3/rooms/{}/invite", encode(&room)),
        Some(&alice.token),
        Some(json!({"user_id": bob.id})),
    )
    .await;
    assert_eq!((status, body["errcode"].as_str()), (403, Some("M_INVITE_BLOCKED")), "{body}");
    // PUT state m.room.member invite
    let member_path = format!(
        "/_matrix/client/v3/rooms/{}/state/m.room.member/{}",
        encode(&room),
        encode(&bob.id)
    );
    let (status, _, body) = raw(
        &server,
        Method::PUT,
        &member_path,
        Some(&alice.token),
        Some(json!({"membership": "invite"})),
    )
    .await;
    assert_eq!((status, body["errcode"].as_str()), (403, Some("M_INVITE_BLOCKED")), "{body}");
    // createRoom with bob in the invite list
    let (status, _, body) = raw(
        &server,
        Method::POST,
        "/_matrix/client/v3/createRoom",
        Some(&alice.token),
        Some(json!({"invite": [bob.id]})),
    )
    .await;
    assert_eq!((status, body["errcode"].as_str()), (403, Some("M_INVITE_BLOCKED")), "{body}");
    // No invite was written to the room.
    let (status, _, _) = raw(&server, Method::GET, &member_path, Some(&alice.token), None).await;
    assert_eq!(status, 404);

    // The pre-existing invite is no longer served by /sync...
    let sync = server
        .request(Method::GET, "/_matrix/client/v3/sync", Some(&bob.token), None, 200)
        .await;
    assert!(sync["rooms"]["invite"].get(&pending).is_none(), "{sync}");
    // ...but other endpoints are unaffected: the invite is still room state.
    let state = member_content(&server, &alice, &pending, &bob.id).await;
    assert_eq!(state["membership"], "invite");

    // Unblocking (the same event without default_action) restores invites.
    server
        .request(Method::PUT, &config_path, Some(&bob.token), Some(json!({})), 200)
        .await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{}/invite", encode(&room)),
            Some(&alice.token),
            Some(json!({"user_id": bob.id})),
            200,
        )
        .await;
    let sync = server
        .request(Method::GET, "/_matrix/client/v3/sync", Some(&bob.token), None, 200)
        .await;
    assert!(sync["rooms"]["invite"].get(&room).is_some(), "{sync}");
    // Unknown actions mean invites flow normally.
    server
        .request(Method::PUT, &config_path, Some(&bob.token), Some(json!({"default_action": "maybe"})), 200)
        .await;
    let other = create_room(&server, &alice, json!({"invite": [bob.id]})).await;
    assert!(other.starts_with('!'));
}
