//! Directory lane journeys (conduit-y99.20) through the shipped binary and
//! real PostgreSQL: the published room directory, room aliases, the user
//! directory, knocking, third-party lookups and application service ping.
//! Assertions follow Matrix v1.19 response shapes and errcodes.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

const HS: &str = "production.test";

fn token(user: &Value) -> &str {
    user["access_token"].as_str().unwrap()
}

fn user_id(user: &Value) -> &str {
    user["user_id"].as_str().unwrap()
}

async fn create_room(server: &Server, token: &str, body: Value) -> String {
    server
        .request(Method::POST, "/_matrix/client/v3/createRoom", Some(token), Some(body), 200)
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn join(server: &Server, token: &str, room: &str) {
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{room}"),
            Some(token),
            Some(json!({})),
            200,
        )
        .await;
}

fn room_ids(response: &Value) -> Vec<String> {
    response["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|room| room["room_id"].as_str().unwrap().to_owned())
        .collect()
}

async fn sync(server: &Server, token: &str, since: Option<&str>) -> Value {
    let path = match since {
        Some(since) => format!("/_matrix/client/v3/sync?timeout=0&since={since}"),
        None => "/_matrix/client/v3/sync?timeout=0".to_owned(),
    };
    server.request(Method::GET, &path, Some(token), None, 200).await
}

async fn make_admin(server: &Server, user: &str) {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&server.database_url)
        .await
        .unwrap();
    sqlx::query("UPDATE accounts SET is_admin = true WHERE user_id = $1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

// ---------------------------------------------------------------------------
// Published room directory
// ---------------------------------------------------------------------------

#[tokio::test]
async fn public_room_directory_lists_filters_and_paginates() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;

    let cheese = create_room(
        &server,
        token(&alice),
        json!({
            "visibility": "public", "preset": "public_chat",
            "name": "Cheese Lovers", "topic": "Tasty cheese", "room_alias_name": "cheese",
            "initial_state": [
                {"type": "m.room.avatar", "state_key": "", "content": {"url": "mxc://production.test/cheese"}},
                {"type": "m.room.guest_access", "state_key": "", "content": {"guest_access": "can_join"}},
                {"type": "m.room.history_visibility", "state_key": "", "content": {"history_visibility": "world_readable"}}
            ]
        }),
    )
    .await;
    let space = create_room(
        &server,
        token(&alice),
        json!({
            "visibility": "public", "preset": "public_chat", "name": "Space Station",
            "creation_content": {"type": "m.space"}
        }),
    )
    .await;
    let hidden = create_room(
        &server,
        token(&alice),
        json!({"preset": "public_chat", "name": "Hidden cheese"}),
    )
    .await;
    join(&server, token(&bob), &cheese).await;

    // GET needs no authentication; largest room first; every field set.
    let all = server
        .request(Method::GET, "/_matrix/client/v3/publicRooms", None, None, 200)
        .await;
    assert_eq!(room_ids(&all), vec![cheese.clone(), space.clone()]);
    assert_eq!(all["total_room_count_estimate"], 2);
    assert!(all.get("next_batch").is_none() && all.get("prev_batch").is_none());
    assert_eq!(
        all["chunk"][0],
        json!({
            "room_id": cheese, "name": "Cheese Lovers", "topic": "Tasty cheese",
            "canonical_alias": format!("#cheese:{HS}"), "num_joined_members": 2,
            "world_readable": true, "guest_can_join": true,
            "avatar_url": "mxc://production.test/cheese", "join_rule": "public"
        })
    );
    assert_eq!(
        all["chunk"][1],
        json!({
            "room_id": space, "name": "Space Station", "num_joined_members": 1,
            "world_readable": false, "guest_can_join": false, "join_rule": "public",
            "room_type": "m.space"
        })
    );

    // Pagination: next_batch forward, prev_batch back.
    let first = server
        .request(Method::GET, "/_matrix/client/v3/publicRooms?limit=1", None, None, 200)
        .await;
    assert_eq!(room_ids(&first), vec![cheese.clone()]);
    assert!(first.get("prev_batch").is_none());
    let next = first["next_batch"].as_str().unwrap();
    let second = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/publicRooms?limit=1&since={next}"),
            None,
            None,
            200,
        )
        .await;
    assert_eq!(room_ids(&second), vec![space.clone()]);
    assert!(second.get("next_batch").is_none());
    let prev = second["prev_batch"].as_str().unwrap();
    let back = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/publicRooms?limit=1&since={prev}"),
            None,
            None,
            200,
        )
        .await;
    assert_eq!(room_ids(&back), vec![cheese.clone()]);
    let bad = server
        .request(Method::GET, "/_matrix/client/v3/publicRooms?since=bogus", None, None, 400)
        .await;
    assert_eq!(bad["errcode"], "M_INVALID_PARAM");

    // POST requires authentication.
    let anon = server
        .request(Method::POST, "/_matrix/client/v3/publicRooms", None, Some(json!({})), 401)
        .await;
    assert_eq!(anon["errcode"], "M_MISSING_TOKEN");

    let post = |body: Value| {
        let server = &server;
        let token = token(&alice).to_owned();
        async move {
            server
                .request(Method::POST, "/_matrix/client/v3/publicRooms", Some(&token), Some(body), 200)
                .await
        }
    };
    // generic_search_term: case-insensitive over name, topic and alias.
    // The unpublished "Hidden cheese" room never appears.
    assert_eq!(room_ids(&post(json!({"filter": {"generic_search_term": "CHEESE"}})).await), vec![cheese.clone()]);
    assert_eq!(room_ids(&post(json!({"filter": {"generic_search_term": "#cheese:"}})).await), vec![cheese.clone()]);
    assert_eq!(room_ids(&post(json!({"filter": {"generic_search_term": "station"}})).await), vec![space.clone()]);
    let none = post(json!({"filter": {"generic_search_term": "nothing matches"}})).await;
    assert_eq!(none["chunk"], json!([]));
    assert_eq!(none["total_room_count_estimate"], 0);
    // room_types: null selects untyped rooms.
    assert_eq!(room_ids(&post(json!({"filter": {"room_types": [null]}})).await), vec![cheese.clone()]);
    assert_eq!(room_ids(&post(json!({"filter": {"room_types": ["m.space"]}})).await), vec![space.clone()]);
    assert_eq!(
        room_ids(&post(json!({"filter": {"room_types": [null, "m.space"]}})).await),
        vec![cheese.clone(), space.clone()]
    );
    let paged = post(json!({"limit": 1})).await;
    assert_eq!(room_ids(&paged), vec![cheese.clone()]);
    assert_eq!(room_ids(&post(json!({"limit": 1, "since": paged["next_batch"]})).await), vec![space.clone()]);
    let conflict = server
        .request(
            Method::POST,
            "/_matrix/client/v3/publicRooms",
            Some(token(&alice)),
            Some(json!({"include_all_networks": true, "third_party_instance_id": "x|y"})),
            400,
        )
        .await;
    assert_eq!(conflict["errcode"], "M_INVALID_PARAM");
    // An explicit server parameter naming this server is the local list.
    let local = server
        .request(Method::GET, &format!("/_matrix/client/v3/publicRooms?server={HS}"), None, None, 200)
        .await;
    assert_eq!(room_ids(&local).len(), 2);

    // Visibility endpoint reflects publication.
    for (room, visibility) in [(&cheese, "public"), (&space, "public"), (&hidden, "private")] {
        let got = server
            .request(Method::GET, &format!("/_matrix/client/v3/directory/list/room/{room}"), None, None, 200)
            .await;
        assert_eq!(got, json!({"visibility": visibility}));
    }
    let unknown = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/directory/list/room/!nope:{HS}"),
            None,
            None,
            404,
        )
        .await;
    assert_eq!(unknown["errcode"], "M_NOT_FOUND");

    // room_alias_name already bound: 400 M_ROOM_IN_USE, nothing created.
    let taken = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token(&alice)),
            Some(json!({"room_alias_name": "cheese"})),
            400,
        )
        .await;
    assert_eq!(taken["errcode"], "M_ROOM_IN_USE");
}

#[tokio::test]
async fn directory_visibility_changes_are_authorized() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let carol = server.register("carol").await;
    let room = create_room(&server, token(&alice), json!({"preset": "public_chat", "name": "Lobby"})).await;
    join(&server, token(&bob), &room).await;
    let path = format!("/_matrix/client/v3/directory/list/room/{room}");

    let anon = server
        .request(Method::PUT, &path, None, Some(json!({"visibility": "public"})), 401)
        .await;
    assert_eq!(anon["errcode"], "M_MISSING_TOKEN");
    // Joined but without the power to set the canonical alias.
    let member = server
        .request(Method::PUT, &path, Some(token(&bob)), Some(json!({"visibility": "public"})), 403)
        .await;
    assert_eq!(member["errcode"], "M_FORBIDDEN");
    // Not in the room at all.
    let outsider = server
        .request(Method::PUT, &path, Some(token(&carol)), Some(json!({"visibility": "public"})), 403)
        .await;
    assert_eq!(outsider["errcode"], "M_FORBIDDEN");
    let invalid = server
        .request(Method::PUT, &path, Some(token(&alice)), Some(json!({"visibility": "secret"})), 400)
        .await;
    assert_eq!(invalid["errcode"], "M_INVALID_PARAM");
    let unknown = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/directory/list/room/!nope:{HS}"),
            Some(token(&alice)),
            Some(json!({"visibility": "public"})),
            404,
        )
        .await;
    assert_eq!(unknown["errcode"], "M_NOT_FOUND");

    // `visibility` defaults to public.
    server
        .request(Method::PUT, &path, Some(token(&alice)), Some(json!({})), 200)
        .await;
    assert_eq!(
        server.request(Method::GET, &path, None, None, 200).await,
        json!({"visibility": "public"})
    );
    let listed = server
        .request(Method::GET, "/_matrix/client/v3/publicRooms", None, None, 200)
        .await;
    assert_eq!(room_ids(&listed), vec![room.clone()]);
    // Idempotent.
    server
        .request(Method::PUT, &path, Some(token(&alice)), Some(json!({"visibility": "public"})), 200)
        .await;

    server
        .request(Method::PUT, &path, Some(token(&alice)), Some(json!({"visibility": "private"})), 200)
        .await;
    let listed = server
        .request(Method::GET, "/_matrix/client/v3/publicRooms", None, None, 200)
        .await;
    assert_eq!(listed["chunk"], json!([]));

    // A server administrator may change any room's listing.
    make_admin(&server, user_id(&carol)).await;
    server
        .request(Method::PUT, &path, Some(token(&carol)), Some(json!({"visibility": "public"})), 200)
        .await;
    assert_eq!(
        server.request(Method::GET, &path, None, None, 200).await,
        json!({"visibility": "public"})
    );
}

// ---------------------------------------------------------------------------
// Room aliases (conduit-e95, conduit-057)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn room_alias_directory_and_join_by_alias() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let carol = server.register("carol").await;
    let room = create_room(&server, token(&alice), json!({"preset": "public_chat"})).await;
    let alias_path = format!("/_matrix/client/v3/directory/room/%23lobby:{HS}");

    server
        .request(Method::PUT, &alias_path, Some(token(&alice)), Some(json!({"room_id": room})), 200)
        .await;
    let resolved = server.request(Method::GET, &alias_path, None, None, 200).await;
    assert_eq!(resolved, json!({"room_id": room, "servers": [HS]}));

    // Join by alias resolves to the room.
    let joined = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/%23lobby:{HS}"),
            Some(token(&bob)),
            Some(json!({})),
            200,
        )
        .await;
    assert_eq!(joined["room_id"], room.as_str());

    let again = server
        .request(Method::PUT, &alias_path, Some(token(&bob)), Some(json!({"room_id": room})), 409)
        .await;
    assert_eq!(again["errcode"], "M_UNKNOWN");
    for bad in ["lobby", "%23lobby", "%23:production.test"] {
        let response = server
            .request(
                Method::PUT,
                &format!("/_matrix/client/v3/directory/room/{bad}"),
                Some(token(&alice)),
                Some(json!({"room_id": room})),
                400,
            )
            .await;
        assert_eq!(response["errcode"], "M_INVALID_PARAM", "{bad}");
    }
    let foreign = server
        .request(
            Method::PUT,
            "/_matrix/client/v3/directory/room/%23lobby:elsewhere.test",
            Some(token(&alice)),
            Some(json!({"room_id": room})),
            400,
        )
        .await;
    assert_eq!(foreign["errcode"], "M_INVALID_PARAM");
    let no_room = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/directory/room/%23ghost:{HS}"),
            Some(token(&alice)),
            Some(json!({"room_id": format!("!nope:{HS}")})),
            404,
        )
        .await;
    assert_eq!(no_room["errcode"], "M_NOT_FOUND");
    let invalid_get = server
        .request(Method::GET, "/_matrix/client/v3/directory/room/lobby", None, None, 400)
        .await;
    assert_eq!(invalid_get["errcode"], "M_INVALID_PARAM");

    // Local alias list: members only, unless world readable.
    let aliases = format!("/_matrix/client/v3/rooms/{room}/aliases");
    let listed = server.request(Method::GET, &aliases, Some(token(&bob)), None, 200).await;
    assert_eq!(listed, json!({"aliases": [format!("#lobby:{HS}")]}));
    let outsider = server.request(Method::GET, &aliases, Some(token(&carol)), None, 403).await;
    assert_eq!(outsider["errcode"], "M_FORBIDDEN");
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.history_visibility"),
            Some(token(&alice)),
            Some(json!({"history_visibility": "world_readable"})),
            200,
        )
        .await;
    server.request(Method::GET, &aliases, Some(token(&carol)), None, 200).await;

    // Deletion: not the creator and no canonical-alias power → 403.
    let denied = server.request(Method::DELETE, &alias_path, Some(token(&bob)), None, 403).await;
    assert_eq!(denied["errcode"], "M_FORBIDDEN");
    server.request(Method::DELETE, &alias_path, Some(token(&alice)), None, 200).await;
    let gone = server.request(Method::DELETE, &alias_path, Some(token(&alice)), None, 404).await;
    assert_eq!(gone["errcode"], "M_NOT_FOUND");
    let missing = server.request(Method::GET, &alias_path, None, None, 404).await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND");
    let join_missing = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/%23lobby:{HS}"),
            Some(token(&carol)),
            Some(json!({})),
            404,
        )
        .await;
    assert_eq!(join_missing["errcode"], "M_NOT_FOUND");

    // A room admin may delete an alias somebody else created.
    let other = format!("/_matrix/client/v3/directory/room/%23bobs:{HS}");
    server
        .request(Method::PUT, &other, Some(token(&bob)), Some(json!({"room_id": room})), 200)
        .await;
    server.request(Method::DELETE, &other, Some(token(&alice)), None, 200).await;
}

// ---------------------------------------------------------------------------
// User directory
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_directory_search_covers_shared_and_public_rooms_only() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let carol = server.register("carol").await;
    let dave = server.register("dave").await;
    for (user, name) in [(&bob, "Bob the Builder"), (&carol, "Carol Singer"), (&dave, "Dave Hidden")] {
        server
            .request(
                Method::PUT,
                &format!("/_matrix/client/v3/profile/{}/displayname", user_id(user)),
                Some(token(user)),
                Some(json!({"displayname": name})),
                200,
            )
            .await;
    }
    // alice + bob share a private room; carol sits in a public room;
    // dave is alone in a private room.
    let private = create_room(&server, token(&alice), json!({"preset": "private_chat", "invite": [user_id(&bob)]})).await;
    join(&server, token(&bob), &private).await;
    create_room(&server, token(&carol), json!({"preset": "public_chat"})).await;
    create_room(&server, token(&dave), json!({"preset": "private_chat"})).await;

    let search = |body: Value, status: u16| {
        let server = &server;
        let token = token(&alice).to_owned();
        async move {
            server
                .request(Method::POST, "/_matrix/client/v3/user_directory/search", Some(&token), Some(body), status)
                .await
        }
    };

    let found = search(json!({"search_term": "bob"}), 200).await;
    assert_eq!(
        found,
        json!({"results": [{"user_id": user_id(&bob), "display_name": "Bob the Builder"}], "limited": false})
    );
    // Display names match case-insensitively.
    let by_name = search(json!({"search_term": "BUILDER"}), 200).await;
    assert_eq!(by_name["results"][0]["user_id"], user_id(&bob));
    // Public-room members are visible without sharing a room.
    let public = search(json!({"search_term": "singer"}), 200).await;
    assert_eq!(public["results"][0]["user_id"], user_id(&carol));
    // Users only in private rooms we are not in are not.
    let hidden = search(json!({"search_term": "dave"}), 200).await;
    assert_eq!(hidden, json!({"results": [], "limited": false}));

    // Everyone visible, shared-room users first, then by user ID.
    let all = search(json!({"search_term": HS}), 200).await;
    let ids: Vec<_> = all["results"].as_array().unwrap().iter().map(|r| r["user_id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec![user_id(&alice), user_id(&bob), user_id(&carol)]);
    assert_eq!(all["limited"], false);
    let limited = search(json!({"search_term": HS, "limit": 1}), 200).await;
    assert_eq!(limited["results"].as_array().unwrap().len(), 1);
    assert_eq!(limited["limited"], true);

    let missing = search(json!({"limit": 3}), 400).await;
    assert_eq!(missing["errcode"], "M_MISSING_PARAM");
    let wrong = search(json!({"search_term": 5}), 400).await;
    assert_eq!(wrong["errcode"], "M_BAD_JSON");
    let anon = server
        .request(Method::POST, "/_matrix/client/v3/user_directory/search", None, Some(json!({"search_term": "bob"})), 401)
        .await;
    assert_eq!(anon["errcode"], "M_MISSING_TOKEN");
}

// ---------------------------------------------------------------------------
// Knocking
// ---------------------------------------------------------------------------

#[tokio::test]
async fn knock_accept_deny_and_rescind() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let carol = server.register("carol").await;
    let dave = server.register("dave").await;
    let room = create_room(
        &server,
        token(&alice),
        json!({
            "preset": "private_chat", "name": "Knock Knock", "topic": "Who is there",
            "room_alias_name": "door",
            "initial_state": [{"type": "m.room.join_rules", "state_key": "", "content": {"join_rule": "knock"}}]
        }),
    )
    .await;
    let bob_sync = sync(&server, token(&bob), None).await;
    let bob_since = bob_sync["next_batch"].as_str().unwrap().to_owned();

    // Knock by room ID with a reason.
    let knocked = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/knock/{room}"),
            Some(token(&bob)),
            Some(json!({"reason": "let me in"})),
            200,
        )
        .await;
    assert_eq!(knocked, json!({"room_id": room}));
    let member = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{}", user_id(&bob)),
            Some(token(&alice)),
            None,
            200,
        )
        .await;
    assert_eq!(member, json!({"membership": "knock", "reason": "let me in"}));

    // The knock shows under rooms.knock with stripped knock_state.
    let after = sync(&server, token(&bob), Some(&bob_since)).await;
    let state = after["rooms"]["knock"][&room]["knock_state"]["events"].as_array().unwrap().clone();
    let has = |kind: &str, key: &str| {
        state.iter().find(|e| e["type"] == kind && e["state_key"] == key).cloned()
    };
    assert_eq!(has("m.room.join_rules", "").unwrap()["content"]["join_rule"], "knock");
    assert_eq!(has("m.room.name", "").unwrap()["content"]["name"], "Knock Knock");
    assert_eq!(has("m.room.topic", "").unwrap()["content"]["topic"], "Who is there");
    assert_eq!(has("m.room.member", user_id(&bob)).unwrap()["content"]["membership"], "knock");
    assert!(state.iter().all(|e| e.get("event_id").is_none()), "stripped state carries no event IDs");
    assert!(after["rooms"]["join"].get(&room).is_none());
    let bob_since = after["next_batch"].as_str().unwrap().to_owned();

    // A knocker cannot simply join a knock room.
    let direct = server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{room}"), Some(token(&bob)), Some(json!({})), 403)
        .await;
    assert_eq!(direct["errcode"], "M_FORBIDDEN");

    // Rescind with /leave; it lands in rooms.leave.
    server
        .request(Method::POST, &format!("/_matrix/client/v3/rooms/{room}/leave"), Some(token(&bob)), Some(json!({})), 200)
        .await;
    let rescinded = sync(&server, token(&bob), Some(&bob_since)).await;
    assert!(rescinded["rooms"]["leave"].get(&room).is_some(), "{rescinded}");
    let bob_since = rescinded["next_batch"].as_str().unwrap().to_owned();

    // Knock again by alias; alice accepts by inviting; bob joins.
    let by_alias = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/knock/%23door:{HS}"),
            Some(token(&bob)),
            Some(json!({})),
            200,
        )
        .await;
    assert_eq!(by_alias["room_id"], room.as_str());
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(token(&alice)),
            Some(json!({"user_id": user_id(&bob)})),
            200,
        )
        .await;
    let invited = sync(&server, token(&bob), Some(&bob_since)).await;
    assert!(invited["rooms"]["invite"].get(&room).is_some(), "{invited}");
    assert!(invited["rooms"]["knock"].get(&room).is_none());
    join(&server, token(&bob), &room).await;
    let joined = sync(&server, token(&bob), Some(invited["next_batch"].as_str().unwrap())).await;
    assert!(joined["rooms"]["join"].get(&room).is_some());

    // Deny: carol knocks, alice kicks; then a ban stops further knocks.
    server
        .request(Method::POST, &format!("/_matrix/client/v3/knock/{room}"), Some(token(&carol)), Some(json!({})), 200)
        .await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/kick"),
            Some(token(&alice)),
            Some(json!({"user_id": user_id(&carol), "reason": "not today"})),
            200,
        )
        .await;
    let denied = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{}", user_id(&carol)),
            Some(token(&alice)),
            None,
            200,
        )
        .await;
    assert_eq!(denied["membership"], "leave");
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/ban"),
            Some(token(&alice)),
            Some(json!({"user_id": user_id(&carol)})),
            200,
        )
        .await;
    let banned = server
        .request(Method::POST, &format!("/_matrix/client/v3/knock/{room}"), Some(token(&carol)), Some(json!({})), 403)
        .await;
    assert_eq!(banned["errcode"], "M_FORBIDDEN");

    // An invited user may not knock.
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(token(&alice)),
            Some(json!({"user_id": user_id(&dave)})),
            200,
        )
        .await;
    let invited_knock = server
        .request(Method::POST, &format!("/_matrix/client/v3/knock/{room}"), Some(token(&dave)), Some(json!({})), 403)
        .await;
    assert_eq!(invited_knock["errcode"], "M_FORBIDDEN");

    // Rooms that are not set up for knocking refuse; unknown rooms 404.
    let public = create_room(&server, token(&alice), json!({"preset": "public_chat"})).await;
    let refused = server
        .request(Method::POST, &format!("/_matrix/client/v3/knock/{public}"), Some(token(&dave)), Some(json!({})), 403)
        .await;
    assert_eq!(refused["errcode"], "M_FORBIDDEN");
    for target in [format!("!nope:{HS}"), format!("%23nope:{HS}")] {
        let missing = server
            .request(Method::POST, &format!("/_matrix/client/v3/knock/{target}"), Some(token(&dave)), Some(json!({})), 404)
            .await;
        assert_eq!(missing["errcode"], "M_NOT_FOUND");
    }
    let anon = server
        .request(Method::POST, &format!("/_matrix/client/v3/knock/{room}"), None, Some(json!({})), 401)
        .await;
    assert_eq!(anon["errcode"], "M_MISSING_TOKEN");
}

// ---------------------------------------------------------------------------
// Third-party networks and application service ping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn thirdparty_lookups_without_bridges_are_empty() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let t = Some(token(&alice));
    let protocols = server.request(Method::GET, "/_matrix/client/v3/thirdparty/protocols", t, None, 200).await;
    assert_eq!(protocols, json!({}));
    for path in [
        "/_matrix/client/v3/thirdparty/protocol/irc",
        "/_matrix/client/v3/thirdparty/location/irc",
        "/_matrix/client/v3/thirdparty/user/irc",
        "/_matrix/client/v3/thirdparty/location?alias=%23room:production.test",
        "/_matrix/client/v3/thirdparty/user?userid=@alice:production.test",
    ] {
        let response = server.request(Method::GET, path, t, None, 404).await;
        assert_eq!(response["errcode"], "M_NOT_FOUND", "{path}");
    }
    for path in ["/_matrix/client/v3/thirdparty/location", "/_matrix/client/v3/thirdparty/user"] {
        let response = server.request(Method::GET, path, t, None, 400).await;
        assert_eq!(response["errcode"], "M_MISSING_PARAM", "{path}");
    }
    let anon = server.request(Method::GET, "/_matrix/client/v3/thirdparty/protocols", None, None, 401).await;
    assert_eq!(anon["errcode"], "M_MISSING_TOKEN");
}

/// What the mock bridge saw.
#[derive(Default)]
struct BridgeLog {
    pings: Vec<(Option<String>, Value)>,
    location_queries: Vec<String>,
}

/// A mock application service: answers ping and the third-party API.
async fn spawn_bridge(ping_status: u16, ping_delay: Duration) -> (String, Arc<Mutex<BridgeLog>>) {
    use axum::{
        extract::{Path, RawQuery},
        http::{HeaderMap, StatusCode},
        routing::{get, post, put},
        Json, Router,
    };
    let log = Arc::new(Mutex::new(BridgeLog::default()));
    let ping_log = Arc::clone(&log);
    let location_log = Arc::clone(&log);
    let app = Router::new()
        .route(
            "/_matrix/app/v1/ping",
            post(move |headers: HeaderMap, Json(body): Json<Value>| {
                let log = Arc::clone(&ping_log);
                async move {
                    tokio::time::sleep(ping_delay).await;
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    log.lock().unwrap().pings.push((auth, body));
                    (
                        StatusCode::from_u16(ping_status).unwrap(),
                        Json(if ping_status == 200 { json!({}) } else { json!({"errcode": "M_UNKNOWN_TOKEN"}) }),
                    )
                }
            }),
        )
        .route(
            "/_matrix/app/v1/thirdparty/protocol/:protocol",
            get(|Path(protocol): Path<String>| async move {
                if protocol != "irc" {
                    return (StatusCode::NOT_FOUND, Json(json!({"errcode": "M_NOT_FOUND"})));
                }
                (
                    StatusCode::OK,
                    Json(json!({
                        "user_fields": ["network", "nickname"],
                        "location_fields": ["network", "channel"],
                        "icon": "mxc://example.org/irc",
                        "field_types": {
                            "network": {"regexp": "([a-z0-9]+\\.)*[a-z0-9]+", "placeholder": "irc.example.org"},
                            "nickname": {"regexp": "[^\\s#]+", "placeholder": "username"},
                            "channel": {"regexp": "#[^\\s]+", "placeholder": "#foobar"}
                        },
                        "instances": [{"desc": "Freenode", "fields": {"network": "freenode"}, "network_id": "freenode"}]
                    })),
                )
            }),
        )
        .route(
            "/_matrix/app/v1/thirdparty/location/:protocol",
            get(move |RawQuery(query): RawQuery| {
                let log = Arc::clone(&location_log);
                async move {
                    log.lock().unwrap().location_queries.push(query.unwrap_or_default());
                    Json(json!([{
                        "alias": "#freenode_#foo:production.test", "protocol": "irc",
                        "fields": {"network": "freenode", "channel": "#foo"}
                    }]))
                }
            }),
        )
        .route("/_matrix/app/v1/thirdparty/user/:protocol", get(|| async { Json(json!([])) }))
        .route(
            "/_matrix/app/v1/thirdparty/location",
            get(|| async {
                Json(json!([{
                    "alias": "#freenode_#foo:production.test", "protocol": "irc",
                    "fields": {"network": "freenode", "channel": "#foo"}
                }]))
            }),
        )
        .route("/_matrix/app/v1/transactions/:txn", put(|| async { Json(json!({})) }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, log)
}

fn registration(id: &str, url: Option<&str>, protocols: &[&str]) -> String {
    let url = url.map_or("null".to_owned(), |u| format!("\"{u}\""));
    format!(
        "id: {id}\nurl: {url}\nas_token: as_{id}\nhs_token: hs_{id}\nsender_localpart: {id}_bot\n\
         namespaces:\n  users:\n    - exclusive: true\n      regex: '@{id}_.*:production\\.test'\n  \
         aliases:\n    - exclusive: true\n      regex: '#{id}_.*:production\\.test'\n  rooms: []\n\
         protocols: [{}]\n",
        protocols.join(", ")
    )
}

#[tokio::test]
async fn appservice_ping_thirdparty_and_network_directory() {
    let mut server = Server::new().await;
    let (bridge_url, bridge_log) = spawn_bridge(200, Duration::ZERO).await;
    let (rejecting_url, _) = spawn_bridge(401, Duration::ZERO).await;
    let (slow_url, _) = spawn_bridge(200, Duration::from_secs(15)).await;
    let dead_url = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    server.stop();
    let dir = server.files.path().join("app-services");
    std::fs::create_dir_all(&dir).unwrap();
    for (id, url, protocols) in [
        ("freenode", Some(bridge_url.as_str()), &["irc"][..]),
        ("nourl", None, &[][..]),
        ("rejecting", Some(rejecting_url.as_str()), &[][..]),
        ("slow", Some(slow_url.as_str()), &[][..]),
        ("dead", Some(dead_url.as_str()), &[][..]),
    ] {
        std::fs::write(dir.join(format!("{id}.yaml")), registration(id, url, protocols)).unwrap();
    }
    server.start().await;
    let alice = server.register("alice").await;

    // --- ping -------------------------------------------------------------
    let ping = |id: &str, as_token: Option<&str>, status: u16| {
        let server = &server;
        let path = format!("/_matrix/client/v1/appservice/{id}/ping");
        let as_token = as_token.map(str::to_owned);
        async move {
            server
                .request(Method::POST, &path, as_token.as_deref(), Some(json!({"transaction_id": "txn-1"})), status)
                .await
        }
    };
    let ok = ping("freenode", Some("as_freenode"), 200).await;
    assert!(ok["duration_ms"].is_u64(), "{ok}");
    {
        let log = bridge_log.lock().unwrap();
        assert_eq!(log.pings.len(), 1);
        assert_eq!(log.pings[0].0.as_deref(), Some("Bearer hs_freenode"));
        assert_eq!(log.pings[0].1, json!({"transaction_id": "txn-1"}));
    }
    let other = ping("freenode", Some("as_nourl"), 403).await;
    assert_eq!(other["errcode"], "M_FORBIDDEN");
    let user = ping("freenode", Some(token(&alice)), 403).await;
    assert_eq!(user["errcode"], "M_FORBIDDEN");
    let anon = ping("freenode", None, 401).await;
    assert_eq!(anon["errcode"], "M_MISSING_TOKEN");
    let unset = ping("nourl", Some("as_nourl"), 400).await;
    assert_eq!(unset["errcode"], "M_URL_NOT_SET");
    let bad = ping("rejecting", Some("as_rejecting"), 502).await;
    assert_eq!(bad["errcode"], "M_BAD_STATUS");
    assert_eq!(bad["status"], 401);
    assert_eq!(serde_json::from_str::<Value>(bad["body"].as_str().unwrap()).unwrap(), json!({"errcode": "M_UNKNOWN_TOKEN"}));
    let dead = ping("dead", Some("as_dead"), 502).await;
    assert_eq!(dead["errcode"], "M_CONNECTION_FAILED");
    // The timeout path needs a client that outlasts the server's 10s limit.
    let slow = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
        .post(format!("{}/_matrix/client/v1/appservice/slow/ping", server.base_url))
        .bearer_auth("as_slow")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(slow.status().as_u16(), 504);
    assert_eq!(slow.json::<Value>().await.unwrap()["errcode"], "M_CONNECTION_TIMEOUT");

    // --- third-party lookups --------------------------------------------
    let t = Some(token(&alice));
    let protocols = server.request(Method::GET, "/_matrix/client/v3/thirdparty/protocols", t, None, 200).await;
    assert_eq!(protocols.as_object().unwrap().keys().collect::<Vec<_>>(), vec!["irc"]);
    assert_eq!(
        protocols["irc"]["instances"],
        json!([{"desc": "Freenode", "fields": {"network": "freenode"}, "network_id": "freenode", "instance_id": "freenode|freenode"}])
    );
    assert_eq!(protocols["irc"]["user_fields"], json!(["network", "nickname"]));
    let irc = server.request(Method::GET, "/_matrix/client/v3/thirdparty/protocol/irc", t, None, 200).await;
    assert_eq!(irc, protocols["irc"]);
    let xmpp = server.request(Method::GET, "/_matrix/client/v3/thirdparty/protocol/xmpp", t, None, 404).await;
    assert_eq!(xmpp["errcode"], "M_NOT_FOUND");
    let locations = server
        .request(Method::GET, "/_matrix/client/v3/thirdparty/location/irc?network=freenode&channel=%23foo", t, None, 200)
        .await;
    assert_eq!(locations[0]["alias"], "#freenode_#foo:production.test");
    assert_eq!(bridge_log.lock().unwrap().location_queries, vec!["network=freenode&channel=%23foo".to_owned()]);
    let users = server.request(Method::GET, "/_matrix/client/v3/thirdparty/user/irc", t, None, 404).await;
    assert_eq!(users["errcode"], "M_NOT_FOUND");
    let reverse = server
        .request(
            Method::GET,
            "/_matrix/client/v3/thirdparty/location?alias=%23freenode_%23foo:production.test",
            t,
            None,
            200,
        )
        .await;
    assert_eq!(reverse[0]["protocol"], "irc");

    // --- application service network directory ---------------------------
    let local = create_room(&server, token(&alice), json!({"visibility": "public", "preset": "public_chat"})).await;
    let bridged = create_room(&server, token(&alice), json!({"preset": "public_chat"})).await;
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/directory/list/appservice/freenode/{bridged}"),
            Some("as_freenode"),
            Some(json!({"visibility": "public"})),
            200,
        )
        .await;
    let refused = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/directory/list/appservice/freenode/{bridged}"),
            Some(token(&alice)),
            Some(json!({"visibility": "public"})),
            401,
        )
        .await;
    assert_eq!(refused["errcode"], "M_UNKNOWN_TOKEN");
    let post = |body: Value| {
        let server = &server;
        let token = token(&alice).to_owned();
        async move {
            let mut ids = room_ids(
                &server
                    .request(Method::POST, "/_matrix/client/v3/publicRooms", Some(&token), Some(body), 200)
                    .await,
            );
            ids.sort();
            ids
        }
    };
    let mut both = vec![local.clone(), bridged.clone()];
    both.sort();
    assert_eq!(post(json!({})).await, vec![local.clone()]);
    assert_eq!(post(json!({"include_all_networks": true})).await, both);
    assert_eq!(post(json!({"third_party_instance_id": "freenode|freenode"})).await, vec![bridged.clone()]);
    assert_eq!(post(json!({"third_party_instance_id": "freenode|efnet"})).await, Vec::<String>::new());
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/directory/list/appservice/freenode/{bridged}"),
            Some("as_freenode"),
            Some(json!({"visibility": "private"})),
            200,
        )
        .await;
    assert_eq!(post(json!({"include_all_networks": true})).await, vec![local]);
}

#[tokio::test]
async fn remote_public_rooms_come_from_the_named_server() {
    use axum::response::IntoResponse;

    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let asked_route = Arc::clone(&asked);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/_matrix/federation/v1/publicRooms",
            axum::routing::any(move |headers: axum::http::HeaderMap, req: axum::extract::Request| {
                let asked = Arc::clone(&asked_route);
                async move {
                    let host = headers.get("host").and_then(|value| value.to_str().ok()).unwrap_or("").to_owned();
                    let method = req.method().as_str().to_owned();
                    let query = req.uri().query().unwrap_or("").to_owned();
                    let bytes = axum::body::to_bytes(req.into_body(), 64 * 1024).await.unwrap_or_default();
                    let text = String::from_utf8_lossy(&bytes);
                    asked.lock().unwrap().push(format!("{method} {host} {query} {text}"));
                    if host == "down.test" {
                        return (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            axum::Json(json!({"errcode": "M_UNKNOWN", "error": "down"})),
                        )
                            .into_response();
                    }
                    (
                        axum::http::StatusCode::OK,
                        axum::Json(json!({
                            "chunk": [
                                {
                                    "room_id": "!alpha:remote.test",
                                    "name": "Alpha",
                                    "topic": "first",
                                    "num_joined_members": 3,
                                    "world_readable": false,
                                    "guest_can_join": false
                                },
                                {
                                    "room_id": "!beta:remote.test",
                                    "name": "Beta",
                                    "topic": "second",
                                    "num_joined_members": 1,
                                    "world_readable": true,
                                    "guest_can_join": true
                                }
                            ],
                            "total_room_count_estimate": 2
                        })),
                    )
                        .into_response()
                }
            }),
        );
        axum::serve(listener, app).await.ok();
    });

    let server = Server::with_env(&[
        ("CONDUIT_FEDERATION", "1"),
        ("CONDUIT_FEDERATION_BASE_URL", &base_url),
    ])
    .await;
    let alice = server.register("alice").await;

    let listed = server
        .request(
            Method::GET,
            "/_matrix/client/v3/publicRooms?server=remote.test&limit=2",
            None,
            None,
            200,
        )
        .await;
    let ids: Vec<&str> = listed["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|room| room["room_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["!alpha:remote.test", "!beta:remote.test"], "{listed}");
    assert_eq!(listed["total_room_count_estimate"], 2);
    {
        let calls = asked.lock().unwrap();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(calls[0].starts_with("GET remote.test "), "{calls:?}");
        assert!(calls[0].contains("limit=2"), "{calls:?}");
    }

    let _local = server
        .request(Method::GET, "/_matrix/client/v3/publicRooms?server=production.test", None, None, 200)
        .await;
    assert_eq!(
        asked.lock().unwrap().len(),
        1,
        "this server's directory is not fetched: {:?}",
        asked.lock().unwrap()
    );

    let filtered = server
        .request(
            Method::POST,
            "/_matrix/client/v3/publicRooms?server=remote.test",
            Some(token(&alice)),
            Some(json!({"filter": {"generic_search_term": "alp"}})),
            200,
        )
        .await;
    let ids: Vec<&str> = filtered["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .map(|room| room["room_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["!alpha:remote.test"], "{filtered}");
    let calls = asked.lock().unwrap().clone();
    let posted = calls.iter().find(|call| call.starts_with("POST ")).expect(&format!("{calls:?}"));
    assert!(posted.contains("remote.test"), "{posted}");
    assert!(posted.contains("alp"), "{posted}");

    let down = server
        .request(Method::GET, "/_matrix/client/v3/publicRooms?server=down.test", None, None, 502)
        .await;
    assert_eq!(down["errcode"], "M_UNKNOWN", "{down}");
}

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Alias, room id, event id, txn id, device id, and event type grammars on the
/// client paths that mint or accept them.
#[tokio::test]
async fn identifier_grammars_reject_illegal_ids_and_accept_spec_forms() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    assert!(conduit::identifiers::valid_opaque_identifier(alice["device_id"].as_str().unwrap()));

    let bad_device = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "test-password",
                "device_id": "bad id"
            })),
            400,
        )
        .await;
    assert_eq!(bad_device["errcode"], "M_INVALID_PARAM", "{bad_device}");
    let phone = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "test-password",
                "device_id": "Phone_1"
            })),
            200,
        )
        .await;
    assert_eq!(phone["device_id"], "Phone_1");

    let nul_alias = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"room_alias_name": "a\u{0}b"})),
            400,
        )
        .await;
    assert_eq!(nul_alias["errcode"], "M_INVALID_PARAM", "{nul_alias}");
    let long_alias = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"room_alias_name": "a".repeat(250)})),
            400,
        )
        .await;
    assert_eq!(long_alias["errcode"], "M_INVALID_PARAM", "{long_alias}");

    let v11 = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat", "room_version": "11", "room_alias_name": "grammar"})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(conduit::identifiers::valid_room_id(&v11), "{v11}");
    assert!(v11.ends_with(":production.test"), "{v11}");
    let alias = server
        .request(Method::GET, "/_matrix/client/v3/directory/room/%23grammar%3Aproduction.test", Some(token), None, 200)
        .await;
    assert_eq!(alias["room_id"], v11);
    let bad_server = server
        .request(
            Method::PUT,
            "/_matrix/client/v3/directory/room/%23room%3A999.1.1.1",
            Some(token),
            Some(json!({"room_id": v11})),
            400,
        )
        .await;
    assert_eq!(bad_server["errcode"], "M_INVALID_PARAM", "{bad_server}");

    let v12 = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token),
            Some(json!({"preset": "public_chat", "room_version": "12"})),
            200,
        )
        .await["room_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(conduit::identifiers::valid_room_id(&v12), "{v12}");
    assert!(!v12.contains(':'), "{v12}");

    let bad_type = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/Bad/ok", enc(&v11)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "no"})),
            400,
        )
        .await;
    assert_eq!(bad_type["errcode"], "M_INVALID_PARAM", "{bad_type}");
    let bad_txn = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/bad%20id", enc(&v11)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "no"})),
            400,
        )
        .await;
    assert_eq!(bad_txn["errcode"], "M_INVALID_PARAM", "{bad_txn}");
    let sent = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{}/send/m.room.message/ok~id", enc(&v11)),
            Some(token),
            Some(json!({"msgtype": "m.text", "body": "yes"})),
            200,
        )
        .await;
    let event_id = sent["event_id"].as_str().unwrap();
    assert!(conduit::identifiers::valid_event_id(event_id), "{event_id}");
}
