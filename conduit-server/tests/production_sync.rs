//! Sync & E2EE semantics through the shipped binary and real PostgreSQL
//! (conduit-y99.13.4, .14, .15, .16).

mod common;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use common::keys::{self, CrossSigning, Device};
use common::production::Server;
use reqwest::Method;
use serde_json::{json, Value};

fn token(login: &Value) -> &str {
    login["access_token"].as_str().unwrap()
}

fn user(login: &Value) -> &str {
    login["user_id"].as_str().unwrap()
}

/// Independent "Signing JSON" verification, written against the spec rather
/// than the server's helper.
fn independently_verified(object: &Value, user: &str, key_id: &str, public: &str) -> bool {
    let mut stripped = object.as_object().unwrap().clone();
    stripped.remove("signatures");
    stripped.remove("unsigned");
    let bytes = conduit::canonical_json::to_canonical_bytes(&Value::Object(stripped)).unwrap();
    let Some(signature) = object["signatures"][user][key_id].as_str() else { return false };
    let public: [u8; 32] = STANDARD_NO_PAD.decode(public).unwrap().try_into().unwrap();
    let signature: [u8; 64] = STANDARD_NO_PAD.decode(signature).unwrap().try_into().unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
        .is_ok()
}

async fn sync(server: &Server, login: &Value, since: Option<&str>) -> Value {
    let path = match since {
        Some(since) => format!("/_matrix/client/v3/sync?since={since}"),
        None => "/_matrix/client/v3/sync".to_owned(),
    };
    server.request(Method::GET, &path, Some(token(login)), None, 200).await
}

fn next_batch(response: &Value) -> String {
    response["next_batch"].as_str().unwrap().to_owned()
}

async fn encrypted_room(server: &Server, creator: &Value) -> String {
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(token(creator)),
            Some(json!({
                "preset": "public_chat",
                "initial_state": [{
                    "type": "m.room.encryption", "state_key": "",
                    "content": {"algorithm": "m.megolm.v1.aes-sha2"}
                }]
            })),
            200,
        )
        .await;
    room["room_id"].as_str().unwrap().to_owned()
}

async fn join(server: &Server, login: &Value, room: &str) {
    server
        .request(Method::POST, &format!("/_matrix/client/v3/join/{room}"), Some(token(login)), Some(json!({})), 200)
        .await;
}

async fn leave(server: &Server, login: &Value, room: &str) {
    server
        .request(Method::POST, &format!("/_matrix/client/v3/rooms/{room}/leave"), Some(token(login)), Some(json!({})), 200)
        .await;
}

async fn upload_device(server: &Server, login: &Value) -> Device {
    let device = Device::from_login(login);
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/upload",
            Some(token(login)),
            Some(json!({"device_keys": device.keys})),
            200,
        )
        .await;
    device
}

fn list(value: &Value) -> Vec<String> {
    let mut users: Vec<String> = value
        .as_array()
        .unwrap_or_else(|| panic!("expected a list: {value}"))
        .iter()
        .map(|user| user.as_str().unwrap().to_owned())
        .collect();
    users.sort();
    users
}

// ---------------------------------------------------------------------------
// conduit-y99.14: authenticated key identities
// ---------------------------------------------------------------------------

#[tokio::test]
async fn key_uploads_must_match_and_be_signed_by_the_authenticated_device() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let upload = |body: Value, status: u16| {
        let server = &server;
        let alice = &alice;
        async move {
            server
                .request(Method::POST, "/_matrix/client/v3/keys/upload", Some(token(alice)), Some(body), status)
                .await
        }
    };

    // Keys claiming another user or another device are refused.
    let foreign_user = Device::new(user(&bob), alice["device_id"].as_str().unwrap());
    let rejected = upload(json!({"device_keys": foreign_user.keys}), 400).await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM");
    let foreign_device = Device::new(user(&alice), "SOMEONEELSE");
    let rejected = upload(json!({"device_keys": foreign_device.keys}), 400).await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM");

    // The object must be signed by the device's own Ed25519 key.
    let device = Device::from_login(&alice);
    let mut unsigned = device.keys.clone();
    unsigned["signatures"] = json!({});
    assert_eq!(upload(json!({"device_keys": unsigned}), 400).await["errcode"], "M_INVALID_SIGNATURE");
    let mut tampered = device.keys.clone();
    tampered["algorithms"] = json!(["m.megolm.v1.aes-sha2"]);
    assert_eq!(upload(json!({"device_keys": tampered}), 400).await["errcode"], "M_INVALID_SIGNATURE");
    let mut swapped = Device::from_login(&alice).keys;
    swapped["keys"][format!("ed25519:{}", alice["device_id"].as_str().unwrap())] = json!(keys::public(&device.key));
    assert_eq!(upload(json!({"device_keys": swapped}), 400).await["errcode"], "M_INVALID_SIGNATURE");
    let mut missing = device.keys.clone();
    missing.as_object_mut().unwrap().remove("algorithms");
    assert_eq!(upload(json!({"device_keys": missing}), 400).await["errcode"], "M_BAD_JSON");

    // A rejected upload persisted nothing.
    let query = json!({"device_keys": {user(&alice): []}});
    let empty = server
        .request(Method::POST, "/_matrix/client/v3/keys/query", Some(token(&bob)), Some(query.clone()), 200)
        .await;
    assert!(empty["device_keys"][user(&alice)].is_null(), "{empty}");

    // A valid upload plus signed one-time keys succeeds.
    let counts = upload(
        json!({
            "device_keys": device.keys,
            "one_time_keys": {"signed_curve25519:AAAA": device.signed_key("b25l", false)},
            "fallback_keys": {"signed_curve25519:FFFF": device.signed_key("ZmFsbA", true)},
        }),
        200,
    )
    .await;
    assert_eq!(counts["one_time_key_counts"]["signed_curve25519"], 1);

    // One-time keys signed by some other key are refused once the device
    // identity is known; malformed key names are refused too.
    let impostor = Device::from_login(&alice);
    let rejected = upload(json!({"one_time_keys": {"signed_curve25519:BBBB": impostor.signed_key("b3Ro", false)}}), 400).await;
    assert_eq!(rejected["errcode"], "M_INVALID_SIGNATURE");
    let rejected = upload(json!({"one_time_keys": {"no-algorithm": "a2V5"}}), 400).await;
    assert_eq!(rejected["errcode"], "M_BAD_JSON");
    let rejected = upload(
        json!({"fallback_keys": {
            "signed_curve25519:F1": device.signed_key("ZjE", true),
            "signed_curve25519:F2": device.signed_key("ZjI", true),
        }}),
        400,
    )
    .await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM");

    // Another user receives exactly the self-signed object, and can verify
    // it independently.
    let device_id = alice["device_id"].as_str().unwrap();
    let returned = server
        .request(Method::POST, "/_matrix/client/v3/keys/query", Some(token(&bob)), Some(query), 200)
        .await;
    let keys = &returned["device_keys"][user(&alice)][device_id];
    assert_eq!(keys["user_id"], user(&alice));
    assert_eq!(keys["device_id"], device_id);
    assert!(independently_verified(
        keys,
        user(&alice),
        &format!("ed25519:{device_id}"),
        keys["keys"][format!("ed25519:{device_id}")].as_str().unwrap()
    ));
}

#[tokio::test]
async fn key_query_withholds_forged_device_keys_and_reports_display_names() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    upload_device(&server, &alice).await;
    let named = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "test-password",
                "initial_device_display_name": "Alice's laptop"
            })),
            200,
        )
        .await;
    upload_device(&server, &named).await;

    // Rows written behind the API (a forged identity and a row whose object
    // names another device) are never served.
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let forged = Device::new(user(&alice), "FORGED");
    let mut unsigned = forged.keys.clone();
    unsigned["signatures"] = json!({});
    sqlx::query("INSERT INTO device_keys (user_id, device_id, keys) VALUES ($1, 'FORGED', $2)")
        .bind(user(&alice))
        .bind(&unsigned)
        .execute(&pool)
        .await
        .unwrap();
    let misplaced = Device::new(user(&alice), "ELSEWHERE");
    sqlx::query("INSERT INTO device_keys (user_id, device_id, keys) VALUES ($1, 'MISPLACED', $2)")
        .bind(user(&alice))
        .bind(&misplaced.keys)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let response = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(token(&bob)),
            Some(json!({"device_keys": {user(&alice): []}})),
            200,
        )
        .await;
    let devices = response["device_keys"][user(&alice)].as_object().unwrap();
    let mut ids: Vec<_> = devices.keys().cloned().collect();
    ids.sort();
    let mut expected = vec![
        alice["device_id"].as_str().unwrap().to_owned(),
        named["device_id"].as_str().unwrap().to_owned(),
    ];
    expected.sort();
    assert_eq!(ids, expected, "{response}");
    assert_eq!(
        devices[named["device_id"].as_str().unwrap()]["unsigned"]["device_display_name"],
        "Alice's laptop"
    );
    // A device filter narrows the result.
    let filtered = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(token(&bob)),
            Some(json!({"device_keys": {user(&alice): [named["device_id"]]}})),
            200,
        )
        .await;
    assert_eq!(filtered["device_keys"][user(&alice)].as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn cross_signing_keys_are_validated_and_replacement_requires_uia() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let path = "/_matrix/client/v3/keys/device_signing/upload";
    let cross = CrossSigning::new(user(&alice));

    // Wrong owner, wrong usage, and a key ID that is not the key.
    let wrong_owner = CrossSigning::new(user(&bob));
    let rejected = server
        .request(Method::POST, path, Some(token(&alice)), Some(json!({"master_key": wrong_owner.master_key})), 400)
        .await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM");
    let rejected = server
        .request(Method::POST, path, Some(token(&alice)), Some(json!({"master_key": cross.self_signing_key})), 400)
        .await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM");
    let mut renamed = cross.master_key.clone();
    renamed["keys"] = json!({"ed25519:alias": keys::public(&cross.master)});
    let rejected = server
        .request(Method::POST, path, Some(token(&alice)), Some(json!({"master_key": renamed})), 400)
        .await;
    assert_eq!(rejected["errcode"], "M_INVALID_PARAM");

    // Self-signing keys must be signed by the accompanying master key.
    let other = CrossSigning::new(user(&alice));
    let rejected = server
        .request(
            Method::POST,
            path,
            Some(token(&alice)),
            Some(json!({"master_key": cross.master_key, "self_signing_key": other.self_signing_key})),
            400,
        )
        .await;
    assert_eq!(rejected["errcode"], "M_INVALID_SIGNATURE");

    // First upload needs no UIA; an exact retry is idempotent.
    server.request(Method::POST, path, Some(token(&alice)), Some(cross.upload_body()), 200).await;
    server.request(Method::POST, path, Some(token(&alice)), Some(cross.upload_body()), 200).await;

    // Replacing keys requires a password stage.
    let replacement = CrossSigning::new(user(&alice));
    let challenge = server
        .request(Method::POST, path, Some(token(&alice)), Some(replacement.upload_body()), 401)
        .await;
    assert_eq!(challenge["flows"], json!([{"stages": ["m.login.password"]}]));
    let session = challenge["session"].as_str().unwrap();
    let mut wrong = replacement.upload_body();
    wrong["auth"] = json!({"type": "m.login.password", "session": session,
        "identifier": {"type": "m.id.user", "user": user(&alice)}, "password": "wrong"});
    let refused = server.request(Method::POST, path, Some(token(&alice)), Some(wrong), 401).await;
    assert_eq!(refused["errcode"], "M_FORBIDDEN");
    let mut right = replacement.upload_body();
    right["auth"] = json!({"type": "m.login.password", "session": session,
        "identifier": {"type": "m.id.user", "user": user(&alice)}, "password": "test-password"});
    server.request(Method::POST, path, Some(token(&alice)), Some(right), 200).await;

    let query = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(token(&bob)),
            Some(json!({"device_keys": {user(&alice): []}})),
            200,
        )
        .await;
    assert_eq!(query["master_keys"][user(&alice)]["keys"], replacement.master_key["keys"]);
    assert!(query["self_signing_keys"][user(&alice)].is_object());
    // The user-signing key is visible only to its owner.
    assert!(query["user_signing_keys"].get(user(&alice)).is_none(), "{query}");
    let own = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/query",
            Some(token(&alice)),
            Some(json!({"device_keys": {user(&alice): []}})),
            200,
        )
        .await;
    assert!(own["user_signing_keys"][user(&alice)].is_object(), "{own}");
}

#[tokio::test]
async fn cross_signing_key_ids_may_not_collide_with_device_ids() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let cross = CrossSigning::new(user(&alice));
    // A device whose ID is the master public key.
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "test-password",
                "device_id": keys::public(&cross.master),
            })),
            200,
        )
        .await;
    let rejected = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/device_signing/upload",
            Some(token(&alice)),
            Some(cross.upload_body()),
            403,
        )
        .await;
    assert_eq!(rejected["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn signature_uploads_verify_signers_and_respect_visibility() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let carol = server.register("carol").await;
    let alice_device = upload_device(&server, &alice).await;
    let alice_cross = CrossSigning::new(user(&alice));
    let bob_cross = CrossSigning::new(user(&bob));
    for (login, cross) in [(&alice, &alice_cross), (&bob, &bob_cross)] {
        server
            .request(Method::POST, "/_matrix/client/v3/keys/device_signing/upload", Some(token(login)), Some(cross.upload_body()), 200)
            .await;
    }
    let device_id = alice["device_id"].as_str().unwrap().to_owned();
    let ssk_id = format!("ed25519:{}", keys::public(&alice_cross.self_signing));
    let usk_id = format!("ed25519:{}", keys::public(&alice_cross.user_signing));
    let bob_master_public = keys::public(&bob_cross.master);

    // Alice signs her device with her self-signing key, and Bob's master
    // key with her user-signing key. A forged device signature fails.
    let mut signed_device = alice_device.keys.clone();
    keys::sign(&mut signed_device, user(&alice), &ssk_id, &alice_cross.self_signing);
    let mut signed_bob = bob_cross.master_key.clone();
    keys::sign(&mut signed_bob, user(&alice), &usk_id, &alice_cross.user_signing);
    let result = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/signatures/upload",
            Some(token(&alice)),
            Some(json!({
                user(&alice): {&device_id: signed_device},
                user(&bob): {&bob_master_public: signed_bob},
            })),
            200,
        )
        .await;
    assert_eq!(result["failures"], json!({}), "{result}");

    let mut forged = alice_device.keys.clone();
    keys::sign(&mut forged, user(&alice), &ssk_id, &keys::generate());
    let mut mismatched = bob_cross.master_key.clone();
    mismatched["usage"] = json!(["master", "extra"]);
    keys::sign(&mut mismatched, user(&alice), &usk_id, &alice_cross.user_signing);
    let result = server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/signatures/upload",
            Some(token(&alice)),
            Some(json!({
                user(&alice): {&device_id: forged, "UNKNOWN": {"signatures": {user(&alice): {}}}},
                user(&bob): {&bob_master_public: mismatched},
            })),
            200,
        )
        .await;
    assert_eq!(result["failures"][user(&alice)][&device_id]["errcode"], "M_INVALID_SIGNATURE", "{result}");
    assert!(result["failures"][user(&alice)]["UNKNOWN"]["errcode"].is_string(), "{result}");
    assert_eq!(result["failures"][user(&bob)][&bob_master_public]["errcode"], "M_INVALID_SIGNATURE", "{result}");

    // Carol sees Alice's self-signing signature on the device, and does not
    // see Alice's private user-signing signature on Bob's master key.
    let query = |login: Value| {
        let server = &server;
        async move {
            server
                .request(
                    Method::POST,
                    "/_matrix/client/v3/keys/query",
                    Some(token(&login)),
                    Some(json!({"device_keys": {"@alice:production.test": [], "@bob:production.test": []}})),
                    200,
                )
                .await
        }
    };
    let as_carol = query(carol.clone()).await;
    let device = &as_carol["device_keys"][user(&alice)][&device_id];
    assert!(independently_verified(device, user(&alice), &ssk_id, &keys::public(&alice_cross.self_signing)), "{as_carol}");
    assert!(as_carol["master_keys"][user(&bob)]["signatures"][user(&alice)].is_null(), "{as_carol}");
    let as_alice = query(alice.clone()).await;
    assert!(independently_verified(
        &as_alice["master_keys"][user(&bob)],
        user(&alice),
        &usk_id,
        &keys::public(&alice_cross.user_signing)
    ), "{as_alice}");
}

// ---------------------------------------------------------------------------
// conduit-y99.14: device-list tracking visibility
// ---------------------------------------------------------------------------

#[tokio::test]
async fn device_lists_report_only_shared_users_and_departures() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let carol = server.register("carol").await;
    let room = encrypted_room(&server, &alice).await;
    join(&server, &bob, &room).await;

    // Initial sync carries no device_lists.
    let bob_initial = sync(&server, &bob, None).await;
    assert!(bob_initial.get("device_lists").is_none(), "{bob_initial}");
    let carol_initial = sync(&server, &carol, None).await;
    let mut bob_since = next_batch(&bob_initial);
    let mut carol_since = next_batch(&carol_initial);
    let keys_from = bob_since.clone();

    // Alice's key update reaches Bob (shared room) but never Carol.
    upload_device(&server, &alice).await;
    let bob_update = sync(&server, &bob, Some(&bob_since)).await;
    assert_eq!(list(&bob_update["device_lists"]["changed"]), vec![user(&alice).to_owned()]);
    assert_eq!(list(&bob_update["device_lists"]["left"]), Vec::<String>::new());
    let carol_update = sync(&server, &carol, Some(&carol_since)).await;
    assert_eq!(list(&carol_update["device_lists"]["changed"]), Vec::<String>::new(), "{carol_update}");
    bob_since = next_batch(&bob_update);
    carol_since = next_batch(&carol_update);

    // Carol joins the encrypted room: Bob learns Carol now shares it, and
    // Carol learns every member she now shares it with.
    join(&server, &carol, &room).await;
    let bob_join = sync(&server, &bob, Some(&bob_since)).await;
    assert_eq!(list(&bob_join["device_lists"]["changed"]), vec![user(&carol).to_owned()]);
    let carol_join = sync(&server, &carol, Some(&carol_since)).await;
    assert_eq!(
        list(&carol_join["device_lists"]["changed"]),
        vec![user(&alice).to_owned(), user(&bob).to_owned(), user(&carol).to_owned()]
    );
    bob_since = next_batch(&bob_join);
    carol_since = next_batch(&carol_join);

    // Carol leaves: both sides report the departure in `left`.
    leave(&server, &carol, &room).await;
    let bob_left = sync(&server, &bob, Some(&bob_since)).await;
    assert_eq!(list(&bob_left["device_lists"]["left"]), vec![user(&carol).to_owned()]);
    assert_eq!(list(&bob_left["device_lists"]["changed"]), Vec::<String>::new());
    let carol_left = sync(&server, &carol, Some(&carol_since)).await;
    assert_eq!(
        list(&carol_left["device_lists"]["left"]),
        vec![user(&alice).to_owned(), user(&bob).to_owned()]
    );
    carol_since = next_batch(&carol_left);

    // After departure Carol no longer sees Alice's updates.
    upload_device(&server, &alice).await;
    let carol_after = sync(&server, &carol, Some(&carol_since)).await;
    assert_eq!(list(&carol_after["device_lists"]["changed"]), Vec::<String>::new());

    // /keys/changes over Bob's whole window agrees: Alice changed, Carol left.
    let bob_now = next_batch(&sync(&server, &bob, Some(&bob_since)).await);
    let changes = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/keys/changes?from={keys_from}&to={bob_now}"),
            Some(token(&bob)),
            None,
            200,
        )
        .await;
    assert_eq!(list(&changes["changed"]), vec![user(&alice).to_owned()], "{changes}");
    assert_eq!(list(&changes["left"]), vec![user(&carol).to_owned()], "{changes}");
    let carol_changes = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/keys/changes?from={carol_since}&to={}", next_batch(&carol_after)),
            Some(token(&carol)),
            None,
            200,
        )
        .await;
    assert_eq!(list(&carol_changes["changed"]), Vec::<String>::new(), "{carol_changes}");
    let missing = server
        .request(Method::GET, "/_matrix/client/v3/keys/changes", Some(token(&bob)), None, 400)
        .await;
    assert_eq!(missing["errcode"], "M_MISSING_PARAM");
    let invalid = server
        .request(Method::GET, "/_matrix/client/v3/keys/changes?from=bogus", Some(token(&bob)), None, 400)
        .await;
    assert_eq!(invalid["errcode"], "M_INVALID_PARAM");
}

#[tokio::test]
async fn enabling_encryption_marks_existing_members_changed() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let since = next_batch(&sync(&server, &bob, None).await);
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.encryption"),
            Some(token(&alice)),
            Some(json!({"algorithm": "m.megolm.v1.aes-sha2"})),
            200,
        )
        .await;
    let update = sync(&server, &bob, Some(&since)).await;
    assert_eq!(
        list(&update["device_lists"]["changed"]),
        vec![user(&alice).to_owned(), user(&bob).to_owned()]
    );
}

// ---------------------------------------------------------------------------
// conduit-y99.15: threaded receipts and typing authorization
// ---------------------------------------------------------------------------

fn ephemeral<'a>(sync: &'a Value, room: &str, kind: &str) -> Vec<&'a Value> {
    sync["rooms"]["join"][room]["ephemeral"]["events"]
        .as_array()
        .map(|events| events.iter().filter(|event| event["type"] == kind).collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn threaded_and_unthreaded_receipts_coexist() {
    let server = Server::new().await;
    let (alice, bob, room, root) = server.chat_pair().await;
    let reply = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/thread-reply"),
            Some(token(&alice)),
            Some(json!({"msgtype": "m.text", "body": "in thread",
                "m.relates_to": {"rel_type": "m.thread", "event_id": root}})),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let since = next_batch(&sync(&server, &alice, None).await);
    let receipt = |kind: &str, event: &str, body: Option<Value>, status: u16| {
        let server = &server;
        let bob = &bob;
        let path = format!("/_matrix/client/v3/rooms/{room}/receipt/{kind}/{event}");
        async move { server.request(Method::POST, &path, Some(token(bob)), body, status).await }
    };
    // A receipt without any body is unthreaded.
    let response = server
        .http
        .post(format!("{}/_matrix/client/v3/rooms/{room}/receipt/m.read/{root}", server.base_url))
        .bearer_auth(token(&bob))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    receipt("m.read", &root, Some(json!({"thread_id": "main"})), 200).await;
    receipt("m.read", &reply, Some(json!({"thread_id": root})), 200).await;
    // A thread root may also anchor its own thread.
    receipt("m.read.private", &root, Some(json!({"thread_id": root})), 200).await;

    let update = sync(&server, &alice, Some(&since)).await;
    let receipts = ephemeral(&update, &room, "m.receipt");
    assert_eq!(receipts.len(), 3, "one event per thread scope: {update}");
    let unthreaded = receipts
        .iter()
        .find(|event| event["content"][&root]["m.read"][user(&bob)]["thread_id"].is_null()
            && event["content"][&root]["m.read"][user(&bob)].is_object())
        .unwrap_or_else(|| panic!("unthreaded receipt missing: {update}"));
    assert!(unthreaded["content"][&root]["m.read"][user(&bob)]["ts"].is_i64());
    let threads: Vec<_> = receipts
        .iter()
        .flat_map(|event| event["content"].as_object().unwrap().values())
        .filter_map(|by_type| by_type["m.read"][user(&bob)]["thread_id"].as_str())
        .collect();
    assert!(threads.contains(&"main") && threads.contains(&root.as_str()), "{update}");
    // Private receipts never reach other users, threaded or not.
    assert!(!update.to_string().contains("m.read.private"), "{update}");
    let since = next_batch(&update);

    // A new unthreaded receipt replaces only the unthreaded scope.
    receipt("m.read", &reply, None, 200).await;
    let delta = sync(&server, &alice, Some(&since)).await;
    let receipts = ephemeral(&delta, &room, "m.receipt");
    assert_eq!(receipts.len(), 1, "{delta}");
    assert!(receipts[0]["content"][&reply]["m.read"][user(&bob)]["thread_id"].is_null(), "{delta}");

    // Bob sees his own private threaded receipt.
    let own = sync(&server, &bob, None).await;
    assert!(ephemeral(&own, &room, "m.receipt").iter().any(|event| {
        event["content"][&root]["m.read.private"][user(&bob)]["thread_id"] == root
    }), "{own}");

    // Invalid thread scopes and receipt types.
    for (body, kind, event) in [
        (json!({"thread_id": ""}), "m.read", &root),
        (json!({"thread_id": 5}), "m.read", &root),
        (json!({"thread_id": "main"}), "m.read", &reply),
        (json!({"thread_id": "$elsewhere"}), "m.read", &reply),
        (json!({}), "m.bogus", &root),
    ] {
        let rejected = receipt(kind, event, Some(body), 400).await;
        assert_eq!(rejected["errcode"], "M_INVALID_PARAM", "{rejected}");
    }
    assert_eq!(receipt("m.read", &root, Some(json!([])), 400).await["errcode"], "M_BAD_JSON");
    let missing = receipt("m.read", "$missing:production.test", None, 404).await;
    assert_eq!(missing["errcode"], "M_NOT_FOUND");
    let carol = server.register("carol").await;
    let outsider = server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{root}"),
            Some(token(&carol)),
            Some(json!({})),
            403,
        )
        .await;
    assert_eq!(outsider["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn typing_requires_membership_and_validates_timeouts() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let carol = server.register("carol").await;
    let typing = |login: &Value, target: &str, body: Value, status: u16| {
        let server = &server;
        let path = format!("/_matrix/client/v3/rooms/{room}/typing/{target}");
        let token = token(login).to_owned();
        async move { server.request(Method::PUT, &path, Some(&token), Some(body), status).await }
    };
    // Not joined, or typing as someone else.
    assert_eq!(typing(&carol, user(&carol), json!({"typing": true, "timeout": 1000}), 403).await["errcode"], "M_FORBIDDEN");
    assert_eq!(typing(&alice, user(&bob), json!({"typing": true, "timeout": 1000}), 403).await["errcode"], "M_FORBIDDEN");
    // Malformed bodies are Matrix errors, never panics.
    assert_eq!(typing(&alice, user(&alice), json!({"typing": "yes"}), 400).await["errcode"], "M_BAD_JSON");
    assert_eq!(typing(&alice, user(&alice), json!({"typing": true, "timeout": -5}), 400).await["errcode"], "M_BAD_JSON");
    // An enormous timeout is bounded, not an overflow.
    typing(&alice, user(&alice), json!({"typing": true, "timeout": 1e30}), 200).await;
    typing(&bob, user(&bob), json!({"typing": true, "timeout": 18446744073709551615u64}), 200).await;
    let both = sync(&server, &alice, None).await;
    let users = &ephemeral(&both, &room, "m.typing")[0]["content"]["user_ids"];
    assert_eq!(list(users), vec![user(&alice).to_owned(), user(&bob).to_owned()]);
    let since = next_batch(&both);

    // A typer who leaves is no longer reported as typing.
    leave(&server, &bob, &room).await;
    typing(&alice, user(&alice), json!({"typing": true, "timeout": 60000}), 200).await;
    let after = sync(&server, &alice, Some(&since)).await;
    let users = &ephemeral(&after, &room, "m.typing")[0]["content"]["user_ids"];
    assert_eq!(list(users), vec![user(&alice).to_owned()], "{after}");
}

// ---------------------------------------------------------------------------
// conduit-y99.16: commit-ordered stream cursors
// ---------------------------------------------------------------------------

use conduit_server::storage_pg::Stream;

/// Wait until some session is blocked on an advisory lock in this database,
/// or the writer has already finished (which the caller then rejects). A
/// barrier on observable state, not a timing guess.
async fn until_writer_waits(pool: &sqlx::PgPool, writer: &tokio::task::JoinHandle<()>) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if writer.is_finished() {
            return;
        }
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
             AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        if waiting > 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the concurrent writer never queued behind the stream lock"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn postgres_sequences_can_commit_out_of_order_without_the_stream_lock() {
    // The hazard the stream locks exist for: a later position can become
    // visible while an earlier one is still in flight.
    let server = Server::new().await;
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let mut early = pool.begin().await.unwrap();
    let first: i64 =
        sqlx::query_scalar("INSERT INTO device_list_changes (user_id) VALUES ('@early:x') RETURNING id")
            .fetch_one(&mut *early)
            .await
            .unwrap();
    let second: i64 =
        sqlx::query_scalar("INSERT INTO device_list_changes (user_id) VALUES ('@late:x') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(second > first);
    let visible: Vec<i64> = sqlx::query_scalar("SELECT id FROM device_list_changes ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(visible, vec![second], "a reader advancing to {second} would skip {first} forever");
    early.commit().await.unwrap();
}

/// Hold `stream`'s lock with an uncommitted row at a lower position, start a
/// real writer of the same stream, prove it queues behind the lock and that a
/// sync in between does not advance past the in-flight row, then commit and
/// require later syncs to deliver both rows.
#[allow(clippy::too_many_arguments)]
async fn prove_commit_order<F, Fut>(
    server: &Server,
    observer: &Value,
    stream: Stream,
    raw_insert: &str,
    binds: Vec<String>,
    writer: F,
    delivered: impl Fn(&Value) -> bool,
) where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let since = next_batch(&sync(server, observer, None).await);
    let mut held = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(stream.lock_key())
        .execute(&mut *held)
        .await
        .unwrap();
    let mut insert = sqlx::query(raw_insert);
    for bind in &binds {
        insert = insert.bind(bind);
    }
    insert.execute(&mut *held).await.unwrap();

    let write = tokio::spawn(writer());
    until_writer_waits(&pool, &write).await;
    assert!(!write.is_finished(), "{stream:?}: writer must not commit past an in-flight lower position");
    let between = sync(server, observer, Some(&since)).await;
    assert!(
        !delivered(&between),
        "{stream:?}: nothing may be delivered before the lower position commits: {between}"
    );

    held.commit().await.unwrap();
    write.await.unwrap();
    // Every update committed below the returned cursor is delivered from the
    // original token...
    let after = sync(server, observer, Some(&since)).await;
    assert!(delivered(&after), "{stream:?}: both commits must be delivered: {after}");
    // ...and the cursor returned while the writer was queued skips nothing.
    let resumed = sync(server, observer, Some(&next_batch(&between))).await;
    assert!(delivered(&resumed), "{stream:?}: the intermediate cursor skipped a commit: {resumed}");
    pool.close().await;
}

#[tokio::test]
async fn sync_never_skips_events_committed_out_of_order() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let base = server.base_url.clone();
    let http = server.http.clone();
    let alice_token = token(&alice).to_owned();
    let send_room = room.clone();
    prove_commit_order(
        &server,
        &bob,
        Stream::Events,
        "INSERT INTO events (event_id, room_id, sender, type, content, auth_events, prev_events,
             signatures, hashes, origin_server_ts, depth)
         VALUES ($1, $2, $3, 'm.room.message', '{\"msgtype\":\"m.text\",\"body\":\"in flight\"}',
             '{}', '{}', '{}', '{}', 1, 1000)",
        vec!["$inflight:production.test".into(), room.clone(), user(&alice).to_owned()],
        move || async move {
            let response = http
                .put(format!("{base}/_matrix/client/v3/rooms/{send_room}/send/m.room.message/concurrent"))
                .bearer_auth(alice_token)
                .json(&json!({"msgtype": "m.text", "body": "committed later"}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
        },
        |sync| {
            let bodies: Vec<_> = sync["rooms"]["join"][&room]["timeline"]["events"]
                .as_array()
                .map(|events| events.iter().filter_map(|event| event["content"]["body"].as_str()).collect())
                .unwrap_or_default();
            let first = bodies.iter().position(|body| *body == "in flight");
            let second = bodies.iter().position(|body| *body == "committed later");
            matches!((first, second), (Some(first), Some(second)) if first < second)
        },
    )
    .await;
}

#[tokio::test]
async fn sync_never_skips_non_room_streams_committed_out_of_order() {
    let server = Server::new().await;
    let (alice, bob, room, event) = server.chat_pair().await;
    let base = server.base_url.clone();
    let bob_id = user(&bob).to_owned();
    let bob_device = bob["device_id"].as_str().unwrap().to_owned();

    // Account data.
    let (http, bearer) = (server.http.clone(), token(&bob).to_owned());
    let path = format!("{base}/_matrix/client/v3/user/{bob_id}/account_data/m.test.later");
    prove_commit_order(
        &server,
        &bob,
        Stream::AccountData,
        "INSERT INTO account_data (user_id, room_id, event_type, content, updated_at)
         VALUES ($1, NULL, 'm.test.inflight', '{\"v\":1}', now())",
        vec![bob_id.clone()],
        move || async move {
            let response = http.put(path).bearer_auth(bearer).json(&json!({"v": 2})).send().await.unwrap();
            assert_eq!(response.status().as_u16(), 200);
        },
        |sync| {
            let types: Vec<_> = sync["account_data"]["events"]
                .as_array()
                .map(|events| events.iter().filter_map(|event| event["type"].as_str()).collect())
                .unwrap_or_default();
            types.contains(&"m.test.inflight") && types.contains(&"m.test.later")
        },
    )
    .await;

    // Receipts: Alice's in flight, Bob's committed later.
    let (http, bearer) = (server.http.clone(), token(&bob).to_owned());
    let path = format!("{base}/_matrix/client/v3/rooms/{room}/receipt/m.read/{event}");
    let alice_id = user(&alice).to_owned();
    prove_commit_order(
        &server,
        &bob,
        Stream::Receipts,
        "INSERT INTO receipts (room_id, user_id, receipt_type, thread_id, event_id, ts)
         VALUES ($1, $2, 'm.read', '', $3, 1)",
        vec![room.clone(), alice_id.clone(), event.clone()],
        move || async move {
            let response = http.post(path).bearer_auth(bearer).json(&json!({})).send().await.unwrap();
            assert_eq!(response.status().as_u16(), 200);
        },
        |sync| {
            let mut seen = std::collections::HashSet::new();
            for receipt in ephemeral(sync, &room, "m.receipt") {
                if let Some(users) = receipt["content"][&event]["m.read"].as_object() {
                    seen.extend(users.keys().cloned());
                }
            }
            seen.contains(&alice_id) && seen.contains("@bob:production.test")
        },
    )
    .await;

    // Device lists: Alice's change in flight, Bob's own upload later.
    let (http, bearer) = (server.http.clone(), token(&bob).to_owned());
    let upload = json!({"device_keys": Device::from_login(&bob).keys});
    let path = format!("{base}/_matrix/client/v3/keys/upload");
    prove_commit_order(
        &server,
        &bob,
        Stream::DeviceLists,
        "INSERT INTO device_list_changes (user_id) VALUES ($1)",
        vec![user(&alice).to_owned()],
        move || async move {
            let response = http.post(path).bearer_auth(bearer).json(&upload).send().await.unwrap();
            assert_eq!(response.status().as_u16(), 200);
        },
        |sync| {
            sync.get("device_lists").is_some()
                && list(&sync["device_lists"]["changed"])
                    == vec!["@alice:production.test".to_owned(), "@bob:production.test".to_owned()]
        },
    )
    .await;

    // To-device: one message in flight, another sent later.
    let (http, bearer) = (server.http.clone(), token(&alice).to_owned());
    let mut devices = serde_json::Map::new();
    devices.insert(bob_device.clone(), json!({"order": "later"}));
    let mut messages = serde_json::Map::new();
    messages.insert(bob_id.clone(), Value::Object(devices));
    let path = format!("{base}/_matrix/client/v3/sendToDevice/m.test/ordered");
    prove_commit_order(
        &server,
        &bob,
        Stream::ToDevice,
        "INSERT INTO to_device_queue (target_user, target_device, sender, event_type, content)
         VALUES ($1, $2, '@alice:production.test', 'm.test', '{\"order\":\"in flight\"}')",
        vec![bob_id.clone(), bob_device.clone()],
        move || async move {
            let response = http
                .put(path)
                .bearer_auth(bearer)
                .json(&json!({"messages": messages}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
        },
        |sync| {
            let orders: Vec<_> = sync["to_device"]["events"]
                .as_array()
                .map(|events| events.iter().filter_map(|event| event["content"]["order"].as_str()).collect())
                .unwrap_or_default();
            orders == vec!["in flight", "later"]
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// conduit-y99.13.4: summaries, unread counts, lazy redundancy, limit edges
// ---------------------------------------------------------------------------

fn filtered(filter: Value, since: Option<&str>) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("filter", &filter.to_string());
    if let Some(since) = since {
        query.append_pair("since", since);
    }
    format!("/_matrix/client/v3/sync?{}", query.finish())
}

async fn sync_with(server: &Server, login: &Value, filter: Value, since: Option<&str>) -> Value {
    server.request(Method::GET, &filtered(filter, since), Some(token(login)), None, 200).await
}

async fn send_text(server: &Server, login: &Value, room: &str, txn: &str, content: Value) -> String {
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"),
            Some(token(login)),
            Some(content),
            200,
        )
        .await["event_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn state_members(sync: &Value, room: &str) -> Vec<String> {
    let mut members: Vec<String> = sync["rooms"]["join"][room]["state"]["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|event| event["type"] == "m.room.member")
                .filter_map(|event| event["state_key"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    members.sort();
    members
}

#[tokio::test]
async fn room_summary_reports_counts_and_heroes() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let carol = server.register("carol").await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/invite"),
            Some(token(&alice)),
            Some(json!({"user_id": user(&carol)})),
            200,
        )
        .await;
    let initial = sync(&server, &bob, None).await;
    let summary = &initial["rooms"]["join"][&room]["summary"];
    assert_eq!(summary["m.joined_member_count"], 2, "{summary}");
    assert_eq!(summary["m.invited_member_count"], 1, "{summary}");
    // Other joined/invited members in membership order, never the requester.
    assert_eq!(summary["m.heroes"], json!([user(&alice), user(&carol)]), "{summary}");

    // Lazy loading must carry the heroes' memberships.
    let lazy = sync_with(
        &server,
        &bob,
        json!({"room": {"timeline": {"limit": 1}, "state": {"lazy_load_members": true}}}),
        None,
    )
    .await;
    let carol_member = |sync: &Value| {
        let in_timeline = sync["rooms"]["join"][&room]["timeline"]["events"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| event["type"] == "m.room.member" && event["state_key"] == user(&carol)));
        in_timeline || state_members(sync, &room).contains(&user(&carol).to_owned())
    };
    assert!(carol_member(&lazy), "hero membership missing: {lazy}");

    // A named room needs no heroes.
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
            Some(token(&alice)),
            Some(json!({"name": "Planning"})),
            200,
        )
        .await;
    let named = sync(&server, &bob, Some(&next_batch(&initial))).await;
    let summary = &named["rooms"]["join"][&room]["summary"];
    assert!(summary.get("m.heroes").is_none(), "{summary}");
    assert_eq!(summary["m.joined_member_count"], 2);
}

#[tokio::test]
async fn unread_counts_follow_push_rules_receipts_and_threads() {
    let server = Server::new().await;
    let (alice, bob, room, initial_event) = server.chat_pair().await;
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/profile/{}/displayname", user(&bob)),
            Some(token(&bob)),
            Some(json!({"displayname": "Bobby"})),
            200,
        )
        .await;
    let counts = |sync: &Value| sync["rooms"]["join"][&room]["unread_notifications"].clone();

    // The display name change was propagated as Bob's own member event
    // (conduit-y99.25), which reads everything before it, including the
    // initial message.  An m.mentions user mention notifies and highlights
    // (v1.17 removed the display-name body rule, so "hi Bobby" alone is an
    // ordinary message); notices do not notify.
    send_text(
        &server,
        &alice,
        &room,
        "mention",
        json!({"msgtype": "m.text", "body": "hi Bobby", "m.mentions": {"user_ids": [user(&bob)]}}),
    )
    .await;
    send_text(&server, &alice, &room, "notice", json!({"msgtype": "m.notice", "body": "bot"})).await;
    let first = sync(&server, &bob, None).await;
    assert_eq!(counts(&first), json!({"notification_count": 1, "highlight_count": 1}), "{first}");

    // A receipt clears notifications up to and including its event; a
    // private receipt that is further ahead wins.
    let mention = send_text(&server, &alice, &room, "after", json!({"msgtype": "m.text", "body": "later"})).await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{initial_event}"),
            Some(token(&bob)),
            Some(json!({})),
            200,
        )
        .await;
    let partly = sync(&server, &bob, Some(&next_batch(&first))).await;
    assert_eq!(counts(&partly), json!({"notification_count": 2, "highlight_count": 1}), "{partly}");
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read.private/{mention}"),
            Some(token(&bob)),
            Some(json!({})),
            200,
        )
        .await;
    let read = sync(&server, &bob, Some(&next_batch(&partly))).await;
    assert_eq!(counts(&read), json!({"notification_count": 0, "highlight_count": 0}), "{read}");

    // Thread replies are partitioned when the filter asks for it.
    send_text(
        &server,
        &alice,
        &room,
        "thread",
        json!({"msgtype": "m.text", "body": "in a thread",
            "m.relates_to": {"rel_type": "m.thread", "event_id": initial_event}}),
    )
    .await;
    let threaded_filter = json!({"room": {"timeline": {"unread_thread_notifications": true}}});
    let threaded = sync_with(&server, &bob, threaded_filter.clone(), None).await;
    let block = &threaded["rooms"]["join"][&room];
    assert_eq!(block["unread_notifications"]["notification_count"], 0, "{block}");
    assert_eq!(block["unread_thread_notifications"][&initial_event]["notification_count"], 1, "{block}");
    let whole = sync(&server, &bob, Some(&next_batch(&read))).await;
    assert_eq!(counts(&whole)["notification_count"], 1, "{whole}");
    assert!(whole["rooms"]["join"][&room].get("unread_thread_notifications").is_none());

    // Bob's own reply in the thread marks the thread read.
    send_text(
        &server,
        &bob,
        &room,
        "reply",
        json!({"msgtype": "m.text", "body": "replying",
            "m.relates_to": {"rel_type": "m.thread", "event_id": initial_event}}),
    )
    .await;
    let after_reply = sync_with(&server, &bob, threaded_filter, None).await;
    let block = &after_reply["rooms"]["join"][&room];
    assert!(block["unread_thread_notifications"][&initial_event].is_null()
        || block["unread_thread_notifications"][&initial_event]["notification_count"] == 0, "{block}");
}

#[tokio::test]
async fn lazy_loading_skips_redundant_members_unless_asked() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.name"),
            Some(token(&alice)),
            Some(json!({"name": "Lazy"})),
            200,
        )
        .await;
    let lazy = json!({"room": {"timeline": {"limit": 1}, "state": {"lazy_load_members": true}}});
    let redundant = json!({"room": {"timeline": {"limit": 1}, "state": {"lazy_load_members": true, "include_redundant_members": true}}});
    let initial = sync_with(&server, &bob, lazy.clone(), None).await;
    assert_eq!(state_members(&initial, &room), vec![user(&alice).to_owned(), user(&bob).to_owned()]);
    let since = next_batch(&initial);

    send_text(&server, &alice, &room, "again", json!({"msgtype": "m.text", "body": "again"})).await;
    let quiet = sync_with(&server, &bob, lazy.clone(), Some(&since)).await;
    assert_eq!(state_members(&quiet, &room), Vec::<String>::new(), "already-sent members are redundant: {quiet}");
    let full = sync_with(&server, &bob, redundant, Some(&since)).await;
    assert!(state_members(&full, &room).contains(&user(&alice).to_owned()), "{full}");

    // A new sender's membership is sent; if that response is lost and the
    // client retries from the older token, it is sent again.
    let carol = server.register("carol").await;
    join(&server, &carol, &room).await;
    send_text(&server, &carol, &room, "carol", json!({"msgtype": "m.text", "body": "hello"})).await;
    let first_try = sync_with(&server, &bob, lazy.clone(), Some(&since)).await;
    let carol_seen = |sync: &Value| {
        state_members(sync, &room).contains(&user(&carol).to_owned())
            || sync["rooms"]["join"][&room]["timeline"]["events"]
                .as_array()
                .is_some_and(|events| events.iter().any(|event| event["type"] == "m.room.member" && event["state_key"] == user(&carol)))
    };
    assert!(carol_seen(&first_try), "{first_try}");
    let retry = sync_with(&server, &bob, lazy.clone(), Some(&since)).await;
    assert!(carol_seen(&retry), "a lost response must not make members redundant: {retry}");
    // Once the client has moved past that response, Carol is redundant.
    send_text(&server, &carol, &room, "carol2", json!({"msgtype": "m.text", "body": "again"})).await;
    let later = sync_with(&server, &bob, lazy, Some(&next_batch(&retry))).await;
    assert!(!state_members(&later, &room).contains(&user(&carol).to_owned()), "{later}");
}

#[tokio::test]
async fn limited_ephemeral_and_state_windows_make_progress() {
    let server = Server::new().await;
    let (alice, bob, room, root) = server.chat_pair().await;
    let reply = send_text(
        &server,
        &alice,
        &room,
        "reply",
        json!({"msgtype": "m.text", "body": "thread", "m.relates_to": {"rel_type": "m.thread", "event_id": root}}),
    )
    .await;
    let start = next_batch(&sync(&server, &alice, None).await);
    for (thread, event) in [(None, &root), (Some("main"), &root), (Some(root.as_str()), &reply)] {
        let body = thread.map(|thread| json!({"thread_id": thread})).unwrap_or(json!({}));
        server
            .request(
                Method::POST,
                &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{event}"),
                Some(token(&bob)),
                Some(body),
                200,
            )
            .await;
    }
    // With one ephemeral event per room, the three receipt scopes arrive
    // over three syncs instead of being held forever.
    let filter = json!({"room": {"ephemeral": {"limit": 1}}});
    let mut since = start;
    let mut scopes = Vec::new();
    for _ in 0..3 {
        let response = sync_with(&server, &alice, filter.clone(), Some(&since)).await;
        let receipts = ephemeral(&response, &room, "m.receipt");
        assert_eq!(receipts.len(), 1, "{response}");
        scopes.push(receipts[0].to_string());
        since = next_batch(&response);
    }
    let rest = sync_with(&server, &alice, filter, Some(&since)).await;
    assert!(ephemeral(&rest, &room, "m.receipt").is_empty(), "{rest}");
    assert!(scopes.iter().any(|scope| scope.contains("\"main\"")) && scopes.iter().any(|scope| scope.contains(&root)));

    // A state limit trims the least necessary state: with lazy loading the
    // kept events are the members the timeline needs.
    let trimmed = sync_with(
        &server,
        &alice,
        json!({"room": {"timeline": {"limit": 1}, "state": {"limit": 2, "lazy_load_members": true}}}),
        None,
    )
    .await;
    let state = trimmed["rooms"]["join"][&room]["state"]["events"].as_array().unwrap();
    assert_eq!(state.len(), 2, "{trimmed}");
    assert!(state.iter().all(|event| event["type"] == "m.room.member"), "{trimmed}");
}

#[tokio::test]
async fn key_inventory_fields_are_always_present() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let device = Device::from_login(&alice);
    let initial = sync(&server, &alice, None).await;
    assert_eq!(initial["device_one_time_keys_count"], json!({}));
    assert_eq!(initial["device_unused_fallback_key_types"], json!([]));
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/keys/upload",
            Some(token(&alice)),
            Some(json!({
                "device_keys": device.keys,
                "one_time_keys": {"signed_curve25519:A": device.signed_key("YQ", false), "signed_curve25519:B": device.signed_key("Yg", false)},
                "fallback_keys": {"signed_curve25519:F": device.signed_key("Zg", true)},
            })),
            200,
        )
        .await;
    let after = sync(&server, &alice, Some(&next_batch(&initial))).await;
    assert_eq!(after["device_one_time_keys_count"], json!({"signed_curve25519": 2}));
    assert_eq!(after["device_unused_fallback_key_types"], json!(["signed_curve25519"]));
}

// ---------------------------------------------------------------------------
// conduit-y99.27 / .26 / .47
// ---------------------------------------------------------------------------

fn timeline<'a>(sync: &'a Value, room: &str) -> Vec<&'a Value> {
    sync["rooms"]["join"][room]["timeline"]["events"]
        .as_array()
        .map(|events| events.iter().collect())
        .unwrap_or_default()
}

#[tokio::test]
async fn only_the_sending_device_sees_its_transaction_id() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let other_device = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "test-password"})),
            200,
        )
        .await;
    let since_alice = next_batch(&sync(&server, &alice, None).await);
    let since_other = next_batch(&sync(&server, &other_device, None).await);
    let since_bob = next_batch(&sync(&server, &bob, None).await);
    let event = send_text(&server, &alice, &room, "local-echo-1", json!({"msgtype": "m.text", "body": "echo"})).await;
    let find = |sync: &Value| -> Value {
        timeline(sync, &room)
            .into_iter()
            .find(|candidate| candidate["event_id"] == event)
            .cloned()
            .unwrap_or_else(|| panic!("event missing: {sync}"))
    };
    let own = find(&sync(&server, &alice, Some(&since_alice)).await);
    assert_eq!(own["unsigned"]["transaction_id"], "local-echo-1", "{own}");
    let other = find(&sync(&server, &other_device, Some(&since_other)).await);
    assert!(other["unsigned"]["transaction_id"].is_null(), "{other}");
    let peer = find(&sync(&server, &bob, Some(&since_bob)).await);
    assert!(peer["unsigned"]["transaction_id"].is_null(), "{peer}");
    // Initial sync on the sending device carries it too.
    let initial = find(&sync(&server, &alice, None).await);
    assert_eq!(initial["unsigned"]["transaction_id"], "local-echo-1");
}

#[tokio::test]
async fn back_pagination_reaches_the_room_creation_under_any_visibility() {
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    for visibility in ["shared", "joined", "invited"] {
        let room = server
            .request(
                Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(token(&alice)),
                Some(json!({"preset": "public_chat", "initial_state": [{
                    "type": "m.room.history_visibility", "state_key": "",
                    "content": {"history_visibility": visibility}}]})),
                200,
            )
            .await["room_id"]
            .as_str()
            .unwrap()
            .to_owned();
        join(&server, &bob, &room).await;
        send_text(&server, &alice, &room, "m", json!({"msgtype": "m.text", "body": "hello"})).await;
        // Page backwards to the start as the creator.
        let mut from: Option<String> = None;
        let mut seen = Vec::new();
        loop {
            let path = match &from {
                Some(from) => format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=3&from={from}"),
                None => format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=3"),
            };
            let page = server.request(Method::GET, &path, Some(token(&alice)), None, 200).await;
            for event in page["chunk"].as_array().unwrap() {
                seen.push((event["type"].as_str().unwrap().to_owned(), event["state_key"].as_str().map(str::to_owned)));
            }
            match page.get("end") {
                Some(end) => {
                    assert!(end.as_str().is_some_and(|end| !end.is_empty()), "end must be a token or omitted: {page}");
                    from = Some(end.as_str().unwrap().to_owned());
                }
                None => break,
            }
            assert!(seen.len() < 100, "pagination did not terminate");
        }
        assert!(seen.contains(&("m.room.create".to_owned(), Some(String::new()))), "{visibility}: {seen:?}");
        assert!(seen.contains(&("m.room.member".to_owned(), Some(user(&alice).to_owned()))), "{visibility}: {seen:?}");
        assert_eq!(seen.last().unwrap().0, "m.room.create", "{visibility}: {seen:?}");
    }
}

#[tokio::test]
async fn state_paths_accept_an_optional_trailing_slash_for_empty_keys() {
    let server = Server::new().await;
    let (alice, _bob, room, _) = server.chat_pair().await;
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic/"),
            Some(token(&alice)),
            Some(json!({"topic": "With slash"})),
            200,
        )
        .await;
    for path in [
        format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic"),
        format!("/_matrix/client/v3/rooms/{room}/state/m.room.topic/"),
    ] {
        let topic = server.request(Method::GET, &path, Some(token(&alice)), None, 200).await;
        assert_eq!(topic["topic"], "With slash", "{path}");
    }
    // Explicit non-empty keys are unaffected.
    server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{}", user(&alice)),
            Some(token(&alice)),
            None,
            200,
        )
        .await;
}
