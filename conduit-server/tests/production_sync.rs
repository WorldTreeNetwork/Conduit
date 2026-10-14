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
