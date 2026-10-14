//! Unattended HTTP journeys through the shipped binary and real PostgreSQL.
//! Every test owns its process, database, port, logs, and media directory.
//! PostgreSQL and `psql` are required; failures are never silently skipped.

use std::fs::File;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::{Client, Method};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tempfile::TempDir;

struct Server {
    child: Option<Child>,
    files: TempDir,
    admin_url: String,
    database_url: String,
    database_name: String,
    base_url: String,
    http: Client,
}

impl Server {
    async fn chat_pair(&self) -> (Value, Value, String, String) {
        let alice = self.register("alice").await;
        let bob = self.register("bob").await;
        let alice_token = alice["access_token"].as_str().unwrap();
        let bob_token = bob["access_token"].as_str().unwrap();
        let room = self
            .request(
                Method::POST,
                "/_matrix/client/v3/createRoom",
                Some(alice_token),
                Some(json!({"preset": "public_chat"})),
                200,
            )
            .await;
        let room_id = room["room_id"].as_str().unwrap().to_owned();
        self.request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{room_id}"),
            Some(bob_token),
            Some(json!({})),
            200,
        )
        .await;
        let event = self
            .request(
                Method::PUT,
                &format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/initial"),
                Some(alice_token),
                Some(json!({"msgtype": "m.text", "body": "Initial message"})),
                200,
            )
            .await;
        (
            alice,
            bob,
            room_id,
            event["event_id"].as_str().unwrap().to_owned(),
        )
    }

    async fn new() -> Self {
        let files = tempfile::tempdir().unwrap();
        let admin_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres@localhost/postgres".into());
        let database_name = format!("conduit_test_production_{}", uuid::Uuid::new_v4().simple());
        let mut database_url = url::Url::parse(&admin_url).unwrap();
        database_url.set_path(&format!("/{database_name}"));
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&admin_url)
            .await
            .expect("production e2e requires PostgreSQL with CREATE DATABASE permission");
        sqlx::query(&format!("CREATE DATABASE {database_name}"))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let mut server = Self {
            child: None,
            files,
            admin_url,
            database_url: database_url.to_string(),
            database_name,
            base_url: String::new(),
            http: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        };
        server.start().await;
        server
    }

    async fn start(&mut self) {
        let ready = self.files.path().join("ready.json");
        if ready.exists() {
            std::fs::remove_file(&ready).unwrap();
        }
        self.launch("127.0.0.1:0", &ready);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                panic!("production server exited {status}: {}", self.logs());
            }
            if let Ok(bytes) = std::fs::read(&ready) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(address) = value["address"].as_str() {
                        let address: std::net::SocketAddr = address.parse().unwrap();
                        assert!(address.ip().is_loopback());
                        assert_ne!(address.port(), 0);
                        self.base_url = format!("http://{address}");
                        if let Ok(response) = self
                            .http
                            .get(format!("{}/health", self.base_url))
                            .send()
                            .await
                        {
                            if response.status().is_success() {
                                assert_eq!(response.text().await.unwrap(), "ok");
                                return;
                            }
                        }
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "production startup timed out: {}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn launch(&mut self, listen_addr: &str, ready: &std::path::Path) {
        self.launch_with_ca(listen_addr, ready, None);
    }

    fn launch_with_ca(
        &mut self,
        listen_addr: &str,
        ready: &std::path::Path,
        ca: Option<&std::path::Path>,
    ) {
        let log = File::create(self.files.path().join("server.log")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_conduit-server"));
        command.env_remove("CONDUIT_TLS_CA");
        if let Some(path) = ca {
            command.env("CONDUIT_TLS_CA", path);
        }
        self.child = Some(
            command
                .current_dir(self.files.path())
                .env("DATABASE_URL", &self.database_url)
                .env("CONDUIT_SERVER_NAME", "production.test")
                .env("CONDUIT_LISTEN_ADDR", listen_addr)
                .env("CONDUIT_READY_FILE", ready)
                .env("CONDUIT_MEDIA_ROOT", self.files.path().join("media"))
                .env("CONDUIT_OIDC_ISSUER", "off")
                .env("CONDUIT_FEDERATION", "0")
                .env_remove("CONDUIT_REMOTE_KEYS_OVERRIDE")
                .env(
                    "CONDUIT_AS_REGISTRATIONS_DIR",
                    self.files.path().join("app-services"),
                )
                .env("RUST_LOG", "info")
                .stdin(Stdio::null())
                .stderr(log.try_clone().unwrap())
                .stdout(log)
                .spawn()
                .unwrap(),
        );
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(self.files.path().join("server.log")).unwrap_or_default()
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            child.wait().expect("reap production server");
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
        status: u16,
    ) -> Value {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base_url));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let actual = response.status().as_u16();
        let text = response.text().await.unwrap();
        assert_eq!(
            actual,
            status,
            "{path}: {text}; server log: {}",
            self.logs()
        );
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{path}: invalid JSON: {error}: {text}"))
    }

    async fn register(&self, username: &str) -> Value {
        let challenge = self
            .request(
                Method::POST,
                "/_matrix/client/v3/register",
                None,
                Some(json!({"username": username, "password": "test-password"})),
                401,
            )
            .await;
        assert!(challenge["flows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|flow| flow["stages"] == json!(["m.login.dummy"])));
        self.request(
            Method::POST,
            "/_matrix/client/v3/register",
            None,
            Some(json!({
                "username": username, "password": "test-password",
                "auth": {"type": "m.login.dummy", "session": challenge["session"]}
            })),
            200,
        )
        .await
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
        let result = Command::new("psql")
            .args([
                "--no-psqlrc",
                &self.admin_url,
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                &format!("DROP DATABASE {} WITH (FORCE)", self.database_name),
            ])
            .stdin(Stdio::null())
            .output();
        match result {
            Ok(output) if output.status.success() => {}
            result => eprintln!(
                "failed to clean production test database {}: {result:?}",
                self.database_name
            ),
        }
    }
}

#[tokio::test]
async fn production_chat_survives_restart() {
    let mut server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let keys_before = server
        .request(Method::GET, "/_matrix/key/v2/server", None, None, 200)
        .await;

    let flows = server
        .request(Method::GET, "/_matrix/client/v3/login", None, None, 200)
        .await;
    assert!(flows["flows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|flow| flow["type"] == "m.login.password"));
    let login = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password", "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "test-password", "device_id": "SECOND"
            })),
            200,
        )
        .await;
    assert_eq!(login["user_id"], alice["user_id"]);

    server
        .request(
            Method::PUT,
            "/_matrix/client/v3/profile/@alice:production.test/displayname",
            Some(alice_token),
            Some(json!({"displayname": "Alice 世界"})),
            200,
        )
        .await;
    let profile = server
        .request(
            Method::GET,
            "/_matrix/client/v3/profile/@alice:production.test/displayname",
            None,
            None,
            200,
        )
        .await;
    assert_eq!(profile["displayname"], "Alice 世界");

    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(alice_token),
            Some(json!({"preset": "public_chat", "name": "Unattended chat"})),
            200,
        )
        .await;
    let room_id = room["room_id"].as_str().unwrap();
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{room_id}"),
            Some(bob_token),
            Some(json!({})),
            200,
        )
        .await;
    let initial = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    let since = initial["next_batch"].as_str().unwrap();
    let send_path = format!("/_matrix/client/v3/rooms/{room_id}/send/m.room.message/txn1");
    let content = json!({"msgtype": "m.text", "body": "Hello, 世界"});
    let sent = server
        .request(
            Method::PUT,
            &send_path,
            Some(alice_token),
            Some(content.clone()),
            200,
        )
        .await;
    let retry = server
        .request(
            Method::PUT,
            &send_path,
            Some(alice_token),
            Some(content.clone()),
            200,
        )
        .await;
    assert_eq!(retry["event_id"], sent["event_id"]);
    let sync = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?since={since}&timeout=0"),
            Some(bob_token),
            None,
            200,
        )
        .await;
    let timeline = sync["rooms"]["join"][room_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    let matches: Vec<_> = timeline
        .iter()
        .filter(|event| event["event_id"] == sent["event_id"])
        .collect();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["content"], content);
    assert_eq!(matches[0]["sender"], alice["user_id"]);

    for path in [
        "/_matrix/federation/v2/send_join/!room:production.test/$join",
        "/_matrix/federation/v2/invite/!room:production.test/$invite",
    ] {
        let response = server
            .request(Method::PUT, path, None, Some(json!({})), 401)
            .await;
        assert_eq!(response["errcode"], "M_UNAUTHORIZED");
    }

    server.stop();
    server.start().await;
    let keys_after = server
        .request(Method::GET, "/_matrix/key/v2/server", None, None, 200)
        .await;
    assert_eq!(keys_before["verify_keys"], keys_after["verify_keys"]);
    let whoami = server
        .request(
            Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(bob_token),
            None,
            200,
        )
        .await;
    assert_eq!(whoami["user_id"], bob["user_id"]);
    let sync = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    let timeline = sync["rooms"]["join"][room_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert!(timeline
        .iter()
        .any(|event| event["event_id"] == sent["event_id"] && event["content"] == content));

    server
        .request(
            Method::POST,
            "/_matrix/client/v3/logout",
            Some(bob_token),
            Some(json!({})),
            200,
        )
        .await;
    let rejected = server
        .request(
            Method::GET,
            "/_matrix/client/v3/account/whoami",
            Some(bob_token),
            None,
            401,
        )
        .await;
    assert_eq!(rejected["errcode"], "M_UNKNOWN_TOKEN");
}

#[tokio::test]
async fn production_to_device_sync_retries_until_acknowledged() {
    let mut server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();

    // Advance the independent key-change stream beyond the first queue ID.
    for _ in 0..3 {
        server
            .request(
                Method::POST,
                "/_matrix/client/v3/keys/upload",
                Some(alice_token),
                Some(json!({"device_keys": {
                    "user_id": alice["user_id"], "device_id": alice["device_id"],
                    "algorithms": [], "keys": {}, "signatures": {}
                }})),
                200,
            )
            .await;
    }
    let initial = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    let since = initial["next_batch"].as_str().unwrap();
    let content = json!({"transaction_id": "verify-1", "message": "Verification request"});
    let mut devices = serde_json::Map::new();
    devices.insert(
        bob["device_id"].as_str().unwrap().to_owned(),
        content.clone(),
    );
    let mut messages = serde_json::Map::new();
    messages.insert(
        bob["user_id"].as_str().unwrap().to_owned(),
        Value::Object(devices),
    );
    server
        .request(
            Method::PUT,
            "/_matrix/client/v3/sendToDevice/m.test/verify-1",
            Some(alice_token),
            Some(json!({"messages": messages})),
            200,
        )
        .await;

    let path = format!("/_matrix/client/v3/sync?since={since}&timeout=4000");
    let started = Instant::now();
    let received = server
        .request(Method::GET, &path, Some(bob_token), None, 200)
        .await;
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "pending to-device messages waited for timeout"
    );
    let expected = json!([{"type": "m.test", "sender": alice["user_id"], "content": content}]);
    assert_eq!(received["to_device"]["events"], expected);
    let retry = server
        .request(Method::GET, &path, Some(bob_token), None, 200)
        .await;
    assert_eq!(
        retry["to_device"]["events"], expected,
        "retry must not lose unacknowledged messages"
    );

    // Queue delivery and acknowledgement survive a real process restart.
    server.stop();
    server.start().await;
    let retry = server
        .request(Method::GET, &path, Some(bob_token), None, 200)
        .await;
    assert_eq!(retry["to_device"]["events"], expected);

    // A message arriving after delivery must survive acknowledgement of the
    // earlier batch. Use the wildcard device form required by Matrix clients.
    let later = json!({"transaction_id": "verify-2"});
    let mut messages = serde_json::Map::new();
    messages.insert(
        bob["user_id"].as_str().unwrap().to_owned(),
        json!({"*": later}),
    );
    server
        .request(
            Method::PUT,
            "/_matrix/client/v3/sendToDevice/m.test/verify-2",
            Some(alice_token),
            Some(json!({"messages": messages})),
            200,
        )
        .await;
    let next = received["next_batch"].as_str().unwrap();
    let acknowledged = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?since={next}&timeout=0"),
            Some(bob_token),
            None,
            200,
        )
        .await;
    assert_eq!(
        acknowledged["to_device"]["events"],
        json!([{
            "type": "m.test", "sender": alice["user_id"], "content": later
        }])
    );
    let next = acknowledged["next_batch"].as_str().unwrap();
    let acknowledged = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?since={next}&timeout=0"),
            Some(bob_token),
            None,
            200,
        )
        .await;
    assert_eq!(acknowledged["to_device"]["events"], json!([]));
    let full = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    assert_eq!(
        full["to_device"]["events"],
        json!([]),
        "acknowledged queue records must be removed"
    );
}

#[tokio::test]
async fn production_startup_rejects_invalid_hooks() {
    let mut server = Server::new().await;
    server.stop();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied_addr = occupied.local_addr().unwrap().to_string();
    let ready_file = server.files.path().join("invalid-startup-ready.json");
    let ready_directory = server.files.path().to_owned();
    for (address, ready) in [
        ("invalid-address", ready_file.as_path()),
        (occupied_addr.as_str(), ready_file.as_path()),
        ("127.0.0.1:0", ready_directory.as_path()),
    ] {
        let ready = ready.to_owned();
        server.launch(address, &ready);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = server.child.as_mut().unwrap().try_wait().unwrap() {
                assert!(
                    !status.success(),
                    "invalid hook configuration must fail startup"
                );
                server.child.take();
                break;
            }
            assert!(
                Instant::now() < deadline,
                "invalid startup did not fail: {}",
                server.logs()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[tokio::test]
async fn production_long_poll_wakes_for_each_non_room_stream() {
    let server = Server::new().await;
    let (alice, bob, room, event) = server.chat_pair().await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let updates = [
        (
            Method::PUT,
            "/_matrix/client/v3/sendToDevice/m.test/poll".to_owned(),
            alice_token,
            json!({"messages": {"@bob:production.test": {"*": {"body": "Wake verification"}}}}),
            "to_device",
        ),
        (
            Method::POST,
            "/_matrix/client/v3/keys/upload".to_owned(),
            alice_token,
            json!({"device_keys": {"user_id": alice["user_id"], "device_id": alice["device_id"], "algorithms": [], "keys": {}, "signatures": {}}}),
            "device_lists",
        ),
        (
            Method::PUT,
            "/_matrix/client/v3/user/@bob:production.test/account_data/m.test".to_owned(),
            bob_token,
            json!({"value": "global"}),
            "account_data",
        ),
        (
            Method::PUT,
            format!(
                "/_matrix/client/v3/user/@bob:production.test/rooms/{room}/account_data/m.test"
            ),
            bob_token,
            json!({"value": "room"}),
            "room_account_data",
        ),
        (
            Method::POST,
            format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{event}"),
            alice_token,
            json!({}),
            "receipt",
        ),
        (
            Method::PUT,
            format!("/_matrix/client/v3/rooms/{room}/typing/@alice:production.test"),
            alice_token,
            json!({"typing": true, "timeout": 10_000}),
            "typing_start",
        ),
        (
            Method::PUT,
            format!("/_matrix/client/v3/rooms/{room}/typing/@alice:production.test"),
            alice_token,
            json!({"typing": false}),
            "typing_stop",
        ),
        (
            Method::PUT,
            "/_matrix/client/v3/presence/@alice:production.test/status".to_owned(),
            alice_token,
            json!({"presence": "online", "status_msg": "Available"}),
            "presence",
        ),
    ];
    for (method, path, token, body, stream) in updates {
        let baseline = server
            .request(
                Method::GET,
                "/_matrix/client/v3/sync",
                Some(bob_token),
                None,
                200,
            )
            .await;
        let since = baseline["next_batch"].as_str().unwrap();
        let http = server.http.clone();
        let url = format!(
            "{}/_matrix/client/v3/sync?since={since}&timeout=4000",
            server.base_url
        );
        let access_token = bob_token.to_owned();
        let poll = tokio::spawn(async move {
            let response = http
                .get(url)
                .bearer_auth(access_token)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
            response.json::<Value>().await.unwrap()
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !poll.is_finished(),
            "{stream}: unchanged data must not finish the poll"
        );
        server
            .request(method, &path, Some(token), Some(body), 200)
            .await;
        let sync = tokio::time::timeout(Duration::from_secs(2), poll)
            .await
            .unwrap_or_else(|_| panic!("{stream}: update did not wake the production long-poll"))
            .unwrap();
        let block = &sync["rooms"]["join"][&room];
        match stream {
            "to_device" => assert_eq!(
                sync["to_device"]["events"][0]["content"]["body"],
                "Wake verification"
            ),
            "device_lists" => assert!(sync["device_lists"]["changed"]
                .as_array()
                .unwrap()
                .contains(&alice["user_id"])),
            "account_data" => assert_eq!(
                sync["account_data"]["events"][0]["content"]["value"],
                "global"
            ),
            "room_account_data" => assert_eq!(
                block["account_data"]["events"][0]["content"]["value"],
                "room"
            ),
            "receipt" => assert!(block["ephemeral"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["type"] == "m.receipt")),
            "typing_start" | "typing_stop" => {
                let event = block["ephemeral"]["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|event| event["type"] == "m.typing")
                    .unwrap();
                let expected = if stream == "typing_start" {
                    json!([alice["user_id"]])
                } else {
                    json!([])
                };
                assert_eq!(event["content"]["user_ids"], expected);
            }
            "presence" => assert_eq!(
                sync["presence"]["events"][0]["content"]["status_msg"],
                "Available"
            ),
            _ => unreachable!(),
        }
        assert_ne!(
            sync["next_batch"], baseline["next_batch"],
            "{stream}: independent cursor must advance"
        );
    }
}

#[tokio::test]
async fn production_account_data_overwrites_advance_real_cursors_without_replay() {
    let server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    // Create stream gaps through another user's writes and updates to one row.
    for value in 0..5 {
        server
            .request(
                Method::PUT,
                "/_matrix/client/v3/user/@alice:production.test/account_data/m.test",
                Some(alice_token),
                Some(json!({"value": value})),
                200,
            )
            .await;
    }
    let baseline = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    let mut since = baseline["next_batch"].as_str().unwrap().to_owned();
    for (scope, path) in [
        (
            "global",
            "/_matrix/client/v3/user/@bob:production.test/account_data/m.test".to_owned(),
        ),
        (
            "room",
            format!(
                "/_matrix/client/v3/user/@bob:production.test/rooms/{room}/account_data/m.test"
            ),
        ),
    ] {
        for value in 1..=2 {
            server
                .request(
                    Method::PUT,
                    &path,
                    Some(bob_token),
                    Some(json!({"scope": scope, "value": value})),
                    200,
                )
                .await;
            let response = server
                .request(
                    Method::GET,
                    &format!("/_matrix/client/v3/sync?since={since}"),
                    Some(bob_token),
                    None,
                    200,
                )
                .await;
            let events = if scope == "global" {
                &response["account_data"]["events"]
            } else {
                &response["rooms"]["join"][&room]["account_data"]["events"]
            };
            assert_eq!(
                events,
                &json!([{"type": "m.test", "content": {"scope": scope, "value": value}}])
            );
            since = response["next_batch"].as_str().unwrap().to_owned();
            let quiet = server
                .request(
                    Method::GET,
                    &format!("/_matrix/client/v3/sync?since={since}"),
                    Some(bob_token),
                    None,
                    200,
                )
                .await;
            assert_eq!(quiet["account_data"]["events"], json!([]));
            assert!(
                quiet["rooms"]["join"].as_object().unwrap().is_empty(),
                "unchanged room account data was replayed: {quiet}"
            );
        }
    }
}

#[tokio::test]
async fn production_typing_expiry_and_restart_clear_client_state() {
    let mut server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let path = format!("/_matrix/client/v3/rooms/{room}/typing/@alice:production.test");
    for timeout in [500, 10_000] {
        server
            .request(
                Method::PUT,
                &path,
                Some(alice_token),
                Some(json!({"typing": true, "timeout": timeout})),
                200,
            )
            .await;
        let initial = server
            .request(
                Method::GET,
                "/_matrix/client/v3/sync",
                Some(bob_token),
                None,
                200,
            )
            .await;
        let typing = initial["rooms"]["join"][&room]["ephemeral"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "m.typing")
            .unwrap();
        assert_eq!(typing["content"]["user_ids"], json!([alice["user_id"]]));
        let since = initial["next_batch"].as_str().unwrap();
        if timeout == 10_000 {
            server.stop();
            server.start().await;
        }
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            server.request(
                Method::GET,
                &format!("/_matrix/client/v3/sync?since={since}&timeout=4000"),
                Some(bob_token),
                None,
                200,
            ),
        )
        .await
        .expect("expiry/restart must promptly clear typing state");
        let typing = response["rooms"]["join"][&room]["ephemeral"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "m.typing")
            .unwrap();
        assert_eq!(typing["content"]["user_ids"], json!([]));
    }
}

#[tokio::test]
async fn production_receipt_overwrites_and_presence_respect_privacy() {
    let server = Server::new().await;
    let (alice, bob, room, first) = server.chat_pair().await;
    let outsider = server.register("outsider").await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let outsider_token = outsider["access_token"].as_str().unwrap();
    for (user, token) in [(&alice, alice_token), (&outsider, outsider_token)] {
        server
            .request(
                Method::PUT,
                &format!(
                    "/_matrix/client/v3/presence/{}/status",
                    user["user_id"].as_str().unwrap()
                ),
                Some(token),
                Some(json!({"presence": "online", "status_msg": "Private status"})),
                200,
            )
            .await;
    }
    let presence_path = "/_matrix/client/v3/presence/@alice:production.test/status";
    server
        .request(Method::GET, presence_path, None, None, 401)
        .await;
    server
        .request(Method::GET, presence_path, Some(outsider_token), None, 403)
        .await;
    let allowed = server
        .request(Method::GET, presence_path, Some(bob_token), None, 200)
        .await;
    assert_eq!(allowed["presence"], "online");
    server
        .request(
            Method::GET,
            "/_matrix/client/v3/presence/@outsider:production.test/status",
            Some(outsider_token),
            None,
            200,
        )
        .await;
    let second = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/second"),
            Some(alice_token),
            Some(json!({"msgtype": "m.text", "body": "Second"})),
            200,
        )
        .await;
    let initial = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    let presence = initial["presence"]["events"].as_array().unwrap();
    assert!(presence
        .iter()
        .any(|event| event["sender"] == alice["user_id"]));
    assert!(!presence
        .iter()
        .any(|event| event["sender"] == outsider["user_id"]));
    // An unrelated presence change is a wake hint, not visible sync data, and
    // must not reset the requested deadline or return another user's status.
    let http = server.http.clone();
    let url = format!(
        "{}/_matrix/client/v3/sync?since={}&timeout=500",
        server.base_url,
        initial["next_batch"].as_str().unwrap()
    );
    let token = bob_token.to_owned();
    let started = Instant::now();
    let poll = tokio::spawn(async move {
        http.get(url)
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !poll.is_finished(),
        "unchanged visible presence must not complete the poll"
    );
    server
        .request(
            Method::PUT,
            "/_matrix/client/v3/presence/@outsider:production.test/status",
            Some(outsider_token),
            Some(json!({"presence": "unavailable"})),
            200,
        )
        .await;
    let quiet = tokio::time::timeout(Duration::from_secs(2), poll)
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(400));
    assert_eq!(quiet["presence"]["events"], json!([]));
    let mut since = initial["next_batch"].as_str().unwrap().to_owned();
    for event_id in [&first, second["event_id"].as_str().unwrap()] {
        // Multiple users reading one event must coexist in the receipt map.
        for token in [alice_token, bob_token] {
            server
                .request(
                    Method::POST,
                    &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read/{event_id}"),
                    Some(token),
                    Some(json!({})),
                    200,
                )
                .await;
        }
        server
            .request(
                Method::POST,
                &format!("/_matrix/client/v3/rooms/{room}/receipt/m.read.private/{event_id}"),
                Some(alice_token),
                Some(json!({})),
                200,
            )
            .await;
        let response = server
            .request(
                Method::GET,
                &format!("/_matrix/client/v3/sync?since={since}"),
                Some(bob_token),
                None,
                200,
            )
            .await;
        let receipt = response["rooms"]["join"][&room]["ephemeral"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event["type"] == "m.receipt")
            .unwrap();
        assert!(receipt["content"][event_id]["m.read"]
            .get("@alice:production.test")
            .is_some());
        assert!(receipt["content"][event_id]["m.read"]
            .get("@bob:production.test")
            .is_some());
        assert!(
            receipt["content"][event_id].get("m.read.private").is_none(),
            "private receipt was exposed: {receipt}"
        );
        since = response["next_batch"].as_str().unwrap().to_owned();
        let quiet = server
            .request(
                Method::GET,
                &format!("/_matrix/client/v3/sync?since={since}"),
                Some(bob_token),
                None,
                200,
            )
            .await;
        assert!(
            quiet["rooms"]["join"].as_object().unwrap().is_empty(),
            "unchanged receipts replayed: {quiet}"
        );
        assert_eq!(
            quiet["presence"]["events"],
            json!([]),
            "unchanged presence replayed"
        );
    }
    let own = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(alice_token),
            None,
            200,
        )
        .await;
    assert!(own["rooms"]["join"][&room]["ephemeral"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["type"] == "m.receipt"
            && event["content"][second["event_id"].as_str().unwrap()]["m.read.private"]
                .get("@alice:production.test")
                .is_some()));
}

#[tokio::test]
async fn production_key_inventory_wakes_sync_and_quiets_after_acknowledgement() {
    let server = Server::new().await;
    let (alice, bob, _, _) = server.chat_pair().await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let device = bob["device_id"].as_str().unwrap();
    let initial = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    let mut since = initial["next_batch"].as_str().unwrap().to_owned();
    server.request(Method::POST, "/_matrix/client/v3/keys/upload", Some(bob_token), Some(json!({
        "one_time_keys": {"signed_curve25519:one": {"key": "one", "signatures": {}}},
        "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback", "signatures": {}}}
    })), 200).await;
    let uploaded = tokio::time::timeout(
        Duration::from_secs(2),
        server.request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?since={since}&timeout=4000"),
            Some(bob_token),
            None,
            200,
        ),
    )
    .await
    .expect("pending key inventory must return promptly");
    assert_eq!(
        uploaded["device_one_time_keys_count"]["signed_curve25519"],
        1
    );
    assert_eq!(
        uploaded["device_unused_fallback_key_types"],
        json!(["signed_curve25519"])
    );
    since = uploaded["next_batch"].as_str().unwrap().to_owned();
    for expected_key in ["signed_curve25519:one", "signed_curve25519:fallback"] {
        let mut devices = serde_json::Map::new();
        devices.insert(device.to_owned(), json!("signed_curve25519"));
        let claimed = server
            .request(
                Method::POST,
                "/_matrix/client/v3/keys/claim",
                Some(alice_token),
                Some(json!({"one_time_keys": {"@bob:production.test": devices}})),
                200,
            )
            .await;
        assert!(claimed["one_time_keys"]["@bob:production.test"][device]
            .get(expected_key)
            .is_some());
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            server.request(
                Method::GET,
                &format!("/_matrix/client/v3/sync?since={since}&timeout=4000"),
                Some(bob_token),
                None,
                200,
            ),
        )
        .await
        .expect("key claim must change own-device inventory promptly");
        assert_eq!(
            response["device_one_time_keys_count"]["signed_curve25519"]
                .as_i64()
                .unwrap_or(0),
            0
        );
        if expected_key.ends_with("fallback") {
            assert_eq!(response["device_unused_fallback_key_types"], json!([]));
        }
        since = response["next_batch"].as_str().unwrap().to_owned();
    }
    let start = Instant::now();
    let quiet = server
        .request(
            Method::GET,
            &format!("/_matrix/client/v3/sync?since={since}&timeout=300"),
            Some(bob_token),
            None,
            200,
        )
        .await;
    assert!(
        start.elapsed() >= Duration::from_millis(250),
        "unchanged key inventory caused busy polling"
    );
    assert_eq!(quiet["to_device"]["events"], json!([]));
    assert_eq!(quiet["presence"]["events"], json!([]));
    assert!(quiet["rooms"]["join"].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn production_room_send_transactions_are_durable_and_endpoint_scoped() {
    let mut server = Server::new().await;
    let (alice, bob, room, _) = server.chat_pair().await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let before = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    let path = format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/repeated");
    let mut requests = Vec::new();
    for value in 0..12 {
        let http = server.http.clone();
        let url = format!("{}{path}", server.base_url);
        let token = alice_token.to_owned();
        requests.push(tokio::spawn(async move {
            let response = http
                .put(url)
                .bearer_auth(token)
                .json(&json!({"msgtype": "m.text", "body": format!("Retry {value}")}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
            response.json::<Value>().await.unwrap()
        }));
    }
    let mut responses = Vec::new();
    for request in requests {
        responses.push(request.await.unwrap());
    }
    assert!(
        responses.iter().all(|response| response == &responses[0]),
        "concurrent retries produced different results: {responses:?}"
    );
    let sent = responses[0].clone();
    let sync = server
        .request(
            Method::GET,
            &format!(
                "/_matrix/client/v3/sync?since={}",
                before["next_batch"].as_str().unwrap()
            ),
            Some(bob_token),
            None,
            200,
        )
        .await;
    let timeline = sync["rooms"]["join"][&room]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert_eq!(
        timeline
            .iter()
            .filter(|event| event["event_id"] == sent["event_id"])
            .count(),
        1
    );
    assert_eq!(
        timeline
            .iter()
            .filter(|event| event["content"]["body"]
                .as_str()
                .is_some_and(|body| body.starts_with("Retry ")))
            .count(),
        1
    );
    server.stop();
    server.start().await;
    let retry = server
        .request(
            Method::PUT,
            &path,
            Some(alice_token),
            Some(json!({"msgtype": "m.text", "body": "Changed after restart"})),
            200,
        )
        .await;
    assert_eq!(retry, sent, "restart lost the transaction result");
    let other_room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(alice_token),
            Some(json!({})),
            200,
        )
        .await;
    let other = server
        .request(
            Method::PUT,
            &format!(
                "/_matrix/client/v3/rooms/{}/send/m.room.message/repeated",
                other_room["room_id"].as_str().unwrap()
            ),
            Some(alice_token),
            Some(json!({"msgtype": "m.text", "body": "Another endpoint"})),
            200,
        )
        .await;
    assert_ne!(
        other["event_id"], sent["event_id"],
        "room paths must not share transaction scope"
    );
    let other_type = server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.custom/repeated"),
            Some(alice_token),
            Some(json!({"body": "Another event type"})),
            200,
        )
        .await;
    assert_ne!(other_type["event_id"], sent["event_id"]);
}

#[tokio::test]
async fn production_to_device_transactions_are_durable_and_do_not_reexpand_wildcards() {
    let mut server = Server::new().await;
    let (alice, bob, _, _) = server.chat_pair().await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let path = "/_matrix/client/v3/sendToDevice/m.test/repeated";
    let body = json!({"messages": {"@bob:production.test": {"*": {"body": "Once"}}}});
    server
        .request(
            Method::PUT,
            "/_matrix/client/v3/sendToDevice/m.test/invalid",
            Some(alice_token),
            Some(json!({"messages": {"@bob:production.test": {"*": {"bad": 0.5}}}})),
            400,
        )
        .await;
    let mut requests = Vec::new();
    for _ in 0..12 {
        let http = server.http.clone();
        let url = format!("{}{path}", server.base_url);
        let token = alice_token.to_owned();
        let body = body.clone();
        requests.push(tokio::spawn(async move {
            let response = http
                .put(url)
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), 200);
        }));
    }
    for request in requests {
        request.await.unwrap();
    }
    let received = server
        .request(
            Method::GET,
            "/_matrix/client/v3/sync",
            Some(bob_token),
            None,
            200,
        )
        .await;
    assert_eq!(received["to_device"]["events"].as_array().unwrap().len(), 1);
    server
        .request(
            Method::GET,
            &format!(
                "/_matrix/client/v3/sync?since={}",
                received["next_batch"].as_str().unwrap()
            ),
            Some(bob_token),
            None,
            200,
        )
        .await;
    let new_device = server.request(Method::POST, "/_matrix/client/v3/login", None, Some(json!({
        "type": "m.login.password", "identifier": {"type": "m.id.user", "user": "bob"}, "password": "test-password", "device_id": "NEW"
    })), 200).await;
    server.stop();
    server.start().await;
    server
        .request(Method::PUT, path, Some(alice_token), Some(body), 200)
        .await;
    for token in [bob_token, new_device["access_token"].as_str().unwrap()] {
        let sync = server
            .request(
                Method::GET,
                "/_matrix/client/v3/sync",
                Some(token),
                None,
                200,
            )
            .await;
        assert_eq!(
            sync["to_device"]["events"],
            json!([]),
            "retry delivered/reexpanded an already acknowledged message"
        );
    }
}

#[tokio::test]
async fn production_startup_rejects_missing_or_invalid_private_ca() {
    let mut server = Server::new().await;
    server.stop();
    let invalid = server.files.path().join("invalid-ca.pem");
    std::fs::write(&invalid, "invalid PEM data").unwrap();
    let missing = server.files.path().join("missing-ca.pem");
    let ready = server.files.path().join("ready.json");
    for ca in [missing, invalid] {
        server.launch_with_ca("127.0.0.1:0", &ready, Some(&ca));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = server.child.as_mut().unwrap().try_wait().unwrap() {
                assert!(!status.success());
                server.child.take();
                break;
            }
            assert!(
                Instant::now() < deadline,
                "invalid CA configuration did not fail startup: {}",
                server.logs()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

#[tokio::test]
async fn production_rejected_transaction_replays_after_permissions_change() {
    let mut server = Server::new().await;
    let alice = server.register("alice").await;
    let bob = server.register("bob").await;
    let alice_token = alice["access_token"].as_str().unwrap();
    let bob_token = bob["access_token"].as_str().unwrap();
    let room = server
        .request(
            Method::POST,
            "/_matrix/client/v3/createRoom",
            Some(alice_token),
            Some(json!({"preset": "public_chat"})),
            200,
        )
        .await;
    let room = room["room_id"].as_str().unwrap();
    let path = format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/denied");
    let original = server
        .request(
            Method::PUT,
            &path,
            Some(bob_token),
            Some(json!({"msgtype": "m.text", "body": "Original"})),
            403,
        )
        .await;
    server
        .request(
            Method::POST,
            &format!("/_matrix/client/v3/join/{room}"),
            Some(bob_token),
            Some(json!({})),
            200,
        )
        .await;
    server.stop();
    server.start().await;
    let retry = server
        .request(
            Method::PUT,
            &path,
            Some(bob_token),
            Some(json!({"msgtype": "m.text", "body": "Changed"})),
            403,
        )
        .await;
    assert_eq!(retry, original);
    server
        .request(
            Method::PUT,
            &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/new"),
            Some(bob_token),
            Some(json!({"msgtype": "m.text", "body": "New request"})),
            200,
        )
        .await;
}

#[tokio::test]
async fn production_completed_transaction_is_replayed_before_body_validation() {
    let mut server = Server::new().await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let path = "/_matrix/client/v3/sendToDevice/m.test/replay";
    let original = server
        .request(
            Method::PUT,
            path,
            Some(token),
            Some(json!({"messages": {}})),
            200,
        )
        .await;
    server.stop();
    server.start().await;
    let response = server
        .http
        .put(format!("{}{path}", server.base_url))
        .bearer_auth(token)
        .header("Content-Type", "text/plain")
        .body("invalid JSON")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.json::<Value>().await.unwrap(), original);
    server
        .request(
            Method::POST,
            "/_matrix/client/v3/logout",
            Some(token),
            Some(json!({})),
            200,
        )
        .await;
    let revoked = server
        .http
        .put(format!("{}{path}", server.base_url))
        .bearer_auth(token)
        .header("Content-Type", "text/plain")
        .body("invalid JSON")
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoked.status().as_u16(),
        401,
        "a cached response must never bypass authentication"
    );
    let login = server
        .request(
            Method::POST,
            "/_matrix/client/v3/login",
            None,
            Some(json!({
                "type": "m.login.password", "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "test-password", "device_id": alice["device_id"]
            })),
            200,
        )
        .await;
    let response = server
        .http
        .put(format!("{}{path}", server.base_url))
        .bearer_auth(login["access_token"].as_str().unwrap())
        .header("Content-Type", "text/plain")
        .body("invalid JSON")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        200,
        "device-scoped replay must survive a new access token"
    );
    assert_eq!(response.json::<Value>().await.unwrap(), original);
}

#[tokio::test]
async fn production_interrupted_body_does_not_freeze_a_transaction() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let server = Server::new().await;
    let alice = server.register("alice").await;
    let token = alice["access_token"].as_str().unwrap();
    let address = server.base_url.strip_prefix("http://").unwrap();
    let path = "/_matrix/client/v3/sendToDevice/m.test/interrupted";
    let mut connection = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!("PUT {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{{");
    connection.write_all(request.as_bytes()).await.unwrap();
    connection.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), connection.read_to_end(&mut reply)).await.unwrap().unwrap();
    server.request(Method::PUT, path, Some(token), Some(json!({"messages": {}})), 200).await;
}
