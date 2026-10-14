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
        let log = File::create(self.files.path().join("server.log")).unwrap();
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_conduit-server"))
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

    let path = format!("/_matrix/client/v3/sync?since={since}&timeout=0");
    let received = server
        .request(Method::GET, &path, Some(bob_token), None, 200)
        .await;
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
