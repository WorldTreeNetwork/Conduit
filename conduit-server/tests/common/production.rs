//! Shared harness for unattended HTTP journeys through the shipped binary and
//! real PostgreSQL. Every test owns its process, database, port, logs, and
//! media directory. PostgreSQL and `psql` are required; failures are never
//! silently skipped.
#![allow(dead_code)]

use std::fs::File;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::{Client, Method};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use tempfile::TempDir;

pub struct Server {
    pub child: Option<Child>,
    pub files: TempDir,
    pub admin_url: String,
    pub database_url: String,
    pub database_name: String,
    pub base_url: String,
    pub http: Client,
    /// Extra environment for the server process (feature switches).
    pub extra_env: Vec<(String, String)>,
}

impl Server {
    pub async fn chat_pair(&self) -> (Value, Value, String, String) {
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

    pub async fn new() -> Self {
        Self::with_env(&[]).await
    }

    /// Like [`Server::new`], with additional server environment.
    pub async fn with_env(env: &[(&str, &str)]) -> Self {
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
            extra_env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        server.start().await;
        server
    }

    pub async fn start(&mut self) {
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

    pub fn launch(&mut self, listen_addr: &str, ready: &std::path::Path) {
        self.launch_with_ca(listen_addr, ready, None);
    }

    pub fn launch_with_ca(
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
                .envs(self.extra_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
                .stdin(Stdio::null())
                .stderr(log.try_clone().unwrap())
                .stdout(log)
                .spawn()
                .unwrap(),
        );
    }

    pub fn logs(&self) -> String {
        std::fs::read_to_string(self.files.path().join("server.log")).unwrap_or_default()
    }

    pub fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            child.wait().expect("reap production server");
        }
    }

    pub async fn request(
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

    pub async fn register(&self, username: &str) -> Value {
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
