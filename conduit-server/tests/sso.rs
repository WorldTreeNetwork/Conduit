//! Matrix SSO + OIDC registration hardening.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use identikey_oidc_client::OidcClient;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::{RwLock, broadcast};
use tower::util::ServiceExt as _;

use conduit::keys::ServerKey;
use conduit::storage::Storage;
use conduit_server::{
    PostgresStorage,
    api::client::{
        self as auth, AuthState, PresenceStore, TxnCacheKey, TypingStore,
        sso::{LoginTokenStore, OidcSsoConfig, SsoSessionStore},
    },
};

struct TempDb {
    admin_url: String,
    db_name: String,
    pool: PgPool,
}

impl TempDb {
    async fn new() -> Self {
        let admin_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres@localhost/postgres".to_owned());
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let tid = format!("{:?}", std::thread::current().id())
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();
        let db_name = format!("conduit_test_sso_{}_{}", tid, nanos).to_lowercase();
        let admin_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&admin_url)
            .await
            .expect("connect to admin postgres");
        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin_pool)
            .await
            .unwrap_or_else(|e| panic!("CREATE DATABASE {db_name}: {e}"));
        admin_pool.close().await;
        let test_url = replace_db_in_url(&admin_url, &db_name);
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&test_url)
            .await
            .unwrap_or_else(|e| panic!("connect to {db_name}: {e}"));
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .unwrap_or_else(|e| panic!("migrations on {db_name}: {e}"));
        TempDb {
            admin_url,
            db_name,
            pool,
        }
    }

    fn storage(&self) -> Arc<dyn Storage> {
        PostgresStorage::new(self.pool.clone()).into_arc()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::process::Command::new("psql")
            .args([
                &self.admin_url,
                "-c",
                &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.db_name),
            ])
            .output();
    }
}

fn replace_db_in_url(url: &str, new_db: &str) -> String {
    let url = url.trim_end_matches('/');
    if let Some(pos) = url.rfind('/') {
        format!("{}/{}", &url[..pos], new_db)
    } else {
        format!("{}/{}", url, new_db)
    }
}

#[derive(Clone)]
struct TestState {
    storage: Arc<dyn Storage>,
    server_name: Arc<str>,
    server_key: Arc<ServerKey>,
    txn_cache: Arc<RwLock<HashMap<TxnCacheKey, String>>>,
    events_tx: broadcast::Sender<i64>,
    typing_store: Arc<TypingStore>,
    typing_tx: broadcast::Sender<String>,
    presence_store: Arc<PresenceStore>,
    oidc_client: Option<Arc<OidcClient>>,
    oidc_sso: Option<Arc<OidcSsoConfig>>,
    sso_sessions: Arc<SsoSessionStore>,
    login_tokens: Arc<LoginTokenStore>,
}

impl AuthState for TestState {
    fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
    fn server_name(&self) -> &str {
        &self.server_name
    }
    fn server_key(&self) -> Arc<ServerKey> {
        Arc::clone(&self.server_key)
    }
    fn txn_cache(&self) -> &Arc<RwLock<HashMap<TxnCacheKey, String>>> {
        &self.txn_cache
    }
    fn events_tx(&self) -> &broadcast::Sender<i64> {
        &self.events_tx
    }
    fn typing_store(&self) -> &Arc<TypingStore> {
        &self.typing_store
    }
    fn typing_tx(&self) -> &broadcast::Sender<String> {
        &self.typing_tx
    }
    fn presence_store(&self) -> &Arc<PresenceStore> {
        &self.presence_store
    }
    fn oidc_client(&self) -> Option<Arc<OidcClient>> {
        self.oidc_client.clone()
    }
    fn oidc_sso(&self) -> Option<Arc<OidcSsoConfig>> {
        self.oidc_sso.clone()
    }
    fn sso_sessions(&self) -> Arc<SsoSessionStore> {
        Arc::clone(&self.sso_sessions)
    }
    fn login_tokens(&self) -> Arc<LoginTokenStore> {
        Arc::clone(&self.login_tokens)
    }
}

fn new_state(storage: Arc<dyn Storage>, sso: bool) -> TestState {
    let (events_tx, _) = broadcast::channel(256);
    let (typing_store, typing_tx) = TypingStore::new();
    let oidc_client = sso.then(|| {
        Arc::new(OidcClient::endpoints_only(
            "https://auth.identikey.me",
            "localhost",
        ))
    });
    let oidc_sso = sso.then(|| {
        Arc::new(OidcSsoConfig {
            client_id: "localhost".into(),
            client_secret: "test-secret".into(),
            redirect_uri: "http://127.0.0.1:8008/_matrix/client/v3/login/identikey/callback"
                .into(),
            allowlist: auth::sso::default_sso_allowlist(),
        })
    });
    TestState {
        storage,
        server_name: "localhost".into(),
        server_key: Arc::new(conduit::keys::generate_server_key()),
        txn_cache: Arc::new(RwLock::new(HashMap::new())),
        events_tx,
        typing_store,
        typing_tx,
        presence_store: PresenceStore::new(),
        oidc_client,
        oidc_sso,
        sso_sessions: Arc::new(SsoSessionStore::new()),
        login_tokens: Arc::new(LoginTokenStore::new()),
    }
}

fn build_router(state: TestState) -> Router {
    Router::new()
        .route(
            "/_matrix/client/v3/register",
            post(auth::register::<TestState>),
        )
        .route(
            "/_matrix/client/v3/login",
            get(auth::get_login_flows::<TestState>).post(auth::login::<TestState>),
        )
        .route(
            "/_matrix/client/v3/login/sso/redirect",
            get(auth::sso::sso_redirect::<TestState>),
        )
        .route(
            "/_matrix/client/v3/login/sso/redirect/:idpId",
            get(auth::sso::sso_redirect_idp::<TestState>),
        )
        .route(
            "/_matrix/client/v3/login/identikey/callback",
            get(auth::sso::identikey_callback::<TestState>),
        )
        .with_state(state)
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

#[tokio::test]
async fn register_rejects_unverified_oidc_sub() {
    let db = TempDb::new().await;
    let app = build_router(new_state(db.storage(), false));
    let body = json!({
        "username": "mallory",
        "password": "secret123",
        "auth": { "type": "m.login.dummy" },
        "io.identikey.oidc_sub": "stolen-sub"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/register")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = json_body(resp).await;
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn login_flows_advertise_sso_when_configured() {
    let db = TempDb::new().await;
    let app = build_router(new_state(db.storage(), true));
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/login")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let types: Vec<&str> = body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["type"].as_str())
        .collect();
    assert!(types.contains(&"m.login.sso"));
    assert!(types.contains(&"m.login.token"));
    assert!(types.contains(&"io.identikey.oidc"));
}

#[tokio::test]
async fn sso_redirect_requires_config() {
    let db = TempDb::new().await;
    let app = build_router(new_state(db.storage(), false));
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/login/sso/redirect?redirectUrl=http://localhost:8080/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn sso_redirect_302_to_op() {
    let db = TempDb::new().await;
    let app = build_router(new_state(db.storage(), true));
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/login/sso/redirect?redirectUrl=http://localhost:8080/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(loc.starts_with("https://auth.identikey.me/authorize?"));
    assert!(loc.contains("client_id=localhost"));
    assert!(loc.contains("code_challenge_method=S256"));
    assert!(loc.contains("response_type=code"));
}

#[tokio::test]
async fn sso_redirect_rejects_foreign_url() {
    let db = TempDb::new().await;
    let app = build_router(new_state(db.storage(), true));
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/login/sso/redirect?redirectUrl=https://evil.example/phish")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unknown_idp_is_404() {
    let db = TempDb::new().await;
    let app = build_router(new_state(db.storage(), true));
    let req = Request::builder()
        .method("GET")
        .uri("/_matrix/client/v3/login/sso/redirect/other?redirectUrl=http://localhost:8080/")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn login_token_roundtrip() {
    let db = TempDb::new().await;
    let storage = db.storage();
    storage
        .create_account("@alice:localhost", None)
        .await
        .unwrap();
    let state = new_state(Arc::clone(&storage), true);
    let token = state.login_tokens.issue("@alice:localhost".into()).await;
    let app = build_router(state);
    let body = json!({ "type": "m.login.token", "token": token });
    let req = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/login")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["user_id"], "@alice:localhost");
    assert!(!body["access_token"].as_str().unwrap().is_empty());

    let body2 = json!({ "type": "m.login.token", "token": token });
    let req2 = Request::builder()
        .method("POST")
        .uri("/_matrix/client/v3/login")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body2).unwrap()))
        .unwrap();
    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
}

#[async_trait::async_trait]
impl conduit::room::RoomEventSender for TestState {
    async fn send_event(
        &self,
        sender: &str,
        room_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: serde_json::Value,
    ) -> conduit::Result<String> {
        match conduit_server::api::client::event_pipeline::build_sign_and_persist(
            self, sender, room_id, event_type, state_key, content,
        )
        .await
        {
            Ok(event_id) => {
                let _ = self.events_tx.send(0);
                Ok(event_id)
            }
            Err((_code, err)) => Err(conduit::Error::InvalidEvent(err.0.errcode.to_string())),
        }
    }
}
