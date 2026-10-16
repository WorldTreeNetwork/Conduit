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

fn mint_id_token(
    pair: &impl josekit::jwk::KeyPair,
    iss: &str,
    aud: &str,
    sub: &str,
    nonce: &str,
) -> String {
    use josekit::jws::{EdDSA, JwsHeader};
    use josekit::jwt::JwtPayload;
    use std::time::{Duration, SystemTime};

    let mut header = JwsHeader::new();
    header.set_algorithm("EdDSA");
    header.set_key_id("test-kid");
    let mut payload = JwtPayload::new();
    payload.set_issuer(iss);
    payload.set_subject(sub);
    payload.set_audience(vec![aud]);
    payload.set_expires_at(&(SystemTime::now() + Duration::from_secs(300)));
    payload
        .set_claim("nonce", Some(josekit::Value::String(nonce.to_owned())))
        .unwrap();
    let signer = EdDSA.signer_from_jwk(&pair.to_jwk_key_pair()).unwrap();
    josekit::jwt::encode_with_signer(&payload, &header, &signer).unwrap()
}

fn stages_of(body: &Value) -> Vec<Vec<String>> {
    body["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|flow| {
            flow["stages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|stage| stage.as_str().unwrap().to_owned())
                .collect()
        })
        .collect()
}

#[tokio::test]
async fn sso_fallback_completes_uia_for_passwordless_account() {
    use axum::extract::State;
    use axum::Json;
    use josekit::jwk::alg::ed::EdCurve;
    use josekit::jws::EdDSA;

    let db = TempDb::new().await;
    let storage = db.storage();
    storage.create_account("@alice:localhost", None).await.unwrap();
    conduit::identity::link_at_registration(
        storage.as_ref(),
        &conduit::identity::oidc_identity_key("sub-alice"),
        "@alice:localhost",
    )
    .await
    .unwrap();

    let mut pair = EdDSA.generate_key_pair(EdCurve::Ed25519).unwrap();
    pair.set_key_id(Some("test-kid".to_string()));
    pair.set_algorithm(Some("EdDSA"));
    let mut jwks = josekit::jwk::JwkSet::new();
    jwks.push_key(pair.to_jwk_public_key());

    let id_token = Arc::new(std::sync::Mutex::new(String::new()));
    let hold = id_token.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let issuer = format!("http://127.0.0.1:{port}");
    let token_app = Router::new()
        .route(
            "/token",
            post(|State(hold): State<Arc<std::sync::Mutex<String>>>| async move {
                let token = hold.lock().unwrap().clone();
                Json(json!({
                    "access_token": "access-token",
                    "id_token": token,
                    "token_type": "Bearer",
                    "expires_in": 300
                }))
            }),
        )
        .with_state(hold);
    tokio::spawn(async move {
        axum::serve(listener, token_app).await.unwrap();
    });

    let mut state = new_state(Arc::clone(&storage), true);
    state.oidc_client = Some(Arc::new(OidcClient::from_jwks(&issuer, "localhost", jwks)));
    let issued = auth::session::issue_session(
        &state,
        "@alice:localhost",
        &auth::session::LoginOptions {
            device_id: Some("MAIN".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|resp| panic!("issue session: {}", resp.status()));
    let other = auth::session::issue_session(
        &state,
        "@alice:localhost",
        &auth::session::LoginOptions {
            device_id: Some("OTHER".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|resp| panic!("issue other: {}", resp.status()));
    let access = issued["access_token"].as_str().unwrap().to_owned();
    assert!(!other["access_token"].as_str().unwrap().is_empty());

    let app = auth::account::router::<TestState>()
        .route(
            "/_matrix/client/v3/login/identikey/callback",
            get(auth::sso::identikey_callback::<TestState>),
        )
        .with_state(state);

    async fn call(app: &Router, method: &str, uri: &str, token: Option<&str>, body: Option<Value>) -> axum::response::Response {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let req = if let Some(body) = body {
            builder
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        app.clone().oneshot(req).await.unwrap()
    }

    for (method, uri, body) in [
        ("POST", "/_matrix/client/v1/login/get_token", json!({})),
        ("POST", "/_matrix/client/v3/account/deactivate", json!({})),
        (
            "POST",
            "/_matrix/client/v3/delete_devices",
            json!({"devices": ["OTHER"]}),
        ),
    ] {
        let resp = call(&app, method, uri, Some(&access), Some(body)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {uri}");
        let challenge = json_body(resp).await;
        let stages = stages_of(&challenge);
        assert!(
            stages.iter().flatten().all(|stage| stage != "m.login.dummy"),
            "{method} {uri} offered dummy: {challenge}"
        );
        assert!(stages.iter().any(|flow| flow == &vec!["m.login.sso".to_owned()]), "{challenge}");
    }

    let challenge = json_body(
        call(
            &app,
            "POST",
            "/_matrix/client/v3/delete_devices",
            Some(&access),
            Some(json!({"devices": ["OTHER"]})),
        )
        .await,
    )
    .await;
    let session = challenge["session"].as_str().unwrap().to_owned();
    let named = call(
        &app,
        "POST",
        "/_matrix/client/v3/delete_devices",
        Some(&access),
        Some(json!({
            "devices": ["OTHER"],
            "auth": {"type": "m.login.sso", "session": session}
        })),
    )
    .await;
    assert_eq!(named.status(), StatusCode::UNAUTHORIZED);
    let named_body = json_body(named).await;
    assert_eq!(named_body["errcode"], "M_FORBIDDEN");
    assert_eq!(named_body["session"], session);

    let fallback = call(
        &app,
        "GET",
        &format!("/_matrix/client/v3/auth/m.login.sso/fallback/web?session={session}"),
        None,
        None,
    )
    .await;
    assert_eq!(fallback.status(), StatusCode::FOUND);
    let location = fallback.headers().get("location").unwrap().to_str().unwrap().to_owned();
    assert!(location.starts_with(&format!("{issuer}/authorize?")), "{location}");
    let authorize = url::Url::parse(&location).unwrap();
    let nonce = authorize
        .query_pairs()
        .find(|(key, _)| key == "nonce")
        .unwrap()
        .1
        .into_owned();
    let oauth_state = authorize
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();

    *id_token.lock().unwrap() = mint_id_token(&pair, &issuer, "localhost", "other-sub", &nonce);
    let rejected = call(
        &app,
        "GET",
        &format!(
            "/_matrix/client/v3/login/identikey/callback?code=one&state={oauth_state}"
        ),
        None,
        None,
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let rejected_html = String::from_utf8(
        axum::body::to_bytes(rejected.into_body(), usize::MAX).await.unwrap().to_vec(),
    )
    .unwrap();
    assert!(!rejected_html.contains("onAuthDone"), "{rejected_html}");

    let still = json_body(
        call(
            &app,
            "POST",
            "/_matrix/client/v3/delete_devices",
            Some(&access),
            Some(json!({"devices": ["OTHER"], "auth": {"session": session}})),
        )
        .await,
    )
    .await;
    assert_eq!(still["session"], session);

    let again = call(
        &app,
        "GET",
        &format!("/_matrix/client/v3/auth/m.login.sso/fallback/web?session={session}"),
        None,
        None,
    )
    .await;
    assert_eq!(again.status(), StatusCode::FOUND);
    let again_loc = again.headers().get("location").unwrap().to_str().unwrap().to_owned();
    let again_url = url::Url::parse(&again_loc).unwrap();
    let nonce = again_url
        .query_pairs()
        .find(|(key, _)| key == "nonce")
        .unwrap()
        .1
        .into_owned();
    let oauth_state = again_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .into_owned();
    *id_token.lock().unwrap() = mint_id_token(&pair, &issuer, "localhost", "sub-alice", &nonce);
    let done = call(
        &app,
        "GET",
        &format!(
            "/_matrix/client/v3/login/identikey/callback?code=two&state={oauth_state}"
        ),
        None,
        None,
    )
    .await;
    assert_eq!(done.status(), StatusCode::OK);
    let html = String::from_utf8(axum::body::to_bytes(done.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("window.onAuthDone"), "{html}");
    assert!(html.contains("postMessage(\"authDone\""), "{html}");

    let finished = call(
        &app,
        "POST",
        "/_matrix/client/v3/delete_devices",
        Some(&access),
        Some(json!({"devices": ["OTHER"], "auth": {"session": session}})),
    )
    .await;
    let finished_status = finished.status();
    let finished_body = String::from_utf8(
        axum::body::to_bytes(finished.into_body(), usize::MAX).await.unwrap().to_vec(),
    )
    .unwrap();
    assert_eq!(finished_status, StatusCode::OK, "{finished_body}");
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
