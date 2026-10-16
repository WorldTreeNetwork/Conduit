//! Basic webserver wrapping the `conduit` library.
//!
//! Tokio + axum (axum sits on hyper, which is the most performant
//! mainstream Rust HTTP stack). Mount Matrix routes here as you build
//! them out in the library.

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use conduit_server::api::client::rate_limit::{cs_rate_limit, CsRateLimiter};

use axum::{extract::State, middleware, routing::{get, post, put}, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::Signer as _;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{RwLock, broadcast};
use tower_http::trace::TraceLayer;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::EnvFilter;

use hickory_resolver::TokioAsyncResolver;

use conduit::{keys::ServerKey, storage::Storage};
use conduit_server::{
    api::client::{AuthState, TxnCacheKey, TypingStore, PresenceStore},
    api::client::media::{MediaState, cleanup_preview_media, cleanup_remote_media},
    app_service::{self, AppService},
    federation,
    federation::{
        FedState, RateLimiter, authenticated_federation_router,
    },
    keys, push_worker, BlobStore, PostgresStorage, RemoteKeyCache,
};

/// Shared application state threaded through axum.
#[derive(Clone)]
struct AppState {
    storage: Arc<dyn Storage>,
    server_key: Arc<ServerKey>,
    /// Biscuit minter key — capability tokens, not events.  Distinct
    /// from `server_key` on purpose.
    minter: Arc<conduit::agency::Minter>,
    /// identikey-auth challenge issuer / verifier for this server name.
    identity_verifier: Arc<conduit::identity::IdentityVerifier>,
    /// Optional RP client for an identikey-core (or any OIDC) issuer.
    oidc_client: Option<Arc<identikey_oidc_client::OidcClient>>,
    /// Confidential-client config for Matrix SSO. None = no browser redirect.
    oidc_sso: Option<Arc<conduit_server::api::client::sso::OidcSsoConfig>>,
    sso_sessions: Arc<conduit_server::api::client::sso::SsoSessionStore>,
    login_tokens: Arc<conduit_server::api::client::sso::LoginTokenStore>,
    server_name: Arc<str>,
    http: reqwest::Client,
    remote_keys: Arc<RemoteKeyCache>,
    txn_cache: Arc<RwLock<HashMap<TxnCacheKey, String>>>,
    /// Broadcast channel: sends the new global stream_position after each
    /// persisted event so `/sync` long-pollers can wake up.
    events_tx: broadcast::Sender<i64>,
    sync_notify: Arc<tokio::sync::Notify>,
    /// Outbound federation HTTP client (E08).
    federation: Arc<federation::Client>,
    /// Per-destination outbound send queue (E08).
    federation_queue: Arc<federation::Queue>,
    /// Ephemeral in-memory typing store (E06 1mo.5).
    typing_store: Arc<TypingStore>,
    /// Broadcast channel: emits room_id when typing state changes.
    typing_tx: broadcast::Sender<String>,
    /// Ephemeral in-memory presence store (E06 1mo.7).
    presence_store: Arc<PresenceStore>,
    /// Blob storage for uploaded / cached media (E07).
    blob_store: BlobStore,
    /// Loaded Application Service registrations (E11 AS1).
    app_services: Arc<Vec<AppService>>,
    /// In-memory dedup cache for inbound federation PDUs (conduit-3qj).
    recent_events: Arc<federation::RecentEventCache>,
    /// iroh endpoint for P2P federation (E12, feature `iroh`).
    #[cfg(feature = "iroh")]
    iroh_endpoint: Option<Arc<iroh::Endpoint>>,
}

#[async_trait::async_trait]
impl conduit::room::RoomEventSender for AppState {
    async fn send_event(
        &self,
        sender: &str,
        room_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        content: Value,
    ) -> conduit::Result<String> {
        use conduit_server::api::client::event_pipeline::build_sign_and_persist;
        match build_sign_and_persist(
            self,
            sender,
            room_id,
            event_type,
            state_key,
            content,
        ).await {
            // The pipeline already broadcasts the persisted event position.
            Ok(event_id) => Ok(event_id),
            Err((_code, err)) => Err(conduit::Error::InvalidEvent(
                err.0 .errcode.to_string()
            )),
        }
    }
}

impl AuthState for AppState {
    fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
    fn server_name(&self) -> &str {
        &self.server_name
    }
    fn server_key(&self) -> Arc<conduit::keys::ServerKey> {
        Arc::clone(&self.server_key)
    }
    fn minter(&self) -> Arc<conduit::agency::Minter> {
        Arc::clone(&self.minter)
    }
    fn identity_verifier(&self) -> Arc<conduit::identity::IdentityVerifier> {
        Arc::clone(&self.identity_verifier)
    }
    fn oidc_client(&self) -> Option<Arc<identikey_oidc_client::OidcClient>> {
        self.oidc_client.clone()
    }
    fn oidc_sso(&self) -> Option<Arc<conduit_server::api::client::sso::OidcSsoConfig>> {
        self.oidc_sso.clone()
    }
    fn sso_sessions(&self) -> Arc<conduit_server::api::client::sso::SsoSessionStore> {
        Arc::clone(&self.sso_sessions)
    }
    fn login_tokens(&self) -> Arc<conduit_server::api::client::sso::LoginTokenStore> {
        Arc::clone(&self.login_tokens)
    }
    fn txn_cache(&self) -> &Arc<RwLock<HashMap<TxnCacheKey, String>>> {
        &self.txn_cache
    }
    fn events_tx(&self) -> &broadcast::Sender<i64> {
        &self.events_tx
    }
    fn sync_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.sync_notify)
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
    fn federation_client(&self) -> Option<&Arc<federation::Client>> {
        Some(&self.federation)
    }
    fn federation_queue(&self) -> Option<&Arc<federation::Queue>> {
        Some(&self.federation_queue)
    }
    fn registered_app_services(&self) -> Option<Arc<Vec<AppService>>> {
        Some(Arc::clone(&self.app_services))
    }
}

impl conduit_server::app_service::AsState for AppState {
    fn app_services(&self) -> &Arc<Vec<AppService>> {
        &self.app_services
    }
    fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
}

impl MediaState for AppState {
    fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
    fn server_name(&self) -> &str {
        &self.server_name
    }
    fn blob_store(&self) -> &BlobStore {
        &self.blob_store
    }
    fn federation_client(&self) -> &Arc<federation::Client> {
        &self.federation
    }
}

/// Read `.env` from the working directory or a parent. Existing process
/// variables stay as they are. A missing file is normal.
fn load_dotenv() -> Result<Option<std::path::PathBuf>, Box<dyn std::error::Error>> {
    match dotenvy::dotenv() {
        Ok(path) => Ok(Some(path)),
        Err(err) if err.not_found() => Ok(None),
        Err(err) => Err(format!("failed to read .env: {err}").into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dotenv_path = load_dotenv()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    if let Some(path) = &dotenv_path {
        tracing::info!(path = %path.display(), "loaded .env");
    }

    let server_name: Arc<str> = env::var("CONDUIT_SERVER_NAME")
        .unwrap_or_else(|_| "localhost".to_owned())
        .into();

    let mut config = conduit::Config::new(&*server_name);
    if env::var("CONDUIT_FEDERATION").ok().as_deref() == Some("0") {
        config.federation_enabled = false;
    }
    tracing::info!(federation = config.federation_enabled, "config ready");

    let database_url = env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set (e.g. postgres://user:pass@host/conduit)")?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;
    tracing::info!("connected to postgres");

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    let storage: Arc<dyn Storage> = PostgresStorage::new(pool).into_arc();

    let server_key = Arc::new(keys::load_or_generate(&*storage).await?);
    tracing::info!(key_id = %server_key.key_id, "server signing key ready");

    let minter = Arc::new(keys::load_or_generate_minter(&*storage).await?);
    tracing::info!("biscuit minter key ready");

    let mut http_builder = reqwest::Client::builder();
    if let Some(path) = env::var_os("CONDUIT_TLS_CA") {
        let pem = std::fs::read(path)?;
        let certificates = reqwest::Certificate::from_pem_bundle(&pem)?;
        if certificates.is_empty() {
            return Err("CONDUIT_TLS_CA must contain at least one PEM certificate".into());
        }
        for certificate in certificates {
            http_builder = http_builder.add_root_certificate(certificate);
        }
    }
    let http = http_builder.build()?;

    let remote_keys = {
        let cache = RemoteKeyCache::new();
        let cache = match env::var("CONDUIT_REMOTE_KEYS_OVERRIDE") {
            Ok(url) => {
                tracing::info!(url = %url, "remote key fetch override active");
                cache.with_test_base_url(url)
            }
            Err(_) => cache,
        };
        Arc::new(cache)
    };

    // Broadcast channel for /sync long-poll wake-ups.
    // Capacity 256: drops lagged receivers, which is fine — they'll just
    // re-poll once the sleep expires.
    let (events_tx, _) = broadcast::channel::<i64>(256);

    // Ephemeral typing + presence stores (E06).
    let (typing_store, typing_tx) = TypingStore::new();
    let presence_store = PresenceStore::new();

    // Build the DNS resolver for federation server discovery.
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .expect("DNS resolver config");

    // Bind iroh endpoint for P2P federation (E12, feature `iroh`).
    #[cfg(feature = "iroh")]
    let iroh_endpoint: Option<Arc<iroh::Endpoint>> = {
        match conduit::transport::iroh::bind_endpoint(&server_key).await {
            Ok(ep) => {
                let node_id = ep.id();
                tracing::info!(
                    node_id = %node_id,
                    "iroh federation endpoint bound",
                );
                Some(Arc::new(ep))
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to bind iroh endpoint — P2P federation disabled");
                None
            }
        }
    };

    // Build the outbound federation client and send queue.
    #[allow(unused_mut)]
    let mut federation_client = federation::Client::new(
        http.clone(),
        resolver,
        Arc::clone(&remote_keys),
        Arc::clone(&server_key),
        Arc::clone(&server_name),
    );
    #[cfg(feature = "iroh")]
    if let Some(ep) = iroh_endpoint.as_ref() {
        federation_client = federation_client.with_iroh_endpoint(Arc::clone(ep));
    }
    if let Ok(url) = env::var("CONDUIT_FEDERATION_BASE_URL") {
        tracing::info!(url = %url, "federation destination override active");
        federation_client = federation_client.with_test_base_url(url);
    }
    let federation_client = Arc::new(federation_client);
    let federation_queue = Arc::new(federation::Queue::new(
        Arc::clone(&federation_client),
        Arc::clone(&storage),
    ));
    // Recover any pending outbound work persisted across restart.
    federation_queue.start().await;

    // add-pdu-wire: classify legacy event rows in the background. Startup is
    // never blocked; federation reads classify an unchecked row inline.
    {
        let storage = Arc::clone(&storage);
        tokio::spawn(async move {
            let mut total = conduit::storage::LegacySweep::default();
            loop {
                match storage.verify_legacy_event_ids(1000).await {
                    Ok(batch) if batch.total() == 0 => break,
                    Ok(batch) => {
                        total.verified += batch.verified;
                        total.content_mismatch += batch.content_mismatch;
                        total.id_mismatch += batch.id_mismatch;
                    }
                    Err(error) => {
                        tracing::error!(%error, "legacy event integrity sweep failed");
                        return;
                    }
                }
            }
            if total.total() > 0 {
                tracing::info!(verified = total.verified, content_mismatch = total.content_mismatch,
                    id_mismatch = total.id_mismatch, "legacy event integrity sweep complete");
            }
        });
    }

    // Blob storage for media.
    let blob_store = BlobStore::from_env()
        .map_err(|e| format!("failed to initialise media blob store: {e}"))?;
    tracing::info!(root = ?std::env::var("CONDUIT_MEDIA_ROOT").unwrap_or_else(|_| "./media-data".to_owned()), "media blob store ready");

    // Load Application Service registrations (E11 AS1).
    let as_dir = env::var("CONDUIT_AS_REGISTRATIONS_DIR")
        .unwrap_or_else(|_| "./as-registrations".to_owned());
    let app_services: Arc<Vec<AppService>> = Arc::new(app_service::load_app_services(&as_dir));
    tracing::info!(count = app_services.len(), "application services loaded");

    let recent_events: Arc<federation::RecentEventCache> =
        Arc::new(federation::RecentEventCache::new());

    let identity_verifier = Arc::new(conduit::identity::IdentityVerifier::new(
        server_name.to_string(),
        conduit::identity::VerifyPolicy::PqOptional,
    ));

    // Default OP is identikey-core hosted at auth.identikey.me (ADR-004).
    // CONDUIT_OIDC_ISSUER=0 / off / empty disables. A custom issuer that
    // fails discovery aborts boot; the default only warns so a homeserver
    // still starts when the public OP is unreachable.
    let oidc_client_id = env::var("CONDUIT_OIDC_CLIENT_ID")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let oidc_audience = env::var("CONDUIT_OIDC_AUDIENCE")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| oidc_client_id.clone())
        .unwrap_or_else(|| server_name.to_string());

    let oidc_client = match oidc_issuer_from_env() {
        None => None,
        Some((issuer, explicit)) => {
            match identikey_oidc_client::OidcClient::discover(
                &issuer,
                &oidc_audience,
                http.clone(),
            )
            .await
            {
                Ok(c) => {
                    tracing::info!(issuer = %issuer, audience = %oidc_audience, "oidc rp client ready");
                    Some(Arc::new(c))
                }
                Err(e) if explicit => {
                    tracing::error!(error = %e, issuer = %issuer, "CONDUIT_OIDC_ISSUER discovery failed");
                    return Err(e.into());
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        issuer = %issuer,
                        "default OIDC issuer unreachable; io.identikey.oidc login disabled"
                    );
                    None
                }
            }
        }
    };

    let oidc_sso = match (
        oidc_client.as_ref(),
        env::var("CONDUIT_OIDC_CLIENT_SECRET")
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()),
    ) {
        (Some(_), Some(secret)) => {
            let sso_client_id = oidc_client_id.unwrap_or_else(|| oidc_audience.clone());
            let redirect_uri = env::var("CONDUIT_OIDC_REDIRECT_URI")
                .ok()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    "http://127.0.0.1:8008/_matrix/client/v3/login/identikey/callback".into()
                });
            let mut allowlist = conduit_server::api::client::sso::default_sso_allowlist();
            if let Ok(extra) = env::var("CONDUIT_SSO_REDIRECT_ALLOWLIST") {
                for prefix in extra.split(',') {
                    let t = prefix.trim();
                    if !t.is_empty() {
                        allowlist.push(t.to_owned());
                    }
                }
            }
            tracing::info!(
                client_id = %sso_client_id,
                redirect_uri = %redirect_uri,
                "oidc sso redirect enabled"
            );
            Some(Arc::new(conduit_server::api::client::sso::OidcSsoConfig {
                client_id: sso_client_id,
                client_secret: secret,
                redirect_uri,
                allowlist,
            }))
        }
        (Some(_), None) => {
            tracing::warn!(
                "CONDUIT_OIDC_CLIENT_SECRET unset; Matrix SSO redirect disabled (JWT-in-hand io.identikey.oidc still works)"
            );
            None
        }
        _ => None,
    };

    let sso_sessions = Arc::new(conduit_server::api::client::sso::SsoSessionStore::new());
    let login_tokens = Arc::new(conduit_server::api::client::sso::LoginTokenStore::new());

    let state = AppState {
        storage,
        server_key,
        minter,
        identity_verifier,
        oidc_client,
        oidc_sso,
        sso_sessions,
        login_tokens,
        server_name,
        http,
        remote_keys,
        txn_cache: Arc::new(RwLock::new(HashMap::new())),
        events_tx,
        sync_notify: Arc::new(tokio::sync::Notify::new()),
        federation: federation_client,
        federation_queue,
        typing_store,
        typing_tx,
        presence_store,
        blob_store,
        app_services,
        recent_events,
        #[cfg(feature = "iroh")]
        iroh_endpoint,
    };

    use conduit_server::api::client as auth;
    use conduit_server::api::client::account_data as account_data_api;
    use conduit_server::api::client::directory as directory_api;
    use conduit_server::api::client::keys as keys_api;
    use conduit_server::api::client::media as media_api;
    use conduit_server::api::client::presence as presence_api;
    use conduit_server::api::client::probe as probe_api;
    use conduit_server::api::client::profile as profile_api;
    use conduit_server::api::client::push as push_api;
    use conduit_server::api::client::receipts as receipts_api;
    use conduit_server::api::client::rooms as rooms;
    use conduit_server::api::client::sync as sync_api;
    use conduit_server::api::client::typing as typing_api;
    use conduit_server::api::admin as admin_api;

    // Spawn push notification background worker (E11 P5).
    {
        let push_rx = state.events_tx.subscribe();
        push_worker::spawn_push_worker(
            Arc::clone(&state.storage),
            Arc::clone(&state.server_name),
            state.http.clone(),
            push_rx,
        );
        tracing::info!("push notification worker started");
    }

    // Spawn durable AS transaction pusher workers (conduit-y99.34).
    conduit_server::appservice_push::spawn_workers(
        &state.app_services,
        conduit_server::appservice_push::PushContext {
            storage: Arc::clone(&state.storage),
            server_name: Arc::clone(&state.server_name),
            http: state.http.clone(),
            typing: Arc::clone(&state.typing_store),
            presence: Arc::clone(&state.presence_store),
            backoff_base: conduit_server::appservice_push::PushContext::backoff_from_env(),
        },
        &state.events_tx,
    );

    // Build the per-origin rate limiter.
    let rate_limiter = RateLimiter::default_federation();

    // Build the federation inbound handler state.
    let fed_state = FedState {
        storage: Arc::clone(&state.storage),
        server_name: Arc::clone(&state.server_name),
        server_key: Arc::clone(&state.server_key),
        remote_keys: Arc::clone(&state.remote_keys),
        http: state.http.clone(),
        events_tx: state.events_tx.clone(),
        fed_client: Arc::clone(&state.federation),
        blob_store: state.blob_store.clone(),
        recent: Arc::clone(&state.recent_events),
        app_services: Arc::clone(&state.app_services),
        typing: Arc::clone(&state.typing_store),
        presence: Arc::clone(&state.presence_store),
    };

    let fed_router: Router<AppState> = authenticated_federation_router(fed_state, rate_limiter);

    let app = Router::new()
        .route("/health", get(health))
        .route("/_matrix/key/v2/server", get(server_keys))
        .route("/_matrix/key/v2/server/:key_id", get(server_keys))
        // Client-Server API: auth
        .route("/_matrix/client/v3/register", post(auth::register::<AppState>))
        .route("/_matrix/client/v3/login", get(auth::get_login_flows::<AppState>).post(auth::login::<AppState>))
        .route("/_matrix/client/v3/logout", post(auth::logout::<AppState>))
        .route("/_matrix/client/v3/logout/all", post(auth::logout_all::<AppState>))
        .route("/_matrix/client/v3/login/identikey/challenge",
            post(auth::identikey_challenge::<AppState>))
        .route("/_matrix/client/v3/login/sso/redirect",
            get(auth::sso::sso_redirect::<AppState>))
        .route("/_matrix/client/v3/login/sso/redirect/:idpId",
            get(auth::sso::sso_redirect_idp::<AppState>))
        .route("/_matrix/client/v3/login/identikey/callback",
            get(auth::sso::identikey_callback::<AppState>))
        .route("/_matrix/client/v3/account/identikey/bind",
            post(auth::identikey_bind::<AppState>))
        .route("/_matrix/client/v3/account/whoami", get(auth::whoami))
        // Client probe endpoints (conduit-eck)
        .route("/_matrix/client/v3/capabilities", get(probe_api::capabilities::<AppState>))
        .route("/_matrix/client/v3/voip/turnServer", get(probe_api::turn_server::<AppState>))
        .route("/_matrix/client/v3/user/:userId/openid/request_token",
            post(probe_api::openid_request_token::<AppState>))
        // Client-Server API: rooms
        .route("/_matrix/client/v3/createRoom", post(rooms::create_room::<AppState>))
        .route("/_matrix/client/v3/join/:roomIdOrAlias", post(rooms::join_room::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/leave", post(rooms::leave_room::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/kick", post(rooms::kick_user::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/ban", post(rooms::ban_user::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/unban", post(rooms::unban_user::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/invite", post(rooms::invite_user::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId",
            put(rooms::send_message_event::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/state/:eventType",
            put(rooms::send_state_event::<AppState>)
            .get(rooms::get_state_event_no_key::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
            put(rooms::send_state_event_with_key::<AppState>)
            .get(rooms::get_state_event::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/state",
            get(rooms::get_room_state::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/joined_members",
            get(rooms::joined_members::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/aliases",
            get(directory_api::list_room_aliases::<AppState>))
        // Directory (conduit-v0y)
        .route("/_matrix/client/v3/directory/room/:alias",
            put(directory_api::put_alias::<AppState>)
            .get(directory_api::get_alias::<AppState>)
            .delete(directory_api::delete_alias::<AppState>))
        .route("/_matrix/client/v3/rooms/:roomId/messages",
            get(rooms::get_messages::<AppState>))
        .route("/_matrix/client/v3/user/:userId/filter", post(conduit_server::api::client::filters::create::<AppState>))
        .route("/_matrix/client/v3/user/:userId/filter/:filterId", get(conduit_server::api::client::filters::get::<AppState>))
        // Client-Server API: sync
        .route("/_matrix/client/v3/sync",
            get(sync_api::sync::<AppState>))
        // Client-Server API: E2EE keys (E10 mrm.1–mrm.9)
        .route("/_matrix/client/v3/keys/upload",
            post(keys_api::keys_upload::<AppState>))
        .route("/_matrix/client/v3/keys/query",
            post(keys_api::keys_query::<AppState>))
        .route("/_matrix/client/v3/keys/claim",
            post(keys_api::keys_claim::<AppState>))
        .route("/_matrix/client/v3/keys/changes",
            get(keys_api::keys_changes::<AppState>))
        .route("/_matrix/client/v3/sendToDevice/:eventType/:txnId",
            put(keys_api::send_to_device::<AppState>))
        .route("/_matrix/client/v3/keys/device_signing/upload",
            post(keys_api::device_signing_upload::<AppState>))
        .route("/_matrix/client/v3/keys/signatures/upload",
            post(keys_api::signatures_upload::<AppState>))
        // Room key backup (mrm.13)
        .route("/_matrix/client/v3/room_keys/version",
            get(keys_api::room_keys_version_get_latest::<AppState>)
            .post(keys_api::room_keys_version_create::<AppState>))
        .route("/_matrix/client/v3/room_keys/version/:version",
            get(keys_api::room_keys_version_get::<AppState>)
            .put(keys_api::room_keys_version_update::<AppState>)
            .delete(keys_api::room_keys_version_delete::<AppState>))
        .route("/_matrix/client/v3/room_keys/keys",
            get(keys_api::room_keys_get_all::<AppState>)
            .put(keys_api::room_keys_put_all::<AppState>)
            .delete(keys_api::room_keys_delete_all::<AppState>))
        .route("/_matrix/client/v3/room_keys/keys/:roomId",
            get(keys_api::room_keys_get_room::<AppState>)
            .put(keys_api::room_keys_put_room::<AppState>)
            .delete(keys_api::room_keys_delete_room::<AppState>))
        .route("/_matrix/client/v3/room_keys/keys/:roomId/:sessionId",
            get(keys_api::room_keys_get_session::<AppState>)
            .put(keys_api::room_keys_put_session::<AppState>)
            .delete(keys_api::room_keys_delete_session::<AppState>))
        // Profile (E06 1mo.1, 1mo.2; extended fields conduit-y99.38)
        .merge(profile_api::router::<AppState>())
        // Account data (E06 1mo.3, 1mo.4)
        .route("/_matrix/client/v3/user/:userId/account_data/:type",
            get(account_data_api::get_account_data::<AppState>)
            .put(account_data_api::put_account_data::<AppState>))
        .route("/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type",
            get(account_data_api::get_room_account_data::<AppState>)
            .put(account_data_api::put_room_account_data::<AppState>))
        // Typing (E06 1mo.5)
        .route("/_matrix/client/v3/rooms/:roomId/typing/:userId",
            put(typing_api::put_typing::<AppState>))
        // Receipts (E06 1mo.6)
        .route("/_matrix/client/v3/rooms/:roomId/receipt/:receiptType/:eventId",
            post(receipts_api::post_receipt::<AppState>))
        // Presence (E06 1mo.7)
        .route("/_matrix/client/v3/presence/:userId/status",
            get(presence_api::get_presence::<AppState>)
            .put(presence_api::put_presence::<AppState>))
        // Media (E07, conduit-y99.21): content repository
        .merge(media_api::router::<AppState>())
        // Push (conduit-y99.30, conduit-y99.31)
        .merge(push_api::router::<AppState>())
        // Admin API (E11 AD1–AD6)
        .route("/_matrix/conduit/admin/v1/users",
            get(admin_api::list_users::<AppState>))
        .route("/_matrix/conduit/admin/v1/users/:userId",
            get(admin_api::get_user::<AppState>))
        .route("/_matrix/conduit/admin/v1/users/:userId/deactivate",
            post(admin_api::deactivate_user::<AppState>))
        .route("/_matrix/conduit/admin/v1/users/:userId/reset_password",
            post(admin_api::reset_password::<AppState>))
        .route("/_matrix/conduit/admin/v1/users/:userId/admin",
            post(admin_api::set_admin::<AppState>))
        .route("/_matrix/conduit/admin/v1/rooms",
            get(admin_api::list_rooms::<AppState>))
        .route("/_matrix/conduit/admin/v1/rooms/:roomId/purge",
            post(admin_api::purge_room::<AppState>))
        .route("/_matrix/conduit/admin/v1/rooms/:roomId/leave_user",
            post(admin_api::leave_user::<AppState>))
        .route("/_matrix/conduit/admin/v1/media",
            get(admin_api::list_media::<AppState>))
        .route("/_matrix/conduit/admin/v1/media/:mediaId",
            axum::routing::delete(admin_api::delete_media::<AppState>))
        .route("/_matrix/conduit/admin/v1/federation/peers",
            get(admin_api::list_federation_peers::<AppState>))
        .route("/_matrix/conduit/admin/v1/federation/disable",
            post(admin_api::disable_federation::<AppState>))
        .route("/_matrix/conduit/admin/v1/federation/dlq",
            get(admin_api::list_federation_dlq::<AppState>))
        .route("/_matrix/conduit/admin/v1/federation/dlq/:id/replay",
            post(admin_api::replay_federation_dlq::<AppState>))
        .route("/_matrix/conduit/admin/v1/federation/dlq/:id",
            axum::routing::delete(admin_api::purge_federation_dlq::<AppState>))
        .route("/_matrix/conduit/admin/v1/audit",
            get(admin_api::get_audit_log::<AppState>))
        // Directory, user directory, knock, third-party, AS ping (conduit-y99.20)
        .merge(conduit_server::api::client::room_directory::router::<AppState>())
        .merge(conduit_server::api::client::user_directory::router::<AppState>())
        .merge(conduit_server::api::client::knock::router::<AppState>())
        .merge(conduit_server::api::client::state_paths::router::<AppState>())
        .merge(conduit_server::api::client::thirdparty::router::<AppState>())
        .merge(conduit_server::api::client::appservice_ping::router::<AppState>())
        .merge(conduit_server::api::client::room_content::router::<AppState>())
        .merge(conduit_server::api::client::account::router::<AppState>())
        .merge(conduit_server::api::client::third_party::router::<AppState>())
        .merge(conduit_server::api::client::standards::router::<AppState>())
        .merge(conduit_server::api::client::room_membership::router::<AppState>())
        .merge(conduit_server::api::client::moderation::router::<AppState>())
        .merge(conduit_server::api::client::server_notices::router::<AppState>())
        .merge(conduit_server::api::client::legacy::router::<AppState>())
        // Apply CS-API rate limiter to everything above (conduit-9m4).
        // Federation routes are nested below and use their own per-origin
        // limiter, so they bypass this one.
        // Application-service `?ts=` timestamp massaging (conduit-y99.35).
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            conduit_server::api::client::appservice_auth::ts_massaging::<AppState>,
        ))
        .route_layer(middleware::from_fn_with_state(
            CsRateLimiter::from_env()?.with_appservices(&state.app_services, &state.server_name),
            cs_rate_limit,
        ))
        // Federation inbound (E09)
        .merge(fed_router)
        .with_state(state.clone())
        // 404/405 -> M_UNRECOGNIZED, Retry-After on 429 (conduit-y99.28).
        .layer(middleware::map_response(
            conduit_server::api::client::standards::normalize_errors,
        ))
        .layer(TraceLayer::new_for_http())
        // CORS (conduit-cws): browser Matrix clients (Element) are served from a
        // different origin and call the CS-API cross-origin. The Matrix spec
        // requires the homeserver to allow any origin. Clients authenticate via
        // the Authorization bearer header (no cookies), so credentials mode is
        // not needed and `Any` origin is correct. This also answers OPTIONS
        // preflight automatically.
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Background task: GC the outbound federation queue (conduit-cgl).
    // Hourly: drop sent rows >7 days old, dead rows >30 days old.
    {
        let storage_clone = Arc::clone(&state.storage);
        tokio::spawn(async move {
            let tick = std::time::Duration::from_secs(60 * 60);
            let week_ms: i64 = 7 * 24 * 60 * 60 * 1000;
            let month_ms: i64 = 30 * 24 * 60 * 60 * 1000;
            loop {
                tokio::time::sleep(tick).await;
                let now_ms = chrono::Utc::now().timestamp_millis();
                match storage_clone
                    .gc_outbound_queue(now_ms - week_ms, Some(now_ms - month_ms))
                    .await
                {
                    Ok(n) if n > 0 => tracing::info!(deleted = n, "fed_outbound_queue GC"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "fed_outbound_queue GC failed"),
                }
            }
        });
    }

    // Background task: clean up stale remote-cached media (h9n.11).
    {
        let retention_days: u64 = env::var("CONDUIT_MEDIA_REMOTE_RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let storage_clone = Arc::clone(&state.storage);
        let blob_clone = state.blob_store.clone();
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(60 * 60); // hourly
            let max_age = std::time::Duration::from_secs(retention_days * 24 * 60 * 60);
            loop {
                tokio::time::sleep(interval).await;
                match cleanup_remote_media(&*storage_clone, &blob_clone, max_age).await {
                    Ok(n) if n > 0 => tracing::info!(deleted = n, "remote media retention cleanup"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "remote media retention cleanup failed"),
                }
                match cleanup_preview_media(&*storage_clone, &blob_clone, max_age).await {
                    Ok(n) if n > 0 => tracing::info!(deleted = n, "preview media retention cleanup"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "preview media retention cleanup failed"),
                }
            }
        });
    }

    // Spawn iroh P2P accept loop (E12 91r.6).
    // We pass the full app router so iroh-arriving federation requests are
    // handled by the same handlers as HTTPS-arriving ones.
    #[cfg(feature = "iroh")]
    if let Some(ep) = state.iroh_endpoint.as_ref().map(Arc::clone) {
        let iroh_router = app.clone();
        conduit_server::federation::iroh_server::spawn_iroh_accept_loop(
            (*ep).clone(),
            iroh_router,
        );
    }

    let addr: SocketAddr = env::var("CONDUIT_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8008".to_owned())
        .parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let addr = listener.local_addr()?;
    // Report the actual bound port, including when port zero was requested.
    // Automation still uses normal HTTP requests and authentication.
    if let Ok(path) = env::var("CONDUIT_READY_FILE") {
        std::fs::write(path, serde_json::to_vec(&json!({"address": addr.to_string()}))?)?;
    }
    tracing::info!(%addr, "conduit-server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

const DEFAULT_OIDC_ISSUER: &str = "https://auth.identikey.me";

/// `(issuer, explicit)`. `explicit` is false when the identikey.me default
/// was used. `CONDUIT_OIDC_ISSUER=0` / `off` / empty disables.
fn oidc_issuer_from_env() -> Option<(String, bool)> {
    oidc_issuer_from(env::var("CONDUIT_OIDC_ISSUER").ok())
}

fn oidc_issuer_from(raw: Option<String>) -> Option<(String, bool)> {
    match raw {
        None => Some((DEFAULT_OIDC_ISSUER.to_owned(), false)),
        Some(s) => {
            let t = s.trim();
            if t.is_empty() || t == "0" || t.eq_ignore_ascii_case("off") {
                None
            } else {
                Some((t.trim_end_matches('/').to_owned(), true))
            }
        }
    }
}

#[cfg(test)]
mod oidc_issuer_tests {
    use super::*;

    #[test]
    fn default_is_auth_identikey_me() {
        let (iss, explicit) = oidc_issuer_from(None).unwrap();
        assert_eq!(iss, "https://auth.identikey.me");
        assert!(!explicit);
    }

    #[test]
    fn off_disables() {
        assert!(oidc_issuer_from(Some("0".into())).is_none());
        assert!(oidc_issuer_from(Some("off".into())).is_none());
        assert!(oidc_issuer_from(Some("OFF".into())).is_none());
        assert!(oidc_issuer_from(Some("".into())).is_none());
        assert!(oidc_issuer_from(Some("  ".into())).is_none());
    }

    #[test]
    fn custom_is_explicit() {
        let (iss, explicit) = oidc_issuer_from(Some("https://idp.example/".into())).unwrap();
        assert_eq!(iss, "https://idp.example");
        assert!(explicit);
    }
}

/// `GET /_matrix/key/v2/server` and `GET /_matrix/key/v2/server/{keyId}`
///
/// Builds a signed server-key response per the Matrix spec:
/// <https://spec.matrix.org/latest/server-server-api/#publishing-keys>
async fn server_keys(State(state): State<AppState>) -> Json<serde_json::Value> {
    let server_name = &*state.server_name;
    let key_id = &state.server_key.key_id;

    // Public key as unpadded standard base64.
    let pub_bytes = conduit::keys::public_bytes(&state.server_key);
    let pub_b64 = STANDARD_NO_PAD.encode(&pub_bytes);

    // valid_until_ts: 24 hours from now in milliseconds.
    let now_ms = Utc::now().timestamp_millis();
    let valid_until_ts = now_ms + 24 * 60 * 60 * 1000;

    // Build old_verify_keys: retired keys whose grace window hasn't expired.
    let mut old_verify_keys = serde_json::Map::new();
    if let Ok(all_keys) = state.storage.signing_keys_for_verification().await {
        for k in all_keys {
            // Skip the current key — it belongs in verify_keys, not old_verify_keys.
            if k.key_id == *key_id {
                continue;
            }
            // Only include keys that are still within their grace window.
            if let Some(expiry) = k.valid_until_ts {
                if expiry > now_ms {
                    let k_pub_b64 = STANDARD_NO_PAD.encode(&k.public_key);
                    old_verify_keys.insert(
                        k.key_id.clone(),
                        json!({ "key": k_pub_b64, "expired_ts": expiry }),
                    );
                }
            }
            // Keys with no valid_until_ts (shouldn't exist for retired keys,
            // but defensively skip them — they aren't retired yet).
        }
    }

    // Build the unsigned response object.
    let unsigned = json!({
        "server_name": server_name,
        "verify_keys": {
            key_id: { "key": pub_b64 }
        },
        "old_verify_keys": old_verify_keys,
        "valid_until_ts": valid_until_ts
    });

    // Sign the canonical JSON of the unsigned object.
    let canonical_bytes = conduit::canonical_json::to_canonical_bytes(&unsigned)
        .expect("server key response must be canonical-JSON serializable");
    let signature = state.server_key.signing_key.sign(&canonical_bytes);
    let sig_b64 = STANDARD_NO_PAD.encode(signature.to_bytes());

    // Splice signatures into the final response.
    let mut response = unsigned;
    response["signatures"] = json!({
        server_name: {
            key_id: sig_b64
        }
    });

    // Advertise the iroh node ID in a non-standard extension field (91r.4).
    // Only peers that also have the `iroh` feature compiled in will use this.
    // This field is NOT part of the Matrix spec.
    #[cfg(feature = "iroh")]
    if let Some(ep) = state.iroh_endpoint.as_ref() {
        let node_id = ep.id();
        response["x_conduit_iroh"] = json!({
            "node_id": node_id.to_string()
        });
    }

    Json(response)
}
