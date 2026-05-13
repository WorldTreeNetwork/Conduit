//! Basic webserver wrapping the `conduit` library.
//!
//! Tokio + axum (axum sits on hyper, which is the most performant
//! mainstream Rust HTTP stack). Mount Matrix routes here as you build
//! them out in the library.

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, middleware, routing::{get, post, put}, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::Signer as _;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{RwLock, broadcast};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use hickory_resolver::TokioAsyncResolver;

use conduit::{keys::ServerKey, storage::Storage};
use conduit_server::{
    api::client::{AuthState, TxnCacheKey, TypingStore, PresenceStore},
    federation,
    federation::{
        FedState, XMatrixMiddlewareState, RateLimiter, federation_router,
        middleware::verify_xmatrix,
        rate_limit::rate_limit,
    },
    keys, PostgresStorage, RemoteKeyCache,
};

/// Shared application state threaded through axum.
#[derive(Clone)]
struct AppState {
    storage: Arc<dyn Storage>,
    server_key: Arc<ServerKey>,
    server_name: Arc<str>,
    http: reqwest::Client,
    remote_keys: Arc<RemoteKeyCache>,
    txn_cache: Arc<RwLock<HashMap<TxnCacheKey, String>>>,
    /// Broadcast channel: sends the new global stream_position after each
    /// persisted event so `/sync` long-pollers can wake up.
    events_tx: broadcast::Sender<i64>,
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let server_name: Arc<str> = env::var("CONDUIT_SERVER_NAME")
        .unwrap_or_else(|_| "localhost".to_owned())
        .into();

    let _config = conduit::Config::new(&*server_name);

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

    let http = reqwest::Client::new();

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

    // Build the outbound federation client and send queue.
    let federation_client = Arc::new(federation::Client::new(
        http.clone(),
        resolver,
        Arc::clone(&remote_keys),
        Arc::clone(&server_key),
        Arc::clone(&server_name),
    ));
    let federation_queue = Arc::new(federation::Queue::new(Arc::clone(&federation_client)));

    let state = AppState {
        storage,
        server_key,
        server_name,
        http,
        remote_keys,
        txn_cache: Arc::new(RwLock::new(HashMap::new())),
        events_tx,
        federation: federation_client,
        federation_queue,
        typing_store,
        typing_tx,
        presence_store,
    };

    use conduit_server::api::client as auth;
    use conduit_server::api::client::account_data as account_data_api;
    use conduit_server::api::client::keys as keys_api;
    use conduit_server::api::client::presence as presence_api;
    use conduit_server::api::client::profile as profile_api;
    use conduit_server::api::client::receipts as receipts_api;
    use conduit_server::api::client::rooms as rooms;
    use conduit_server::api::client::sync as sync_api;
    use conduit_server::api::client::typing as typing_api;

    // Build the X-Matrix middleware state (for inbound federation auth).
    let xmatrix_state = XMatrixMiddlewareState {
        server_name: Arc::clone(&state.server_name),
        remote_keys: Arc::clone(&state.remote_keys),
        http: state.http.clone(),
    };

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
    };

    // Federation inbound subrouter: X-Matrix auth → rate limit → handlers.
    // Layers are applied before with_state so the middleware state is bound.
    // with_state::<AppState> converts Router<FedState> → Router<AppState>.
    let fed_router: Router<AppState> = federation_router()
        .layer(middleware::from_fn_with_state(rate_limiter, rate_limit))
        .layer(middleware::from_fn_with_state(xmatrix_state, verify_xmatrix))
        .with_state::<AppState>(fed_state);

    let app = Router::new()
        .route("/health", get(health))
        .route("/_matrix/client/versions", get(versions))
        .route("/_matrix/key/v2/server", get(server_keys))
        .route("/_matrix/key/v2/server/:key_id", get(server_keys))
        // Client-Server API: auth
        .route("/_matrix/client/v3/register", post(auth::register::<AppState>))
        .route("/_matrix/client/v3/login", get(auth::get_login_flows).post(auth::login::<AppState>))
        .route("/_matrix/client/v3/logout", post(auth::logout::<AppState>))
        .route("/_matrix/client/v3/account/whoami", get(auth::whoami))
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
        .route("/_matrix/client/v3/rooms/:roomId/messages",
            get(rooms::get_messages::<AppState>))
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
            .put(keys_api::room_keys_put_room::<AppState>))
        .route("/_matrix/client/v3/room_keys/keys/:roomId/:sessionId",
            get(keys_api::room_keys_get_session::<AppState>)
            .put(keys_api::room_keys_put_session::<AppState>))
        // Profile (E06 1mo.1, 1mo.2)
        .route("/_matrix/client/v3/profile/:userId/displayname",
            get(profile_api::get_displayname::<AppState>)
            .put(profile_api::put_displayname::<AppState>))
        .route("/_matrix/client/v3/profile/:userId/avatar_url",
            get(profile_api::get_avatar_url::<AppState>)
            .put(profile_api::put_avatar_url::<AppState>))
        .route("/_matrix/client/v3/profile/:userId",
            get(profile_api::get_profile::<AppState>))
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
        // Federation inbound (E09)
        .nest("/_matrix/federation/v1", fed_router)
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = "0.0.0.0:8008".parse()?;
    tracing::info!(%addr, "conduit-server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn versions() -> Json<serde_json::Value> {
    Json(json!({ "versions": conduit::api::client::SUPPORTED_VERSIONS }))
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

    Json(response)
}
