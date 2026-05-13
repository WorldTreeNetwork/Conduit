//! Basic webserver wrapping the `conduit` library.
//!
//! Tokio + axum (axum sits on hyper, which is the most performant
//! mainstream Rust HTTP stack). Mount Matrix routes here as you build
//! them out in the library.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, routing::get, Json, Router};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use chrono::Utc;
use ed25519_dalek::Signer as _;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use conduit::{keys::ServerKey, storage::Storage};
use conduit_server::{keys, PostgresStorage, RemoteKeyCache};

/// Shared application state threaded through axum.
#[derive(Clone)]
struct AppState {
    storage: Arc<dyn Storage>,
    server_key: Arc<ServerKey>,
    server_name: Arc<str>,
    http: reqwest::Client,
    remote_keys: Arc<RemoteKeyCache>,
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

    let state = AppState {
        storage,
        server_key,
        server_name,
        http,
        remote_keys,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/_matrix/client/versions", get(versions))
        .route("/_matrix/key/v2/server", get(server_keys))
        .route("/_matrix/key/v2/server/{key_id}", get(server_keys))
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
    let valid_until_ts = Utc::now().timestamp_millis() + 24 * 60 * 60 * 1000;

    // Build the unsigned response object.
    let unsigned = json!({
        "server_name": server_name,
        "verify_keys": {
            key_id: { "key": pub_b64 }
        },
        "old_verify_keys": {},
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
