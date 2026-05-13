//! Basic webserver wrapping the `conduit` library.
//!
//! Tokio + axum (axum sits on hyper, which is the most performant
//! mainstream Rust HTTP stack). Mount Matrix routes here as you build
//! them out in the library.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::get, Json, Router};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use conduit::storage::Storage;
use conduit_server::PostgresStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let _config = conduit::Config::new("localhost");

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

    let app = Router::new()
        .route("/health", get(health))
        .route("/_matrix/client/versions", get(versions))
        .with_state(storage)
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
