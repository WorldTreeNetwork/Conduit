//! Basic webserver wrapping the `conduit` library.
//!
//! Tokio + axum (axum sits on hyper, which is the most performant
//! mainstream Rust HTTP stack). Mount Matrix routes here as you build
//! them out in the library.

use std::net::SocketAddr;

use axum::{routing::get, Json, Router};
use serde_json::json;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let _config = conduit::Config::new("localhost");

    let app = Router::new()
        .route("/health", get(health))
        .route("/_matrix/client/versions", get(versions))
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
