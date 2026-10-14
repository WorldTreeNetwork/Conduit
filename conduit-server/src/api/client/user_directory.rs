//! User directory (conduit-y99.20).
//!
//! `POST /_matrix/client/v3/user_directory/search`
//!
//! Searches, case-insensitively by user ID and display name, the users
//! the spec says a server must at least consider: those sharing a room
//! with the requester, and those joined to rooms with a `public` join
//! rule or `world_readable` history. Users sharing a room rank first.
//! Remote users are found through the rooms this server knows; querying
//! remote directories is not done.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::{AuthState, AuthedUser, MatrixError};

/// Default `limit` per the spec.
const DEFAULT_LIMIT: i64 = 10;
/// Upper bound so one request cannot ask for the whole directory.
const MAX_LIMIT: i64 = 1000;

pub fn router<S: AuthState>() -> Router<S> {
    Router::new().route(
        "/_matrix/client/v3/user_directory/search",
        post(search::<S>),
    )
}

#[derive(Debug, Deserialize)]
pub struct SearchBody {
    pub search_term: String,
    pub limit: Option<i64>,
}

fn bad_json(msg: &str) -> Response {
    MatrixError::bad_json(msg).into_response()
}

pub async fn search<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Ok(Json(body)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_NOT_JSON", "error": "request body is not JSON"})),
        )
            .into_response();
    };
    if body.get("search_term").is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"errcode": "M_MISSING_PARAM", "error": "search_term is required"})),
        )
            .into_response();
    }
    let body: SearchBody = match serde_json::from_value(body) {
        Ok(b) => b,
        Err(e) => return bad_json(&e.to_string()),
    };
    let limit = body.limit.unwrap_or(DEFAULT_LIMIT).clamp(0, MAX_LIMIT);
    let term = body.search_term.trim();
    if term.is_empty() {
        return (StatusCode::OK, Json(json!({"results": [], "limited": false}))).into_response();
    }
    // Ask for one more than the limit to learn whether we truncated.
    let mut rows = match state
        .storage()
        .search_user_directory(&authed.user_id, term, limit + 1)
        .await
    {
        Ok(rows) => rows,
        Err(e) => return MatrixError::unknown(e.to_string()).into_response(),
    };
    let limited = rows.len() as i64 > limit;
    rows.truncate(limit as usize);
    let results: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let mut user = Map::new();
            user.insert("user_id".into(), json!(row.user_id));
            if let Some(name) = row.display_name {
                user.insert("display_name".into(), json!(name));
            }
            if let Some(avatar) = row.avatar_url {
                user.insert("avatar_url".into(), json!(avatar));
            }
            Value::Object(user)
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({"results": results, "limited": limited})),
    )
        .into_response()
}
