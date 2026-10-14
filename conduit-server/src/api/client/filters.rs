use super::{AuthState, AuthedUser, MatrixError};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

pub async fn create<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(user): Path<String>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if user != authed.user_id {
        return MatrixError::forbidden("cannot create another user's filter").into_response();
    }
    let value = match body {
        Ok(Json(value)) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"errcode":"M_NOT_JSON", "error":error.body_text()})),
            )
                .into_response()
        }
    };
    if let Err(error) = serde_json::from_value::<conduit::filter::Filter>(value.clone()) {
        return MatrixError::bad_json(error.to_string()).into_response();
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
    match state.storage().put_filter(&user, &id, &value).await {
        Ok(()) => (StatusCode::OK, Json(json!({"filter_id": id}))).into_response(),
        Err(error) => MatrixError::unknown(error.to_string()).into_response(),
    }
}

pub async fn get<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path((user, id)): Path<(String, String)>,
) -> Response {
    if user != authed.user_id {
        return MatrixError::forbidden("cannot read another user's filter").into_response();
    }
    match state.storage().get_filter(&user, &id).await {
        Ok(Some(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(None) => MatrixError::new_not_found("filter not found").into_response(),
        Err(error) => MatrixError::unknown(error.to_string()).into_response(),
    }
}
