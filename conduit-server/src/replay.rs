//! Host-side replay of authenticated transaction requests. Storage retains
//! domain keys and opaque JSON; HTTP parsing/status mapping stays in the host.

use std::sync::Arc;

use axum::{
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use conduit::storage::{Storage, TransactionGuard, TransactionKey};
use serde_json::{json, Value};

pub enum Start {
    Cached(Response),
    Execute(Replay),
}

pub struct Replay {
    storage: Arc<dyn Storage>,
    key: TransactionKey,
    _guard: Box<dyn TransactionGuard>,
}

pub fn status(body: &Value) -> StatusCode {
    match body.get("errcode").and_then(Value::as_str) {
        None => StatusCode::OK,
        Some("M_FORBIDDEN") => StatusCode::FORBIDDEN,
        Some("M_NOT_FOUND") => StatusCode::NOT_FOUND,
        Some("M_UNAUTHORIZED" | "M_MISSING_TOKEN" | "M_UNKNOWN_TOKEN") => StatusCode::UNAUTHORIZED,
        Some("M_TOO_LARGE") => StatusCode::PAYLOAD_TOO_LARGE,
        Some("M_LIMIT_EXCEEDED") => StatusCode::TOO_MANY_REQUESTS,
        Some("M_UNKNOWN") => StatusCode::INTERNAL_SERVER_ERROR,
        Some(_) => StatusCode::BAD_REQUEST,
    }
}

pub fn error(message: impl ToString) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"errcode": "M_UNKNOWN", "error": message.to_string()})),
    )
        .into_response()
}

impl Replay {
    pub async fn start(storage: Arc<dyn Storage>, key: TransactionKey) -> Result<Start, Response> {
        let guard = storage.lock_transaction(&key).await.map_err(error)?;
        let cached = storage.transaction_result(&key).await.map_err(error)?;
        if let Some(body) = cached {
            return Ok(Start::Cached((status(&body), Json(body)).into_response()));
        }
        Ok(Start::Execute(Self {
            storage,
            key,
            _guard: guard,
        }))
    }

    pub async fn body(&mut self, request: Request) -> Result<Value, Response> {
        // An interrupted request resumes the original body before trying to
        // parse a later retransmission. Final replies were checked even earlier.
        if let Some(original) = self
            .storage
            .transaction_original(&self.key)
            .await
            .map_err(error)?
        {
            return Ok(original);
        }
        let parsed = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Json::<Value>::from_request(request, &()),
        )
        .await;
        let Json(body) = match parsed {
            Ok(Ok(body)) => body,
            Ok(Err(rejection)) => {
                let too_large = rejection.status() == StatusCode::PAYLOAD_TOO_LARGE;
                // An incomplete transport body is not a completed invalid JSON
                // request. Do not freeze a network failure as a final result.
                if matches!(
                    rejection,
                    axum::extract::rejection::JsonRejection::BytesRejection(_)
                ) && !too_large
                {
                    return Err(error(rejection.body_text()));
                }
                let code = if too_large {
                    "M_TOO_LARGE"
                } else {
                    "M_NOT_JSON"
                };
                let body = json!({"errcode": code, "error": rejection.body_text()});
                return Err(self.finish(status(&body), body).await);
            }
            Err(_) => {
                return Err((
                    StatusCode::REQUEST_TIMEOUT,
                    Json(json!({"errcode": "M_UNKNOWN", "error": "request body timed out"})),
                )
                    .into_response())
            }
        };
        self.storage
            .transaction_request(&self.key, &body)
            .await
            .map_err(error)
    }

    pub async fn finish(&mut self, code: StatusCode, body: Value) -> Response {
        // Network/server/rate-limit failures remain retryable using the pinned
        // request. Successful effects commit their result inside storage.
        let final_reply = code == StatusCode::OK
            || (code.is_client_error()
                && code != StatusCode::REQUEST_TIMEOUT
                && code != StatusCode::TOO_MANY_REQUESTS);
        let body = if final_reply {
            match self.storage.finish_transaction(&self.key, &body).await {
                Ok(original) => original,
                Err(failure) => return error(failure),
            }
        } else {
            body
        };
        let code = if final_reply { status(&body) } else { code };
        (code, Json(body)).into_response()
    }
}
