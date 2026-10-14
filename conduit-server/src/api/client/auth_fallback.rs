//! User-Interactive Authentication fallback pages (conduit-y99.18).
//!
//! <https://spec.matrix.org/v1.19/client-server-api/#fallback>
//!
//!   GET  /_matrix/client/v3/auth/{authType}/fallback/web?session=…
//!   POST /_matrix/client/v3/auth/{authType}/fallback/web   (form submit)
//!
//! Supported stages: `m.login.password`, `m.login.dummy`,
//! `m.login.registration_token`.  On success the page runs the
//! spec-mandated `onAuthDone` / `postMessage("authDone")` script and the
//! client resubmits its request with only the session ID.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use serde_json::json;

use super::{uia, AuthState};

#[derive(Debug, Deserialize)]
pub struct FallbackQuery {
    pub session: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FallbackForm {
    pub session: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{title}</title>\
<style>body{{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;line-height:1.5}}\
label,input,button{{display:block;width:100%;box-sizing:border-box;margin:.5rem 0}}\
input,button{{padding:.6rem;font-size:1rem}}.error{{color:#b00020}}</style>\
</head><body><h1>{title}</h1>{body}</body></html>",
        title = escape(title),
        body = body,
    );
    (status, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

const DONE_SCRIPT: &str = "<script>\nif (window.onAuthDone) {\n    window.onAuthDone();\n} else if (window.opener && window.opener.postMessage) {\n    window.opener.postMessage(\"authDone\", \"*\");\n}\n</script>";

fn form(auth_type: &str, session: &str, error: Option<&str>) -> String {
    let err = error
        .map(|e| format!("<p class=\"error\" role=\"alert\">{}</p>", escape(e)))
        .unwrap_or_default();
    let fields = match auth_type {
        uia::PASSWORD => "<label for=\"password\">Password</label>\
<input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required autofocus>",
        uia::REGISTRATION_TOKEN => "<label for=\"token\">Registration token</label>\
<input id=\"token\" name=\"token\" type=\"text\" autocomplete=\"off\" required autofocus>",
        _ => "<p>Confirm to continue.</p>",
    };
    format!(
        "{err}<form method=\"post\" action=\"web\">\
<input type=\"hidden\" name=\"session\" value=\"{session}\">{fields}\
<button type=\"submit\">Continue</button></form>",
        session = escape(session),
    )
}

fn supported(auth_type: &str) -> bool {
    matches!(auth_type, uia::PASSWORD | uia::DUMMY | uia::REGISTRATION_TOKEN)
}

fn unsupported(auth_type: &str) -> Response {
    page(
        StatusCode::NOT_FOUND,
        "Unsupported authentication",
        &format!("<p>{} has no fallback on this server.</p>", escape(auth_type)),
    )
}

#[allow(clippy::result_large_err)]
fn check_session(auth_type: &str, session: Option<&str>) -> Result<String, Response> {
    let Some(session) = session.filter(|s| !s.is_empty()) else {
        return Err(page(StatusCode::BAD_REQUEST, "Missing session", "<p>No session was given.</p>"));
    };
    let Some(pending) = uia::pending(session) else {
        return Err(page(
            StatusCode::BAD_REQUEST,
            "Unknown session",
            "<p>This authentication session is unknown or has expired.</p>",
        ));
    };
    if !pending.expects.iter().any(|s| s == auth_type) {
        return Err(page(
            StatusCode::BAD_REQUEST,
            "Not expected",
            "<p>This step is not expected for this session.</p>",
        ));
    }
    Ok(session.to_owned())
}

pub async fn fallback_page<S: AuthState>(
    Path(auth_type): Path<String>,
    Query(q): Query<FallbackQuery>,
) -> Response {
    if !supported(&auth_type) {
        return unsupported(&auth_type);
    }
    match check_session(&auth_type, q.session.as_deref()) {
        Ok(session) => page(StatusCode::OK, "Authentication", &form(&auth_type, &session, None)),
        Err(r) => r,
    }
}

pub async fn fallback_submit<S: AuthState>(
    State(state): State<S>,
    Path(auth_type): Path<String>,
    Form(f): Form<FallbackForm>,
) -> Response {
    if !supported(&auth_type) {
        return unsupported(&auth_type);
    }
    let session = match check_session(&auth_type, f.session.as_deref()) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let auth = match auth_type.as_str() {
        uia::PASSWORD => {
            let user = uia::pending(&session).and_then(|p| p.user_id);
            let Some(user) = user else {
                return page(
                    StatusCode::BAD_REQUEST,
                    "Unknown account",
                    "<p>This session is not bound to an account.</p>",
                );
            };
            json!({
                "type": uia::PASSWORD,
                "identifier": {"type": "m.id.user", "user": user},
                "password": f.password.unwrap_or_default(),
            })
        }
        uia::REGISTRATION_TOKEN => json!({
            "type": uia::REGISTRATION_TOKEN,
            "token": f.token.unwrap_or_default(),
        }),
        _ => json!({ "type": uia::DUMMY }),
    };
    match uia::complete_out_of_band(&state, &session, &auth_type, &auth).await {
        Ok(()) => page(
            StatusCode::OK,
            "Authentication complete",
            &format!("<p>You may now close this window and return to the application.</p>{DONE_SCRIPT}"),
        ),
        Err(e) => page(StatusCode::UNAUTHORIZED, "Authentication", &form(&auth_type, &session, Some(&e))),
    }
}
