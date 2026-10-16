//! User-Interactive Authentication (UIA).
//!
//! <https://spec.matrix.org/v1.19/client-server-api/#user-interactive-authentication-api>
//!
//! Sessions live in process memory (single-node homeserver).  A session
//! is bound to the operation that created it and, once known, to the
//! user it authenticates: replaying a session against another endpoint
//! or another user is refused.  Completed stages are remembered, so a
//! retry of a completed stage either succeeds (flow complete) or reports
//! the completed stages again — never re-runs the stage.  Sessions are
//! deleted once the operation is authorised, so every protected request
//! (notably `/login/get_token`) re-prompts.
//!
//! Supported stages: `m.login.password`, `m.login.dummy`,
//! `m.login.registration_token`, and, when a validation sink is
//! configured, `m.login.email.identity` and `m.login.msisdn`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde_json::{json, Value};

use super::account_config::AccountConfig;
use super::{verify_password, AuthState, MatrixError};

pub const PASSWORD: &str = "m.login.password";
pub const DUMMY: &str = "m.login.dummy";
pub const REGISTRATION_TOKEN: &str = "m.login.registration_token";
pub const EMAIL_IDENTITY: &str = "m.login.email.identity";
pub const MSISDN: &str = "m.login.msisdn";

const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
struct Session {
    operation: String,
    user_id: Option<String>,
    flows: Vec<Vec<String>>,
    params: Value,
    completed: Vec<String>,
    created: Instant,
    threepid: Option<super::threepid_validation::ValidatedThreepid>,
}

static SESSIONS: Mutex<Option<HashMap<String, Session>>> = Mutex::new(None);

fn with_sessions<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, Session>) -> R,
{
    let mut guard = SESSIONS.lock().unwrap_or_else(|p| p.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    map.retain(|_, s| s.created.elapsed() < SESSION_TTL);
    f(map)
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a bare session ID (legacy helper, kept for callers that only
/// need an opaque ID).
pub fn new_session_id() -> String {
    random_id()
}

/// Forget a session.
pub fn mark_session_used(session_id: &str) {
    with_sessions(|s| s.remove(session_id));
}

/// What an endpoint requires.
#[derive(Debug, Clone)]
pub struct UiaRequest {
    /// Stable name of the protected operation, e.g. `"POST /delete_devices"`.
    pub operation: String,
    /// The user being authenticated, when the caller already knows it
    /// (from an access token).  `None` lets `m.login.password` decide.
    pub user_id: Option<String>,
    pub flows: Vec<Vec<String>>,
    pub params: Value,
}

impl UiaRequest {
    pub fn new(operation: impl Into<String>, user_id: Option<&str>, flows: Vec<Vec<&str>>) -> Self {
        Self {
            operation: operation.into(),
            user_id: user_id.map(str::to_owned),
            flows: flows
                .into_iter()
                .map(|f| f.into_iter().map(str::to_owned).collect())
                .collect(),
            params: json!({}),
        }
    }
}

/// A completed UIA exchange.
#[derive(Debug, Clone)]
pub struct UiaPassed {
    /// The user the stages proved, if any stage identified one.
    pub user_id: Option<String>,
    /// Set when an email or phone stage proved a homeserver validation session.
    pub threepid: Option<super::threepid_validation::ValidatedThreepid>,
}

/// The flows protecting an account operation for `user_id`.
///
/// Accounts with a password re-prove it.  Accounts without one
/// (identikey / SSO only) have no re-authentication stage this server
/// can run yet, so they are offered `m.login.dummy`: possession of a
/// valid access token is the proof (tracked as a follow-up).
pub async fn account_flows<S: AuthState>(state: &S, user_id: &str) -> Vec<Vec<&'static str>> {
    match state.storage().get_account(user_id).await {
        Ok(Some(a)) if a.password_hash.is_some() => vec![vec![PASSWORD]],
        _ => vec![vec![DUMMY]],
    }
}

fn challenge(
    session_id: &str,
    session: &Session,
    error: Option<(&'static str, String)>,
) -> Response {
    let mut body = json!({
        "flows": session
            .flows
            .iter()
            .map(|stages| json!({ "stages": stages }))
            .collect::<Vec<_>>(),
        "params": session.params,
        "session": session_id,
    });
    if !session.completed.is_empty() {
        body["completed"] = json!(session.completed);
    }
    if let Some((errcode, msg)) = error {
        body["errcode"] = json!(errcode);
        body["error"] = json!(msg);
    }
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

fn flow_complete(session: &Session) -> bool {
    session.flows.contains(&session.completed)
}

fn stage_allowed(session: &Session, stage: &str) -> bool {
    let done = session.completed.len();
    session.flows.iter().any(|f| {
        f.len() > done && f[..done] == session.completed[..] && f[done] == stage
    })
}

/// Resolve the user named by an `m.login.password` auth dict.
fn password_user(auth: &Value, server_name: &str) -> Result<String, String> {
    let identifier = auth.get("identifier");
    let raw = match identifier {
        Some(id) => match id.get("type").and_then(Value::as_str) {
            Some("m.id.user") => id.get("user").and_then(Value::as_str),
            Some("m.id.thirdparty") | Some("m.id.phone") => {
                return Err("unknown third-party identifier".into())
            }
            _ => return Err("unsupported identifier type".into()),
        },
        // Deprecated top-level `user`.
        None => auth.get("user").and_then(Value::as_str),
    };
    let raw = raw.filter(|s| !s.is_empty()).ok_or("missing user identifier")?;
    if let Some(full) = raw.strip_prefix('@') {
        let (local, server) = full.split_once(':').ok_or("malformed user ID")?;
        if server != server_name {
            return Err("user is not local to this server".into());
        }
        Ok(format!("@{local}:{server_name}"))
    } else {
        Ok(format!("@{raw}:{server_name}"))
    }
}

/// Run one stage against `session`.  On success the stage is appended
/// to `completed`.
async fn run_stage<S: AuthState>(
    state: &S,
    session: &mut Session,
    stage: &str,
    auth: &Value,
) -> Result<(), (&'static str, String)> {
    match stage {
        DUMMY => {}
        PASSWORD => {
            let user = password_user(auth, state.server_name())
                .map_err(|e| ("M_FORBIDDEN", e))?;
            if let Some(expected) = &session.user_id {
                if *expected != user {
                    return Err(("M_FORBIDDEN", "identifier does not match the authenticated user".into()));
                }
            }
            let password = auth
                .get("password")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let account = state
                .storage()
                .get_account(&user)
                .await
                .map_err(|e| ("M_UNKNOWN", e.to_string()))?;
            let Some(hash) = account
                .filter(|a| a.deactivated_at.is_none())
                .and_then(|a| a.password_hash)
            else {
                return Err(("M_FORBIDDEN", "Invalid username or password".into()));
            };
            match verify_password(password, hash).await {
                Ok(true) => session.user_id = Some(user),
                Ok(false) => return Err(("M_FORBIDDEN", "Invalid username or password".into())),
                Err(e) => return Err(("M_UNKNOWN", e)),
            }
        }
        REGISTRATION_TOKEN => {
            let token = auth.get("token").and_then(Value::as_str).unwrap_or_default();
            if !AccountConfig::get().registration_token_valid(token) {
                return Err(("M_FORBIDDEN", "Invalid registration token".into()));
            }
        }
        EMAIL_IDENTITY | MSISDN => {
            let medium = if stage == EMAIL_IDENTITY { "email" } else { "msisdn" };
            let creds = auth.get("threepid_creds").cloned().unwrap_or(Value::Null);
            let (user_id, proved) =
                super::threepid_validation::identity_stage(state, &session.operation, medium, &creds).await?;
            if let (Some(expected), Some(user_id)) = (&session.user_id, &user_id) {
                if expected != user_id {
                    return Err((
                        "M_FORBIDDEN",
                        "identifier does not match the authenticated user".into(),
                    ));
                }
            }
            if let Some(user_id) = user_id {
                session.user_id = Some(user_id);
            }
            session.threepid = Some(proved);
        }
        other => {
            return Err(("M_UNRECOGNIZED", format!("unsupported authentication type {other}")));
        }
    }
    session.completed.push(stage.to_owned());
    Ok(())
}

/// Drive one request through UIA.
///
/// `Ok` means the operation is authorised now.  `Err` is the response to
/// return: a 401 challenge (possibly carrying an errcode for a failed
/// stage) or a 4xx for a misused session.
pub async fn authenticate<S: AuthState>(
    state: &S,
    req: UiaRequest,
    auth: Option<&Value>,
) -> Result<UiaPassed, Response> {
    let auth = auth.filter(|a| a.is_object());
    let session_id = auth
        .and_then(|a| a.get("session"))
        .and_then(Value::as_str)
        .map(str::to_owned);

    let (session_id, mut session) = match session_id {
        Some(id) => {
            let found = with_sessions(|m| m.get(&id).cloned());
            let Some(session) = found else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"errcode": "M_UNKNOWN", "error": "Unknown UIA session"})),
                )
                    .into_response());
            };
            if session.operation != req.operation {
                return Err(MatrixError::forbidden(
                    "Requested operation has changed during the UI authentication session",
                )
                .into_response());
            }
            if let (Some(a), Some(b)) = (&session.user_id, &req.user_id) {
                if a != b {
                    return Err(MatrixError::forbidden(
                        "UI authentication session belongs to another user",
                    )
                    .into_response());
                }
            }
            (id, session)
        }
        None => {
            let session = Session {
                operation: req.operation.clone(),
                user_id: req.user_id.clone(),
                flows: req.flows.clone(),
                params: req.params.clone(),
                completed: Vec::new(),
                created: Instant::now(),
                threepid: None,
            };
            (random_id(), session)
        }
    };
    if session.user_id.is_none() {
        session.user_id = req.user_id.clone();
    }

    let Some(auth) = auth else {
        with_sessions(|m| m.insert(session_id.clone(), session.clone()));
        return Err(challenge(&session_id, &session, None));
    };

    let mut error = None;
    if let Some(stage) = auth.get("type").and_then(Value::as_str) {
        if !session.completed.iter().any(|c| c == stage) {
            if !stage_allowed(&session, stage) {
                error = Some((
                    "M_FORBIDDEN",
                    format!("authentication stage {stage} is not expected now"),
                ));
            } else if let Err(e) = run_stage(state, &mut session, stage, auth).await {
                error = Some(e);
            }
        }
    }

    if error.is_none() && flow_complete(&session) {
        with_sessions(|m| m.remove(&session_id));
        return Ok(UiaPassed { user_id: session.user_id, threepid: session.threepid });
    }
    with_sessions(|m| m.insert(session_id.clone(), session.clone()));
    Err(challenge(&session_id, &session, error))
}

/// Information the fallback page needs about a pending session.
#[derive(Debug, Clone)]
pub struct PendingSession {
    pub user_id: Option<String>,
    pub expects: Vec<String>,
}

pub fn pending(session_id: &str) -> Option<PendingSession> {
    with_sessions(|m| {
        m.get(session_id).map(|s| {
            let done = s.completed.len();
            let expects = s
                .flows
                .iter()
                .filter(|f| f.len() > done && f[..done] == s.completed[..])
                .map(|f| f[done].clone())
                .collect();
            PendingSession { user_id: s.user_id.clone(), expects }
        })
    })
}

/// Complete a stage out of band (the fallback web page).  The client
/// then resubmits with only the session ID.
pub async fn complete_out_of_band<S: AuthState>(
    state: &S,
    session_id: &str,
    stage: &str,
    auth: &Value,
) -> Result<(), String> {
    let Some(mut session) = with_sessions(|m| m.get(session_id).cloned()) else {
        return Err("Unknown or expired session".into());
    };
    if session.completed.iter().any(|c| c == stage) {
        return Ok(());
    }
    if !stage_allowed(&session, stage) {
        return Err(format!("{stage} is not expected for this session"));
    }
    run_stage(state, &mut session, stage, auth)
        .await
        .map_err(|(_, msg)| msg)?;
    with_sessions(|m| m.insert(session_id.to_owned(), session));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(flows: &[&[&str]], completed: &[&str]) -> Session {
        Session {
            operation: "op".into(),
            user_id: None,
            flows: flows
                .iter()
                .map(|f| f.iter().map(|s| s.to_string()).collect())
                .collect(),
            params: json!({}),
            completed: completed.iter().map(|s| s.to_string()).collect(),
            created: Instant::now(),
            threepid: None,
        }
    }

    #[test]
    fn stages_must_follow_a_flow_in_order() {
        let s = session(&[&["a", "b"], &["c"]], &[]);
        assert!(stage_allowed(&s, "a"));
        assert!(stage_allowed(&s, "c"));
        assert!(!stage_allowed(&s, "b"));
        let s = session(&[&["a", "b"], &["c"]], &["a"]);
        assert!(stage_allowed(&s, "b"));
        assert!(!stage_allowed(&s, "c"));
        assert!(!flow_complete(&s));
        let s = session(&[&["a", "b"]], &["a", "b"]);
        assert!(flow_complete(&s));
    }

    #[test]
    fn password_identifier_resolution() {
        let local = json!({"identifier": {"type": "m.id.user", "user": "alice"}});
        assert_eq!(password_user(&local, "hs").unwrap(), "@alice:hs");
        let full = json!({"identifier": {"type": "m.id.user", "user": "@alice:hs"}});
        assert_eq!(password_user(&full, "hs").unwrap(), "@alice:hs");
        let remote = json!({"identifier": {"type": "m.id.user", "user": "@alice:other"}});
        assert!(password_user(&remote, "hs").is_err());
        let legacy = json!({"user": "bob"});
        assert_eq!(password_user(&legacy, "hs").unwrap(), "@bob:hs");
        let tp = json!({"identifier": {"type": "m.id.thirdparty", "medium": "email", "address": "x@y"}});
        assert!(password_user(&tp, "hs").is_err());
    }
}
