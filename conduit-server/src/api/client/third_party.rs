//! Third-party invites and identity-server-backed account 3PIDs
//! (conduit-y99.36).
//!
//! <https://spec.matrix.org/v1.19/client-server-api/#third-party-invites>
//!
//! * `POST /rooms/{roomId}/invite` with `id_server`/`id_access_token`/
//!   `medium`/`address` (and `createRoom` `invite_3pid`): look the 3PID up on
//!   the identity server (`hash_details` + `lookup`); a bound user gets an
//!   ordinary invite, otherwise the invite is stored on the identity server
//!   (`store-invite`) and an `m.room.third_party_invite` state event is
//!   emitted with the returned token and public keys.
//! * `PUT /_matrix/federation/v1/3pid/onbind` (called by identity servers,
//!   unauthenticated): for rooms on this server the signed proof is
//!   exchanged for an `m.room.member` invite carrying
//!   `content.third_party_invite`, which the v11 auth rules verify against
//!   the `m.room.third_party_invite` keys.  Rooms on other servers are
//!   exchanged with the inviting server.
//! * `POST /account/3pid/bind`, `/unbind`, `/delete` and deactivation proxy
//!   to the identity server and remember bindings so unbinding knows where.

// Handlers answer with ready-made `Response`s on every error path.
#![allow(clippy::result_large_err)]

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::put,
    Json, Router,
};
use serde_json::{json, Value};
use tracing::{info, warn};

use conduit::auth::third_party_signed_matches;
use conduit::room::Room;
use conduit::signing::server_of_user_id;

use crate::identity_service::{canonical_3pid, IdentityClient, IsError, Unbind};

use super::event_pipeline::{build_sign_and_persist, RoomEventSenderWrapper};
use super::{AuthState, AuthedUser, MatrixError};

/// `PUT /_matrix/federation/v1/3pid/onbind` (identity server -> homeserver).
pub fn router<S: AuthState>() -> Router<S> {
    Router::new().route("/_matrix/federation/v1/3pid/onbind", put(onbind::<S>))
}

fn error(status: StatusCode, errcode: &str, message: impl Into<String>) -> Response {
    (status, Json(json!({"errcode": errcode, "error": message.into()}))).into_response()
}

/// Map an identity-server failure to a client response.  A Matrix error
/// from the identity server is passed through (spec: unbind errors "should
/// be passed through to the client").
fn is_error(e: IsError) -> Response {
    match e {
        IsError::InvalidServer(s) => error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            format!("id_server must be a hostname[:port], got {s}"),
        ),
        IsError::Status(status, body) if body["errcode"].is_string() => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(body),
        )
            .into_response(),
        other => error(StatusCode::BAD_GATEWAY, "M_UNKNOWN", other.to_string()),
    }
}

fn required<'a>(body: &'a Value, field: &str) -> Result<&'a str, Response> {
    match body.get(field) {
        None | Some(Value::Null) => Err(error(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            format!("{field} is required"),
        )),
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(MatrixError::bad_json(format!("{field} must be a string")).into_response()),
    }
}

/// Whether `body` is the third-party form of `/invite`.
pub fn is_3pid_invite(body: &Value) -> bool {
    body.get("user_id").is_none()
        && ["id_server", "medium", "address"].iter().any(|k| body.get(*k).is_some())
}

/// The third-party form of `POST /rooms/{roomId}/invite`.
pub async fn invite_by_3pid<S: AuthState>(
    state: &S,
    sender: &str,
    room_id: &str,
    body: &Value,
) -> Result<(), Response> {
    let id_server = required(body, "id_server")?;
    let id_access_token = required(body, "id_access_token")?;
    let medium = required(body, "medium")?;
    let address = required(body, "address")?;
    let Some(address) = canonical_3pid(medium, address) else {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "M_INVALID_PARAM",
            format!("not a valid {medium} address"),
        ));
    };

    // Only joined members may invite (checked before involving the IS).
    let storage = state.storage();
    let joined = storage
        .get_state_entry(room_id, "m.room.member", sender)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
        .is_some_and(|ev| ev.content["membership"] == "join");
    if !joined {
        return Err(MatrixError::forbidden("You are not joined to this room").into_response());
    }

    let identity = IdentityClient::shared();
    let found = identity
        .lookup(id_server, id_access_token, medium, &address)
        .await
        .map_err(is_error)?;
    if let Some(mxid) = found {
        super::room_membership::check_invite_allowed(state, &mxid).await?;
        return Room::new(room_id)
            .invite(sender, &mxid, false, &RoomEventSenderWrapper(state))
            .await
            .map(|_| ())
            .map_err(|e| MatrixError::from_conduit(e).into_response());
    }

    // Unbound: store the invite and emit m.room.third_party_invite.
    let mut request = json!({
        "medium": medium,
        "address": address,
        "room_id": room_id,
        "sender": sender,
    });
    let state_content = |ty: &str| {
        let storage = storage.clone();
        let (room_id, ty) = (room_id.to_owned(), ty.to_owned());
        async move {
            storage
                .get_state_entry(&room_id, &ty, "")
                .await
                .ok()
                .flatten()
                .map(|e| e.content.clone())
                .unwrap_or(Value::Null)
        }
    };
    let extras = [
        ("room_alias", state_content("m.room.canonical_alias").await["alias"].clone()),
        ("room_avatar_url", state_content("m.room.avatar").await["url"].clone()),
        ("room_join_rules", state_content("m.room.join_rules").await["join_rule"].clone()),
        ("room_name", state_content("m.room.name").await["name"].clone()),
        ("room_type", state_content("m.room.create").await["type"].clone()),
    ];
    for (key, value) in extras {
        if value.is_string() {
            request[key] = value;
        }
    }
    if let Ok(Some(member)) = storage.get_state_entry(room_id, "m.room.member", sender).await {
        for (from, to) in [("displayname", "sender_display_name"), ("avatar_url", "sender_avatar_url")] {
            if member.content[from].is_string() {
                request[to] = member.content[from].clone();
            }
        }
    }
    let stored = identity
        .store_invite(id_server, id_access_token, &request)
        .await
        .map_err(is_error)?;
    let first = &stored.public_keys[0];
    let content = json!({
        "display_name": stored.display_name,
        "key_validity_url": first["key_validity_url"],
        "public_key": first["public_key"],
        "public_keys": stored.public_keys,
    });
    build_sign_and_persist(
        state,
        sender,
        room_id,
        "m.room.third_party_invite",
        Some(&stored.token),
        content,
    )
    .await
    .map(|_| ())
    .map_err(|(status, body)| (status, body).into_response())
}

/// `PUT /_matrix/federation/v1/3pid/onbind`.
pub async fn onbind<S: AuthState>(State(state): State<S>, Json(body): Json<Value>) -> Response {
    let Some(mxid) = body["mxid"].as_str() else {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "mxid is required");
    };
    let Some(invites) = body["invites"].as_array() else {
        return error(StatusCode::BAD_REQUEST, "M_MISSING_PARAM", "invites is required");
    };
    let server_name = state.server_name().to_owned();
    for invite in invites {
        let (Some(room_id), Some(sender)) = (invite["room_id"].as_str(), invite["sender"].as_str()) else {
            warn!("onbind invite without room_id/sender ignored");
            continue;
        };
        if invite["mxid"].as_str() != Some(mxid) {
            warn!(room_id, "onbind invite for a different mxid ignored");
            continue;
        }
        // Room version 12 ids are `!` + the create-event reference hash and
        // carry no server name. A room this server stores is local. Older
        // ids are local only when the domain matches.
        let local = match room_id.split_once(':') {
            Some((_, server)) => server == server_name,
            None => state
                .storage()
                .get_state_entry(room_id, "m.room.create", "")
                .await
                .ok()
                .flatten()
                .is_some(),
        };
        if !local {
            exchange_remote(&state, room_id, sender, mxid, invite).await;
            continue;
        }
        if let Err(e) = exchange_local(&state, room_id, sender, mxid, &invite["signed"]).await {
            warn!(room_id, mxid, error = %e, "third-party invite exchange rejected");
        } else {
            info!(room_id, mxid, "third-party invite exchanged for a membership invite");
        }
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

/// Ask the inviting server to auth a third-party invite for a room this
/// server is not in. `onbind` still answers 200 when the exchange fails.
async fn exchange_remote<S: AuthState>(state: &S, room_id: &str, sender: &str, mxid: &str, invite: &Value) {
    let Some(dest) = server_of_user_id(sender) else {
        warn!(room_id, sender, "onbind sender is not a user id");
        return;
    };
    let Some(client) = state.federation_client() else {
        warn!(room_id, "onbind remote exchange needs federation");
        return;
    };
    let display_name = invite["display_name"]
        .as_str()
        .or_else(|| invite["address"].as_str())
        .unwrap_or("");
    let body = json!({
        "type": "m.room.member",
        "room_id": room_id,
        "sender": sender,
        "state_key": mxid,
        "content": {
            "membership": "invite",
            "third_party_invite": {
                "display_name": display_name,
                "signed": invite["signed"],
            },
        },
    });
    match client.exchange_third_party_invite(dest, room_id, &body).await {
        Ok(_) => info!(room_id, mxid, dest, "third-party invite exchanged with the inviting server"),
        Err(error) => warn!(room_id, mxid, dest, %error, "third-party invite exchange failed"),
    }
}

/// Turn a signed third-party invite into an `m.room.member` invite in a
/// local room.  The auth rules verify `signed` against the room's
/// `m.room.third_party_invite` keys. The resident server also checks
/// `key_validity_url` before that invite is stored.
pub async fn exchange_local<S: AuthState>(
    state: &S,
    room_id: &str,
    sender: &str,
    mxid: &str,
    signed: &Value,
) -> Result<String, String> {
    let token = signed["token"].as_str().ok_or("signed has no token")?;
    let tpi = state
        .storage()
        .get_state_entry(room_id, "m.room.third_party_invite", token)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no m.room.third_party_invite for the token")?;
    if !key_validity_allows(signed, &tpi.content).await {
        return Err("third-party invite key is not valid".to_owned());
    }
    issue_third_party_member_invite(state, room_id, sender, mxid, signed, &tpi.content).await
}

/// A local join presented `third_party_signed`. Verify it against the
/// pending `m.room.third_party_invite` and, when that event names a
/// `key_validity_url` for the signing key, require the identity server to
/// report the key valid. A `public_keys` entry with no URL is valid
/// indefinitely and is not fetched. The check is deliberately outside
/// `check_auth`: another homeserver must not reject the resulting
/// membership because this URL failed.
pub async fn accept_third_party_join<S: AuthState>(
    state: &S,
    user_id: &str,
    room_id: &str,
    signed: &Value,
) -> Result<(), Response> {
    let mxid = signed_str(signed, "mxid")?;
    let sender = signed_str(signed, "sender")?;
    let token = signed_str(signed, "token")?;
    if !signed["signatures"].is_object() {
        return Err(error(StatusCode::BAD_REQUEST, "M_BAD_JSON", "signatures is required"));
    }
    if mxid != user_id {
        return Err(error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "third_party_signed mxid does not match the joining user",
        ));
    }
    let tpi = state
        .storage()
        .get_state_entry(room_id, "m.room.third_party_invite", token)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
        .ok_or_else(|| error(StatusCode::FORBIDDEN, "M_FORBIDDEN", "No third-party invite for that token"))?;
    if tpi.sender != sender {
        return Err(error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "sender does not match the third-party invite",
        ));
    }
    if !key_validity_allows(signed, &tpi.content).await {
        return Err(error(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "third-party invite key is not valid",
        ));
    }
    let membership = state
        .storage()
        .get_state_entry(room_id, "m.room.member", user_id)
        .await
        .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
        .and_then(|event| event.content["membership"].as_str().map(str::to_owned));
    if !matches!(membership.as_deref(), Some("invite") | Some("join")) {
        issue_third_party_member_invite(state, room_id, sender, user_id, signed, &tpi.content)
            .await
            .map_err(|message| error(StatusCode::FORBIDDEN, "M_FORBIDDEN", message))?;
    }
    Ok(())
}

fn signed_str<'a>(signed: &'a Value, field: &str) -> Result<&'a str, Response> {
    match signed.get(field) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value),
        Some(Value::String(_)) | None | Some(Value::Null) => Err(error(
            StatusCode::BAD_REQUEST,
            "M_MISSING_PARAM",
            format!("{field} is required"),
        )),
        Some(_) => Err(error(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            format!("{field} must be a string"),
        )),
    }
}

async fn issue_third_party_member_invite<S: AuthState>(
    state: &S,
    room_id: &str,
    sender: &str,
    mxid: &str,
    signed: &Value,
    invite_content: &Value,
) -> Result<String, String> {
    let content = json!({
        "membership": "invite",
        "third_party_invite": {
            "display_name": invite_content["display_name"],
            "signed": signed,
        },
    });
    build_sign_and_persist(state, sender, room_id, "m.room.member", Some(mxid), content)
        .await
        .map_err(|(_, body)| body.0.error.clone())
}

/// A signature-matching key allows the join when its URL reports `valid`,
/// or when that key publishes no `key_validity_url`. A `public_keys` entry
/// does not inherit the top-level URL: an absent entry URL is valid
/// indefinitely.
async fn key_validity_allows(signed: &Value, content: &Value) -> bool {
    let identity = IdentityClient::shared();
    if let Some(key) = content["public_key"].as_str() {
        if third_party_signed_matches(signed, key) {
            match content["key_validity_url"].as_str() {
                Some(url) => {
                    if identity.key_is_valid(url, key).await.unwrap_or(false) {
                        return true;
                    }
                }
                None => return true,
            }
        }
    }
    let Some(list) = content["public_keys"].as_array() else {
        return false;
    };
    for entry in list {
        let Some(key) = entry["public_key"].as_str() else { continue };
        if !third_party_signed_matches(signed, key) {
            continue;
        }
        match entry["key_validity_url"].as_str() {
            None => return true,
            Some(url) => {
                if identity.key_is_valid(url, key).await.unwrap_or(false) {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Account 3PID bindings
// ---------------------------------------------------------------------------

/// `POST /account/3pid/bind`.
pub async fn account_bind<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let fields = (|| {
        Ok::<_, Response>((
            required(&body, "client_secret")?,
            required(&body, "id_server")?,
            required(&body, "id_access_token")?,
            required(&body, "sid")?,
        ))
    })();
    let (client_secret, id_server, id_access_token, sid) = match fields {
        Ok(f) => f,
        Err(r) => return r,
    };
    let association = match IdentityClient::shared()
        .bind(id_server, id_access_token, sid, client_secret, &authed.user_id)
        .await
    {
        Ok(a) => a,
        Err(e) => return is_error(e),
    };
    if let (Some(medium), Some(address)) = (association["medium"].as_str(), association["address"].as_str()) {
        if let Err(e) = state
            .storage()
            .add_threepid_binding(&authed.user_id, medium, address, id_server)
            .await
        {
            return MatrixError::unknown(e.to_string()).into_response();
        }
    }
    (StatusCode::OK, Json(json!({}))).into_response()
}

/// Unbind `(medium, address)` of `user_id` from `id_server` (or from every
/// server it was bound on through this homeserver).  `Ok("success")` when
/// every server unbound it, `Ok("no-support")` when there was nothing known
/// to unbind or a server cannot unbind.
pub async fn unbind<S: AuthState>(
    state: &S,
    user_id: &str,
    medium: &str,
    address: &str,
    id_server: Option<&str>,
) -> Result<&'static str, Response> {
    let storage = state.storage();
    let servers: Vec<String> = match id_server {
        Some(s) => vec![s.to_owned()],
        None => storage
            .threepid_bindings(user_id)
            .await
            .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?
            .into_iter()
            .filter(|(m, a, _)| m == medium && a == address)
            .map(|(_, _, s)| s)
            .collect(),
    };
    if servers.is_empty() {
        return Ok("no-support");
    }
    let identity = IdentityClient::shared();
    let key = state.server_key();
    let mut result = "success";
    for server in servers {
        match identity
            .unbind(&server, user_id, medium, address, state.server_name(), &key)
            .await
        {
            Ok(Unbind::Success) => {
                storage
                    .remove_threepid_binding(user_id, medium, address, Some(&server))
                    .await
                    .map_err(|e| MatrixError::unknown(e.to_string()).into_response())?;
            }
            Ok(Unbind::NoSupport) => result = "no-support",
            Err(e @ IsError::Status(..)) => return Err(is_error(e)),
            Err(e) => {
                warn!(id_server = server, error = %e, "identity server unbind failed");
                result = "no-support";
            }
        }
    }
    Ok(result)
}

/// `POST /account/3pid/unbind` and `POST /account/3pid/delete`.
///
/// Removes a homeserver-validated address, then unbinds it from any
/// identity server this homeserver published it to.
pub async fn account_unbind<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    body: Option<Json<Value>>,
) -> Response {
    let body = body.map(|Json(v)| v).unwrap_or(Value::Null);
    let (medium, address) = match (required(&body, "medium"), required(&body, "address")) {
        (Ok(m), Ok(a)) => (m, a),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let id_server = match body.get("id_server") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return MatrixError::bad_json("id_server must be a string").into_response(),
    };
    let address = canonical_3pid(medium, address).unwrap_or_else(|| address.to_owned());
    if let Err(e) = state
        .storage()
        .remove_account_threepid(&authed.user_id, medium, &address)
        .await
    {
        return MatrixError::unknown(e.to_string()).into_response();
    }
    match unbind(&state, &authed.user_id, medium, &address, id_server).await {
        Ok(result) => (StatusCode::OK, Json(json!({ "id_server_unbind_result": result }))).into_response(),
        Err(r) => r,
    }
}

/// Unbind every remembered binding of a deactivating user; the
/// `id_server_unbind_result` for `POST /account/deactivate`.
pub async fn unbind_all<S: AuthState>(state: &S, user_id: &str, id_server: Option<&str>) -> &'static str {
    let bindings = state.storage().threepid_bindings(user_id).await.unwrap_or_default();
    let mut result = "success";
    for (medium, address, server) in bindings {
        if id_server.is_some_and(|s| s != server) {
            continue;
        }
        match unbind(state, user_id, &medium, &address, Some(&server)).await {
            Ok("success") => {}
            _ => result = "no-support",
        }
    }
    result
}
