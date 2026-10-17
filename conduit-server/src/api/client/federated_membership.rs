//! Outbound membership when this server is not already in the room, and
//! delivery of a normal invite to the invitee's server.
//!
//! Resident rooms keep the local authoring path. A room with no `m.room.create`
//! is joined or knocked through `make_*` / `send_*`. Room versions 1 and 2 use
//! the v1 event format and `/send_join` v1. A remote invite is stored locally
//! and offered over `/invite`. An HTTP error and a 200 that fails co-signature
//! admission both retract that membership. A verified co-signature replaces
//! the row. An unreachable invitee leaves the local invite in place.

use std::future::Future;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

use conduit::event::{Event, Pdu, WirePdu};
use conduit::signing::server_of_user_id;
use conduit::storage::Storage;

use super::event_pipeline::fan_out_authored;
use super::{AuthState, MatrixError};

const ATTEMPT: Duration = Duration::from_secs(3);
const STRIPPED_STATE: &[&str] = &[
    "m.room.create",
    "m.room.name",
    "m.room.avatar",
    "m.room.topic",
    "m.room.join_rules",
    "m.room.canonical_alias",
    "m.room.encryption",
    "m.room.history_visibility",
];

pub(crate) fn federation_enabled() -> bool {
    std::env::var("CONDUIT_FEDERATION").ok().as_deref() != Some("0")
}

/// Repeated `via` and the deprecated `server_name` query parameter.
pub(crate) fn query_servers(query: Option<&str>) -> Vec<String> {
    let Some(query) = query else { return Vec::new() };
    url::form_urlencoded::parse(query.as_bytes())
        .filter(|(key, value)| (key == "via" || key == "server_name") && !value.is_empty())
        .map(|(_, value)| value.into_owned())
        .collect()
}

fn push_dest(out: &mut Vec<String>, name: &str, local: &str) {
    if name.is_empty() || name == local || out.iter().any(|existing| existing == name) {
        return;
    }
    out.push(name.to_owned());
}

fn domain_of(id: &str) -> Option<&str> {
    id.split_once(':').map(|(_, server)| server).filter(|server| !server.is_empty())
}

fn destinations(id: &str, hinted: &[String], local: &str) -> Vec<String> {
    let mut out = Vec::new();
    for name in hinted {
        push_dest(&mut out, name, local);
    }
    if let Some(server) = domain_of(id) {
        push_dest(&mut out, server, local);
    }
    out.truncate(5);
    out
}

async fn attempt<T, E: std::fmt::Display>(future: impl Future<Output = Result<T, E>>) -> Result<T, String> {
    match tokio::time::timeout(ATTEMPT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("timed out".into()),
    }
}

fn bad_gateway(message: impl Into<String>) -> Response {
    MatrixError::forwarded(StatusCode::BAD_GATEWAY, "M_UNKNOWN", message).into_response()
}

fn incompatible(version: &str) -> Response {
    MatrixError::forwarded(
        StatusCode::BAD_REQUEST,
        "M_INCOMPATIBLE_ROOM_VERSION",
        format!("room version {version} cannot be joined with this server's event format"),
    )
    .into_response()
}

async fn local_create(storage: &dyn Storage, room_id: &str) -> Result<bool, Response> {
    match storage.get_state_entry(room_id, "m.room.create", "").await {
        Ok(found) => Ok(found.is_some()),
        Err(error) => Err(MatrixError::unknown(error.to_string()).into_response()),
    }
}

pub(crate) async fn room_is_resident<S: AuthState>(state: &S, room_id: &str) -> Result<bool, Response> {
    local_create(state.storage().as_ref(), room_id).await
}

async fn fill_profile(storage: &dyn Storage, sender: &str, event: &mut Value) {
    let Some(content) = event.get_mut("content") else { return };
    if content.get("displayname").is_some() || content.get("avatar_url").is_some() {
        return;
    }
    let Ok(Some(account)) = storage.get_account(sender).await else { return };
    let Some(object) = content.as_object_mut() else { return };
    if let Some(name) = account.displayname {
        object.insert("displayname".into(), json!(name));
    }
    if let Some(url) = account.avatar_url {
        object.insert("avatar_url".into(), json!(url));
    }
}

enum SignedMembership {
    /// Room versions 3 and later. The path id is `event_id_for`.
    Modern(WirePdu),
    /// Room versions 1 and 2. The body includes `event_id`.
    Legacy(Value),
}

fn sign_legacy_membership<S: AuthState>(
    state: &S,
    room_id: &str,
    sender: &str,
    membership: &str,
    mut event: Value,
    reason: Option<&str>,
) -> Result<Value, Response> {
    let Some(object) = event.as_object_mut() else {
        return Err(MatrixError::invalid_param("membership template is not a supported event").into_response());
    };
    if object.get("room_id").and_then(Value::as_str).unwrap_or("").is_empty() {
        object.insert("room_id".into(), json!(room_id));
    }
    if object.get("sender").and_then(Value::as_str) != Some(sender)
        || object.get("state_key").and_then(Value::as_str) != Some(sender)
        || object.get("type").and_then(Value::as_str) != Some("m.room.member")
    {
        return Err(MatrixError::invalid_param("membership template does not name this user").into_response());
    }
    if object.get("content").and_then(|content| content.get("membership")).and_then(Value::as_str) != Some(membership) {
        return Err(MatrixError::invalid_param("membership template has the wrong membership").into_response());
    }
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        if let Some(content) = object.get_mut("content").and_then(Value::as_object_mut) {
            content.insert("reason".into(), json!(reason));
        }
    }
    object.entry("origin".to_owned()).or_insert_with(|| json!(state.server_name()));
    let timestamp = object.get("origin_server_ts").and_then(Value::as_u64).unwrap_or_else(crate::federation::now_ms);
    object.insert("origin_server_ts".into(), json!(timestamp));
    object.remove("room_version");
    let event_id = format!("${}:{}", uuid::Uuid::new_v4().simple(), state.server_name());
    object.insert("event_id".into(), json!(event_id));
    crate::federation::spec_v119::seal_v1_event(&mut event, state.server_key().as_ref(), state.server_name())
        .map_err(|_| MatrixError::unknown("signing error: v1 membership").into_response())?;
    Ok(event)
}

fn sign_template<S: AuthState>(
    state: &S,
    room_id: &str,
    sender: &str,
    membership: &str,
    event: Value,
    reason: Option<&str>,
    minimum_version: u32,
) -> Result<(SignedMembership, String), Response> {
    let version = event
        .get("room_version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut template = event;
    if let Some(object) = template.as_object_mut() {
        object.remove("room_version");
    }
    let version = version.unwrap_or_else(|| "11".into());
    let parsed = conduit::room_version::parse(&version).unwrap_or(0);
    if parsed == 0 || parsed < minimum_version {
        return Err(incompatible(&version));
    }
    if parsed < 3 {
        let legacy = sign_legacy_membership(state, room_id, sender, membership, template, reason)?;
        return Ok((SignedMembership::Legacy(legacy), version));
    }
    let mut pdu: Pdu = serde_json::from_value(template)
        .map_err(|_| MatrixError::invalid_param("membership template is not a supported event").into_response())?;
    if pdu.room_id.is_empty() {
        pdu.room_id = room_id.to_owned();
    }
    if pdu.sender != sender || pdu.state_key.as_deref() != Some(sender) || pdu.event_type != "m.room.member" {
        return Err(MatrixError::invalid_param("membership template does not name this user").into_response());
    }
    if pdu.content.get("membership").and_then(Value::as_str) != Some(membership) {
        return Err(MatrixError::invalid_param("membership template has the wrong membership").into_response());
    }
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        pdu.content["reason"] = json!(reason);
    }
    conduit::signing::sign_authored_for_version(&mut pdu, parsed, state.server_key().as_ref(), state.server_name()).map_err(|error| {
        MatrixError::unknown(format!("signing error: {error}")).into_response()
    })?;
    let wire = WirePdu::checked_for_version(parsed, pdu)
        .ok_or_else(|| MatrixError::unknown("signed membership does not reproduce its event id").into_response())?;
    Ok((SignedMembership::Modern(wire), version))
}

async fn store_join_state(
    storage: &dyn Storage,
    client: &crate::federation::Client,
    room_id: &str,
    join: &Pdu,
    state: Vec<Value>,
    auth_chain: Vec<Value>,
) -> Result<(), Response> {
    let (state, chain, _) = crate::federation::admit::admit_send_join(
        &client._keys,
        &client.http,
        room_id,
        join,
        state,
        auth_chain,
    )
    .await
    .map_err(|error| bad_gateway(format!("send_join state was refused: {error}")))?;
    for admitted in chain.into_iter().chain(state) {
        let event = admitted.into_event();
        if storage.get_event(&event.event_id).await.ok().flatten().is_some() {
            continue;
        }
        storage.publish_event(&event).await.map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    }
    Ok(())
}

async fn store_event<S: AuthState>(state: &S, event: Event) -> Result<(), Response> {
    state.storage().publish_event(&event).await.map_err(|error| MatrixError::unknown(error.to_string()).into_response())?;
    if let Ok(position) = state.storage().global_max_stream_position().await {
        let _ = state.events_tx().send(position);
    }
    Ok(())
}

async fn store_signed_membership<S: AuthState>(state: &S, wire: WirePdu) -> Result<(), Response> {
    store_event(state, Event::new(wire.event_id(), wire.into_pdu())).await
}

/// `make_join` + `send_join` against `via` and the room's own server.
/// Returns the room id once the signed join and the returned state are stored.
pub(crate) async fn join_remote_room<S: AuthState>(
    state: &S,
    sender: &str,
    room_id: &str,
    hinted: &[String],
    reason: Option<&str>,
) -> Result<String, Response> {
    let Some(client) = state.federation_client() else {
        return Err(bad_gateway("federation client is not configured"));
    };
    let dests = destinations(room_id, hinted, state.server_name());
    if dests.is_empty() {
        return Err(MatrixError::new_not_found("That room does not appear to exist").into_response());
    }
    let mut last = "no resident server accepted the join".to_owned();
    for dest in dests {
        let made = match attempt(client.make_join(&dest, room_id, sender)).await {
            Ok(made) => made,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let mut template = made.event;
        if let Some(version) = made.room_version {
            if let Some(object) = template.as_object_mut() {
                object.insert("room_version".into(), json!(version));
            }
        }
        fill_profile(state.storage().as_ref(), sender, &mut template).await;
        let signed = match sign_template(state, room_id, sender, "join", template, reason, 1) {
            Ok((signed, _)) => signed,
            Err(response) => return Err(response),
        };
        match signed {
            SignedMembership::Modern(wire) => {
                let sent = match attempt(client.send_join(&dest, room_id, &wire)).await {
                    Ok(sent) => sent,
                    Err(error) => {
                        last = error;
                        continue;
                    }
                };
                store_join_state(state.storage().as_ref(), client, room_id, wire.pdu(), sent.state, sent.auth_chain).await?;
                store_signed_membership(state, wire).await?;
            }
            SignedMembership::Legacy(event) => {
                let sent = match attempt(client.send_join_v1(&dest, room_id, &event)).await {
                    Ok(sent) => sent,
                    Err(error) => {
                        last = error;
                        continue;
                    }
                };
                let decoded = conduit::wire::decode_pdu_for_version(event.clone(), 1, crate::federation::now_ms()).map_err(|error| {
                    MatrixError::unknown(format!("v1 join does not decode: {error}")).into_response()
                })?;
                store_join_state(state.storage().as_ref(), client, room_id, &decoded.pdu, sent.state, sent.auth_chain).await?;
                let Some(event_id) = decoded.explicit_event_id else {
                    return Err(MatrixError::unknown("v1 join is missing event_id").into_response());
                };
                let mut pdu = decoded.pdu;
                pdu.extensions.insert(super::event_pipeline::LEGACY_WIRE.to_owned(), json!(event.to_string()));
                store_event(state, Event { event_id, pdu, unsigned: decoded.unsigned }).await?;
            }
        }
        return Ok(room_id.to_owned());
    }
    Err(bad_gateway(last))
}

/// Resolve an alias through federation directory, then join the room id.
pub(crate) async fn join_remote_alias<S: AuthState>(
    state: &S,
    sender: &str,
    alias: &str,
    hinted: &[String],
    reason: Option<&str>,
) -> Result<String, Response> {
    let Some(client) = state.federation_client() else {
        return Err(MatrixError::new_not_found("Room alias not found").into_response());
    };
    let mut lookup = destinations(alias, hinted, state.server_name());
    if lookup.is_empty() {
        return Err(MatrixError::new_not_found("Room alias not found").into_response());
    }
    let mut room_id = None;
    let mut servers = Vec::new();
    for dest in &lookup {
        if let Ok(found) = attempt(client.query_directory(dest, alias)).await {
            servers = found.servers;
            room_id = Some(found.room_id);
            break;
        }
    }
    let Some(room_id) = room_id else {
        return Err(MatrixError::new_not_found("Room alias not found").into_response());
    };
    lookup.extend(servers);
    join_remote_room(state, sender, &room_id, &lookup, reason).await
}

enum InviteFailure {
    /// The invitee's server answered with an error status.
    Remote { status: u16, body: String },
    /// No HTTP answer: DNS, connection, or timeout.
    Unreachable(String),
}

async fn attempt_invite<T>(
    future: impl Future<Output = Result<T, crate::federation::FederationError>>,
) -> Result<T, InviteFailure> {
    match tokio::time::timeout(ATTEMPT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(crate::federation::FederationError::RemoteError { status, body })) => {
            Err(InviteFailure::Remote { status, body })
        }
        Ok(Err(error)) => Err(InviteFailure::Unreachable(error.to_string())),
        Err(_) => Err(InviteFailure::Unreachable("timed out".into())),
    }
}

/// What the invitee's server did with the invite.
enum InviteAnswer {
    /// DNS, connection, or timeout. No HTTP status.
    Unreachable,
    /// The invitee's server returned an error status.
    HttpError { status: u16, body: String },
    /// The returned event passed co-signature admission.
    Admitted,
    /// A 200 body failed `admit_cosigned_as` (or the v1 equivalent decode).
    AdmitRejected,
}

/// Whether the local invite stays.
enum InviteDisposition {
    Keep,
    Retract { status: u16, body: String },
}

/// Only silence and a verified co-signature keep the membership.
/// An HTTP error and a rejected co-signature both retract it.
fn invite_disposition(answer: InviteAnswer) -> InviteDisposition {
    match answer {
        InviteAnswer::Unreachable | InviteAnswer::Admitted => InviteDisposition::Keep,
        InviteAnswer::HttpError { status, body } => InviteDisposition::Retract { status, body },
        InviteAnswer::AdmitRejected => InviteDisposition::Retract {
            status: 403,
            body: serde_json::json!({
                "errcode": "M_FORBIDDEN",
                "error": "The invitee's server rejected the invite",
            })
            .to_string(),
        },
    }
}

fn refusal(status: u16, body: &str) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let message = parsed
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("The invitee's server rejected the invite");
    let errcode = if code == StatusCode::FORBIDDEN { "M_FORBIDDEN" } else { "M_UNKNOWN" };
    MatrixError::forwarded(code, errcode, message).into_response()
}

fn legacy_invite_document(event: &Event) -> Result<Value, Response> {
    let Some(raw) = event.extensions.get(super::event_pipeline::LEGACY_WIRE).and_then(Value::as_str) else {
        return Err(MatrixError::unknown("room version 1 invite has no wire document").into_response());
    };
    serde_json::from_str(raw).map_err(|error| MatrixError::unknown(format!("room version 1 invite is unreadable: {error}")).into_response())
}

/// Offer a stored invite to the invitee's server.
///
/// An HTTP error, including 403, and a 200 that fails co-signature admission
/// both fail the client request and retract the invite. No answer from the
/// peer leaves the local invite in place.
pub(crate) async fn deliver_remote_invite<S: AuthState>(state: &S, room_id: &str, event_id: &str) -> Result<(), Response> {
    if !federation_enabled() {
        return Ok(());
    }
    let Some(client) = state.federation_client() else { return Ok(()) };
    let Ok(Some(event)) = state.storage().get_event(event_id).await else { return Ok(()) };
    let Some(target) = event.state_key.clone() else { return Ok(()) };
    let Some(dest) = server_of_user_id(&target).map(str::to_owned) else { return Ok(()) };
    if dest == state.server_name() {
        return Ok(());
    }
    let Ok(version) = room_version_of(state.storage().as_ref(), room_id).await else { return Ok(()) };
    let Ok(stripped) = stripped_state(state.storage().as_ref(), room_id).await else { return Ok(()) };
    let parsed = conduit::room_version::parse(&version).unwrap_or(0);
    let modern = if parsed <= 2 {
        None
    } else {
        Some(WirePdu::checked_for_version(parsed, event.pdu.clone()).ok_or_else(|| {
            MatrixError::unknown("invite PDU does not match its room version").into_response()
        })?)
    };
    let legacy = if parsed <= 2 { Some(legacy_invite_document(&event)?) } else { None };
    let sent = if let Some(document) = &legacy {
        attempt_invite(client.invite_v1(&dest, room_id, document)).await
    } else {
        let wire = modern.as_ref().expect("modern invite");
        attempt_invite(client.invite(&dest, room_id, &version, stripped, wire)).await
    };
    let answer = match sent {
        Err(InviteFailure::Unreachable(reason)) => {
            tracing::debug!(reason, "remote invite had no HTTP answer");
            InviteAnswer::Unreachable
        }
        Err(InviteFailure::Remote { status, body }) => InviteAnswer::HttpError { status, body },
        Ok(returned) => match &modern {
            Some(wire) => match crate::federation::admit::admit_cosigned_as(
                &client._keys,
                &client.http,
                returned,
                wire,
                &dest,
                state.server_name(),
                &state.server_key(),
            )
            .await
            {
                Ok(admitted) => {
                    match state.storage().replace_cosigned_pdu(&admitted.into_event()).await {
                        Ok(true) => {}
                        Ok(false) => tracing::warn!(event_id, "co-signed invite did not replace the stored PDU"),
                        Err(error) => tracing::warn!(%error, "co-signed invite was not stored"),
                    }
                    InviteAnswer::Admitted
                }
                Err(_) => InviteAnswer::AdmitRejected,
            },
            None => {
                let sent_document = legacy.as_ref().expect("legacy invite");
                match crate::federation::admit::admit_legacy_cosign(
                    &client._keys,
                    &client.http,
                    returned,
                    sent_document,
                    &dest,
                )
                .await
                {
                    Ok(accepted) => {
                        let decoded = conduit::wire::decode_pdu_for_version(accepted.clone(), parsed.max(1), crate::federation::now_ms());
                        let stored = decoded.ok().and_then(|decoded| {
                            let accepted_id = decoded.explicit_event_id?;
                            if accepted_id != event_id {
                                return None;
                            }
                            let mut pdu = decoded.pdu;
                            pdu.extensions.insert(
                                super::event_pipeline::LEGACY_WIRE.to_owned(),
                                serde_json::json!(accepted.to_string()),
                            );
                            Some(Event { event_id: accepted_id, pdu, unsigned: decoded.unsigned })
                        });
                        if let Some(stored) = stored {
                            match state.storage().replace_cosigned_pdu(&stored).await {
                                Ok(true) => InviteAnswer::Admitted,
                                Ok(false) => {
                                    tracing::warn!(event_id, "co-signed invite did not replace the stored PDU");
                                    InviteAnswer::AdmitRejected
                                }
                                Err(error) => {
                                    tracing::warn!(%error, "co-signed invite was not stored");
                                    InviteAnswer::AdmitRejected
                                }
                            }
                        } else {
                            tracing::debug!("co-signed room version 1 invite does not decode");
                            InviteAnswer::AdmitRejected
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "room version 1 invite co-signature was rejected");
                        InviteAnswer::AdmitRejected
                    }
                }
            }
        },
    };
    match invite_disposition(answer) {
        InviteDisposition::Keep => Ok(()),
        InviteDisposition::Retract { status, body } => {
            if let Err(error) = state.storage().retract_current_membership(room_id, &target, event_id).await {
                return Err(MatrixError::unknown(format!("invite was refused and could not be retracted: {error}")).into_response());
            }
            Err(refusal(status, &body))
        }
    }
}

pub(crate) async fn fan_out_stored<S: AuthState>(state: &S, room_id: &str, event_id: &str) {
    fan_out_authored(
        state.storage().as_ref(),
        state.server_name(),
        state.federation_queue(),
        room_id,
        event_id,
    )
    .await;
}

async fn room_version_of(storage: &dyn Storage, room_id: &str) -> Result<String, ()> {
    let create = storage.get_state_entry(room_id, "m.room.create", "").await.map_err(|_| ())?.ok_or(())?;
    Ok(create.content.get("room_version").and_then(Value::as_str).unwrap_or("1").to_owned())
}

async fn stripped_state(storage: &dyn Storage, room_id: &str) -> Result<Vec<Value>, ()> {
    let events = storage.get_current_state(room_id).await.map_err(|_| ())?;
    Ok(events
        .into_iter()
        .filter(|event| STRIPPED_STATE.contains(&event.event_type.as_str()) || event.event_type == "m.room.member")
        .map(|event| {
            json!({
                "type": event.event_type,
                "state_key": event.state_key,
                "sender": event.sender,
                "content": event.content,
            })
        })
        .collect())
}

/// `make_knock` + `send_knock` for a room this server does not participate in.
pub(crate) async fn knock_remote_room<S: AuthState>(
    state: &S,
    sender: &str,
    room_id: &str,
    hinted: &[String],
    reason: Option<&str>,
) -> Result<String, Response> {
    let Some(client) = state.federation_client() else {
        return Err(MatrixError::new_not_found("That room does not appear to exist").into_response());
    };
    let dests = destinations(room_id, hinted, state.server_name());
    if dests.is_empty() {
        return Err(MatrixError::new_not_found("That room does not appear to exist").into_response());
    }
    let mut last = "no resident server accepted the knock".to_owned();
    for dest in dests {
        let made = match attempt(client.make_knock(&dest, room_id, sender)).await {
            Ok(made) => made,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let mut template = made.event;
        let parsed_version = made.room_version.as_deref().and_then(conduit::room_version::parse).unwrap_or(11);
        if let Some(version) = made.room_version.as_deref() {
            if let Some(object) = template.as_object_mut() {
                object.insert("room_version".into(), json!(version));
            }
        }
        fill_profile(state.storage().as_ref(), sender, &mut template).await;
        let wire = match sign_template(state, room_id, sender, "knock", template, reason, 7) {
            Ok((SignedMembership::Modern(wire), _)) => wire,
            Ok((SignedMembership::Legacy(_), version)) => return Err(incompatible(&version)),
            Err(response) => return Err(response),
        };
        let sent = match attempt(client.send_knock(&dest, room_id, &wire)).await {
            Ok(sent) => sent,
            Err(error) => {
                last = error;
                continue;
            }
        };
        if let Some(events) = sent.get("knock_room_state").and_then(Value::as_array) {
            let version = parsed_version;
            for value in events {
                let version = if value.get("event_id").and_then(Value::as_str).is_some_and(|id| id.starts_with('$') && id.contains(':')) {
                    1
                } else {
                    version
                };
                let Ok(decoded) = crate::federation::pipeline::admit_received(version, value.clone()) else { continue };
                let origin = server_of_user_id(&decoded.pdu.sender).unwrap_or(dest.as_str()).to_owned();
                if version < 3 {
                    let unsigned = decoded.unsigned.clone();
                    let Ok(received) = crate::federation::pipeline::receive_legacy_pdu(&client._keys, &client.http, value, decoded).await else {
                        continue;
                    };
                    let _ = crate::federation::pipeline::process_received(
                        state.storage(),
                        &client._keys,
                        &client.http,
                        state.events_tx(),
                        Some(client),
                        None,
                        received,
                        unsigned,
                        &origin,
                    )
                    .await;
                } else {
                    let _ = crate::federation::pipeline::process_incoming_pdu(
                        state.storage(),
                        &client._keys,
                        &client.http,
                        state.events_tx(),
                        Some(client),
                        None,
                        decoded,
                        &origin,
                    )
                    .await;
                }
            }
        }
        store_signed_membership(state, wire).await?;
        return Ok(room_id.to_owned());
    }
    Err(bad_gateway(last))
}

/// Knock a room id, or an alias resolved through the federation directory.
pub(crate) async fn knock_remote<S: AuthState>(
    state: &S,
    sender: &str,
    room_id_or_alias: &str,
    hinted: &[String],
    reason: Option<&str>,
) -> Result<String, Response> {
    if !room_id_or_alias.starts_with('#') {
        return knock_remote_room(state, sender, room_id_or_alias, hinted, reason).await;
    }
    let Some(client) = state.federation_client() else {
        return Err(MatrixError::new_not_found("Room alias not found").into_response());
    };
    let lookup = destinations(room_id_or_alias, hinted, state.server_name());
    let mut found = None;
    for dest in &lookup {
        if let Ok(directory) = attempt(client.query_directory(dest, room_id_or_alias)).await {
            found = Some((directory.room_id, directory.servers));
            break;
        }
    }
    let Some((room_id, servers)) = found else {
        return Err(MatrixError::new_not_found("Room alias not found").into_response());
    };
    let mut hinted = hinted.to_vec();
    hinted.extend(servers);
    knock_remote_room(state, sender, &room_id, &hinted, reason).await
}

#[cfg(test)]
mod tests {
    use super::{invite_disposition, InviteAnswer, InviteDisposition};

    #[test]
    fn invite_answers_keep_only_silence_and_admission() {
        assert!(matches!(invite_disposition(InviteAnswer::Unreachable), InviteDisposition::Keep));
        assert!(matches!(invite_disposition(InviteAnswer::Admitted), InviteDisposition::Keep));
        match invite_disposition(InviteAnswer::HttpError { status: 403, body: "no".into() }) {
            InviteDisposition::Retract { status, body } => {
                assert_eq!(status, 403);
                assert_eq!(body, "no");
            }
            InviteDisposition::Keep => panic!("an HTTP error kept the invite"),
        }
        match invite_disposition(InviteAnswer::AdmitRejected) {
            InviteDisposition::Retract { status, body } => {
                assert_eq!(status, 403);
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(parsed["errcode"], "M_FORBIDDEN");
                assert_eq!(parsed["error"], "The invitee's server rejected the invite");
            }
            InviteDisposition::Keep => panic!("a rejected co-signature kept the invite"),
        }
    }
}
