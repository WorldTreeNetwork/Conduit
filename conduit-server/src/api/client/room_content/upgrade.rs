//! POST /rooms/:roomId/upgrade (conduit-y99.19).
//!
//! Spec "Room Upgrades → Server behaviour":
//! 1. the user must be allowed to send `m.room.tombstone` in the old room;
//! 2. create the replacement with `predecessor` and the old room's `type`;
//! 3. replicate the recommended transferable state;
//! 4. move local aliases (and the canonical alias);
//! 5. tombstone the old room;
//! 6. restrict the old room's power levels (`events_default` and `invite`
//!    to max(50, users_default + 1)).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};

use conduit::auth::StateMap;
use conduit::event::Event;
use conduit::state_events::parse_power_levels;

use super::{error, storage_error};
use crate::api::client::event_pipeline::build_sign_and_persist;
use crate::api::client::rooms::generate_room_id;
use crate::api::client::{AuthState, AuthedUser, MatrixError};

/// Spec-recommended state carried into the replacement room, in order.
/// Power levels go last so the upgrader keeps authority while copying.
const TRANSFERABLE: [&str; 8] = [
    "m.room.server_acl",
    "m.room.encryption",
    "m.room.name",
    "m.room.avatar",
    "m.room.topic",
    "m.room.guest_access",
    "m.room.history_visibility",
    "m.room.join_rules",
];

fn get<'a>(state: &'a StateMap<Event>, kind: &str) -> Option<&'a Event> {
    state.get(&(kind.to_owned(), String::new()))
}

/// Copy the user's room-scoped account data (tags, read markers, and any
/// other per-room type) and a room push rule from `old_room` onto `new_room`.
/// Existing data on the new room is left in place. Failures are ignored so a
/// settings copy never undoes a join that already landed.
pub(crate) async fn copy_personal_settings(
    storage: &dyn conduit::storage::Storage,
    user: &str,
    old_room: &str,
    new_room: &str,
) {
    if let Ok(rows) = storage.account_data_since(user, 0).await {
        for (room, event_type, content, _) in rows {
            if room.as_deref() != Some(old_room) {
                continue;
            }
            let already = storage
                .get_account_data(user, Some(new_room), &event_type)
                .await
                .ok()
                .flatten()
                .is_some();
            if already {
                continue;
            }
            let _ = storage.set_account_data(user, Some(new_room), &event_type, &content).await;
        }
    }
    if let Ok(rules) = storage.list_push_rules(user).await {
        for rule in rules {
            if rule.kind == "room" && rule.rule_id == old_room {
                let mut cloned = rule;
                cloned.rule_id = new_room.to_owned();
                let _ = storage.upsert_push_rule(&cloned).await;
            }
        }
    }
}

pub async fn upgrade_room<S: AuthState>(
    State(state): State<S>,
    authed: AuthedUser,
    Path(room_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let user = authed.user_id.as_str();
    let Some(new_version) = body.get("new_version").and_then(Value::as_str) else {
        return MatrixError::bad_json("new_version is required").into_response();
    };
    if let Err(e) = conduit::error::require_room_version(new_version) {
        return MatrixError::from_conduit(e).into_response();
    }
    let version_num = conduit::room_version::parse(new_version).unwrap_or(11);
    // v12 additional creators come only from this request. The old room's
    // list is not copied (spec v1.16). Versions before 12 ignore the field.
    let extra_creators = if version_num >= 12 {
        match body.get("additional_creators") {
            None => None,
            Some(Value::Array(items)) => {
                let mut ids = Vec::with_capacity(items.len());
                for item in items {
                    let Some(id) = item.as_str() else {
                        return MatrixError::bad_json("additional_creators entries must be user ids").into_response();
                    };
                    if !conduit::room_version::valid_user_id(id) {
                        return MatrixError::invalid_param(format!("not a user id: {id}")).into_response();
                    }
                    ids.push(id.to_owned());
                }
                Some(ids)
            }
            Some(_) => {
                return MatrixError::bad_json("additional_creators must be an array of user ids").into_response();
            }
        }
    } else {
        None
    };
    let storage = state.storage().as_ref();
    let old_state = match conduit::auth::current_state_map(storage, &room_id).await {
        Ok(old_state) => old_state,
        Err(e) => return storage_error(e),
    };
    let Some(create) = get(&old_state, "m.room.create") else {
        return error(StatusCode::NOT_FOUND, "M_NOT_FOUND", "Unknown room");
    };

    // 1. Permission to tombstone the old room.
    let joined = old_state
        .get(&("m.room.member".to_owned(), user.to_owned()))
        .is_some_and(|member| member.content["membership"] == "join");
    let old_pl_event = get(&old_state, "m.room.power_levels");
    let old_pl = old_pl_event
        .and_then(|event| parse_power_levels(&event.content).ok())
        .unwrap_or_default();
    let level = conduit::auth::effective_user_level(user, &old_state);
    // v12 creators are infinite. That value is not a JSON-safe integer and
    // must not be written into a power-level event. A transferred finite
    // level of 100 is the same authority Room::create grants a creator.
    let finite_level = if level == i64::MAX { 100 } else { level };
    let needed = conduit::auth::level_required_for_event("m.room.tombstone", true, &old_pl);
    if !joined || level < needed {
        return MatrixError::forbidden("You are not permitted to upgrade this room").into_response();
    }

    // 2. The replacement room.
    let generated = generate_room_id(state.server_name());
    let new_room = if version_num >= 12 { String::new() } else { generated };
    let predecessor = storage
        .room_events_with_positions(&room_id)
        .await
        .ok()
        .and_then(|events| events.last().map(|(_, event)| event.event_id.clone()));
    let mut create_content = json!({
        "room_version": new_version,
        "predecessor": {"room_id": room_id, "event_id": predecessor},
    });
    if let Some(room_type) = create.content.get("type") {
        create_content["type"] = room_type.clone();
    }
    if version_num < 11 {
        create_content["creator"] = json!(user);
    }
    if let Some(ids) = &extra_creators {
        create_content["additional_creators"] = json!(ids);
    }
    // The upgrader holds authority while state is copied; the old power
    // levels are restored afterwards with the upgrader at least as
    // powerful as needed to have performed the upgrade.
    let mut final_pl = old_pl_event.map(|event| event.content.clone()).unwrap_or_else(|| json!({}));
    if !final_pl["users"].is_object() {
        final_pl["users"] = json!({});
    }
    let kept_level = final_pl["users"]
        .get(user)
        .and_then(Value::as_i64)
        .unwrap_or(finite_level)
        .max(finite_level);
    if version_num >= 12 {
        if let Some(users) = final_pl["users"].as_object_mut() {
            users.remove(user);
            if let Some(ids) = &extra_creators {
                for id in ids {
                    users.remove(id);
                }
            }
        }
    } else {
        final_pl["users"][user] = json!(kept_level);
    }
    let mut bootstrap_pl = final_pl.clone();
    if version_num < 12 {
        bootstrap_pl["users"][user] = json!(kept_level.max(100));
    }

    let send = |kind: &'static str, key: Option<String>, content: Value, room: String| {
        let state = state.clone();
        let user = user.to_owned();
        async move {
            build_sign_and_persist(&state, &user, &room, kind, key.as_deref(), content)
                .await
                .map_err(|(code, json)| (code, json).into_response())
        }
    };
    let steps = async {
        let create_id = send("m.room.create", Some(String::new()), create_content, new_room.clone()).await?;
        let new_room = if new_room.is_empty() {
            conduit::room_version::room_id_from_event_id(&create_id)
        } else {
            new_room
        };
        send("m.room.member", Some(user.to_owned()), json!({"membership": "join"}), new_room.clone()).await?;
        send("m.room.power_levels", Some(String::new()), bootstrap_pl.clone(), new_room.clone()).await?;

        // 3. Transferable state.
        for kind in TRANSFERABLE {
            if let Some(event) = get(&old_state, kind) {
                send(kind, Some(String::new()), event.content.clone(), new_room.clone()).await?;
            }
        }

        // 4. Aliases: local aliases move; the canonical alias follows.
        let aliases = storage.list_aliases_for_room(&room_id).await.map_err(storage_error)?;
        for alias in &aliases {
            storage.delete_alias(alias).await.map_err(storage_error)?;
            storage.upsert_alias(alias, &new_room, user).await.map_err(storage_error)?;
        }
        if let Some(canonical) = get(&old_state, "m.room.canonical_alias") {
            if canonical.content.as_object().is_some_and(|content| !content.is_empty()) {
                send("m.room.canonical_alias", Some(String::new()), canonical.content.clone(), new_room.clone())
                    .await?;
                send("m.room.canonical_alias", Some(String::new()), json!({}), room_id.clone()).await?;
            }
        }
        if bootstrap_pl != final_pl {
            send("m.room.power_levels", Some(String::new()), final_pl.clone(), new_room.clone()).await?;
        }

        // 5. Tombstone the old room.
        send(
            "m.room.tombstone",
            Some(String::new()),
            json!({"body": "This room has been replaced", "replacement_room": new_room.clone()}),
            room_id.clone(),
        )
        .await?;

        // 6. Restrict the old room.
        let restricted = (old_pl.users_default + 1).max(50);
        let mut old_content = old_pl_event.map(|event| event.content.clone()).unwrap_or_else(|| json!({}));
        let (current_events, current_invite) = (old_pl.events_default, old_pl.invite);
        if current_events < restricted || current_invite < restricted {
            old_content["events_default"] = json!(current_events.max(restricted));
            old_content["invite"] = json!(current_invite.max(restricted));
            if !old_content["users"].is_object() {
                // A v12 creator must stay out of `users`. Other versions record
                // the upgrader so the lockdown event itself still authorises.
                let old_version = conduit::room_version::version_of_content(&create.content);
                old_content["users"] = if old_version >= 12 {
                    json!({})
                } else {
                    json!({user: finite_level})
                };
            }
            send("m.room.power_levels", Some(String::new()), old_content, room_id.clone()).await?;
        }
        // The upgrader joined as the create sender, not through /join.
        // Personal settings move at join time for everyone else.
        copy_personal_settings(storage, user, &room_id, &new_room).await;
        Ok::<String, Response>(new_room)
    };
    match steps.await {
        Ok(new_room) => (StatusCode::OK, Json(json!({"replacement_room": new_room}))).into_response(),
        Err(response) => response,
    }
}
