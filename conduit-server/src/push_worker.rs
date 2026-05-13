//! Push notification background worker (E11 P5).
//!
//! Subscribes to the `events_tx` broadcast, evaluates push rules for every
//! joined member of the event's room, and POSTs to their configured HTTP
//! pushers.

use std::sync::Arc;

use reqwest::Client as HttpClient;
use serde_json::{json, Value};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use conduit::storage::Storage;

use crate::api::client::push::rules::{evaluate_rule, parse_actions, EvalContext};

/// Spawn the push worker. Returns immediately; the task runs in the background.
pub fn spawn_push_worker(
    storage: Arc<dyn Storage>,
    http: HttpClient,
    mut events_rx: broadcast::Receiver<i64>,
) {
    tokio::spawn(async move {
        loop {
            let stream_pos = match events_rx.recv().await {
                Ok(pos) => pos,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(missed = n, "push worker lagged behind event broadcast");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            };

            // Fetch the event at this stream position.
            // We don't have a direct stream_pos → event lookup, so we fetch
            // via events_since with a limit of 1 from stream_pos-1.
            let events = match storage.events_since(stream_pos - 1, 1).await {
                Ok(evs) => evs,
                Err(e) => {
                    warn!(error = %e, "push worker: events_since failed");
                    continue;
                }
            };

            let event = match events.into_iter().next() {
                Some(e) => e,
                None => continue,
            };

            let room_id = event.room_id.clone();
            let event_json = match serde_json::to_value(&event) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "push worker: event serialization failed");
                    continue;
                }
            };

            // Get joined members of the room.
            let state = match storage.get_current_state(&room_id).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "push worker: get_current_state failed");
                    continue;
                }
            };

            let member_count = state.iter()
                .filter(|ev| ev.event_type == "m.room.member")
                .filter(|ev| {
                    ev.content.get("membership")
                        .and_then(Value::as_str)
                        .map(|m| m == "join")
                        .unwrap_or(false)
                })
                .count();

            let joined_users: Vec<String> = state.iter()
                .filter(|ev| {
                    ev.event_type == "m.room.member"
                        && ev.content.get("membership")
                            .and_then(Value::as_str)
                            .map(|m| m == "join")
                            .unwrap_or(false)
                })
                .filter_map(|ev| ev.state_key.clone())
                .collect();

            // Get power levels for sender_notification_permission evaluation.
            let power_levels = state.iter()
                .find(|ev| ev.event_type == "m.room.power_levels" && ev.state_key.as_deref() == Some(""))
                .map(|ev| ev.content.clone());

            for user_id in &joined_users {
                // Skip the sender — they don't get pushed for their own events.
                if user_id == &event.sender {
                    continue;
                }

                // Get user's display name for contains_display_name conditions.
                let displayname = match storage.get_account(user_id).await {
                    Ok(Some(acct)) => acct.displayname,
                    _ => None,
                };

                // Get user's push rules (or defaults).
                let mut rules = match storage.list_push_rules(user_id).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                if rules.is_empty() {
                    rules = crate::api::client::push::rules::default_push_rules(user_id);
                }

                // Evaluate rules in priority order.
                let ctx = EvalContext {
                    event: &event_json,
                    displayname: displayname.as_deref(),
                    member_count,
                    power_levels: power_levels.as_ref(),
                    sender: &event.sender,
                };

                let mut matched_actions = None;
                for rule in &rules {
                    if let Some(actions) = evaluate_rule(rule, &ctx) {
                        matched_actions = Some(actions);
                        break;
                    }
                }

                let actions = match matched_actions {
                    Some(a) if a.should_notify => a,
                    _ => continue, // no notification
                };

                // Deliver to all of the user's pushers.
                let pushers = match storage.list_pushers(user_id).await {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                for pusher in &pushers {
                    if pusher.kind != "http" {
                        continue;
                    }
                    let url = match &pusher.url {
                        Some(u) => u.clone(),
                        None => continue,
                    };

                    // Build the notification payload per the push gateway spec.
                    let mut tweaks = json!({});
                    if actions.highlight {
                        tweaks["highlight"] = json!(true);
                    }
                    if let Some(sound) = &actions.sound {
                        tweaks["sound"] = json!(sound);
                    }

                    // event_id_only format: only send event_id + room_id.
                    let notification = if pusher.format.as_deref() == Some("event_id_only") {
                        json!({
                            "notification": {
                                "event_id": event.event_id,
                                "room_id": room_id,
                                "type": event.event_type,
                                "sender": event.sender,
                                "counts": {
                                    "unread": 1
                                },
                                "devices": [{
                                    "app_id": pusher.app_id,
                                    "pushkey": pusher.pushkey,
                                    "pushkey_ts": 0,
                                    "data": pusher.data,
                                    "tweaks": tweaks
                                }]
                            }
                        })
                    } else {
                        json!({
                            "notification": {
                                "event_id": event.event_id,
                                "room_id": room_id,
                                "type": event.event_type,
                                "sender": event.sender,
                                "content": event.content,
                                "counts": {
                                    "unread": 1
                                },
                                "devices": [{
                                    "app_id": pusher.app_id,
                                    "pushkey": pusher.pushkey,
                                    "pushkey_ts": 0,
                                    "data": pusher.data,
                                    "tweaks": tweaks
                                }]
                            }
                        })
                    };

                    let notify_url = format!("{}/_matrix/push/v1/notify", url.trim_end_matches('/'));
                    let resp = http.post(&notify_url)
                        .json(&notification)
                        .send()
                        .await;

                    match resp {
                        Ok(r) if r.status().is_success() => {
                            debug!(user_id, pushkey = pusher.pushkey, "push delivered");
                        }
                        Ok(r) if r.status().is_client_error() => {
                            // 4xx: drop; gateway rejected this pusher.
                            warn!(
                                user_id,
                                pushkey = pusher.pushkey,
                                status = r.status().as_u16(),
                                "push gateway rejected pusher (4xx), dropping"
                            );
                        }
                        Ok(r) => {
                            // 5xx: log and move on (no retry in v0).
                            warn!(
                                user_id,
                                pushkey = pusher.pushkey,
                                status = r.status().as_u16(),
                                "push gateway returned 5xx, will not retry in v0"
                            );
                        }
                        Err(e) => {
                            warn!(user_id, pushkey = pusher.pushkey, error = %e, "push delivery error");
                        }
                    }
                }
            }
        }
    });
}
