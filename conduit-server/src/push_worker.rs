//! Push worker (conduit-y99.30, conduit-y99.31; Matrix v1.19
//! push-gateway-api #homeserver-behaviour).
//!
//! Wakes on every persisted event (and once a second), runs the push
//! evaluation engine, then drains the durable `push_outbox`: one
//! `POST /_matrix/push/v1/notify` per pusher and event. Gateway errors are
//! retried with exponential backoff for up to a day; pushkeys the gateway
//! lists in `rejected` lose their pusher.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client as HttpClient;
use serde_json::{json, Map, Value};
use tokio::sync::broadcast;
use tracing::{debug, warn};

use conduit::event::Event;
use conduit::storage::{PushDelivery, Pusher, Storage};

use crate::api::client::push::{notifications, rules};

/// Give up on a notification this long after it was queued.
const DELIVERY_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Cap on the backoff between attempts.
const MAX_BACKOFF_MS: i64 = 10 * 60 * 1000;

fn retry_base_ms() -> i64 {
    std::env::var("CONDUIT_PUSH_RETRY_BASE_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v: &i64| *v > 0)
        .unwrap_or(1000)
}

/// Delay before attempt `attempts + 1`: base * 2^attempts, capped.
pub fn backoff_ms(base: i64, attempts: i32) -> i64 {
    base.saturating_mul(1i64 << attempts.clamp(0, 30)).min(MAX_BACKOFF_MS)
}

/// Spawn the push worker. Returns immediately.
pub fn spawn_push_worker(
    storage: Arc<dyn Storage>,
    server_name: Arc<str>,
    http: HttpClient,
    mut events_rx: broadcast::Receiver<i64>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                received = events_rx.recv() => {
                    if let Err(broadcast::error::RecvError::Closed) = received {
                        break;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            if let Err(e) = notifications::process_pending(storage.as_ref(), &server_name).await {
                warn!(error = %e, "push evaluation failed");
            }
            if let Err(e) = deliver_due(storage.as_ref(), &http).await {
                warn!(error = %e, "push delivery pass failed");
            }
        }
    });
}

/// Send every due delivery once.
pub async fn deliver_due(storage: &dyn Storage, http: &HttpClient) -> conduit::Result<()> {
    let now = chrono::Utc::now().timestamp_millis();
    for delivery in storage.due_push_deliveries(now, 100).await? {
        deliver(storage, http, delivery, now).await?;
    }
    Ok(())
}

enum Attempt {
    Done,
    Retry,
}

async fn deliver(storage: &dyn Storage, http: &HttpClient, delivery: PushDelivery, now: i64) -> conduit::Result<()> {
    let pusher = storage
        .list_pushers(&delivery.user_id)
        .await?
        .into_iter()
        .find(|p| p.app_id == delivery.app_id && p.pushkey == delivery.pushkey);
    let (Some(pusher), Some(event)) = (pusher, storage.get_event(&delivery.event_id).await?) else {
        // The pusher was removed or the event purged: nothing to send.
        return storage.finish_push_delivery(delivery.id).await;
    };
    let Some(url) = pusher.url.clone() else {
        return storage.finish_push_delivery(delivery.id).await;
    };
    let unread = crate::api::client::notification_counts::total_unread(storage, &delivery.user_id).await?;
    let body = notify_body(storage, &pusher, &delivery, &event, unread).await?;
    let outcome = match http.post(&url).timeout(Duration::from_secs(30)).json(&body).send().await {
        Ok(response) if response.status().is_success() => {
            let rejected: Vec<String> = response
                .json::<Value>()
                .await
                .ok()
                .and_then(|v| v.get("rejected").cloned())
                .and_then(|r| serde_json::from_value(r).ok())
                .unwrap_or_default();
            if rejected.contains(&pusher.pushkey) {
                // Spec: stop sending to rejected pushkeys and remove the pushers.
                warn!(user_id = %pusher.user_id, app_id = %pusher.app_id, "push gateway rejected pushkey; removing pusher");
                storage.delete_pusher(&pusher.user_id, &pusher.pushkey, &pusher.app_id).await?;
            }
            debug!(user_id = %pusher.user_id, event_id = %delivery.event_id, "push delivered");
            Attempt::Done
        }
        Ok(response) if response.status().is_client_error() && response.status().as_u16() != 429 => {
            warn!(status = response.status().as_u16(), url, "push gateway refused notification; dropping it");
            Attempt::Done
        }
        Ok(response) => {
            warn!(status = response.status().as_u16(), url, "push gateway error; will retry");
            Attempt::Retry
        }
        Err(e) => {
            warn!(error = %e, url, "push gateway unreachable; will retry");
            Attempt::Retry
        }
    };
    match outcome {
        Attempt::Done => storage.finish_push_delivery(delivery.id).await,
        Attempt::Retry if now - delivery.created_ms >= DELIVERY_TTL_MS => {
            warn!(event_id = %delivery.event_id, "push delivery expired after retries");
            storage.finish_push_delivery(delivery.id).await
        }
        Attempt::Retry => {
            let next = now + backoff_ms(retry_base_ms(), delivery.attempts);
            storage.retry_push_delivery(delivery.id, delivery.attempts + 1, next).await
        }
    }
}

fn state_content<'a>(state: &'a [Event], kind: &str, key: &str) -> Option<&'a Value> {
    state
        .iter()
        .find(|e| e.event_type == kind && e.state_key.as_deref() == Some(key))
        .map(|e| &e.content)
}

/// The `/_matrix/push/v1/notify` request body.
pub async fn notify_body(
    storage: &dyn Storage,
    pusher: &Pusher,
    delivery: &PushDelivery,
    event: &Event,
    unread: u64,
) -> conduit::Result<Value> {
    let actions = delivery.actions.as_array().cloned().unwrap_or_default();
    let outcome = rules::outcome(&actions);
    // PusherData minus url; format and custom keys are forwarded.
    let mut data = pusher.data.as_object().cloned().unwrap_or_default();
    data.remove("url");
    let device = json!({
        "app_id": pusher.app_id,
        "pushkey": pusher.pushkey,
        "pushkey_ts": pusher.pushkey_ts,
        "data": Value::Object(data),
        "tweaks": Value::Object(outcome.tweaks.clone()),
    });
    let mut counts = Map::new();
    if unread > 0 {
        counts.insert("unread".into(), json!(unread));
    }
    // Synapse-compatible priority: sound, highlight or encrypted is high.
    let high = event.event_type == "m.room.encrypted"
        || outcome.highlight
        || outcome.tweaks.get("sound").is_some_and(|v| !v.is_null());
    let mut notification = json!({
        "event_id": event.event_id,
        "room_id": event.room_id,
        "counts": Value::Object(counts),
        "devices": [device],
        "prio": if high { "high" } else { "low" },
    });
    if pusher.format.as_deref() != Some("event_id_only") {
        notification["type"] = json!(event.event_type);
        notification["sender"] = json!(event.sender);
        if event.content.as_object().is_some_and(|c| !c.is_empty()) {
            notification["content"] = event.content.clone();
        }
        let state = storage.get_current_state(&event.room_id).await?;
        // The sender's name in the room, else their profile name.
        let room_name = state_content(&state, "m.room.member", &event.sender)
            .and_then(|c| c.get("displayname"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let display_name = match room_name {
            Some(name) => Some(name),
            None => storage.get_account(&event.sender).await?.and_then(|a| a.displayname),
        };
        if let Some(name) = display_name {
            notification["sender_display_name"] = json!(name);
        }
        if let Some(name) = state_content(&state, "m.room.name", "").and_then(|c| c.get("name")).and_then(Value::as_str) {
            if !name.is_empty() {
                notification["room_name"] = json!(name);
            }
        }
        if let Some(alias) = state_content(&state, "m.room.canonical_alias", "")
            .and_then(|c| c.get("alias"))
            .and_then(Value::as_str)
        {
            notification["room_alias"] = json!(alias);
        }
        if event.event_type == "m.room.member" {
            notification["user_is_target"] = json!(event.state_key.as_deref() == Some(pusher.user_id.as_str()));
            if let Some(membership) = event.content.get("membership") {
                notification["membership"] = membership.clone();
            }
        }
    }
    Ok(json!({ "notification": notification }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_ms(1000, 0), 1000);
        assert_eq!(backoff_ms(1000, 1), 2000);
        assert_eq!(backoff_ms(1000, 3), 8000);
        assert_eq!(backoff_ms(1000, 40), MAX_BACKOFF_MS);
    }
}
