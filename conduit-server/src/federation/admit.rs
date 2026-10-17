//! Admission of PDUs that Conduit received as the answer to a request.
//!
//! Nothing a peer returns is persisted until it passes this module:
//! decode ("is a valid event"), the signature stage with event-time keys,
//! ID derivation, the content-hash check, and then the endpoint's
//! **expectation**:
//!
//! | endpoint | expectation |
//! |---|---|
//! | `/event/{id}`, auth-event fetch | [`Expect::Exactly`] |
//! | outbound `/invite` response, `/send_join` response `event` | [`admit_cosigned`]: `Exactly`, unchanged `hashes`, co-signer signature verifies |
//! | `/state_ids` | stores nothing; its IDs gate `/state` |
//! | `/state` | [`admit_state`]: `OneOf(pdu_ids ∪ auth_chain_ids)`, state events of the room |
//! | `/send_join` response `state` | [`admit_send_join`]: asserted, no duplicate `(type, state_key)` |
//! | `/send_join` response `auth_chain` | [`admit_send_join`]: `auth_events` closure of `state ∪ {join}` |
//! | `/backfill`, `/get_missing_events` | [`admit_closure`] over `prev_events` from the seeds |
//!
//! The closure walk is a fixed point that does not depend on response
//! order; events nothing references are never stored. A fetched event whose
//! content hash mismatches is admitted in redacted form under its ID.

use std::collections::{HashMap, HashSet};

use serde_json::Value;
use thiserror::Error;

use conduit::event::{Event, Pdu, WirePdu};
use conduit::signing::{Received, VerifyError};
use conduit::wire::PduDecodeError;

use crate::RemoteKeyCache;
use crate::federation::StateIdsResponse;

/// A fetched PDU that passed admission.
#[derive(Debug, Clone, PartialEq)]
pub struct Admitted {
    pub received: Received,
    pub unsigned: Option<Value>,
}

impl Admitted {
    pub fn event_id(&self) -> &str {
        &self.received.event_id
    }

    pub fn pdu(&self) -> &Pdu {
        &self.received.pdu
    }

    pub fn into_event(self) -> Event {
        Event { event_id: self.received.event_id, pdu: self.received.pdu, unsigned: self.unsigned }
    }
}

/// What the requested ID set is for a by-ID answer.
#[derive(Debug, Clone, Copy)]
pub enum Expect<'a> {
    Exactly(&'a str),
    OneOf(&'a HashSet<String>),
}

#[derive(Debug, Error, PartialEq)]
pub enum FetchError {
    #[error("{0}")]
    Decode(#[from] PduDecodeError),
    #[error("signature stage failed: {0}")]
    Signature(String),
    #[error("derived event ID {derived} does not match requested {requested}")]
    IdMismatch { requested: String, derived: String },
    #[error("derived event ID {derived} is not in the expected set")]
    NotExpected { derived: String },
    #[error("returned event is not a state event of the requested room")]
    NotRoomState,
    #[error("send_join state holds a duplicate (type, state_key)")]
    DuplicateState,
    #[error("co-signed event changed its hashes")]
    HashesChanged,
    #[error("co-signed event lacks a valid signature from {0}")]
    MissingCoSignature(String),
    #[error("/state requires a preceding /state_ids for the same room and event")]
    MissingStateIds,
}

impl From<VerifyError> for FetchError {
    fn from(error: VerifyError) -> Self {
        FetchError::Signature(error.to_string())
    }
}

/// Room versions 1 and 2 are the only formats that carry `event_id`.
fn returned_room_version(value: &Value) -> u32 {
    match value.get("event_id").and_then(Value::as_str) {
        Some(id) if id.starts_with('$') && id.split_once(':').is_some_and(|(opaque, domain)| !opaque.is_empty() && !domain.is_empty()) => 1,
        _ => 11,
    }
}

/// Decode, verify and hash-check one returned PDU.
///
/// A PDU with `$opaque:server` is a room-version-1 or 2 event: the signature
/// covers that document, and the legacy JSON is kept even when the content
/// hash does not match.
pub async fn verify_returned(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    value: Value,
) -> Result<Admitted, FetchError> {
    let version = returned_room_version(&value);
    let decoded = super::pipeline::admit_received(version, value.clone())?;
    let unsigned = decoded.unsigned.clone();
    let received = if version < 3 {
        super::pipeline::receive_legacy_pdu(remote_keys, http, &value, decoded).await.map_err(|error| FetchError::Signature(error.to_string()))?
    } else {
        super::pipeline::verify_received(remote_keys, http, decoded.pdu, decoded.explicit_event_id).await?
    };
    Ok(Admitted { received, unsigned })
}

fn check_expect(admitted: &Admitted, expect: Expect<'_>) -> Result<(), FetchError> {
    match expect {
        Expect::Exactly(requested) if admitted.event_id() != requested => Err(FetchError::IdMismatch {
            requested: requested.to_owned(),
            derived: admitted.event_id().to_owned(),
        }),
        Expect::OneOf(set) if !set.contains(admitted.event_id()) => {
            Err(FetchError::NotExpected { derived: admitted.event_id().to_owned() })
        }
        _ => Ok(()),
    }
}

/// Admit one PDU returned for a request naming IDs (`/event`, auth fetch).
pub async fn admit_fetched(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    value: Value,
    expect: Expect<'_>,
) -> Result<Admitted, FetchError> {
    let admitted = verify_returned(remote_keys, http, value).await?;
    check_expect(&admitted, expect)?;
    Ok(admitted)
}

/// Admit a PDU we sent and a peer co-signed (outbound `/invite` response,
/// restricted `/send_join` response `event`): same ID, byte-identical
/// `hashes`, and a valid eligible signature from `cosigner`.
pub async fn admit_cosigned(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    value: Value,
    sent: &WirePdu,
    cosigner: &str,
) -> Result<Admitted, FetchError> {
    let admitted = admit_fetched(remote_keys, http, value, Expect::Exactly(&sent.event_id())).await?;
    require_cosigner(remote_keys, http, admitted, sent, cosigner).await
}

/// [`admit_cosigned`] for an event this server authored. The sender signature
/// is checked with `local_key` instead of a key fetch for `local_server`.
pub async fn admit_cosigned_as(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    value: Value,
    sent: &WirePdu,
    cosigner: &str,
    local_server: &str,
    local_key: &conduit::keys::ServerKey,
) -> Result<Admitted, FetchError> {
    let version = returned_room_version(&value);
    let decoded = super::pipeline::admit_received(version, value.clone())?;
    let unsigned = decoded.unsigned.clone();
    let received = if version < 3 {
        super::pipeline::receive_legacy_pdu(remote_keys, http, &value, decoded).await.map_err(|error| FetchError::Signature(error.to_string()))?
    } else {
        super::pipeline::verify_received_as(remote_keys, http, decoded.pdu, local_server, local_key, decoded.explicit_event_id).await?
    };
    let admitted = Admitted { received, unsigned };
    check_expect(&admitted, Expect::Exactly(&sent.event_id()))?;
    require_cosigner(remote_keys, http, admitted, sent, cosigner).await
}

async fn require_cosigner(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    admitted: Admitted,
    sent: &WirePdu,
    cosigner: &str,
) -> Result<Admitted, FetchError> {
    if admitted.pdu().hashes != sent.hashes {
        return Err(FetchError::HashesChanged);
    }
    let pdu = admitted.pdu();
    let signed = match pdu.signatures.get(cosigner).and_then(Value::as_object) {
        Some(keys) if !keys.is_empty() => {
            let mut eligible = 0;
            let mut ok = true;
            for key_id in keys.keys() {
                if let Some(public) = remote_keys.eligible_key(http, cosigner, key_id, pdu.origin_server_ts).await {
                    eligible += 1;
                    ok &= conduit::signing::verify_event_signature(pdu, cosigner, key_id, &public).is_ok();
                }
            }
            eligible > 0 && ok
        }
        _ => false,
    };
    if !signed {
        return Err(FetchError::MissingCoSignature(cosigner.to_owned()));
    }
    Ok(admitted)
}

/// Admit a room-version-1 or 2 `/invite` response.
///
/// The body is the event itself. The invitee may add its signature and must
/// leave every other field, including `event_id`, `hashes`, and the tuple
/// `auth_events` / `prev_events`, as this server sent them. `cosigner` must
/// have a signature over the v1 redacted bytes.
pub async fn admit_legacy_cosign(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    returned: Value,
    sent: &Value,
    cosigner: &str,
) -> Result<Value, FetchError> {
    if without_signatures(sent) != without_signatures(&returned) || !signatures_preserved(sent, &returned) {
        return Err(FetchError::HashesChanged);
    }
    let requested = sent.get("event_id").and_then(Value::as_str).unwrap_or("").to_owned();
    let derived = returned.get("event_id").and_then(Value::as_str).unwrap_or("").to_owned();
    if requested.is_empty() || requested != derived {
        return Err(FetchError::IdMismatch { requested, derived });
    }
    let timestamp = returned.get("origin_server_ts").and_then(Value::as_u64).unwrap_or(0);
    let Some(keys) = returned.get("signatures").and_then(|value| value.get(cosigner)).and_then(Value::as_object) else {
        return Err(FetchError::MissingCoSignature(cosigner.to_owned()));
    };
    if keys.is_empty() {
        return Err(FetchError::MissingCoSignature(cosigner.to_owned()));
    }
    let mut eligible = 0;
    for (key_id, signature) in keys {
        let Some(public) = remote_keys.eligible_key(http, cosigner, key_id, timestamp).await else { continue };
        eligible += 1;
        if !super::spec_v119::v1_signature_verifies(&returned, signature, &public) {
            return Err(FetchError::MissingCoSignature(cosigner.to_owned()));
        }
    }
    if eligible == 0 {
        return Err(FetchError::MissingCoSignature(cosigner.to_owned()));
    }
    Ok(returned)
}

fn without_signatures(value: &Value) -> Value {
    let mut copy = value.clone();
    if let Some(object) = copy.as_object_mut() {
        object.remove("signatures");
    }
    copy
}

/// Every signature this server sent is still present with the same value.
fn signatures_preserved(sent: &Value, returned: &Value) -> bool {
    let Some(sent_map) = sent.get("signatures").and_then(Value::as_object) else { return false };
    let Some(got_map) = returned.get("signatures").and_then(Value::as_object) else { return false };
    for (server, keys) in sent_map {
        let Some(got_keys) = got_map.get(server).and_then(Value::as_object) else { return false };
        let Some(keys) = keys.as_object() else { return false };
        for (key_id, signature) in keys {
            if got_keys.get(key_id) != Some(signature) {
                return false;
            }
        }
    }
    true
}

fn require_room_state(admitted: &Admitted, room_id: &str) -> Result<(), FetchError> {
    if admitted.pdu().state_key.is_none() || admitted.pdu().room_id != room_id {
        return Err(FetchError::NotRoomState);
    }
    Ok(())
}

/// Admit a `/state` answer: every PDU and auth-chain event must be named by
/// the preceding `/state_ids` answer for the same room and event, and the
/// state PDUs must be state events of the room. Any failure refuses the
/// whole answer.
pub async fn admit_state(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    room_id: &str,
    state_ids: Option<&StateIdsResponse>,
    pdus: Vec<Value>,
    auth_chain: Vec<Value>,
) -> Result<(Vec<Admitted>, Vec<Admitted>), FetchError> {
    let ids = state_ids.ok_or(FetchError::MissingStateIds)?;
    let expected: HashSet<String> = ids.pdu_ids.iter().chain(ids.auth_chain_ids.iter()).cloned().collect();
    let mut state = Vec::new();
    for value in pdus {
        let admitted = admit_fetched(remote_keys, http, value, Expect::OneOf(&expected)).await?;
        require_room_state(&admitted, room_id)?;
        state.push(admitted);
    }
    let mut chain = Vec::new();
    for value in auth_chain {
        chain.push(admit_fetched(remote_keys, http, value, Expect::OneOf(&expected)).await?);
    }
    Ok((state, chain))
}

/// Which reference edge a closure walk follows.
#[derive(Debug, Clone, Copy)]
pub enum Edge {
    Prev,
    Auth,
}

/// Admit the events of a response by walking references from `seeds`:
/// an event is admitted when its derived ID is a seed or is referenced
/// (via `edge`) by an event already admitted. The walk repeats until
/// nothing new is admitted, so response order does not matter. `stop` IDs
/// are never admitted (the `earliest_events` bound). At most `max` events
/// are admitted. Returns the admitted events and the count left over.
pub async fn admit_closure(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    values: Vec<Value>,
    seeds: HashSet<String>,
    edge: Edge,
    stop: &HashSet<String>,
    max: usize,
) -> (Vec<Admitted>, usize) {
    let mut candidates: HashMap<String, Admitted> = HashMap::new();
    for value in values {
        match verify_returned(remote_keys, http, value).await {
            Ok(admitted) => {
                candidates.insert(admitted.event_id().to_owned(), admitted);
            }
            Err(error) => tracing::debug!(%error, "closure candidate refused"),
        }
    }
    let total = candidates.len();
    let mut frontier = seeds;
    let mut admitted = Vec::new();
    loop {
        let ready: Vec<String> = candidates
            .keys()
            .filter(|id| frontier.contains(*id) && !stop.contains(*id))
            .cloned()
            .collect();
        if ready.is_empty() || admitted.len() >= max {
            break;
        }
        for id in ready {
            if admitted.len() >= max {
                break;
            }
            let event = candidates.remove(&id).expect("ready candidate");
            let refs = match edge {
                Edge::Prev => &event.pdu().prev_events,
                Edge::Auth => &event.pdu().auth_events,
            };
            frontier.extend(refs.iter().cloned());
            admitted.push(event);
        }
    }
    let leftover = total - admitted.len();
    if leftover > 0 {
        tracing::info!(leftover, "response events outside the reference closure were not stored");
    }
    (admitted, leftover)
}

/// Admit a `/send_join` answer for our `join`: `state` is asserted by the
/// resident server (IDs derived, signatures verified, state events of the
/// room, no duplicate `(type, state_key)` — a duplicate fails the whole
/// join), and `auth_chain` is admitted within the `auth_events` closure of
/// `state ∪ {join}`.
pub async fn admit_send_join(
    remote_keys: &RemoteKeyCache,
    http: &reqwest::Client,
    room_id: &str,
    join: &Pdu,
    state: Vec<Value>,
    auth_chain: Vec<Value>,
) -> Result<(Vec<Admitted>, Vec<Admitted>, usize), FetchError> {
    let mut admitted_state = Vec::new();
    let mut keys = HashSet::new();
    for value in state {
        let admitted = verify_returned(remote_keys, http, value).await?;
        require_room_state(&admitted, room_id)?;
        let key = (admitted.pdu().event_type.clone(), admitted.pdu().state_key.clone());
        if !keys.insert(key) {
            return Err(FetchError::DuplicateState);
        }
        admitted_state.push(admitted);
    }
    let seeds: HashSet<String> = admitted_state
        .iter()
        .flat_map(|a| a.pdu().auth_events.iter().cloned())
        .chain(join.auth_events.iter().cloned())
        .collect();
    let max = auth_chain.len();
    let (chain, leftover) = admit_closure(remote_keys, http, auth_chain, seeds, Edge::Auth, &HashSet::new(), max).await;
    Ok((admitted_state, chain, leftover))
}

#[cfg(test)]
mod tests {
    use super::*;
    use conduit::keys::{generate_server_key, public_bytes, ServerKey};
    use conduit::signing::{add_signature, sign_authored};
    use serde_json::json;

    const TS: u64 = 1_700_000_000_000;

    async fn cache(keys: &[(&str, &ServerKey)]) -> RemoteKeyCache {
        let cache = RemoteKeyCache::new().with_test_base_url("http://127.0.0.1:1".into());
        for (server, key) in keys {
            cache.insert_key(server, &key.key_id, public_bytes(key), i64::MAX / 4, TS as i64, None).await;
        }
        cache
    }

    fn signed(key: &ServerKey, event_type: &str, state_key: Option<&str>, prev: Vec<String>, auth: Vec<String>, body: &str) -> Pdu {
        let mut pdu = Pdu::new("!r:a.org", "@u:a.org", event_type, state_key.map(str::to_owned),
            json!({"body": body}), TS, auth, prev, 1);
        sign_authored(&mut pdu, key, "a.org").unwrap();
        pdu
    }

    fn id(pdu: &Pdu) -> String {
        conduit::hashing::event_id(pdu).unwrap()
    }

    fn value(pdu: &Pdu) -> Value {
        serde_json::to_value(pdu).unwrap()
    }

    #[tokio::test]
    async fn substituted_event_is_refused() {
        let key = generate_server_key();
        let keys = cache(&[("a.org", &key)]).await;
        let http = reqwest::Client::new();
        let a = signed(&key, "m.room.message", None, vec![], vec![], "A");
        let b = signed(&key, "m.room.message", None, vec![], vec![], "B");
        let err = admit_fetched(&keys, &http, value(&b), Expect::Exactly(&id(&a))).await.unwrap_err();
        assert!(matches!(err, FetchError::IdMismatch { .. }));
        assert!(admit_fetched(&keys, &http, value(&a), Expect::Exactly(&id(&a))).await.is_ok());
    }

    #[tokio::test]
    async fn fetched_event_with_hash_mismatch_is_admitted_redacted() {
        let key = generate_server_key();
        let keys = cache(&[("a.org", &key)]).await;
        let http = reqwest::Client::new();
        let mut a = signed(&key, "m.room.message", None, vec![], vec![], "A");
        let requested = id(&a);
        a.content = json!({"body": "tampered"});
        let admitted = admit_fetched(&keys, &http, value(&a), Expect::Exactly(&requested)).await.unwrap();
        assert!(admitted.received.redacted_on_receipt);
        assert_eq!(admitted.event_id(), requested);
        assert_eq!(admitted.pdu().content, json!({}));
    }

    #[tokio::test]
    async fn unreferenced_extra_event_is_not_admitted() {
        let key = generate_server_key();
        let keys = cache(&[("a.org", &key)]).await;
        let http = reqwest::Client::new();
        let e1 = signed(&key, "m.room.message", None, vec![], vec![], "1");
        let e2 = signed(&key, "m.room.message", None, vec![id(&e1)], vec![], "2");
        let e3 = signed(&key, "m.room.message", None, vec![id(&e2)], vec![], "3");
        let extra = signed(&key, "m.room.message", None, vec![], vec![], "extra");
        // Seeds: the prev_events of the latest event we hold (e4 -> e3).
        let seeds: HashSet<String> = [id(&e3)].into_iter().collect();
        // Response order deliberately scrambled.
        let values = vec![value(&e1), value(&extra), value(&e3), value(&e2)];
        let (admitted, leftover) = admit_closure(&keys, &http, values, seeds, Edge::Prev, &HashSet::new(), 20).await;
        let ids: HashSet<String> = admitted.iter().map(|a| a.event_id().to_owned()).collect();
        assert_eq!(ids, [id(&e1), id(&e2), id(&e3)].into_iter().collect());
        assert_eq!(leftover, 1);
    }

    #[tokio::test]
    async fn closure_stops_at_earliest_events() {
        let key = generate_server_key();
        let keys = cache(&[("a.org", &key)]).await;
        let http = reqwest::Client::new();
        let e1 = signed(&key, "m.room.message", None, vec![], vec![], "1");
        let e2 = signed(&key, "m.room.message", None, vec![id(&e1)], vec![], "2");
        let stop: HashSet<String> = [id(&e1)].into_iter().collect();
        let (admitted, _) = admit_closure(&keys, &http, vec![value(&e1), value(&e2)],
            [id(&e2)].into_iter().collect(), Edge::Prev, &stop, 20).await;
        assert_eq!(admitted.len(), 1);
    }

    #[tokio::test]
    async fn send_join_auth_chain_outside_closure_and_duplicate_state() {
        let key = generate_server_key();
        let keys = cache(&[("a.org", &key)]).await;
        let http = reqwest::Client::new();
        let create = signed(&key, "m.room.create", Some(""), vec![], vec![], "c");
        let member = signed(&key, "m.room.member", Some("@u:a.org"), vec![], vec![id(&create)], "m");
        let outside = signed(&key, "m.room.message", None, vec![], vec![], "outside");
        let join = signed(&key, "m.room.member", Some("@j:a.org"), vec![], vec![id(&create)], "j");
        let (state, chain, leftover) = admit_send_join(&keys, &http, "!r:a.org", &join,
            vec![value(&member)], vec![value(&create), value(&outside)]).await.unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(chain.iter().map(|a| a.event_id().to_owned()).collect::<Vec<_>>(), vec![id(&create)]);
        assert_eq!(leftover, 1);

        let duplicate = signed(&key, "m.room.member", Some("@u:a.org"), vec![], vec![id(&create)], "m2");
        let err = admit_send_join(&keys, &http, "!r:a.org", &join,
            vec![value(&member), value(&duplicate)], vec![]).await.unwrap_err();
        assert_eq!(err, FetchError::DuplicateState);
    }

    #[tokio::test]
    async fn state_requires_state_ids_and_room_state_events() {
        let key = generate_server_key();
        let keys = cache(&[("a.org", &key)]).await;
        let http = reqwest::Client::new();
        let create = signed(&key, "m.room.create", Some(""), vec![], vec![], "c");
        let message = signed(&key, "m.room.message", None, vec![], vec![], "m");
        assert_eq!(admit_state(&keys, &http, "!r:a.org", None, vec![value(&create)], vec![]).await.unwrap_err(),
            FetchError::MissingStateIds);
        let ids = StateIdsResponse { pdu_ids: vec![id(&create), id(&message)], auth_chain_ids: vec![] };
        assert!(admit_state(&keys, &http, "!r:a.org", Some(&ids), vec![value(&create)], vec![]).await.is_ok());
        assert_eq!(admit_state(&keys, &http, "!r:a.org", Some(&ids), vec![value(&message)], vec![]).await.unwrap_err(),
            FetchError::NotRoomState);
        let other = StateIdsResponse { pdu_ids: vec![], auth_chain_ids: vec![] };
        assert!(matches!(admit_state(&keys, &http, "!r:a.org", Some(&other), vec![value(&create)], vec![]).await,
            Err(FetchError::NotExpected { .. })));
    }

    #[tokio::test]
    async fn cosigned_response_must_keep_hashes_and_carry_cosignature() {
        let inviter = generate_server_key();
        let invitee = generate_server_key();
        let keys = cache(&[("a.org", &inviter), ("b.org", &invitee)]).await;
        let http = reqwest::Client::new();
        let mut invite = Pdu::new("!r:a.org", "@u:a.org", "m.room.member", Some("@v:b.org".into()),
            json!({"membership": "invite"}), TS, vec![], vec![], 1);
        sign_authored(&mut invite, &inviter, "a.org").unwrap();
        let sent = WirePdu::checked(&id(&invite), invite.clone()).unwrap();
        // Not co-signed.
        assert_eq!(admit_cosigned(&keys, &http, value(&invite), &sent, "b.org").await.unwrap_err(),
            FetchError::MissingCoSignature("b.org".into()));
        let mut cosigned = invite.clone();
        add_signature(&mut cosigned, &invitee, "b.org").unwrap();
        assert!(admit_cosigned(&keys, &http, value(&cosigned), &sent, "b.org").await.is_ok());
    }
}
