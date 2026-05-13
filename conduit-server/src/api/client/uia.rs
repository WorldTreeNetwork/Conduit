//! Minimal UIA (User-Interactive Authentication) session state.
//!
//! For v0 we only support `m.login.dummy` — no real state needs to persist
//! across requests.  We still hand out session IDs so that spec-compliant
//! clients (e.g. Element) can complete the UIA dance.
//!
//! The session store is an in-process `DashMap`-free implementation using
//! a plain `Mutex<HashSet>` — sufficient for a single-node homeserver at
//! this stage.  Sessions auto-expire on next GC sweep (not yet wired up).

use std::collections::HashSet;
use std::sync::Mutex;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;

/// Global UIA session store.  Keyed by session_id string.
static SESSIONS: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn with_sessions<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashSet<String>) -> R,
{
    let mut guard = SESSIONS.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);
    f(set)
}

/// Generate a new UIA session ID and register it.
pub fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let id = URL_SAFE_NO_PAD.encode(bytes);
    with_sessions(|s| s.insert(id.clone()));
    id
}

/// Mark a session as completed / consumed.
/// For `m.login.dummy` this is a no-op, but the call keeps the interface clean.
pub fn mark_session_used(session_id: &str) {
    with_sessions(|s| s.remove(session_id));
}
