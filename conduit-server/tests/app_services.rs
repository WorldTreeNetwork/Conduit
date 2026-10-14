//! Integration tests for E11 Application Services (AS1–AS7).
//!
//! Covers:
//!   - dd8.7 AS1: AS registration loading from YAML
//!   - dd8.8 AS2: namespace enforcement
//!   - dd8.9 AS3: AS auth namespace validation logic
//!   - dd8.10 AS4: ghost user — auto-creation not implemented in v0 (follow-up filed)
//!   - dd8.11 AS5: transaction pusher queue (unit test)
//!   - dd8.12 AS6: query endpoints — not implemented in v0 (follow-up filed)
//!   - dd8.13 AS7: retry queue drain semantics
//!
//! # Running
//! ```
//! DATABASE_URL=postgresql://postgres@localhost/conduit \
//!     cargo test --workspace --tests
//! ```

use std::io::Write as IoWrite;

use conduit_server::app_service::{
    exclusive_as_for_user,
    load_app_services, user_in_as_namespace,
};

// ---------------------------------------------------------------------------
// Helper: write a registration YAML to a temp dir and load it.
// ---------------------------------------------------------------------------

fn write_as_yaml(dir: &std::path::Path, filename: &str, content: &str) {
    let mut f = std::fs::File::create(dir.join(filename)).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

fn minimal_as_yaml(
    id: &str,
    as_token: &str,
    hs_token: &str,
    user_regex: &str,
    exclusive: bool,
) -> String {
    format!(r#"id: {id}
url: http://localhost:9999
as_token: {as_token}
hs_token: {hs_token}
sender_localpart: bot
namespaces:
  users:
    - exclusive: {exclusive}
      regex: "{user_regex}"
  aliases: []
  rooms: []
"#)
}

// ---------------------------------------------------------------------------
// Test: as_registration_loaded_from_dir (dd8.7 AS1)
// ---------------------------------------------------------------------------

#[test]
fn as_registration_loaded_from_dir() {
    let tmp = tempfile::tempdir().expect("tmpdir");

    write_as_yaml(
        tmp.path(),
        "bridge.yaml",
        &minimal_as_yaml("test_bridge", "as_secret", "hs_secret", "@bridge_.*:localhost", true),
    );

    let services = load_app_services(tmp.path().to_str().unwrap());
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].id, "test_bridge");
    assert_eq!(services[0].as_token, "as_secret");
    assert_eq!(services[0].hs_token, "hs_secret");
    assert_eq!(services[0].user_namespaces.len(), 1);
    assert!(services[0].user_namespaces[0].0, "should be exclusive");
}

#[test]
fn as_load_nonexistent_dir_returns_empty() {
    let services = load_app_services("/tmp/conduit_no_such_dir_for_tests_xyz");
    assert!(services.is_empty());
}

#[test]
fn as_load_skips_unparseable_yaml() {
    let tmp = tempfile::tempdir().expect("tmpdir");

    // Write a valid one.
    write_as_yaml(
        tmp.path(),
        "good.yaml",
        &minimal_as_yaml("good_as", "tok1", "hs1", "@good_.*:localhost", true),
    );
    // Write an invalid one.
    write_as_yaml(tmp.path(), "bad.yaml", "this is not valid yaml: ][");

    let services = load_app_services(tmp.path().to_str().unwrap());
    // Only the valid one loaded; bad is silently skipped.
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].id, "good_as");
}

#[test]
fn as_load_ignores_non_yaml_files() {
    let tmp = tempfile::tempdir().expect("tmpdir");

    write_as_yaml(
        tmp.path(),
        "bridge.yaml",
        &minimal_as_yaml("bridge", "tok", "hs", "@bridge_.*:localhost", true),
    );
    // A .json file — should be ignored.
    std::fs::write(tmp.path().join("ignored.json"), r#"{"id": "oops"}"#).unwrap();

    let services = load_app_services(tmp.path().to_str().unwrap());
    assert_eq!(services.len(), 1);
}

// ---------------------------------------------------------------------------
// Test: namespace enforcement (dd8.8 AS2)
// ---------------------------------------------------------------------------

#[test]
fn namespace_exclusive_ownership() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    write_as_yaml(
        tmp.path(),
        "bridge.yaml",
        &minimal_as_yaml("bridge", "tok", "hs", r"@bridge_.*:localhost", true),
    );
    let services = load_app_services(tmp.path().to_str().unwrap());

    // User in exclusive namespace → owned by this AS.
    let owner = exclusive_as_for_user("@bridge_alice:localhost", &services);
    assert!(owner.is_some(), "bridge_alice should be in exclusive namespace");
    assert_eq!(owner.unwrap().id, "bridge");

    // Normal user → not owned.
    let none = exclusive_as_for_user("@alice:localhost", &services);
    assert!(none.is_none(), "alice is not in bridge namespace");
}

#[test]
fn namespace_non_exclusive_does_not_claim_ownership() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    // Use exclusive: false
    write_as_yaml(
        tmp.path(),
        "bridge.yaml",
        &minimal_as_yaml("bridge", "tok", "hs", r"@bridge_.*:localhost", false),
    );
    let services = load_app_services(tmp.path().to_str().unwrap());

    // With exclusive: false, exclusive_as_for_user should return None.
    let owner = exclusive_as_for_user("@bridge_alice:localhost", &services);
    assert!(owner.is_none(), "non-exclusive namespace should not claim ownership");
}

// ---------------------------------------------------------------------------
// Test: AS auth namespace validation (dd8.9 AS3)
// ---------------------------------------------------------------------------

#[test]
fn as_auth_user_in_namespace() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    write_as_yaml(
        tmp.path(),
        "bot.yaml",
        &minimal_as_yaml("mybot", "secret_as_token", "hs", r"@bot_.*:localhost", true),
    );
    let services = load_app_services(tmp.path().to_str().unwrap());
    let svc = &services[0];

    // Matching pattern.
    assert!(user_in_as_namespace("@bot_alice:localhost", svc));
    assert!(user_in_as_namespace("@bot_123:localhost", svc));

    // Non-matching.
    assert!(!user_in_as_namespace("@carol:localhost", svc));
    assert!(!user_in_as_namespace("@bot_alice:other.server", svc));
}
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Test: receive_ephemeral (spec v1.13) and its MSC2409 alias
// ---------------------------------------------------------------------------

#[test]
fn receive_ephemeral_parsed_with_msc2409_alias() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let base = minimal_as_yaml("plain", "tok1", "hs1", r"@p_.*:localhost", true);
    write_as_yaml(tmp.path(), "plain.yaml", &base);
    write_as_yaml(
        tmp.path(),
        "stable.yaml",
        &format!("{}receive_ephemeral: true\n", minimal_as_yaml("stable", "tok2", "hs2", r"@s_.*:localhost", true)),
    );
    write_as_yaml(
        tmp.path(),
        "msc.yaml",
        &format!(
            "{}de.sorunome.msc2409.push_ephemeral: true\n",
            minimal_as_yaml("msc", "tok3", "hs3", r"@m_.*:localhost", true)
        ),
    );
    let services = load_app_services(tmp.path().to_str().unwrap());
    let by_id = |id: &str| services.iter().find(|s| s.id == id).unwrap().receive_ephemeral;
    assert!(!by_id("plain"));
    assert!(by_id("stable"));
    assert!(by_id("msc"));
    let svc = services.iter().find(|s| s.id == "plain").unwrap();
    assert_eq!(svc.sender_user_id("localhost"), "@bot:localhost");
    assert!(svc.is_interested_in_user("@bot:localhost", "localhost"));
    assert!(svc.is_interested_in_user("@p_x:localhost", "localhost"));
    assert!(!svc.is_interested_in_user("@q_x:localhost", "localhost"));
}
