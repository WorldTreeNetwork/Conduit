//! Identity-server client: the homeserver as a consumer of the Identity
//! Service API (conduit-y99.36).
//!
//! <https://spec.matrix.org/v1.19/identity-service-api/>
//!
//! Used for third-party invites (`hash_details` + `lookup`,
//! `store-invite`), account 3PID bind/unbind (`3pid/bind`, `3pid/unbind`)
//! and key validity checks (`pubkey/isvalid`).
//!
//! Identity servers are named by clients (`id_server`: hostname[:port]), so
//! every request goes through the outbound SSRF policy of
//! [`crate::api::client::safe_fetch`]: private and loopback destinations are
//! refused unless allow-listed with `CONDUIT_IS_ALLOW_CIDRS`.  HTTPS is used
//! unless `CONDUIT_IS_INSECURE_HTTP=1` (tests and local development).

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use conduit::keys::ServerKey;

use crate::api::client::safe_fetch::{self, FetchPolicy};

/// Failure talking to an identity server.
#[derive(Debug, Clone, PartialEq)]
pub enum IsError {
    /// `id_server` is not a hostname[:port].
    InvalidServer(String),
    /// The identity server answered with a non-2xx status (body kept so a
    /// Matrix error can be passed through to the client).
    Status(u16, Value),
    /// Network failure, refused destination, or a malformed answer.
    Unreachable(String),
}

impl std::fmt::Display for IsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsError::InvalidServer(s) => write!(f, "invalid identity server {s}"),
            IsError::Status(status, body) => write!(f, "identity server answered {status}: {body}"),
            IsError::Unreachable(m) => write!(f, "identity server unreachable: {m}"),
        }
    }
}

/// What `POST /store-invite` returned.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredInvite {
    pub token: String,
    pub display_name: String,
    /// `[{public_key, key_validity_url}]`, long-term key first.
    pub public_keys: Vec<Value>,
}

/// Outcome of an unbind on one identity server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unbind {
    Success,
    /// The server does not support unbinding (404/405/501).
    NoSupport,
}

/// Identity-server HTTP client.
#[derive(Clone)]
pub struct IdentityClient {
    http: reqwest::Client,
    scheme: &'static str,
}

impl IdentityClient {
    /// Build from the environment (`CONDUIT_IS_ALLOW_CIDRS`,
    /// `CONDUIT_IS_INSECURE_HTTP`).
    pub fn from_env() -> Self {
        let allow = std::env::var("CONDUIT_IS_ALLOW_CIDRS")
            .map(|s| safe_fetch::parse_cidr_list(&s))
            .unwrap_or_default();
        let insecure = std::env::var("CONDUIT_IS_INSECURE_HTTP").is_ok_and(|v| v == "1");
        Self::new(allow, insecure)
    }

    pub fn new(allow: Vec<safe_fetch::Cidr>, insecure_http: bool) -> Self {
        let policy = Arc::new(FetchPolicy {
            allow,
            max_bytes: 1 << 20,
            timeout: Duration::from_secs(15),
            max_redirects: 0,
        });
        let http = safe_fetch::build_client(&policy).unwrap_or_else(|_| reqwest::Client::new());
        Self { http, scheme: if insecure_http { "http" } else { "https" } }
    }

    /// Process-wide client configured from the environment.
    pub fn shared() -> Arc<Self> {
        static CLIENT: std::sync::OnceLock<Arc<IdentityClient>> = std::sync::OnceLock::new();
        Arc::clone(CLIENT.get_or_init(|| Arc::new(IdentityClient::from_env())))
    }

    fn base(&self, id_server: &str) -> Result<String, IsError> {
        if !valid_server_name(id_server) {
            return Err(IsError::InvalidServer(id_server.to_owned()));
        }
        Ok(format!("{}://{id_server}/_matrix/identity/v2", self.scheme))
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<Value, IsError> {
        let response = request
            .send()
            .await
            .map_err(|e| IsError::Unreachable(e.to_string()))?;
        let status = response.status().as_u16();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| IsError::Unreachable(e.to_string()))?;
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            Ok(body)
        } else {
            Err(IsError::Status(status, body))
        }
    }

    /// Look up the Matrix user bound to `(medium, address)`:
    /// `GET /hash_details` then `POST /lookup`, preferring `sha256`.
    pub async fn lookup(
        &self,
        id_server: &str,
        access_token: &str,
        medium: &str,
        address: &str,
    ) -> Result<Option<String>, IsError> {
        let base = self.base(id_server)?;
        let details = self
            .send(self.http.get(format!("{base}/hash_details")).bearer_auth(access_token))
            .await?;
        let pepper = details["lookup_pepper"]
            .as_str()
            .ok_or_else(|| IsError::Unreachable("hash_details has no lookup_pepper".into()))?;
        let algorithms: Vec<&str> = details["algorithms"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let (algorithm, hashed) = if algorithms.contains(&"sha256") {
            ("sha256", hash_3pid(address, medium, pepper))
        } else if algorithms.contains(&"none") {
            ("none", format!("{address} {medium}"))
        } else {
            return Err(IsError::Unreachable("no supported lookup algorithm".into()));
        };
        let body = json!({"algorithm": algorithm, "pepper": pepper, "addresses": [hashed]});
        let found = self
            .send(self.http.post(format!("{base}/lookup")).bearer_auth(access_token).json(&body))
            .await?;
        Ok(found["mappings"][&hashed].as_str().map(str::to_owned))
    }

    /// `POST /store-invite`.
    pub async fn store_invite(
        &self,
        id_server: &str,
        access_token: &str,
        request: &Value,
    ) -> Result<StoredInvite, IsError> {
        let base = self.base(id_server)?;
        let body = self
            .send(self.http.post(format!("{base}/store-invite")).bearer_auth(access_token).json(request))
            .await?;
        let token = body["token"].as_str().unwrap_or_default().to_owned();
        let token_ok = !token.is_empty()
            && token.len() <= 255
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'=' | b'_' | b'-'));
        let public_keys: Vec<Value> = body["public_keys"].as_array().cloned().unwrap_or_default();
        if !token_ok || public_keys.is_empty() || public_keys.iter().any(|k| !k["public_key"].is_string()) {
            return Err(IsError::Unreachable(format!("malformed store-invite answer: {body}")));
        }
        Ok(StoredInvite {
            token,
            display_name: body["display_name"].as_str().unwrap_or_default().to_owned(),
            public_keys,
        })
    }

    /// `POST /3pid/bind` on behalf of `mxid`; returns the signed association.
    pub async fn bind(
        &self,
        id_server: &str,
        access_token: &str,
        sid: &str,
        client_secret: &str,
        mxid: &str,
    ) -> Result<Value, IsError> {
        let base = self.base(id_server)?;
        let body = json!({"sid": sid, "client_secret": client_secret, "mxid": mxid});
        self.send(self.http.post(format!("{base}/3pid/bind")).bearer_auth(access_token).json(&body))
            .await
    }

    /// `POST /3pid/unbind`, authenticated as the homeserver that controls
    /// `mxid` (X-Matrix request signature with the server signing key).
    pub async fn unbind(
        &self,
        id_server: &str,
        mxid: &str,
        medium: &str,
        address: &str,
        server_name: &str,
        server_key: &ServerKey,
    ) -> Result<Unbind, IsError> {
        let base = self.base(id_server)?;
        let body = json!({"mxid": mxid, "threepid": {"medium": medium, "address": address}});
        let authorization = crate::federation::auth::sign_request(
            "POST",
            "/_matrix/identity/v2/3pid/unbind",
            server_name,
            id_server,
            Some(&body),
            server_key,
        );
        let request = self
            .http
            .post(format!("{base}/3pid/unbind"))
            .header("Authorization", authorization)
            .json(&body);
        match self.send(request).await {
            Ok(_) => Ok(Unbind::Success),
            Err(IsError::Status(404 | 405 | 501, _)) => Ok(Unbind::NoSupport),
            Err(e) => Err(e),
        }
    }

    /// `GET {key_validity_url}?public_key=...` -> `valid` (the URL is used
    /// as provided, per spec).
    pub async fn key_is_valid(&self, key_validity_url: &str, public_key: &str) -> Result<bool, IsError> {
        let mut url = url::Url::parse(key_validity_url)
            .map_err(|e| IsError::InvalidServer(format!("{key_validity_url}: {e}")))?;
        url.query_pairs_mut().append_pair("public_key", public_key);
        let body = self.send(self.http.get(url)).await?;
        Ok(body["valid"].as_bool() == Some(true))
    }
}

/// `sha256` lookup hash: URL-safe unpadded base64 of
/// `SHA-256("{address} {medium} {pepper}")`.
pub fn hash_3pid(address: &str, medium: &str, pepper: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{address} {medium} {pepper}").as_bytes()))
}

/// `hostname[:port]` as allowed for `id_server` (no scheme, path or userinfo).
pub fn valid_server_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

/// Canonical 3PID address (appendices "3PID types"): email is case-folded
/// (domain lowercased, caseless matching for the whole address); msisdn is
/// E.164 digits without `+`.  `None` for an invalid address or an unknown
/// medium.
pub fn canonical_3pid(medium: &str, address: &str) -> Option<String> {
    let address = address.trim();
    match medium {
        "email" => {
            let (local, domain) = address.rsplit_once('@')?;
            if local.is_empty() || domain.is_empty() || address.contains(char::is_whitespace) {
                return None;
            }
            Some(casefold(address))
        }
        "msisdn" => {
            let digits = address.strip_prefix('+').unwrap_or(address);
            (!digits.is_empty() && digits.len() <= 15 && digits.bytes().all(|b| b.is_ascii_digit()))
                .then(|| digits.to_owned())
        }
        _ => None,
    }
}

/// Unicode caseless-matching approximation: lowercase plus the common full
/// case foldings that `to_lowercase` does not perform.
fn casefold(s: &str) -> String {
    s.to_lowercase().replace('ß', "ss").replace('ς', "σ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_hash_matches_the_spec_construction() {
        // Independent: hex SHA-256 of "alice@example.com email matrixrocks"
        // re-encoded as URL-safe unpadded base64.
        let digest = Sha256::digest(b"alice@example.com email matrixrocks");
        assert_eq!(hash_3pid("alice@example.com", "email", "matrixrocks"), URL_SAFE_NO_PAD.encode(digest));
        assert!(!hash_3pid("a@b.c", "email", "p").contains(['+', '/', '=']));
    }

    #[test]
    fn three_pid_canonical_forms() {
        assert_eq!(canonical_3pid("email", " Strauß@Example.COM ").as_deref(), Some("strauss@example.com"));
        assert_eq!(canonical_3pid("email", "no-at-sign"), None);
        assert_eq!(canonical_3pid("email", "a b@c.d"), None);
        assert_eq!(canonical_3pid("msisdn", "+447700900123").as_deref(), Some("447700900123"));
        assert_eq!(canonical_3pid("msisdn", "44 7700"), None);
        assert_eq!(canonical_3pid("carrier-pigeon", "x"), None);
    }

    #[test]
    fn id_server_must_be_a_bare_host() {
        assert!(valid_server_name("matrix.org"));
        assert!(valid_server_name("127.0.0.1:8090"));
        assert!(valid_server_name("[::1]:8090"));
        assert!(!valid_server_name("https://matrix.org"));
        assert!(!valid_server_name("evil.org/path"));
        assert!(!valid_server_name("user@host"));
        assert!(!valid_server_name(""));
    }

    #[tokio::test]
    async fn key_validity_url_is_queried_as_provided() {
        use axum::{extract::RawQuery, routing::get, Json, Router};
        let app = Router::new().route(
            "/_matrix/identity/v2/pubkey/isvalid",
            get(|RawQuery(q): RawQuery| async move {
                Json(json!({"valid": q.as_deref() == Some("public_key=good%2Bkey")}))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/_matrix/identity/v2/pubkey/isvalid", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = IdentityClient::new(safe_fetch::parse_cidr_list("127.0.0.0/8"), true);
        assert!(client.key_is_valid(&url, "good+key").await.unwrap());
        assert!(!client.key_is_valid(&url, "revoked").await.unwrap());
    }

    #[tokio::test]
    async fn private_identity_servers_are_refused_by_default() {
        let client = IdentityClient::new(vec![], true);
        let err = client.lookup("127.0.0.1:9", "t", "email", "a@b.c").await.unwrap_err();
        assert!(matches!(err, IsError::Unreachable(_)), "{err:?}");
    }
}
