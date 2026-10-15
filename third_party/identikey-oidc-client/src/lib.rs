//! Relying-party client for an identikey-core OpenID Provider (or any
//! OIDC issuer that signs ID tokens with EdDSA and publishes JWKS).
//!
//! This crate is **not** the OP. It never mints tokens, never holds a
//! user key, and does not depend on `identikey-oidc`. A homeserver
//! (Conduit) validates a JWT here, then mints its *own* agency token.
//! The OP JWT is identity, not a grant.
//!
//! What it gives an RP:
//! 1. Discover `{issuer}/.well-known/openid-configuration`
//! 2. Cache the JWKS
//! 3. Build an authorization-code URL (PKCE S256 + state + nonce)
//! 4. Confidential `/token` exchange (`client_secret_basic`)
//! 5. Verify EdDSA signature, `iss`, `aud`, `exp`, optional `nonce`
//! 6. Return opaque `sub` (identikey-core: a XID or pairwise subject)

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use josekit::jwk::{Jwk, JwkSet};
use josekit::jws::EdDSA;
use josekit::jwt::{self, JwtPayload};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

/// Verified identity from an OP JWT. Not a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcClientError {
    #[error("oidc discovery failed: {0}")]
    Discovery(String),
    #[error("jwks fetch failed: {0}")]
    Jwks(String),
    #[error("token is not a JWT: {0}")]
    Malformed(String),
    #[error("token signature did not verify")]
    BadSignature,
    #[error("token issuer mismatch")]
    BadIssuer,
    #[error("token audience mismatch")]
    BadAudience,
    #[error("token nonce mismatch")]
    BadNonce,
    #[error("token is expired")]
    Expired,
    #[error("token has no subject")]
    NoSubject,
    #[error("no signing key for this token")]
    NoKey,
    #[error("authorization endpoint is not a URL: {0}")]
    BadAuthorizeUrl(String),
    #[error("token exchange failed: {0}")]
    Token(String),
    #[error("entropy: {0}")]
    Entropy(String),
}

/// PKCE S256 pair. `verifier` is sent to `/token`; `challenge` is sent
/// to `/authorize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// Inputs for [`OidcClient::authorize_url`].
#[derive(Debug, Clone)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
}

/// Result of a successful authorization-code exchange.
#[derive(Debug, Clone)]
pub struct TokenSet {
    pub access_token: String,
    pub id_token: String,
    pub expires_in: u64,
}

type Result<T> = std::result::Result<T, OidcClientError>;

#[derive(Debug, Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponseBody {
    access_token: String,
    id_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct TokenErrorBody {
    error: Option<String>,
    error_description: Option<String>,
}

/// RP client. Construct via [`OidcClient::discover`] (live OP) or
/// [`OidcClient::from_jwks`] (tests / pinned keys).
pub struct OidcClient {
    issuer: String,
    audience: String,
    jwks_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks: RwLock<JwkSet>,
    http: reqwest::Client,
}

impl OidcClient {
    /// Fetch discovery + JWKS from `issuer`. `audience` is this RP
    /// (Conduit: the Matrix server name).
    pub async fn discover(
        issuer: &str,
        audience: &str,
        http: reqwest::Client,
    ) -> Result<Self> {
        let issuer = issuer.trim_end_matches('/').to_owned();
        let url = format!("{issuer}/.well-known/openid-configuration");
        let disco: Discovery = http
            .get(&url)
            .send()
            .await
            .map_err(|e| OidcClientError::Discovery(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcClientError::Discovery(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcClientError::Discovery(e.to_string()))?;
        if disco.issuer.trim_end_matches('/') != issuer {
            return Err(OidcClientError::Discovery(format!(
                "discovery issuer {} != {issuer}",
                disco.issuer
            )));
        }
        let jwks = fetch_jwks(&http, &disco.jwks_uri).await?;
        Ok(Self {
            issuer,
            audience: audience.to_owned(),
            jwks_uri: disco.jwks_uri,
            authorization_endpoint: disco.authorization_endpoint,
            token_endpoint: disco.token_endpoint,
            jwks: RwLock::new(jwks),
            http,
        })
    }

    /// Endpoints inferred from `issuer`; empty JWKS. Enough to build
    /// `/authorize` URLs in tests. [`validate`] will fail with [`OidcClientError::NoKey`].
    pub fn endpoints_only(issuer: &str, audience: &str) -> Self {
        Self::from_jwks(issuer, audience, JwkSet::new())
    }

    /// Test / offline constructor: no HTTP, keys supplied.
    /// Authorization/token endpoints are inferred as `{issuer}/authorize`
    /// and `{issuer}/token` (identikey-core shape).
    pub fn from_jwks(issuer: &str, audience: &str, jwks: JwkSet) -> Self {
        let issuer = issuer.trim_end_matches('/').to_owned();
        Self {
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            issuer,
            audience: audience.to_owned(),
            jwks_uri: String::new(),
            jwks: RwLock::new(jwks),
            http: reqwest::Client::new(),
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    /// Authorization-code URL with PKCE S256. `scope` is always `openid`.
    pub fn authorize_url(&self, req: &AuthorizeRequest) -> Result<String> {
        let mut url = Url::parse(&self.authorization_endpoint).map_err(|e| {
            OidcClientError::BadAuthorizeUrl(e.to_string())
        })?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &req.client_id)
            .append_pair("redirect_uri", &req.redirect_uri)
            .append_pair("scope", "openid")
            .append_pair("state", &req.state)
            .append_pair("nonce", &req.nonce)
            .append_pair("code_challenge", &req.code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.to_string())
    }

    /// Confidential client: POST `/token` with HTTP Basic + PKCE verifier.
    pub async fn exchange_authorization_code(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenSet> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_verifier", code_verifier)
            .finish();
        let response = self
            .http
            .post(&self.token_endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .header(
                "authorization",
                basic_auth_header(client_id, client_secret),
            )
            .body(body)
            .send()
            .await
            .map_err(|e| OidcClientError::Token(e.to_string()))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| OidcClientError::Token(e.to_string()))?;
        if !status.is_success() {
            let err = serde_json::from_slice::<TokenErrorBody>(&bytes).ok();
            let msg = err
                .map(|e| {
                    format!(
                        "{}: {}",
                        e.error.unwrap_or_else(|| status.to_string()),
                        e.error_description.unwrap_or_default()
                    )
                })
                .unwrap_or_else(|| {
                    String::from_utf8_lossy(&bytes).into_owned()
                });
            return Err(OidcClientError::Token(msg));
        }
        let parsed: TokenResponseBody = serde_json::from_slice(&bytes)
            .map_err(|e| OidcClientError::Token(e.to_string()))?;
        Ok(TokenSet {
            access_token: parsed.access_token,
            id_token: parsed.id_token,
            expires_in: parsed.expires_in,
        })
    }

    /// Verify an ID/access token and return `iss` + `sub`.
    pub async fn validate(&self, token: &str, now_unix: u64) -> Result<OidcIdentity> {
        self.validate_with_nonce(token, now_unix, None).await
    }

    /// Same as [`validate`], plus `nonce` when the RP sent one at authorize.
    pub async fn validate_with_nonce(
        &self,
        token: &str,
        now_unix: u64,
        expected_nonce: Option<&str>,
    ) -> Result<OidcIdentity> {
        let header = jwt::decode_header(token)
            .map_err(|e| OidcClientError::Malformed(e.to_string()))?;
        let kid = header.claim("kid").and_then(|v| v.as_str()).map(str::to_owned);

        let jwk = self.lookup_jwk(kid.as_deref()).await?;
        let verifier = EdDSA
            .verifier_from_jwk(&jwk)
            .map_err(|_| OidcClientError::BadSignature)?;
        let (payload, _header) = jwt::decode_with_verifier(token, &verifier)
            .map_err(|_| OidcClientError::BadSignature)?;

        self.check_claims(&payload, now_unix, expected_nonce)?;
        let subject = payload
            .subject()
            .ok_or(OidcClientError::NoSubject)?
            .to_owned();
        Ok(OidcIdentity {
            issuer: self.issuer.clone(),
            subject,
        })
    }

    async fn lookup_jwk(&self, kid: Option<&str>) -> Result<Jwk> {
        if let Some(jwk) = find_jwk(&*self.jwks.read().await, kid) {
            return Ok(jwk);
        }
        if !self.jwks_uri.is_empty() {
            let fresh = fetch_jwks(&self.http, &self.jwks_uri).await?;
            let found = find_jwk(&fresh, kid);
            *self.jwks.write().await = fresh;
            if let Some(jwk) = found {
                return Ok(jwk);
            }
        }
        Err(OidcClientError::NoKey)
    }

    fn check_claims(
        &self,
        payload: &JwtPayload,
        now_unix: u64,
        expected_nonce: Option<&str>,
    ) -> Result<()> {
        let iss = payload.issuer().unwrap_or("");
        if iss.trim_end_matches('/') != self.issuer {
            return Err(OidcClientError::BadIssuer);
        }
        let aud_ok = payload.audience().map(|list| {
            list.iter()
                .any(|a| a == &self.audience)
        }).unwrap_or(false);
        if !aud_ok {
            return Err(OidcClientError::BadAudience);
        }
        if let Some(exp) = payload.expires_at() {
            let exp_unix = exp.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if now_unix >= exp_unix {
                return Err(OidcClientError::Expired);
            }
        }
        if let Some(expected) = expected_nonce {
            let got = payload
                .claim("nonce")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if got != expected {
                return Err(OidcClientError::BadNonce);
            }
        }
        Ok(())
    }
}

/// 32 random bytes, unpadded base64url verifier + S256 challenge.
pub fn generate_pkce() -> Result<Pkce> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| OidcClientError::Entropy(e.to_string()))?;
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    Ok(Pkce {
        challenge: s256_challenge(&verifier),
        verifier,
    })
}

/// Opaque CSRF/nonce value (16 random bytes, unpadded base64url).
pub fn generate_state() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| OidcClientError::Entropy(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn basic_auth_header(id: &str, secret: &str) -> String {
    let raw = format!("{id}:{secret}");
    format!("Basic {}", STANDARD.encode(raw.as_bytes()))
}

fn find_jwk(set: &JwkSet, kid: Option<&str>) -> Option<Jwk> {
    let keys: Vec<Jwk> = set.keys().iter().cloned().cloned().collect();
    if let Some(kid) = kid {
        return keys.into_iter().find(|k| k.key_id() == Some(kid));
    }
    keys.into_iter().next()
}

async fn fetch_jwks(http: &reqwest::Client, uri: &str) -> Result<JwkSet> {
    let bytes = http
        .get(uri)
        .send()
        .await
        .map_err(|e| OidcClientError::Jwks(e.to_string()))?
        .error_for_status()
        .map_err(|e| OidcClientError::Jwks(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| OidcClientError::Jwks(e.to_string()))?;
    JwkSet::from_bytes(&bytes).map_err(|e| OidcClientError::Jwks(e.to_string()))
}

/// Unix seconds. Hosts that already have a clock should pass it in.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use josekit::jwk::alg::ed::EdCurve;
    use josekit::jws::{EdDSA, JwsHeader};
    use josekit::jwt::JwtPayload;
    use std::time::{Duration, SystemTime};

    fn keypair() -> impl josekit::jwk::KeyPair {
        let mut pair = EdDSA.generate_key_pair(EdCurve::Ed25519).unwrap();
        pair.set_key_id(Some("test-kid".to_string()));
        pair.set_algorithm(Some("EdDSA"));
        pair
    }

    fn mint(
        pair: &impl josekit::jwk::KeyPair,
        iss: &str,
        aud: &str,
        sub: &str,
        exp_secs: i64,
        nonce: Option<&str>,
    ) -> String {
        let mut header = JwsHeader::new();
        header.set_algorithm("EdDSA");
        header.set_key_id("test-kid");
        let mut payload = JwtPayload::new();
        payload.set_issuer(iss);
        payload.set_subject(sub);
        payload.set_audience(vec![aud]);
        let exp = SystemTime::now() + Duration::from_secs(exp_secs.max(0) as u64);
        if exp_secs >= 0 {
            payload.set_expires_at(&exp);
        } else {
            payload.set_expires_at(&(SystemTime::now() - Duration::from_secs(60)));
        }
        if let Some(nonce) = nonce {
            payload
                .set_claim("nonce", Some(josekit::Value::String(nonce.to_owned())))
                .unwrap();
        }
        let jwk = pair.to_jwk_key_pair();
        let signer = EdDSA.signer_from_jwk(&jwk).unwrap();
        jwt::encode_with_signer(&payload, &header, &signer).unwrap()
    }

    fn client_for(pair: &impl josekit::jwk::KeyPair) -> OidcClient {
        let mut set = JwkSet::new();
        set.push_key(pair.to_jwk_public_key());
        OidcClient::from_jwks("https://idp.example", "conduit.example", set)
    }

    #[tokio::test]
    async fn valid_token_yields_sub() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://idp.example", "conduit.example", "xid-alice", 300, None);
        let id = client.validate(&token, now_unix()).await.unwrap();
        assert_eq!(id.subject, "xid-alice");
        assert_eq!(id.issuer, "https://idp.example");
    }

    #[tokio::test]
    async fn wrong_audience_fails() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://idp.example", "other-rp", "xid-alice", 300, None);
        let err = client.validate(&token, now_unix()).await.unwrap_err();
        assert!(matches!(err, OidcClientError::BadAudience));
    }

    #[tokio::test]
    async fn expired_fails() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://idp.example", "conduit.example", "xid-alice", -1, None);
        let err = client.validate(&token, now_unix()).await.unwrap_err();
        assert!(matches!(err, OidcClientError::Expired));
    }

    #[tokio::test]
    async fn wrong_issuer_fails() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(&pair, "https://evil.example", "conduit.example", "xid-alice", 300, None);
        let err = client.validate(&token, now_unix()).await.unwrap_err();
        assert!(matches!(err, OidcClientError::BadIssuer));
    }

    #[tokio::test]
    async fn nonce_mismatch_fails() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(
            &pair,
            "https://idp.example",
            "conduit.example",
            "xid-alice",
            300,
            Some("expected-nonce"),
        );
        let err = client
            .validate_with_nonce(&token, now_unix(), Some("other-nonce"))
            .await
            .unwrap_err();
        assert!(matches!(err, OidcClientError::BadNonce));
    }

    #[tokio::test]
    async fn matching_nonce_passes() {
        let pair = keypair();
        let client = client_for(&pair);
        let token = mint(
            &pair,
            "https://idp.example",
            "conduit.example",
            "xid-alice",
            300,
            Some("n1"),
        );
        let id = client
            .validate_with_nonce(&token, now_unix(), Some("n1"))
            .await
            .unwrap();
        assert_eq!(id.subject, "xid-alice");
    }

    #[test]
    fn authorize_url_includes_pkce_and_nonce() {
        let pair = keypair();
        let client = client_for(&pair);
        let url = client
            .authorize_url(&AuthorizeRequest {
                client_id: "localhost".into(),
                redirect_uri: "http://127.0.0.1:8008/_matrix/client/v3/login/identikey/callback"
                    .into(),
                state: "st".into(),
                nonce: "nn".into(),
                code_challenge: "cc".into(),
            })
            .unwrap();
        assert!(url.starts_with("https://idp.example/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=localhost"));
        assert!(url.contains("code_challenge=cc"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("nonce=nn"));
        assert!(url.contains("state=st"));
        assert!(url.contains("scope=openid"));
    }

    #[test]
    fn pkce_verifier_is_s256_length() {
        let pkce = generate_pkce().unwrap();
        assert_eq!(pkce.verifier.len(), 43);
        assert_eq!(pkce.challenge, s256_challenge(&pkce.verifier));
        let state = generate_state().unwrap();
        assert_eq!(state.len(), 22);
    }
}
