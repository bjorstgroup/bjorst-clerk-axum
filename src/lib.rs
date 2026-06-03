//! Clerk JWT verification for Axum.
//!
//! Verifies Clerk-issued RS256 JWTs against the Clerk JWKS endpoint.
//! JWKS keys are cached in-memory with a configurable TTL to avoid a
//! network round-trip on every request.
//!
//! ## Usage
//!
//! ```ignore
//! use bjorst_clerk_axum::{ClerkConfig, ClerkClaims, verify_session};
//!
//! let config = ClerkConfig {
//!     jwks_url: "https://<clerk-domain>/.well-known/jwks.json".into(),
//!     audience: None,
//! };
//!
//! let claims: Option<ClerkClaims> =
//!     verify_session(&headers, &http_client, &config).await?;
//! ```

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::http::{HeaderMap, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::warn;

// ── Config ─────────────────────────────────────────────────────────────────────

/// Clerk connection config required to verify JWTs.
#[derive(Debug, Clone)]
pub struct ClerkConfig {
    /// JWKS endpoint URL, e.g.
    /// `https://<your-clerk-domain>/.well-known/jwks.json`
    pub jwks_url: String,
    /// Expected `aud` claim. Leave `None` to skip audience validation.
    pub audience: Option<String>,
}

// ── Claims ─────────────────────────────────────────────────────────────────────

/// Standard claims present in every Clerk-issued JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClerkClaims {
    /// Clerk user ID (`user_xxx`).
    pub sub: String,
    /// Clerk session ID (`sess_xxx`).
    pub sid: String,
    /// Issuer — your Clerk frontend API URL.
    pub iss: Option<String>,
    /// Authorized party (frontend origin).
    pub azp: Option<String>,
    /// Expiry (Unix timestamp).
    pub exp: i64,
    /// Issued-at (Unix timestamp).
    pub iat: i64,
    /// Not-before (Unix timestamp).
    pub nbf: Option<i64>,
    /// Organization claims (present when an org is active in the session).
    #[serde(rename = "o", default)]
    pub org: Option<ClerkOrgClaims>,
}

/// Clerk organization claims embedded in the JWT when an org context is active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClerkOrgClaims {
    /// Org ID (`org_xxx`).
    pub id: String,
    /// Org role (`org:admin`, `org:member`, …).
    pub rol: Option<String>,
    /// Org slug.
    pub slg: Option<String>,
    /// Org permissions.
    #[serde(default)]
    pub per: Vec<String>,
}

// ── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ClerkError {
    #[error("JWKS fetch failed: {0}")]
    JwksFetch(#[from] reqwest::Error),
    #[error("JWKS parse failed: {0}")]
    JwksParse(String),
    #[error("no matching key found for kid={0:?}")]
    KeyNotFound(Option<String>),
    #[error("JWT verification failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

// ── JWKS cache ─────────────────────────────────────────────────────────────────

/// Cached JWKS — a map from `kid` → raw JWK JSON string.
type JwksCache = Arc<RwLock<Option<(Instant, HashMap<String, serde_json::Value>)>>>;

/// In-process JWKS cache shared across all verification calls.
///
/// Keyed by `kid`. Refreshed when a key is missing or after the TTL expires.
#[derive(Clone, Debug)]
pub struct ClerkJwksCache {
    inner: JwksCache,
    ttl: Duration,
}

impl Default for ClerkJwksCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600))
    }
}

impl ClerkJwksCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
            ttl,
        }
    }

    async fn get_or_refresh(
        &self,
        client: &reqwest::Client,
        jwks_url: &str,
        required_kid: Option<&str>,
    ) -> Result<HashMap<String, serde_json::Value>, ClerkError> {
        // Fast path: cache hit and TTL not expired and key present
        {
            let guard = self.inner.read().await;
            if let Some((fetched_at, ref keys)) = *guard {
                let key_found = required_kid.map_or(true, |kid| keys.contains_key(kid));
                if key_found && fetched_at.elapsed() < self.ttl {
                    return Ok(keys.clone());
                }
            }
        }

        // Slow path: fetch and update
        let keys = fetch_jwks(client, jwks_url).await?;
        *self.inner.write().await = Some((Instant::now(), keys.clone()));
        Ok(keys)
    }
}

async fn fetch_jwks(
    client: &reqwest::Client,
    url: &str,
) -> Result<HashMap<String, serde_json::Value>, ClerkError> {
    let body: serde_json::Value = client
        .get(url)
        .send()
        .await?
        .json()
        .await?;

    let keys = body["keys"]
        .as_array()
        .ok_or_else(|| ClerkError::JwksParse("missing 'keys' array".into()))?;

    let mut map = HashMap::new();
    for key in keys {
        let kid = key["kid"]
            .as_str()
            .ok_or_else(|| ClerkError::JwksParse("key missing 'kid'".into()))?
            .to_owned();
        map.insert(kid, key.clone());
    }
    Ok(map)
}

// ── Token extraction ───────────────────────────────────────────────────────────

/// Extract the Bearer token from `Authorization: Bearer <token>`.
pub fn extract_access_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(ToOwned::to_owned)
}

// ── Verification ───────────────────────────────────────────────────────────────

/// Verify the Clerk JWT in the `Authorization: Bearer` header.
///
/// Returns `Ok(None)` when no token is present.
/// Returns `Ok(Some(claims))` on success.
/// Returns `Err` on network or verification failure.
pub async fn verify_session(
    headers: &HeaderMap,
    client: &reqwest::Client,
    config: &ClerkConfig,
    cache: &ClerkJwksCache,
) -> Result<Option<ClerkClaims>, ClerkError> {
    let Some(token) = extract_access_token(headers) else {
        return Ok(None);
    };

    verify_token(&token, client, config, cache).await.map(Some)
}

/// Verify an explicit token string.
pub async fn verify_token(
    token: &str,
    client: &reqwest::Client,
    config: &ClerkConfig,
    cache: &ClerkJwksCache,
) -> Result<ClerkClaims, ClerkError> {
    let header = decode_header(token)?;
    let kid = header.kid.as_deref();

    let keys = cache
        .get_or_refresh(client, &config.jwks_url, kid)
        .await?;

    let jwk = keys
        .get(kid.unwrap_or(""))
        .or_else(|| keys.values().next())
        .ok_or_else(|| ClerkError::KeyNotFound(kid.map(ToOwned::to_owned)))?;

    let decoding_key = decoding_key_from_jwk(jwk)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    if let Some(ref aud) = config.audience {
        validation.set_audience(&[aud]);
    } else {
        validation.validate_aud = false;
    }

    let token_data = decode::<ClerkClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

fn decoding_key_from_jwk(jwk: &serde_json::Value) -> Result<DecodingKey, ClerkError> {
    // Build a minimal JwkSet from the single key and use jsonwebtoken's parser.
    let set = serde_json::json!({ "keys": [jwk] });
    let jwk_set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(set)
        .map_err(|e| ClerkError::JwksParse(e.to_string()))?;

    let key = jwk_set
        .keys
        .into_iter()
        .next()
        .ok_or_else(|| ClerkError::JwksParse("empty JwkSet".into()))?;

    DecodingKey::from_jwk(&key).map_err(|e| {
        warn!("failed to build decoding key from JWK: {e}");
        ClerkError::JwksParse(e.to_string())
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, header};

    #[test]
    fn extract_access_token_should_read_bearer_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer test-token-123"),
        );
        assert_eq!(
            extract_access_token(&headers).as_deref(),
            Some("test-token-123")
        );
    }

    #[test]
    fn extract_access_token_returns_none_without_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Token test-token-123"),
        );
        assert_eq!(extract_access_token(&headers), None);
    }

    #[test]
    fn extract_access_token_returns_none_when_no_header() {
        assert_eq!(extract_access_token(&HeaderMap::new()), None);
    }
}
