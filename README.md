# bjorst-clerk-axum

Clerk JWT verification for Axum APIs. Verifies RS256 JWTs against the Clerk JWKS endpoint with an in-process key cache.

## Features

- Fetches and caches JWKS keys (configurable TTL, default 1 hour)
- Refreshes automatically on cache miss or unknown `kid`
- Zero Clerk SDK dependency — pure JWKS/JWT verification via `jsonwebtoken`
- Exposes typed `ClerkClaims` and optional `ClerkOrgClaims`

## Installation

```toml
# Cargo.toml
bjorst-clerk-axum = { git = "https://github.com/bjorstgroup/bjorst-clerk-axum" }
```

## Usage

### Minimal setup

```rust
use bjorst_clerk_axum::{ClerkConfig, ClerkJwksCache, verify_session};
use reqwest::Client;
use std::time::Duration;

let config = ClerkConfig {
    jwks_url: "https://<your-clerk-domain>/.well-known/jwks.json".into(),
    audience: None,
};

let cache = ClerkJwksCache::new(Duration::from_secs(3600));
let client = Client::new();

// In an Axum handler or middleware:
let claims = verify_session(&headers, &client, &config, &cache).await?;
// Returns Ok(None)  — no token present
// Returns Ok(Some(claims)) — verified
// Returns Err(_)    — network or JWT error
```

### With Axum `AppState`

```rust
#[derive(Clone)]
pub struct AppState {
    pub http: reqwest::Client,
    pub clerk_config: ClerkConfig,
    pub jwks_cache: ClerkJwksCache,
}

// In middleware:
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    match verify_session(req.headers(), &state.http, &state.clerk_config, &state.jwks_cache).await {
        Ok(Some(claims)) => { /* attach claims to extensions */ }
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => return StatusCode::UNAUTHORIZED.into_response(),
    }
    next.run(req).await
}
```

### Extract token manually

```rust
use bjorst_clerk_axum::extract_access_token;

let token: Option<String> = extract_access_token(req.headers());
```

## API

### `ClerkConfig`

| Field | Type | Description |
|-------|------|-------------|
| `jwks_url` | `String` | `https://<clerk-domain>/.well-known/jwks.json` |
| `audience` | `Option<String>` | Expected `aud` claim. `None` skips audience validation. |

### `ClerkClaims`

| Field | Type | Description |
|-------|------|-------------|
| `sub` | `String` | Clerk user ID (`user_xxx`) |
| `sid` | `String` | Clerk session ID (`sess_xxx`) |
| `iss` | `Option<String>` | Issuer (Clerk frontend API URL) |
| `azp` | `Option<String>` | Authorized party (frontend origin) |
| `exp` | `i64` | Expiry (Unix timestamp) |
| `iat` | `i64` | Issued-at |
| `nbf` | `Option<i64>` | Not-before |
| `org` | `Option<ClerkOrgClaims>` | Present when an org is active in the session |

### `ClerkOrgClaims`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | Org ID (`org_xxx`) |
| `rol` | `Option<String>` | Org role (`org:admin`, `org:member`, …) |
| `slg` | `Option<String>` | Org slug |
| `per` | `Vec<String>` | Org permissions |

### `ClerkJwksCache`

```rust
ClerkJwksCache::new(ttl: Duration) -> Self
ClerkJwksCache::default()           // 1-hour TTL
```

Keys are fetched lazily on first call and refreshed when the TTL expires or an unknown `kid` is encountered.

## Environment variable

The JWKS URL comes from your Clerk dashboard under **API Keys → Advanced → JWKS URL**:

```
CLERK_JWKS_URL=https://<your-clerk-domain>/.well-known/jwks.json
```
