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

// The JWT half needs jsonwebtoken and its RSA backend; a consumer that only
// checks webhook signatures turns `jwt` off and carries none of it.
#[cfg(feature = "jwt")]
mod jwt;
#[cfg(feature = "jwt")]
pub use jwt::*;

#[cfg(feature = "webhook")]
pub mod webhook;
#[cfg(feature = "webhook")]
pub use webhook::{verify_webhook, WebhookError};
