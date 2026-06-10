//! Svix-signed Clerk webhook signature verification.
//!
//! Enabled by the `webhook` feature. Clerk delivers webhooks signed with the
//! [Svix](https://docs.svix.com/receiving/verifying-payloads/how-manual)
//! scheme: an HMAC-SHA256 over `"<svix-id>.<svix-timestamp>.<body>"` keyed by
//! the base64-decoded webhook secret (the part after the `whsec_` prefix).
//!
//! ```no_run
//! use bjorst_clerk_axum::webhook::verify_webhook;
//!
//! # fn handle(secret: &str, body: &[u8], id: &str, ts: &str, sig: &str) {
//! match verify_webhook(secret, body, id, ts, sig) {
//!     Ok(()) => { /* trusted payload */ }
//!     Err(e) => { /* reject 401 */ let _ = e; }
//! }
//! # }
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

/// Tolerance window applied to the `svix-timestamp` header, in seconds.
const TOLERANCE_SECS: i64 = 300;

/// Errors returned by [`verify_webhook`].
#[derive(Debug, Error)]
pub enum WebhookError {
    /// `svix-timestamp` header was not a valid unix timestamp.
    #[error("invalid svix-timestamp")]
    InvalidTimestamp,
    /// System clock is before the unix epoch.
    #[error("system clock error: {0}")]
    Clock(String),
    /// The webhook timestamp fell outside the ±5 minute tolerance window.
    #[error("webhook timestamp outside ±5 min tolerance")]
    TimestampTolerance,
    /// The webhook secret could not be base64-decoded.
    #[error("failed to decode webhook secret")]
    SecretDecode,
    /// The request body was not valid UTF-8.
    #[error("non-UTF-8 webhook body")]
    NonUtf8Body,
    /// The decoded secret was not a valid HMAC key length.
    #[error("invalid HMAC key length")]
    HmacKey,
    /// None of the provided signatures matched the expected value.
    #[error("webhook signature mismatch")]
    SignatureMismatch,
}

/// Verify a Clerk/Svix webhook signature.
///
/// * `secret` — the raw `CLERK_WEBHOOK_SECRET` value (e.g. `whsec_...`).
/// * `payload` — the raw request body bytes.
/// * `svix_id`, `svix_timestamp`, `svix_signature` — the corresponding request
///   header values.
///
/// The tolerance window is ±5 minutes from the current system clock.
pub fn verify_webhook(
    secret: &str,
    payload: &[u8],
    svix_id: &str,
    svix_timestamp: &str,
    svix_signature: &str,
) -> Result<(), WebhookError> {
    // Validate timestamp tolerance (±5 minutes).
    let ts: i64 = svix_timestamp
        .parse()
        .map_err(|_| WebhookError::InvalidTimestamp)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| WebhookError::Clock(e.to_string()))?
        .as_secs() as i64;
    if (now - ts).abs() > TOLERANCE_SECS {
        return Err(WebhookError::TimestampTolerance);
    }

    // Decode secret: strip "whsec_" prefix and base64-decode.
    let raw_secret = secret.trim_start_matches("whsec_");
    let secret_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw_secret)
        .map_err(|_| WebhookError::SecretDecode)?;

    // Build signed content: "<svix-id>.<svix-timestamp>.<body>".
    let body_str = std::str::from_utf8(payload).map_err(|_| WebhookError::NonUtf8Body)?;
    let signed = format!("{svix_id}.{svix_timestamp}.{body_str}");

    // HMAC-SHA256.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&secret_bytes).map_err(|_| WebhookError::HmacKey)?;
    mac.update(signed.as_bytes());
    let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    // svix-signature may contain multiple space-separated "v1,<b64>" entries.
    for part in svix_signature.split(' ') {
        if let Some(sig) = part.strip_prefix("v1,") {
            if sig == expected {
                return Ok(());
            }
        }
    }
    Err(WebhookError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produce a valid signature for the given inputs, mirroring the Svix scheme.
    fn sign(secret_b64: &str, id: &str, ts: &str, body: &str) -> String {
        let secret_bytes = base64::engine::general_purpose::STANDARD
            .decode(secret_b64)
            .unwrap();
        let signed = format!("{id}.{ts}.{body}");
        let mut mac = Hmac::<Sha256>::new_from_slice(&secret_bytes).unwrap();
        mac.update(signed.as_bytes());
        let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        format!("v1,{sig}")
    }

    fn now_ts() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    #[test]
    fn accepts_valid_signature() {
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(b"super-secret-key");
        let secret = format!("whsec_{secret_b64}");
        let id = "msg_123";
        let ts = now_ts();
        let body = r#"{"type":"user.created"}"#;
        let sig = sign(&secret_b64, id, &ts, body);
        assert!(verify_webhook(&secret, body.as_bytes(), id, &ts, &sig).is_ok());
    }

    #[test]
    fn rejects_tampered_body() {
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(b"super-secret-key");
        let secret = format!("whsec_{secret_b64}");
        let id = "msg_123";
        let ts = now_ts();
        let sig = sign(&secret_b64, id, &ts, r#"{"type":"user.created"}"#);
        let tampered = r#"{"type":"user.deleted"}"#;
        assert!(matches!(
            verify_webhook(&secret, tampered.as_bytes(), id, &ts, &sig),
            Err(WebhookError::SignatureMismatch)
        ));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(b"super-secret-key");
        let secret = format!("whsec_{secret_b64}");
        let id = "msg_123";
        let ts = "1000000000"; // far in the past
        let body = "{}";
        let sig = sign(&secret_b64, id, ts, body);
        assert!(matches!(
            verify_webhook(&secret, body.as_bytes(), id, ts, &sig),
            Err(WebhookError::TimestampTolerance)
        ));
    }

    #[test]
    fn accepts_signature_among_multiple() {
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode(b"super-secret-key");
        let secret = format!("whsec_{secret_b64}");
        let id = "msg_123";
        let ts = now_ts();
        let body = "{}";
        let valid = sign(&secret_b64, id, &ts, body);
        let multi = format!("v1,wrongsig {valid}");
        assert!(verify_webhook(&secret, body.as_bytes(), id, &ts, &multi).is_ok());
    }
}
