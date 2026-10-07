//! Token creation, attenuation, and verification.

use std::collections::BTreeMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::clock::{Clock, VerifyTime};
use crate::constraint::Constraints;
use crate::encoding::encode_canonical_v6;
use crate::revocation::RevocationList;
use crate::use_store::{UseResult, UseStore};
use crate::verifier::Verifier;

type HmacSha256 = Hmac<Sha256>;

/// A capability token for a tool call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub tool_name: String,
    pub arg_keys: Vec<String>,
    pub expiry: u64,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mac: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// Token identifier for revocation and replay detection (16 random bytes, hex-encoded).
    /// When present, covered by the MAC. Attenuated tokens inherit their parent's jti.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Optional not-before unix timestamp. When present, covered by the MAC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// How many times this token has been attenuated. Covered by the MAC when non-zero.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub depth: u32,
    /// Optional maximum attenuation depth. When present, covered by the MAC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// Errors that can occur during token operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidMac,
    Expired,
    AttenuationWidens,
    AudienceMismatch,
    ToolMismatch {
        expected: String,
        got: String,
    },
    ArgKeyNotAllowed {
        key: String,
    },
    UnknownKeyId {
        kid: String,
    },
    NoActiveKey,
    MissingKeyId,
    ConstraintViolation {
        key: String,
    },
    /// Token has been revoked (jti found in revocation list).
    Revoked {
        jti: String,
    },
    /// Token replay detected (use count exceeded).
    ReplayDetected {
        jti: String,
    },
    /// Token has no jti but revocation/replay check was requested.
    MissingJti,
    /// Token is not yet valid (`current_time + leeway < nbf`).
    NotYetValid,
    /// Attenuation would exceed the token's maximum delegation depth.
    MaxDepthExceeded {
        depth: u32,
        max: u32,
    },
    /// Request is not a usable `tools/call` payload (wrong method, missing
    /// name, or a nested value on a constrained argument).
    MalformedRequest,
    /// The token or call is not permitted by the current policy.
    PolicyDenied {
        reason: String,
    },
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::InvalidMac => write!(f, "invalid MAC"),
            TokenError::Expired => write!(f, "token expired"),
            TokenError::AttenuationWidens => write!(f, "attenuation cannot widen capabilities"),
            TokenError::AudienceMismatch => write!(f, "audience mismatch"),
            TokenError::ToolMismatch { expected, got } => {
                write!(f, "tool mismatch: expected '{}', got '{}'", expected, got)
            }
            TokenError::ArgKeyNotAllowed { key } => {
                write!(f, "argument key '{}' not in token allowlist", key)
            }
            TokenError::UnknownKeyId { kid } => {
                write!(f, "unknown key id: '{}'", kid)
            }
            TokenError::NoActiveKey => write!(f, "no active key in keyring"),
            TokenError::MissingKeyId => write!(f, "token has no key id"),
            TokenError::ConstraintViolation { key } => {
                write!(f, "argument '{}' violates constraint", key)
            }
            TokenError::Revoked { jti } => {
                write!(f, "token has been revoked (jti: {})", jti)
            }
            TokenError::ReplayDetected { jti } => {
                write!(f, "token replay detected (jti: {})", jti)
            }
            TokenError::MissingJti => write!(f, "token has no jti for revocation/replay check"),
            TokenError::NotYetValid => write!(f, "token not yet valid"),
            TokenError::MaxDepthExceeded { depth, max } => {
                write!(f, "attenuation depth {} exceeds maximum {}", depth, max)
            }
            TokenError::MalformedRequest => write!(f, "malformed request"),
            TokenError::PolicyDenied { reason } => write!(f, "denied by policy: {reason}"),
        }
    }
}

impl std::error::Error for TokenError {}

impl TokenError {
    /// Stable machine-readable kind, matching CLI `error_kind` values.
    pub fn kind(&self) -> &'static str {
        match self {
            TokenError::InvalidMac => "invalid_mac",
            TokenError::Expired => "expired",
            TokenError::AttenuationWidens => "attenuation_widens",
            TokenError::AudienceMismatch => "audience_mismatch",
            TokenError::ToolMismatch { .. } => "tool_mismatch",
            TokenError::ArgKeyNotAllowed { .. } => "arg_key_not_allowed",
            TokenError::UnknownKeyId { .. } => "unknown_key_id",
            TokenError::NoActiveKey => "no_active_key",
            TokenError::MissingKeyId => "missing_key_id",
            TokenError::ConstraintViolation { .. } => "constraint_violation",
            TokenError::Revoked { .. } => "revoked",
            TokenError::ReplayDetected { .. } => "replay_detected",
            TokenError::MissingJti => "missing_jti",
            TokenError::NotYetValid => "not_yet_valid",
            TokenError::MaxDepthExceeded { .. } => "max_depth_exceeded",
            TokenError::MalformedRequest => "malformed_request",
            TokenError::PolicyDenied { .. } => "policy_denied",
        }
    }
}

impl Token {
    /// Mint a new token with the given parameters.
    ///
    /// Use `mint_with_audience` to create a token bound to a specific audience,
    /// or `mint_with_kid` to include a key identifier for keyring-based verification.
    pub fn mint(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
    ) -> Self {
        Self::mint_full(secret, tool_name, arg_keys, expiry, None, None, None)
    }

    /// Mint a new token with an optional audience binding.
    ///
    /// When `audience` is `Some(value)`, the token is bound to that audience
    /// and verification will fail if a different audience is expected.
    /// When `audience` is `None`, the token is unbound.
    pub fn mint_with_audience(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
    ) -> Self {
        Self::mint_full(secret, tool_name, arg_keys, expiry, audience, None, None)
    }

    /// Mint a new token with optional audience binding and key identifier.
    ///
    /// The `kid` (key identifier) is included in the MAC computation and allows
    /// verifiers to look up the correct signing key from a keyring.
    pub fn mint_with_kid(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
        kid: Option<String>,
    ) -> Self {
        Self::mint_full(secret, tool_name, arg_keys, expiry, audience, kid, None)
    }

    /// Mint a new token with optional audience, key identifier, and constraints.
    ///
    /// Constraints restrict the allowed values for specific argument keys.
    /// Keys with constraints must also be present in `arg_keys`.
    pub fn mint_full(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
        kid: Option<String>,
        constraints: Option<Constraints>,
    ) -> Self {
        Self::mint_with_jti(
            secret,
            tool_name,
            arg_keys,
            expiry,
            audience,
            kid,
            constraints,
            false,
        )
    }

    /// Mint a new token with all parameters including optional token identifier.
    ///
    /// When `generate_jti` is true, a unique 16-byte token identifier is generated
    /// and included in the MAC. This enables revocation and replay detection.
    /// When false, no jti is generated (backward compatible with v0.4.0).
    #[allow(clippy::too_many_arguments)]
    pub fn mint_with_jti(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
        kid: Option<String>,
        constraints: Option<Constraints>,
        generate_jti: bool,
    ) -> Self {
        Self::mint_complete(
            secret,
            tool_name,
            arg_keys,
            expiry,
            audience,
            kid,
            constraints,
            generate_jti,
            None,
            None,
        )
    }

    /// Mint a token with optional not-before (`nbf`) and max attenuation depth.
    ///
    /// `nbf` is a unix timestamp; verification fails before that time (subject
    /// to leeway). `max_depth` limits how many times the token may be attenuated.
    /// Freshly minted tokens start at `depth` 0.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_complete(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
        kid: Option<String>,
        constraints: Option<Constraints>,
        generate_jti: bool,
        nbf: Option<u64>,
        max_depth: Option<u32>,
    ) -> Self {
        let tool_name = tool_name.into();
        let nonce: [u8; 16] = rand::random();

        // Normalize empty constraints to None
        let constraints = constraints.filter(|c| !c.is_empty());

        // Generate jti if requested
        let jti = if generate_jti {
            let jti_bytes: [u8; 16] = rand::random();
            Some(hex::encode(jti_bytes))
        } else {
            None
        };

        let depth = 0u32;
        let canonical = encode_canonical_v6(
            &tool_name,
            &arg_keys,
            expiry,
            &nonce,
            audience.as_deref(),
            kid.as_deref(),
            constraints.as_ref(),
            jti.as_deref(),
            nbf,
            depth,
            max_depth,
        );
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let mac = hmac.finalize().into_bytes().to_vec();

        Token {
            tool_name,
            arg_keys,
            expiry,
            nonce: nonce.to_vec(),
            mac,
            audience,
            kid,
            constraints,
            jti,
            nbf,
            depth,
            max_depth,
        }
    }

    /// Verify the token's MAC and check expiry.
    /// Uses constant-time comparison for the MAC.
    ///
    /// This does not check audience. Use `verify_with_audience` if you need
    /// to verify that the token is bound to a specific audience.
    ///
    /// `current_time` is treated as a [`FixedClock`] with zero leeway.
    pub fn verify(&self, secret: &[u8], current_time: u64) -> Result<(), TokenError> {
        self.verify_with_audience(secret, current_time, None)
    }

    /// Verify the token's MAC, expiry, not-before, and optionally audience.
    ///
    /// If `expected_audience` is `Some(aud)`:
    /// - Token must have a matching audience, or
    /// - Token must be unbound (audience=None), which matches any expected audience
    ///
    /// If `expected_audience` is `None`, audience is not checked.
    pub fn verify_with_audience(
        &self,
        secret: &[u8],
        current_time: u64,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        self.verify_at(secret, &VerifyTime::unix(current_time), expected_audience)
    }

    /// Verify using an explicit unix timestamp and clock-skew leeway.
    pub fn verify_with_leeway(
        &self,
        secret: &[u8],
        current_time: u64,
        leeway: Duration,
    ) -> Result<(), TokenError> {
        self.verify_at(
            secret,
            &VerifyTime::unix_with_leeway(current_time, leeway),
            None,
        )
    }

    /// Verify using a swappable [`Clock`] and clock-skew leeway.
    pub fn verify_with_clock<C: Clock>(
        &self,
        secret: &[u8],
        clock: &C,
        leeway: Duration,
    ) -> Result<(), TokenError> {
        self.verify_with_clock_and_audience(secret, clock, leeway, None)
    }

    /// Verify using a swappable [`Clock`], leeway, and optional audience.
    pub fn verify_with_clock_and_audience<C: Clock>(
        &self,
        secret: &[u8],
        clock: &C,
        leeway: Duration,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        self.verify_at(
            secret,
            &VerifyTime::unix_with_leeway(clock.now_unix(), leeway),
            expected_audience,
        )
    }

    /// Verify using a bundled clock and leeway.
    pub fn verify_at<C: Clock>(
        &self,
        secret: &[u8],
        time: &VerifyTime<C>,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let mut verifier = Verifier::new(secret)
            .at(time.now_unix())
            .leeway(time.leeway);
        if let Some(audience) = expected_audience {
            verifier = verifier.audience(audience);
        }
        verifier.verify(self)
    }

    /// MAC, expiry, not-before, and optional audience. Used by [`Verifier`].
    pub(crate) fn verify_mac_audience(
        &self,
        secret: &[u8],
        now: u64,
        leeway: Duration,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        self.check_time_window(now, leeway)?;

        // Check audience if required
        if let Some(expected) = expected_audience {
            if let Some(ref token_aud) = self.audience {
                if token_aud != expected {
                    return Err(TokenError::AudienceMismatch);
                }
            }
            // Token with no audience (unbound) matches any expected audience
        }

        // Recompute MAC
        let canonical = encode_canonical_v6(
            &self.tool_name,
            &self.arg_keys,
            self.expiry,
            &self.nonce,
            self.audience.as_deref(),
            self.kid.as_deref(),
            self.constraints.as_ref(),
            self.jti.as_deref(),
            self.nbf,
            self.depth,
            self.max_depth,
        );
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let expected_mac = hmac.finalize().into_bytes();

        // Constant-time comparison
        if expected_mac.ct_eq(&self.mac).into() {
            Ok(())
        } else {
            Err(TokenError::InvalidMac)
        }
    }

    /// Check expiry and optional not-before against `now`, applying `leeway`.
    ///
    /// A token is expired if `now > expiry + leeway`.
    /// A token is not yet valid if `now + leeway < nbf`.
    fn check_time_window(&self, now: u64, leeway: Duration) -> Result<(), TokenError> {
        let leeway_secs = leeway.as_secs();
        if now > self.expiry.saturating_add(leeway_secs) {
            return Err(TokenError::Expired);
        }
        if let Some(nbf) = self.nbf {
            if now.saturating_add(leeway_secs) < nbf {
                return Err(TokenError::NotYetValid);
            }
        }
        Ok(())
    }

    /// Verify the token's MAC, expiry, and check against a revocation list.
    ///
    /// The token must have a jti to be checked against the revocation list.
    /// Returns `Err(TokenError::Revoked)` if the token's jti is in the revocation list.
    /// Returns `Err(TokenError::MissingJti)` if the token has no jti.
    pub fn verify_with_revocation(
        &self,
        secret: &[u8],
        current_time: u64,
        revocation_list: &RevocationList,
    ) -> Result<(), TokenError> {
        self.verify_with_revocation_and_audience(secret, current_time, revocation_list, None)
    }

    /// Verify the token's MAC, expiry, audience, and check against a revocation list.
    ///
    /// The token must have a jti to be checked against the revocation list.
    /// Returns `Err(TokenError::Revoked)` if the token's jti is in the revocation list.
    /// Returns `Err(TokenError::MissingJti)` if the token has no jti.
    pub fn verify_with_revocation_and_audience(
        &self,
        secret: &[u8],
        current_time: u64,
        revocation_list: &RevocationList,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let mut verifier = Verifier::new(secret)
            .at(current_time)
            .revocation(revocation_list);
        if let Some(audience) = expected_audience {
            verifier = verifier.audience(audience);
        }
        verifier.verify(self)
    }

    /// Verify the token and consume one use from the use store.
    ///
    /// This provides single-use token verification. The token must have a jti.
    /// Returns `Err(TokenError::ReplayDetected)` if the token has already been used.
    /// Returns `Err(TokenError::MissingJti)` if the token has no jti.
    pub fn verify_single_use<S: UseStore>(
        &self,
        secret: &[u8],
        current_time: u64,
        use_store: &mut S,
    ) -> Result<(), TokenError> {
        self.verify_with_max_uses(secret, current_time, use_store, 1, None)
    }

    /// Verify the token and consume one use from the use store, up to max_uses.
    ///
    /// The token must have a jti. Returns `Err(TokenError::ReplayDetected)` if
    /// the token has exceeded its maximum use count.
    /// Returns `Err(TokenError::MissingJti)` if the token has no jti.
    pub fn verify_with_max_uses<S: UseStore>(
        &self,
        secret: &[u8],
        current_time: u64,
        use_store: &mut S,
        max_uses: u64,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        // First verify basic token properties
        self.verify_with_audience(secret, current_time, expected_audience)?;

        // Check and consume use
        match &self.jti {
            Some(jti) => {
                if use_store.try_use(jti, max_uses) == UseResult::Exceeded {
                    return Err(TokenError::ReplayDetected { jti: jti.clone() });
                }
            }
            None => {
                return Err(TokenError::MissingJti);
            }
        }

        Ok(())
    }

    /// Verify the token with both revocation list and use store checking.
    ///
    /// This provides comprehensive replay prevention: both explicit revocation
    /// and use-count limiting. The token must have a jti.
    pub fn verify_with_revocation_and_use_store<S: UseStore>(
        &self,
        secret: &[u8],
        current_time: u64,
        revocation_list: &RevocationList,
        use_store: &mut S,
        max_uses: u64,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        // First verify basic token properties
        self.verify_with_audience(secret, current_time, expected_audience)?;

        match &self.jti {
            Some(jti) => {
                // Check revocation first
                if revocation_list.is_revoked(jti) {
                    return Err(TokenError::Revoked { jti: jti.clone() });
                }

                // Then check and consume use
                if use_store.try_use(jti, max_uses) == UseResult::Exceeded {
                    return Err(TokenError::ReplayDetected { jti: jti.clone() });
                }
            }
            None => {
                return Err(TokenError::MissingJti);
            }
        }

        Ok(())
    }

    /// Verify that this token authorizes a specific tool call.
    ///
    /// This performs full verification:
    /// 1. MAC validity
    /// 2. Expiry check
    /// 3. Audience match (if `expected_audience` is provided)
    /// 4. Tool name must match exactly
    /// 5. All requested argument keys must be in the token's allowlist
    ///
    /// This does NOT check argument values against constraints.
    /// Use `verify_call_with_args` to also validate argument values.
    ///
    /// Returns `Ok(())` if the call is authorized, or a specific error.
    pub fn verify_call(
        &self,
        secret: &[u8],
        current_time: u64,
        tool_name: &str,
        requested_arg_keys: &[&str],
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        self.verify_call_at(
            secret,
            &VerifyTime::unix(current_time),
            tool_name,
            requested_arg_keys,
            expected_audience,
        )
    }

    /// Verify a tool call using a bundled clock and leeway.
    pub fn verify_call_at<C: Clock>(
        &self,
        secret: &[u8],
        time: &VerifyTime<C>,
        tool_name: &str,
        requested_arg_keys: &[&str],
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let mut verifier = Verifier::new(secret)
            .at(time.now_unix())
            .leeway(time.leeway);
        if let Some(audience) = expected_audience {
            verifier = verifier.audience(audience);
        }
        verifier.verify_call(self, tool_name, requested_arg_keys)
    }

    pub(crate) fn check_call_keys(
        &self,
        tool_name: &str,
        requested_arg_keys: &[&str],
    ) -> Result<(), TokenError> {
        if self.tool_name != tool_name {
            return Err(TokenError::ToolMismatch {
                expected: tool_name.to_string(),
                got: self.tool_name.clone(),
            });
        }

        for key in requested_arg_keys {
            if !self.arg_keys.iter().any(|k| k == *key) {
                return Err(TokenError::ArgKeyNotAllowed {
                    key: (*key).to_string(),
                });
            }
        }

        Ok(())
    }

    /// Verify that this token authorizes a specific tool call with argument values.
    ///
    /// This performs full verification including constraint checking:
    /// 1. MAC validity
    /// 2. Expiry check
    /// 3. Audience match (if `expected_audience` is provided)
    /// 4. Tool name must match exactly
    /// 5. All requested argument keys must be in the token's allowlist
    /// 6. All argument values must satisfy their constraints (if any)
    ///
    /// Returns `Ok(())` if the call is authorized, or a specific error.
    pub fn verify_call_with_args(
        &self,
        secret: &[u8],
        current_time: u64,
        tool_name: &str,
        args: &BTreeMap<String, String>,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        self.verify_call_with_args_at(
            secret,
            &VerifyTime::unix(current_time),
            tool_name,
            args,
            expected_audience,
        )
    }

    /// Verify a tool call with argument values using a bundled clock and leeway.
    pub fn verify_call_with_args_at<C: Clock>(
        &self,
        secret: &[u8],
        time: &VerifyTime<C>,
        tool_name: &str,
        args: &BTreeMap<String, String>,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let mut verifier = Verifier::new(secret)
            .at(time.now_unix())
            .leeway(time.leeway);
        if let Some(audience) = expected_audience {
            verifier = verifier.audience(audience);
        }
        verifier.verify_call_with_args(self, tool_name, args)
    }

    pub(crate) fn check_arg_constraints(
        &self,
        args: &BTreeMap<String, String>,
    ) -> Result<(), TokenError> {
        if let Some(ref constraints) = self.constraints {
            for (key, value) in args.iter() {
                if let Some(constraint) = constraints.get(key) {
                    if !constraint.check(value) {
                        return Err(TokenError::ConstraintViolation { key: key.clone() });
                    }
                }
            }
        }
        Ok(())
    }

    /// Attenuate the token by removing argument keys or shortening expiry.
    /// Cannot add keys or extend expiry. Audience, kid, jti, nbf, and max_depth are preserved.
    /// Each attenuation increments `depth`; if `max_depth` is set and would be
    /// exceeded, returns [`TokenError::MaxDepthExceeded`].
    ///
    /// To attenuate with constraints, use `attenuate_with_constraints`.
    pub fn attenuate(
        &self,
        secret: &[u8],
        new_arg_keys: Option<Vec<String>>,
        new_expiry: Option<u64>,
    ) -> Result<Token, TokenError> {
        self.attenuate_with_constraints(secret, new_arg_keys, new_expiry, None)
    }

    /// Attenuate the token by removing argument keys, shortening expiry, or adding/tightening constraints.
    /// Cannot add keys, extend expiry, or loosen constraints. Audience, kid, jti, nbf, and max_depth are preserved.
    /// Each attenuation increments `depth` and is rejected when `max_depth` would be exceeded.
    pub fn attenuate_with_constraints(
        &self,
        secret: &[u8],
        new_arg_keys: Option<Vec<String>>,
        new_expiry: Option<u64>,
        new_constraints: Option<Constraints>,
    ) -> Result<Token, TokenError> {
        // Validate attenuation doesn't widen
        let final_arg_keys = match new_arg_keys {
            Some(ref keys) => {
                // Check all new keys exist in original
                for key in keys {
                    if !self.arg_keys.contains(key) {
                        return Err(TokenError::AttenuationWidens);
                    }
                }
                keys.clone()
            }
            None => self.arg_keys.clone(),
        };

        let final_expiry = match new_expiry {
            Some(exp) => {
                if exp > self.expiry {
                    return Err(TokenError::AttenuationWidens);
                }
                exp
            }
            None => self.expiry,
        };

        // Merge constraints: new constraints must be subset of old constraints
        let final_constraints =
            Self::merge_constraints(self.constraints.as_ref(), new_constraints.as_ref())?;

        let new_depth = self.depth.saturating_add(1);
        if let Some(max) = self.max_depth {
            if new_depth > max {
                return Err(TokenError::MaxDepthExceeded {
                    depth: new_depth,
                    max,
                });
            }
        }

        // Generate new nonce and MAC for the attenuated token
        // Audience, kid, jti, nbf, and max_depth are preserved unchanged.
        let nonce: [u8; 16] = rand::random();
        let canonical = encode_canonical_v6(
            &self.tool_name,
            &final_arg_keys,
            final_expiry,
            &nonce,
            self.audience.as_deref(),
            self.kid.as_deref(),
            final_constraints.as_ref(),
            self.jti.as_deref(),
            self.nbf,
            new_depth,
            self.max_depth,
        );
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let mac = hmac.finalize().into_bytes().to_vec();

        Ok(Token {
            tool_name: self.tool_name.clone(),
            arg_keys: final_arg_keys,
            expiry: final_expiry,
            nonce: nonce.to_vec(),
            mac,
            audience: self.audience.clone(),
            kid: self.kid.clone(),
            constraints: final_constraints,
            jti: self.jti.clone(),
            nbf: self.nbf,
            depth: new_depth,
            max_depth: self.max_depth,
        })
    }

    /// Merge constraints, ensuring attenuation only tightens.
    fn merge_constraints(
        old: Option<&Constraints>,
        new: Option<&Constraints>,
    ) -> Result<Option<Constraints>, TokenError> {
        use crate::constraint::Constraint;

        match (old, new) {
            // No old constraints, any new constraints are allowed (including None)
            (None, None) => Ok(None),
            (None, Some(new)) => Ok(Some(new.clone())),

            // Old constraints preserved if no new ones specified
            (Some(old), None) => Ok(Some(old.clone())),

            // Must merge and validate
            (Some(old), Some(new)) => {
                let mut merged: BTreeMap<String, Constraint> = old.clone();

                for (key, new_constraint) in new.iter() {
                    match old.get(key) {
                        // Key had no constraint, adding one is allowed
                        None => {
                            merged.insert(key.clone(), new_constraint.clone());
                        }
                        // Key had constraint, new one must be subset (tighter)
                        Some(old_constraint) => {
                            if !new_constraint.is_subset_of(old_constraint) {
                                return Err(TokenError::AttenuationWidens);
                            }
                            merged.insert(key.clone(), new_constraint.clone());
                        }
                    }
                }

                if merged.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(merged))
                }
            }
        }
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";

    #[test]
    fn mint_and_verify_happy_path() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "offset".into()],
            2000000000,
        );

        assert_eq!(token.tool_name, "read_file");
        assert_eq!(token.arg_keys, vec!["path", "offset"]);
        assert_eq!(token.expiry, 2000000000);
        assert_eq!(token.nonce.len(), 16);
        assert_eq!(token.mac.len(), 32);
        assert_eq!(token.audience, None);
        assert_eq!(token.kid, None);

        // Verify with time before expiry
        assert!(token.verify(SECRET, 1999999999).is_ok());
        assert!(token.verify(SECRET, 2000000000).is_ok());
    }

    #[test]
    fn expired_token_fails() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1700000000);

        // Time after expiry
        let result = token.verify(SECRET, 1700000001);
        assert_eq!(result, Err(TokenError::Expired));
    }

    #[test]
    fn tampered_mac_fails() {
        let mut token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        // Tamper with MAC
        token.mac[0] ^= 0xFF;

        let result = token.verify(SECRET, 1999999999);
        assert_eq!(result, Err(TokenError::InvalidMac));
    }

    #[test]
    fn wrong_secret_fails() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.verify(b"wrong-secret", 1999999999);
        assert_eq!(result, Err(TokenError::InvalidMac));
    }

    #[test]
    fn attenuate_can_drop_keys() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "offset".into(), "limit".into()],
            2000000000,
        );

        let attenuated = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.tool_name, "read_file");
        assert_eq!(attenuated.arg_keys, vec!["path"]);
        assert_eq!(attenuated.expiry, 2000000000);
        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuate_can_shorten_expiry() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let attenuated = token.attenuate(SECRET, None, Some(1900000000)).unwrap();

        assert_eq!(attenuated.expiry, 1900000000);
        assert!(attenuated.verify(SECRET, 1899999999).is_ok());
    }

    #[test]
    fn attenuation_cannot_add_keys() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.attenuate(SECRET, Some(vec!["path".into(), "offset".into()]), None);
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn attenuation_cannot_extend_expiry() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.attenuate(SECRET, None, Some(2100000000));
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn token_json_roundtrip() {
        let token = Token::mint(
            SECRET,
            "write_file",
            vec!["path".into(), "data".into()],
            2000000000,
        );

        let json = serde_json::to_string(&token).unwrap();
        let parsed: Token = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.tool_name, token.tool_name);
        assert_eq!(parsed.arg_keys, token.arg_keys);
        assert_eq!(parsed.expiry, token.expiry);
        assert_eq!(parsed.nonce, token.nonce);
        assert_eq!(parsed.mac, token.mac);
        assert!(parsed.verify(SECRET, 1999999999).is_ok());
    }

    // ===== Audience tests =====

    #[test]
    fn mint_with_audience() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        assert_eq!(token.audience, Some("client-abc".to_string()));
        assert!(token.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn audience_match_succeeds() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        assert!(token
            .verify_with_audience(SECRET, 1999999999, Some("client-abc"))
            .is_ok());
    }

    #[test]
    fn audience_mismatch_fails() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        let result = token.verify_with_audience(SECRET, 1999999999, Some("client-xyz"));
        assert_eq!(result, Err(TokenError::AudienceMismatch));
    }

    #[test]
    fn unbound_token_matches_any_audience() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        assert!(token
            .verify_with_audience(SECRET, 1999999999, Some("any-client"))
            .is_ok());
        assert!(token
            .verify_with_audience(SECRET, 1999999999, Some("other-client"))
            .is_ok());
    }

    #[test]
    fn audience_preserved_after_attenuation() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        let attenuated = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.audience, Some("client-abc".to_string()));
        assert!(attenuated
            .verify_with_audience(SECRET, 1999999999, Some("client-abc"))
            .is_ok());
    }

    #[test]
    fn audience_json_roundtrip() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-123".to_string()),
        );

        let json = serde_json::to_string(&token).unwrap();
        let parsed: Token = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.audience, Some("client-123".to_string()));
        assert!(parsed
            .verify_with_audience(SECRET, 1999999999, Some("client-123"))
            .is_ok());
    }

    #[test]
    fn no_audience_omitted_from_json() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("audience"));
    }

    // ===== verify_call tests =====

    #[test]
    fn verify_call_happy_path() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
        );

        assert!(token
            .verify_call(SECRET, 1999999999, "read_file", &["path", "limit"], None)
            .is_ok());
    }

    #[test]
    fn verify_call_subset_of_keys() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into(), "offset".into()],
            2000000000,
        );

        assert!(token
            .verify_call(SECRET, 1999999999, "read_file", &["path"], None)
            .is_ok());
    }

    #[test]
    fn verify_call_tool_mismatch() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.verify_call(SECRET, 1999999999, "write_file", &["path"], None);
        assert!(matches!(result, Err(TokenError::ToolMismatch { .. })));

        if let Err(TokenError::ToolMismatch { expected, got }) = result {
            assert_eq!(expected, "write_file");
            assert_eq!(got, "read_file");
        }
    }

    #[test]
    fn verify_call_arg_key_not_allowed() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.verify_call(SECRET, 1999999999, "read_file", &["path", "limit"], None);
        assert!(matches!(result, Err(TokenError::ArgKeyNotAllowed { .. })));

        if let Err(TokenError::ArgKeyNotAllowed { key }) = result {
            assert_eq!(key, "limit");
        }
    }

    #[test]
    fn verify_call_with_audience() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        assert!(token
            .verify_call(
                SECRET,
                1999999999,
                "read_file",
                &["path"],
                Some("client-abc")
            )
            .is_ok());

        let result = token.verify_call(
            SECRET,
            1999999999,
            "read_file",
            &["path"],
            Some("client-xyz"),
        );
        assert_eq!(result, Err(TokenError::AudienceMismatch));
    }

    #[test]
    fn verify_call_expired() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1700000000);

        let result = token.verify_call(SECRET, 1700000001, "read_file", &["path"], None);
        assert_eq!(result, Err(TokenError::Expired));
    }

    #[test]
    fn verify_call_invalid_mac() {
        let mut token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        token.mac[0] ^= 0xFF;

        let result = token.verify_call(SECRET, 1999999999, "read_file", &["path"], None);
        assert_eq!(result, Err(TokenError::InvalidMac));
    }

    #[test]
    fn verify_call_empty_keys() {
        let token = Token::mint(SECRET, "ping", vec![], 2000000000);

        assert!(token
            .verify_call(SECRET, 1999999999, "ping", &[], None)
            .is_ok());

        let result = token.verify_call(SECRET, 1999999999, "ping", &["extra"], None);
        assert!(matches!(result, Err(TokenError::ArgKeyNotAllowed { .. })));
    }

    // ===== Key ID tests =====

    #[test]
    fn mint_with_kid() {
        let token = Token::mint_with_kid(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            Some("key-2024".to_string()),
        );

        assert_eq!(token.kid, Some("key-2024".to_string()));
        assert!(token.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn kid_included_in_mac() {
        let token1 = Token::mint_with_kid(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            Some("key-1".to_string()),
        );

        // Verify that changing kid breaks verification (kid is covered by MAC)
        let mut tampered = token1.clone();
        tampered.kid = Some("key-2".to_string());
        assert_eq!(
            tampered.verify(SECRET, 1999999999),
            Err(TokenError::InvalidMac)
        );
    }

    #[test]
    fn kid_preserved_after_attenuation() {
        let token = Token::mint_with_kid(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            Some("client-abc".to_string()),
            Some("key-2024".to_string()),
        );

        let attenuated = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.kid, Some("key-2024".to_string()));
        assert_eq!(attenuated.audience, Some("client-abc".to_string()));
        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn kid_json_roundtrip() {
        let token = Token::mint_with_kid(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            Some("key-2024".to_string()),
        );

        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("key-2024"));

        let parsed: Token = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kid, Some("key-2024".to_string()));
        assert!(parsed.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn no_kid_omitted_from_json() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("kid"));
    }

    // ===== Constraints tests =====

    #[test]
    fn mint_with_constraints() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        assert_eq!(token.constraints, Some(constraints));
        assert!(token.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn constraints_included_in_mac() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Tamper with constraints
        let mut tampered = token.clone();
        let mut new_constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        new_constraints.insert("path".to_string(), Constraint::Prefix("/var/".to_string()));
        tampered.constraints = Some(new_constraints);

        assert_eq!(
            tampered.verify(SECRET, 1999999999),
            Err(TokenError::InvalidMac)
        );
    }

    #[test]
    fn attenuation_can_add_constraint_to_unconstrained_key() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        assert!(token.constraints.is_none());

        let mut new_constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        new_constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let attenuated = token
            .attenuate_with_constraints(SECRET, None, None, Some(new_constraints.clone()))
            .unwrap();

        assert_eq!(attenuated.constraints, Some(new_constraints));
        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuation_can_tighten_prefix() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Tighten prefix from /tmp/ to /tmp/subdir/
        let mut tighter: BTreeMap<String, Constraint> = BTreeMap::new();
        tighter.insert(
            "path".to_string(),
            Constraint::Prefix("/tmp/subdir/".to_string()),
        );

        let attenuated = token
            .attenuate_with_constraints(SECRET, None, None, Some(tighter.clone()))
            .unwrap();

        // Should have the tighter constraint
        assert_eq!(
            attenuated.constraints.as_ref().unwrap().get("path"),
            tighter.get("path")
        );
        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuation_cannot_loosen_prefix() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Prefix("/tmp/subdir/".to_string()),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Try to loosen prefix from /tmp/subdir/ to /tmp/
        let mut looser: BTreeMap<String, Constraint> = BTreeMap::new();
        looser.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let result = token.attenuate_with_constraints(SECRET, None, None, Some(looser));
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn attenuation_can_narrow_oneof() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec![
                "read".to_string(),
                "write".to_string(),
                "list".to_string(),
            ]),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Narrow to only read|list
        let mut narrower: BTreeMap<String, Constraint> = BTreeMap::new();
        narrower.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["read".to_string(), "list".to_string()]),
        );

        let attenuated = token
            .attenuate_with_constraints(SECRET, None, None, Some(narrower))
            .unwrap();

        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuation_cannot_widen_oneof() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["read".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Try to widen to read|write
        let mut wider: BTreeMap<String, Constraint> = BTreeMap::new();
        wider.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["read".to_string(), "write".to_string()]),
        );

        let result = token.attenuate_with_constraints(SECRET, None, None, Some(wider));
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn attenuation_can_reduce_maxlen() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("query".to_string(), Constraint::MaxLen(256));

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Reduce max length
        let mut smaller: BTreeMap<String, Constraint> = BTreeMap::new();
        smaller.insert("query".to_string(), Constraint::MaxLen(100));

        let attenuated = token
            .attenuate_with_constraints(SECRET, None, None, Some(smaller))
            .unwrap();

        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuation_cannot_increase_maxlen() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("query".to_string(), Constraint::MaxLen(100));

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Try to increase max length
        let mut larger: BTreeMap<String, Constraint> = BTreeMap::new();
        larger.insert("query".to_string(), Constraint::MaxLen(256));

        let result = token.attenuate_with_constraints(SECRET, None, None, Some(larger));
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn attenuation_can_narrow_intrange() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let token = Token::mint_full(
            SECRET,
            "fetch",
            vec!["limit".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Narrow to 1..50
        let mut narrower: BTreeMap<String, Constraint> = BTreeMap::new();
        narrower.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 50 },
        );

        let attenuated = token
            .attenuate_with_constraints(SECRET, None, None, Some(narrower))
            .unwrap();

        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuation_cannot_widen_intrange() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 10, max: 50 },
        );

        let token = Token::mint_full(
            SECRET,
            "fetch",
            vec!["limit".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Try to widen to 1..100
        let mut wider: BTreeMap<String, Constraint> = BTreeMap::new();
        wider.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let result = token.attenuate_with_constraints(SECRET, None, None, Some(wider));
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn attenuation_can_replace_with_exact() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["read".to_string(), "write".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Replace with exact value that satisfies the OneOf
        let mut exact: BTreeMap<String, Constraint> = BTreeMap::new();
        exact.insert("mode".to_string(), Constraint::Exact("read".to_string()));

        let attenuated = token
            .attenuate_with_constraints(SECRET, None, None, Some(exact))
            .unwrap();

        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuation_preserves_existing_constraints() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert("mode".to_string(), Constraint::Exact("read".to_string()));

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["path".into(), "mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Only tighten path, mode should be preserved
        let mut update: BTreeMap<String, Constraint> = BTreeMap::new();
        update.insert(
            "path".to_string(),
            Constraint::Prefix("/tmp/subdir/".to_string()),
        );

        let attenuated = token
            .attenuate_with_constraints(SECRET, None, None, Some(update))
            .unwrap();

        let final_constraints = attenuated.constraints.as_ref().unwrap();
        assert_eq!(
            final_constraints.get("path"),
            Some(&Constraint::Prefix("/tmp/subdir/".to_string()))
        );
        assert_eq!(
            final_constraints.get("mode"),
            Some(&Constraint::Exact("read".to_string()))
        );
        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn constraints_json_roundtrip() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let json = serde_json::to_string(&token).unwrap();
        let parsed: Token = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.constraints, Some(constraints));
        assert!(parsed.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn no_constraints_omitted_from_json() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("constraints"));
    }

    // ===== verify_call_with_args tests =====

    #[test]
    fn verify_call_with_args_no_constraints() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("path".to_string(), "/any/path".to_string());
        args.insert("limit".to_string(), "999999".to_string());

        // No constraints, any values should work
        assert!(token
            .verify_call_with_args(SECRET, 1999999999, "read_file", &args, None)
            .is_ok());
    }

    #[test]
    fn verify_call_with_args_prefix_satisfied() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("path".to_string(), "/tmp/myfile.txt".to_string());

        assert!(token
            .verify_call_with_args(SECRET, 1999999999, "read_file", &args, None)
            .is_ok());
    }

    #[test]
    fn verify_call_with_args_prefix_violated() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("path".to_string(), "/etc/passwd".to_string());

        let result = token.verify_call_with_args(SECRET, 1999999999, "read_file", &args, None);
        assert!(matches!(
            result,
            Err(TokenError::ConstraintViolation { key }) if key == "path"
        ));
    }

    #[test]
    fn verify_call_with_args_oneof_satisfied() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["read".to_string(), "list".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("mode".to_string(), "read".to_string());

        assert!(token
            .verify_call_with_args(SECRET, 1999999999, "file_op", &args, None)
            .is_ok());
    }

    #[test]
    fn verify_call_with_args_oneof_violated() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["read".to_string(), "list".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("mode".to_string(), "write".to_string());

        let result = token.verify_call_with_args(SECRET, 1999999999, "file_op", &args, None);
        assert!(matches!(
            result,
            Err(TokenError::ConstraintViolation { key }) if key == "mode"
        ));
    }

    #[test]
    fn verify_call_with_args_intrange_satisfied() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let token = Token::mint_full(
            SECRET,
            "fetch",
            vec!["limit".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("limit".to_string(), "50".to_string());

        assert!(token
            .verify_call_with_args(SECRET, 1999999999, "fetch", &args, None)
            .is_ok());
    }

    #[test]
    fn verify_call_with_args_intrange_violated() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let token = Token::mint_full(
            SECRET,
            "fetch",
            vec!["limit".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("limit".to_string(), "200".to_string());

        let result = token.verify_call_with_args(SECRET, 1999999999, "fetch", &args, None);
        assert!(matches!(
            result,
            Err(TokenError::ConstraintViolation { key }) if key == "limit"
        ));
    }

    #[test]
    fn verify_call_with_args_maxlen_satisfied() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert("query".to_string(), Constraint::MaxLen(10));

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("query".to_string(), "hello".to_string());

        assert!(token
            .verify_call_with_args(SECRET, 1999999999, "search", &args, None)
            .is_ok());
    }

    #[test]
    fn verify_call_with_args_maxlen_violated() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert("query".to_string(), Constraint::MaxLen(5));

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("query".to_string(), "toolong".to_string());

        let result = token.verify_call_with_args(SECRET, 1999999999, "search", &args, None);
        assert!(matches!(
            result,
            Err(TokenError::ConstraintViolation { key }) if key == "query"
        ));
    }

    #[test]
    fn verify_call_with_args_unconstrained_key_allowed() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into(), "format".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut args = std::collections::BTreeMap::new();
        args.insert("path".to_string(), "/tmp/test.txt".to_string());
        args.insert("format".to_string(), "anything".to_string()); // No constraint on format

        assert!(token
            .verify_call_with_args(SECRET, 1999999999, "read_file", &args, None)
            .is_ok());
    }

    #[test]
    fn verify_call_with_args_multiple_constraints() {
        use crate::constraint::Constraint;

        let mut constraints = std::collections::BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        // Both constraints satisfied
        let mut args = std::collections::BTreeMap::new();
        args.insert("path".to_string(), "/tmp/test.txt".to_string());
        args.insert("limit".to_string(), "50".to_string());

        assert!(token
            .verify_call_with_args(SECRET, 1999999999, "read_file", &args, None)
            .is_ok());

        // First constraint violated
        let mut args2 = std::collections::BTreeMap::new();
        args2.insert("path".to_string(), "/etc/test.txt".to_string());
        args2.insert("limit".to_string(), "50".to_string());

        let result = token.verify_call_with_args(SECRET, 1999999999, "read_file", &args2, None);
        assert!(matches!(
            result,
            Err(TokenError::ConstraintViolation { key }) if key == "path"
        ));
    }

    // ===== JTI tests =====

    #[test]
    fn mint_with_jti() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        assert!(token.jti.is_some());
        let jti = token.jti.as_ref().unwrap();
        assert_eq!(jti.len(), 32); // 16 bytes hex-encoded
        assert!(token.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn mint_without_jti() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
        );

        assert!(token.jti.is_none());
        assert!(token.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn jti_included_in_mac() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        // Tamper with jti
        let mut tampered = token.clone();
        tampered.jti = Some("different_jti_value_here".to_string());
        assert_eq!(
            tampered.verify(SECRET, 1999999999),
            Err(TokenError::InvalidMac)
        );
    }

    #[test]
    fn jti_preserved_after_attenuation() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let attenuated = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.jti, token.jti);
        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn jti_json_roundtrip() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("jti"));

        let parsed: Token = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jti, token.jti);
        assert!(parsed.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn no_jti_omitted_from_json() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("jti"));
    }

    // ===== nbf / depth field tests =====

    #[test]
    fn mint_complete_sets_nbf_and_max_depth() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            Some(3),
        );

        assert_eq!(token.nbf, Some(1_900_000_000));
        assert_eq!(token.max_depth, Some(3));
        assert_eq!(token.depth, 0);
        assert!(token.verify(SECRET, 1_950_000_000).is_ok());
    }

    #[test]
    fn nbf_included_in_mac() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            None,
        );

        let mut tampered = token.clone();
        tampered.nbf = Some(1_800_000_000);
        assert_eq!(
            tampered.verify(SECRET, 1_950_000_000),
            Err(TokenError::InvalidMac)
        );
    }

    #[test]
    fn max_depth_included_in_mac() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            None,
            Some(2),
        );

        let mut tampered = token.clone();
        tampered.max_depth = Some(9);
        assert_eq!(
            tampered.verify(SECRET, 1999999999),
            Err(TokenError::InvalidMac)
        );
    }

    #[test]
    fn nbf_and_depth_omitted_from_json_when_unset() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("nbf"));
        assert!(!json.contains("depth"));
        assert!(!json.contains("max_depth"));
    }

    #[test]
    fn nbf_json_roundtrip() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            Some(1),
        );

        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("nbf"));
        assert!(json.contains("max_depth"));

        let parsed: Token = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nbf, Some(1_900_000_000));
        assert_eq!(parsed.max_depth, Some(1));
        assert_eq!(parsed.depth, 0);
        assert!(parsed.verify(SECRET, 1_950_000_000).is_ok());
    }

    #[test]
    fn nbf_accepts_when_current_time_reached() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            None,
        );

        assert!(token.verify(SECRET, 1_900_000_000).is_ok());
        assert!(token.verify(SECRET, 1_950_000_000).is_ok());
    }

    #[test]
    fn nbf_rejects_before_not_before() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            None,
        );

        assert_eq!(
            token.verify(SECRET, 1_899_999_999),
            Err(TokenError::NotYetValid)
        );
    }

    #[test]
    fn verify_with_fixed_clock() {
        use crate::clock::FixedClock;

        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1000);
        let clock = FixedClock::at(999);
        assert!(token
            .verify_with_clock(SECRET, &clock, Duration::ZERO)
            .is_ok());

        let clock = FixedClock::at(1001);
        assert_eq!(
            token.verify_with_clock(SECRET, &clock, Duration::ZERO),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn leeway_accepts_recently_expired_token() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1000);

        assert_eq!(token.verify(SECRET, 1010), Err(TokenError::Expired));
        assert!(token
            .verify_with_leeway(SECRET, 1010, Duration::from_secs(30))
            .is_ok());
        assert_eq!(
            token.verify_with_leeway(SECRET, 1031, Duration::from_secs(30)),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn leeway_accepts_token_slightly_before_nbf() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000,
            None,
            None,
            None,
            false,
            Some(1000),
            None,
        );

        assert_eq!(token.verify(SECRET, 990), Err(TokenError::NotYetValid));
        assert!(token
            .verify_with_leeway(SECRET, 990, Duration::from_secs(30))
            .is_ok());
        assert_eq!(
            token.verify_with_leeway(SECRET, 969, Duration::from_secs(30)),
            Err(TokenError::NotYetValid)
        );
    }

    #[test]
    fn verify_at_uses_bundled_clock_and_leeway() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1000);
        let time = VerifyTime::unix_with_leeway(1010, Duration::from_secs(15));
        assert!(token.verify_at(SECRET, &time, None).is_ok());
    }

    #[test]
    fn attenuate_increments_depth() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        assert_eq!(token.depth, 0);

        let once = token.attenuate(SECRET, None, Some(1900000000)).unwrap();
        assert_eq!(once.depth, 1);
        assert!(once.verify(SECRET, 1899999999).is_ok());

        let twice = once.attenuate(SECRET, None, Some(1800000000)).unwrap();
        assert_eq!(twice.depth, 2);
        assert!(twice.verify(SECRET, 1799999999).is_ok());
    }

    #[test]
    fn attenuate_rejects_when_max_depth_exceeded() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            None,
            false,
            None,
            Some(2),
        );

        let once = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();
        assert_eq!(once.depth, 1);

        let twice = once.attenuate(SECRET, None, Some(1900000000)).unwrap();
        assert_eq!(twice.depth, 2);

        let result = twice.attenuate(SECRET, None, Some(1800000000));
        assert_eq!(
            result,
            Err(TokenError::MaxDepthExceeded { depth: 3, max: 2 })
        );
    }

    #[test]
    fn max_depth_zero_cannot_attenuate() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            None,
            Some(0),
        );

        let result = token.attenuate(SECRET, None, Some(1900000000));
        assert_eq!(
            result,
            Err(TokenError::MaxDepthExceeded { depth: 1, max: 0 })
        );
    }

    #[test]
    fn attenuate_preserves_nbf_and_max_depth() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            Some(5),
        );

        let attenuated = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.nbf, Some(1_900_000_000));
        assert_eq!(attenuated.max_depth, Some(5));
        assert_eq!(attenuated.depth, 1);
        assert!(attenuated.verify(SECRET, 1_950_000_000).is_ok());
    }

    #[test]
    fn depth_included_in_mac() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        let attenuated = token.attenuate(SECRET, None, Some(1900000000)).unwrap();
        assert_eq!(attenuated.depth, 1);

        let mut tampered = attenuated.clone();
        tampered.depth = 2;
        assert_eq!(
            tampered.verify(SECRET, 1899999999),
            Err(TokenError::InvalidMac)
        );
    }

    // ===== Revocation tests =====

    #[test]
    fn verify_with_revocation_valid() {
        use crate::revocation::RevocationList;

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let revocation_list = RevocationList::new();
        assert!(token
            .verify_with_revocation(SECRET, 1999999999, &revocation_list)
            .is_ok());
    }

    #[test]
    fn verify_with_revocation_revoked() {
        use crate::revocation::RevocationList;

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let mut revocation_list = RevocationList::new();
        revocation_list.revoke(token.jti.clone().unwrap());

        let result = token.verify_with_revocation(SECRET, 1999999999, &revocation_list);
        assert!(matches!(result, Err(TokenError::Revoked { jti }) if jti == token.jti.unwrap()));
    }

    #[test]
    fn verify_with_revocation_missing_jti() {
        use crate::revocation::RevocationList;

        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        assert!(token.jti.is_none());

        let revocation_list = RevocationList::new();
        let result = token.verify_with_revocation(SECRET, 1999999999, &revocation_list);
        assert_eq!(result, Err(TokenError::MissingJti));
    }

    // ===== UseStore tests =====

    #[test]
    fn verify_single_use_accepted() {
        use crate::use_store::MemoryUseStore;

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let mut store = MemoryUseStore::new();
        assert!(token
            .verify_single_use(SECRET, 1999999999, &mut store)
            .is_ok());
    }

    #[test]
    fn verify_single_use_replay() {
        use crate::use_store::MemoryUseStore;

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let mut store = MemoryUseStore::new();
        assert!(token
            .verify_single_use(SECRET, 1999999999, &mut store)
            .is_ok());

        // Second use should fail
        let result = token.verify_single_use(SECRET, 1999999999, &mut store);
        assert!(
            matches!(result, Err(TokenError::ReplayDetected { jti }) if jti == token.jti.unwrap())
        );
    }

    #[test]
    fn verify_max_uses() {
        use crate::use_store::MemoryUseStore;

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let mut store = MemoryUseStore::new();

        // Allow 3 uses
        assert!(token
            .verify_with_max_uses(SECRET, 1999999999, &mut store, 3, None)
            .is_ok());
        assert!(token
            .verify_with_max_uses(SECRET, 1999999999, &mut store, 3, None)
            .is_ok());
        assert!(token
            .verify_with_max_uses(SECRET, 1999999999, &mut store, 3, None)
            .is_ok());

        // Fourth use should fail
        let result = token.verify_with_max_uses(SECRET, 1999999999, &mut store, 3, None);
        assert!(matches!(result, Err(TokenError::ReplayDetected { .. })));
    }

    #[test]
    fn verify_single_use_missing_jti() {
        use crate::use_store::MemoryUseStore;

        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let mut store = MemoryUseStore::new();
        let result = token.verify_single_use(SECRET, 1999999999, &mut store);
        assert_eq!(result, Err(TokenError::MissingJti));
    }

    #[test]
    fn verify_with_revocation_and_use_store() {
        use crate::revocation::RevocationList;
        use crate::use_store::MemoryUseStore;

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let revocation_list = RevocationList::new();
        let mut store = MemoryUseStore::new();

        // First use succeeds
        assert!(token
            .verify_with_revocation_and_use_store(
                SECRET,
                1999999999,
                &revocation_list,
                &mut store,
                1,
                None
            )
            .is_ok());

        // Second use fails (max_uses=1)
        let result = token.verify_with_revocation_and_use_store(
            SECRET,
            1999999999,
            &revocation_list,
            &mut store,
            1,
            None,
        );
        assert!(matches!(result, Err(TokenError::ReplayDetected { .. })));
    }

    #[test]
    fn verify_revocation_checked_before_use_store() {
        use crate::revocation::RevocationList;
        use crate::use_store::MemoryUseStore;

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );

        let mut revocation_list = RevocationList::new();
        revocation_list.revoke(token.jti.clone().unwrap());
        let mut store = MemoryUseStore::new();

        // Should fail with Revoked, not consume a use
        let result = token.verify_with_revocation_and_use_store(
            SECRET,
            1999999999,
            &revocation_list,
            &mut store,
            1,
            None,
        );
        assert!(matches!(result, Err(TokenError::Revoked { .. })));
        assert_eq!(store.get_count(token.jti.as_ref().unwrap()), 0);
    }
}
