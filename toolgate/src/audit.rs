//! Structured audit records for verification decisions.
//!
//! A [`Decision`] captures what a verify/check concluded and why. Attach an
//! [`AuditSink`] to a [`crate::Verifier`] to receive one record per check.

use std::collections::BTreeMap;

use crate::token::TokenError;

/// Allow or deny outcome of a verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// The check authorized the token or call.
    Allow,
    /// The check rejected the token or call.
    Deny,
}

/// Structured record of a verification decision.
///
/// Argument values in [`Decision::arguments`] are expected to be redacted
/// before the record is emitted so secrets never reach a sink.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Decision {
    /// Whether the check allowed or denied the operation.
    pub outcome: Outcome,
    /// Human-readable reason (typically [`TokenError`]'s display text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Stable machine-readable error kind on deny (see [`TokenError::kind`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Token identifier (`jti`) when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// Tool name that was checked, or the token's tool on a bare verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Audience bound on the token, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Unix timestamp from the verifier [`crate::Clock`].
    pub timestamp: u64,
    /// Token delegation depth at the time of the check.
    pub depth: u32,
    /// Call arguments after redaction (keys preserved).
    #[serde(default)]
    pub arguments: BTreeMap<String, String>,
}

impl Decision {
    /// Build a decision from a verification `result`.
    ///
    /// `arguments` should already be redacted by the caller.
    pub fn from_result(
        result: &Result<(), TokenError>,
        token_id: Option<String>,
        tool_name: Option<String>,
        audience: Option<String>,
        timestamp: u64,
        depth: u32,
        arguments: BTreeMap<String, String>,
    ) -> Self {
        match result {
            Ok(()) => Decision {
                outcome: Outcome::Allow,
                reason: None,
                error_kind: None,
                token_id,
                tool_name,
                audience,
                timestamp,
                depth,
                arguments,
            },
            Err(err) => Decision {
                outcome: Outcome::Deny,
                reason: Some(err.to_string()),
                error_kind: Some(err.kind().to_string()),
                token_id,
                tool_name,
                audience,
                timestamp,
                depth,
                arguments,
            },
        }
    }

    /// Convenience constructor for an allow decision.
    pub fn allow(
        token_id: Option<String>,
        tool_name: Option<String>,
        audience: Option<String>,
        timestamp: u64,
        depth: u32,
        arguments: BTreeMap<String, String>,
    ) -> Self {
        Self::from_result(
            &Ok(()),
            token_id,
            tool_name,
            audience,
            timestamp,
            depth,
            arguments,
        )
    }

    /// Convenience constructor for a deny decision.
    pub fn deny(
        error: &TokenError,
        token_id: Option<String>,
        tool_name: Option<String>,
        audience: Option<String>,
        timestamp: u64,
        depth: u32,
        arguments: BTreeMap<String, String>,
    ) -> Self {
        Self::from_result(
            &Err(error.clone()),
            token_id,
            tool_name,
            audience,
            timestamp,
            depth,
            arguments,
        )
    }
}
