//! Structured audit records for verification decisions.
//!
//! A [`Decision`] captures what a verify/check concluded and why. Attach an
//! [`AuditSink`] to a [`crate::Verifier`] to receive one record per check.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::sync::Mutex;

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
    ///
    /// Gate revocation and replay denials use `revoked` and `replay_detected`.
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

/// Error from writing or serializing an audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// The sink's I/O writer failed.
    Io(String),
    /// The decision could not be serialized.
    Serialize(String),
    /// The sink's lock was poisoned.
    Poisoned,
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::Io(msg) => write!(f, "audit I/O error: {msg}"),
            AuditError::Serialize(msg) => write!(f, "audit serialize error: {msg}"),
            AuditError::Poisoned => write!(f, "audit sink lock poisoned"),
        }
    }
}

impl std::error::Error for AuditError {}

/// Pluggable destination for [`Decision`] records.
pub trait AuditSink {
    /// Persist one decision. Verification does not fail if this returns an error.
    fn record(&self, decision: &Decision) -> Result<(), AuditError>;
}

/// In-memory sink that collects decisions for tests and in-process inspection.
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    records: Mutex<Vec<Decision>>,
}

impl MemoryAuditSink {
    /// Create an empty sink.
    pub fn new() -> Self {
        MemoryAuditSink {
            records: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of recorded decisions, in emission order.
    pub fn decisions(&self) -> Vec<Decision> {
        self.records
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Number of recorded decisions.
    pub fn len(&self) -> usize {
        self.records.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    /// Whether no decisions have been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every recorded decision.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.records.lock() {
            guard.clear();
        }
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, decision: &Decision) -> Result<(), AuditError> {
        let mut guard = self.records.lock().map_err(|_| AuditError::Poisoned)?;
        guard.push(decision.clone());
        Ok(())
    }
}

/// JSON Lines sink that writes one serialized [`Decision`] per line.
pub struct JsonlAuditSink<W: Write> {
    writer: Mutex<W>,
}

impl<W: Write> JsonlAuditSink<W> {
    /// Wrap any [`Write`] target.
    pub fn new(writer: W) -> Self {
        JsonlAuditSink {
            writer: Mutex::new(writer),
        }
    }

    /// Recover the inner writer.
    pub fn into_inner(self) -> Result<W, AuditError> {
        self.writer.into_inner().map_err(|_| AuditError::Poisoned)
    }
}

impl<W: Write> fmt::Debug for JsonlAuditSink<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonlAuditSink").finish_non_exhaustive()
    }
}

/// Replacement written in place of a redacted argument value.
pub const REDACTED: &str = "[REDACTED]";

#[derive(Debug, Clone, PartialEq, Eq)]
enum RedactionPolicy {
    AllValues,
    Keys(BTreeSet<String>),
    None,
}

/// Policy for stripping argument values from audit records.
///
/// The default keeps argument keys and replaces every value with [`REDACTED`]
/// so secrets in tool args never reach a sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    policy: RedactionPolicy,
}

impl Default for Redaction {
    fn default() -> Self {
        Self::all_values()
    }
}

impl Redaction {
    /// Redact every argument value. This is the default.
    pub fn all_values() -> Self {
        Redaction {
            policy: RedactionPolicy::AllValues,
        }
    }

    /// Redact only the listed argument keys; other values are kept as-is.
    pub fn keys<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Redaction {
            policy: RedactionPolicy::Keys(keys.into_iter().map(Into::into).collect()),
        }
    }

    /// Keep every argument value. Intended for tests, not production logs.
    pub fn none() -> Self {
        Redaction {
            policy: RedactionPolicy::None,
        }
    }

    /// Return a copy of `args` with this policy applied.
    pub fn apply(&self, args: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        args.iter()
            .map(|(key, value)| {
                let next = if self.should_redact(key) {
                    REDACTED.to_string()
                } else {
                    value.clone()
                };
                (key.clone(), next)
            })
            .collect()
    }

    fn should_redact(&self, key: &str) -> bool {
        match &self.policy {
            RedactionPolicy::AllValues => true,
            RedactionPolicy::Keys(keys) => keys.contains(key),
            RedactionPolicy::None => false,
        }
    }
}

impl<W: Write> AuditSink for JsonlAuditSink<W> {
    fn record(&self, decision: &Decision) -> Result<(), AuditError> {
        let mut writer = self.writer.lock().map_err(|_| AuditError::Poisoned)?;
        serde_json::to_writer(&mut *writer, decision)
            .map_err(|e| AuditError::Serialize(e.to_string()))?;
        writer
            .write_all(b"\n")
            .map_err(|e| AuditError::Io(e.to_string()))?;
        writer.flush().map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_args() -> BTreeMap<String, String> {
        let mut args = BTreeMap::new();
        args.insert("path".to_string(), "/tmp/secret.txt".to_string());
        args.insert("token".to_string(), "super-secret".to_string());
        args
    }

    fn allow_decision() -> Decision {
        Decision::allow(
            Some("jti-1".to_string()),
            Some("read_file".to_string()),
            Some("client-abc".to_string()),
            1_699_999_999,
            1,
            Redaction::default().apply(&sample_args()),
        )
    }

    #[test]
    fn token_error_kind_matches_cli_strings() {
        assert_eq!(TokenError::Expired.kind(), "expired");
        assert_eq!(TokenError::MalformedRequest.kind(), "malformed_request");
        assert_eq!(
            TokenError::ToolMismatch {
                expected: "a".into(),
                got: "b".into()
            }
            .kind(),
            "tool_mismatch"
        );
        assert_eq!(
            TokenError::ConstraintViolation { key: "path".into() }.kind(),
            "constraint_violation"
        );
        assert_eq!(TokenError::Revoked { jti: "abc".into() }.kind(), "revoked");
        assert_eq!(
            TokenError::ReplayDetected { jti: "abc".into() }.kind(),
            "replay_detected"
        );
    }

    #[test]
    fn decision_from_ok_is_allow_without_error_fields() {
        let decision = Decision::from_result(
            &Ok(()),
            Some("abc".into()),
            Some("read_file".into()),
            None,
            42,
            0,
            BTreeMap::new(),
        );
        assert_eq!(decision.outcome, Outcome::Allow);
        assert_eq!(decision.reason, None);
        assert_eq!(decision.error_kind, None);
        assert_eq!(decision.token_id.as_deref(), Some("abc"));
        assert_eq!(decision.timestamp, 42);
        assert_eq!(decision.depth, 0);
    }

    #[test]
    fn decision_from_err_is_deny_with_kind_and_reason() {
        let err = TokenError::Expired;
        let decision = Decision::deny(
            &err,
            None,
            Some("read_file".into()),
            None,
            7,
            2,
            BTreeMap::new(),
        );
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.error_kind.as_deref(), Some("expired"));
        assert_eq!(decision.reason.as_deref(), Some("token expired"));
        assert_eq!(decision.depth, 2);
    }

    #[test]
    fn decision_serializes_to_stable_json() {
        let json = serde_json::to_value(allow_decision()).unwrap();
        assert_eq!(json["outcome"], "allow");
        assert_eq!(json["token_id"], "jti-1");
        assert_eq!(json["tool_name"], "read_file");
        assert_eq!(json["audience"], "client-abc");
        assert_eq!(json["timestamp"], 1_699_999_999);
        assert_eq!(json["depth"], 1);
        assert_eq!(json["arguments"]["path"], REDACTED);
        assert_eq!(json["arguments"]["token"], REDACTED);
        assert!(json.get("reason").is_none());
        assert!(json.get("error_kind").is_none());
    }

    #[test]
    fn memory_sink_collects_decisions_in_order() {
        let sink = MemoryAuditSink::new();
        assert!(sink.is_empty());
        sink.record(&allow_decision()).unwrap();
        let deny = Decision::deny(
            &TokenError::AudienceMismatch,
            None,
            Some("read_file".into()),
            None,
            8,
            0,
            BTreeMap::new(),
        );
        sink.record(&deny).unwrap();
        assert_eq!(sink.len(), 2);
        let recorded = sink.decisions();
        assert_eq!(recorded[0].outcome, Outcome::Allow);
        assert_eq!(recorded[1].error_kind.as_deref(), Some("audience_mismatch"));
        sink.clear();
        assert!(sink.is_empty());
    }

    #[test]
    fn jsonl_sink_writes_one_object_per_line() {
        let sink = JsonlAuditSink::new(Vec::new());
        sink.record(&allow_decision()).unwrap();
        sink.record(&Decision::deny(
            &TokenError::Expired,
            Some("jti-1".into()),
            Some("read_file".into()),
            None,
            9,
            0,
            BTreeMap::new(),
        ))
        .unwrap();
        let bytes = sink.into_inner().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Decision = serde_json::from_str(lines[0]).unwrap();
        let second: Decision = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first.outcome, Outcome::Allow);
        assert_eq!(second.outcome, Outcome::Deny);
        assert_eq!(second.error_kind.as_deref(), Some("expired"));
        assert!(!text.contains("super-secret"));
        assert!(!text.contains("/tmp/secret.txt"));
    }

    #[test]
    fn redaction_default_replaces_all_values() {
        let redacted = Redaction::default().apply(&sample_args());
        assert_eq!(redacted.get("path").unwrap(), REDACTED);
        assert_eq!(redacted.get("token").unwrap(), REDACTED);
        assert_eq!(redacted.len(), 2);
    }

    #[test]
    fn redaction_keys_only_strips_listed_values() {
        let redacted = Redaction::keys(["token"]).apply(&sample_args());
        assert_eq!(redacted.get("path").unwrap(), "/tmp/secret.txt");
        assert_eq!(redacted.get("token").unwrap(), REDACTED);
    }

    #[test]
    fn redaction_none_keeps_values() {
        let redacted = Redaction::none().apply(&sample_args());
        assert_eq!(redacted.get("token").unwrap(), "super-secret");
    }
}
