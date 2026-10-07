//! Structured audit records for verification decisions.
//!
//! A [`Decision`] captures what a verify/check concluded and why. Attach an
//! [`AuditSink`] to a [`crate::Verifier`] to receive one record per check.

use std::collections::BTreeMap;
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
