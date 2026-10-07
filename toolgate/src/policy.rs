//! Declarative policy files describing which tools an agent may call.
//!
//! A policy is a JSON document: a version, optional defaults (audience, TTL,
//! max attenuation depth, key id), and a list of tool grants. Each grant
//! names a tool, the argument keys it may receive, and optional per-key
//! [`Constraint`](crate::Constraint)s in the same serde form used on tokens.

use crate::constraint::Constraints;

/// Supported policy document version.
pub const POLICY_VERSION: &str = "1";

/// A declarative policy: tool grants plus optional defaults.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    /// Document version. Currently only [`POLICY_VERSION`] is accepted by validation.
    pub version: String,
    /// Audience applied to grants that do not set their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_audience: Option<String>,
    /// Time-to-live in seconds applied to grants that do not set their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ttl_seconds: Option<u64>,
    /// Max attenuation depth applied to grants that do not set their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_max_depth: Option<u32>,
    /// Key id stamped on tokens minted with a raw secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_kid: Option<String>,
    /// Tool grants. Each tool name may appear at most once.
    #[serde(default)]
    pub tools: Vec<ToolGrant>,
}

/// Permission to call one tool, with optional overrides of policy defaults.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ToolGrant {
    /// Tool name this grant authorizes.
    pub name: String,
    /// Allowlist of argument keys.
    #[serde(default)]
    pub arg_keys: Vec<String>,
    /// Optional per-key value constraints (same serde form as [`crate::Constraint`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    /// Per-grant TTL in seconds; overrides [`Policy::default_ttl_seconds`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Per-grant audience; overrides [`Policy::default_audience`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Per-grant max attenuation depth; overrides [`Policy::default_max_depth`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
}

/// Errors from parsing or applying a [`Policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The document is not valid JSON or does not match the schema.
    InvalidJson(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::InvalidJson(msg) => write!(f, "invalid policy JSON: {msg}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Parse a policy from a JSON document. Does not validate semantic rules.
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(json).map_err(|e| PolicyError::InvalidJson(e.to_string()))
    }
}
