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
    /// `version` is not a supported policy schema version.
    UnknownVersion {
        version: String,
    },
    /// The same tool name appears in more than one grant.
    DuplicateTool {
        name: String,
    },
    /// A constraint is attached to a key that is not in the grant's allowlist.
    ConstraintKeyNotAllowed {
        tool: String,
        key: String,
    },
    /// A TTL (default or per-grant) is present and zero.
    ZeroTtl {
        /// `None` when the policy default TTL is zero; otherwise the grant name.
        tool: Option<String>,
    },
    /// A grant has an empty tool name.
    EmptyToolName,
    /// More than one validation error.
    Multiple(Vec<PolicyError>),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::InvalidJson(msg) => write!(f, "invalid policy JSON: {msg}"),
            PolicyError::UnknownVersion { version } => {
                write!(
                    f,
                    "unknown policy version '{version}' (supported: {POLICY_VERSION})"
                )
            }
            PolicyError::DuplicateTool { name } => {
                write!(f, "duplicate tool name: '{name}'")
            }
            PolicyError::ConstraintKeyNotAllowed { tool, key } => {
                write!(
                    f,
                    "constraint key '{key}' on tool '{tool}' is not in the allowed key list"
                )
            }
            PolicyError::ZeroTtl { tool: Some(tool) } => {
                write!(f, "ttl_seconds for tool '{tool}' must be greater than zero")
            }
            PolicyError::ZeroTtl { tool: None } => {
                write!(f, "default_ttl_seconds must be greater than zero")
            }
            PolicyError::EmptyToolName => write!(f, "tool name must not be empty"),
            PolicyError::Multiple(errors) => {
                let joined = errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                write!(f, "{joined}")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Parse a policy from a JSON document. Does not validate semantic rules.
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(json).map_err(|e| PolicyError::InvalidJson(e.to_string()))
    }

    /// Collect every semantic validation error.
    pub fn validation_errors(&self) -> Vec<PolicyError> {
        let mut errors = Vec::new();

        if self.version != POLICY_VERSION {
            errors.push(PolicyError::UnknownVersion {
                version: self.version.clone(),
            });
        }

        if self.default_ttl_seconds == Some(0) {
            errors.push(PolicyError::ZeroTtl { tool: None });
        }

        let mut seen = std::collections::BTreeSet::new();
        for grant in &self.tools {
            if grant.name.is_empty() {
                errors.push(PolicyError::EmptyToolName);
            } else if !seen.insert(grant.name.clone()) {
                errors.push(PolicyError::DuplicateTool {
                    name: grant.name.clone(),
                });
            }

            if grant.ttl_seconds == Some(0) {
                errors.push(PolicyError::ZeroTtl {
                    tool: Some(grant.name.clone()),
                });
            }

            if let Some(constraints) = &grant.constraints {
                for key in constraints.keys() {
                    if !grant.arg_keys.iter().any(|k| k == key) {
                        errors.push(PolicyError::ConstraintKeyNotAllowed {
                            tool: grant.name.clone(),
                            key: key.clone(),
                        });
                    }
                }
            }
        }

        errors
    }

    /// Validate semantic rules. Returns the first error, or
    /// [`PolicyError::Multiple`] when several fail.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let mut errors = self.validation_errors();
        match errors.len() {
            0 => Ok(()),
            1 => Err(errors.remove(0)),
            _ => Err(PolicyError::Multiple(errors)),
        }
    }
}
