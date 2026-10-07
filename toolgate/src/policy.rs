//! Declarative policy files describing which tools an agent may call.
//!
//! A policy is a JSON document: a version, optional defaults (audience, TTL,
//! max attenuation depth, key id), and a list of tool grants. Each grant
//! names a tool, the argument keys it may receive, and optional per-key
//! [`Constraint`](crate::Constraint)s in the same serde form used on tokens.

use std::collections::BTreeMap;

use crate::constraint::Constraints;
use crate::keyring::Keyring;
use crate::token::{Token, TokenError};
use crate::verifier::Verifier;

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
    /// No grant exists for the requested tool.
    UnknownTool {
        name: String,
    },
    /// Neither the grant nor the policy default specifies a TTL.
    MissingTtl {
        tool: String,
    },
    /// The keyring has no active key to mint with.
    NoActiveKey,
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
            PolicyError::UnknownTool { name } => {
                write!(f, "unknown tool '{name}' is not granted by policy")
            }
            PolicyError::MissingTtl { tool } => {
                write!(
                    f,
                    "no ttl_seconds for tool '{tool}' and no default_ttl_seconds"
                )
            }
            PolicyError::NoActiveKey => write!(f, "no active key in keyring"),
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

    /// Look up the grant for `tool`.
    pub fn grant(&self, tool: &str) -> Option<&ToolGrant> {
        self.tools.iter().find(|g| g.name == tool)
    }

    /// Effective audience: grant override, else policy default.
    pub fn audience_for(&self, grant: &ToolGrant) -> Option<String> {
        grant
            .audience
            .clone()
            .or_else(|| self.default_audience.clone())
    }

    /// Effective TTL: grant override, else policy default.
    pub fn ttl_for(&self, grant: &ToolGrant) -> Option<u64> {
        grant.ttl_seconds.or(self.default_ttl_seconds)
    }

    /// Effective max depth: grant override, else policy default.
    pub fn max_depth_for(&self, grant: &ToolGrant) -> Option<u32> {
        grant.max_depth.or(self.default_max_depth)
    }

    fn resolve_grant<'a>(&'a self, tool: &str, now: u64) -> Result<ResolvedGrant<'a>, PolicyError> {
        self.validate()?;
        let grant = self.grant(tool).ok_or_else(|| PolicyError::UnknownTool {
            name: tool.to_string(),
        })?;
        let ttl = self
            .ttl_for(grant)
            .ok_or_else(|| PolicyError::MissingTtl {
                tool: tool.to_string(),
            })?;
        Ok(ResolvedGrant {
            grant,
            expiry: now.saturating_add(ttl),
            audience: self.audience_for(grant),
            max_depth: self.max_depth_for(grant),
        })
    }

    /// Mint a token for `tool` using `secret`.
    ///
    /// Expiry is `now + ttl`. Audience, max depth, and argument constraints
    /// come from the grant with policy defaults applied. `kid` is
    /// [`Policy::default_kid`].
    pub fn mint(&self, tool: &str, secret: &[u8], now: u64) -> Result<Token, PolicyError> {
        let resolved = self.resolve_grant(tool, now)?;
        Ok(Token::mint_complete(
            secret,
            resolved.grant.name.clone(),
            resolved.grant.arg_keys.clone(),
            resolved.expiry,
            resolved.audience,
            self.default_kid.clone(),
            resolved.grant.constraints.clone(),
            false,
            None,
            resolved.max_depth,
        ))
    }

    /// Mint a token for `tool` using the keyring's active key.
    ///
    /// The token `kid` is the active key id (not [`Policy::default_kid`]).
    pub fn mint_with_keyring(
        &self,
        tool: &str,
        keyring: &Keyring,
        now: u64,
    ) -> Result<Token, PolicyError> {
        let resolved = self.resolve_grant(tool, now)?;
        keyring
            .mint_complete(
                resolved.grant.name.clone(),
                resolved.grant.arg_keys.clone(),
                resolved.expiry,
                resolved.audience,
                resolved.grant.constraints.clone(),
                false,
                None,
                resolved.max_depth,
            )
            .map_err(|_| PolicyError::NoActiveKey)
    }

    /// True when `token`'s capabilities are within this policy.
    ///
    /// Used after mint: a later, tighter policy denies older broader tokens
    /// even if the token MAC is still valid.
    pub fn authorize_token(&self, token: &Token) -> Result<(), TokenError> {
        let grant = self.grant(&token.tool_name).ok_or_else(|| {
            TokenError::PolicyDenied {
                reason: format!("tool '{}' is not permitted by policy", token.tool_name),
            }
        })?;

        for key in &token.arg_keys {
            if !grant.arg_keys.iter().any(|k| k == key) {
                return Err(TokenError::ArgKeyNotAllowed { key: key.clone() });
            }
        }

        if let Some(policy_constraints) = &grant.constraints {
            for (key, policy_constraint) in policy_constraints {
                match token.constraints.as_ref().and_then(|c| c.get(key)) {
                    None => {
                        return Err(TokenError::PolicyDenied {
                            reason: format!("token is missing required constraint on '{key}'"),
                        });
                    }
                    Some(token_constraint) => {
                        if !token_constraint.is_subset_of(policy_constraint) {
                            return Err(TokenError::PolicyDenied {
                                reason: format!(
                                    "token constraint on '{key}' is broader than policy"
                                ),
                            });
                        }
                    }
                }
            }
        }

        if let Some(expected) = self.audience_for(grant) {
            match &token.audience {
                Some(got) if got == &expected => {}
                Some(got) => {
                    return Err(TokenError::PolicyDenied {
                        reason: format!("token audience '{got}' does not match policy '{expected}'"),
                    });
                }
                None => {
                    return Err(TokenError::PolicyDenied {
                        reason: format!("token has no audience; policy requires '{expected}'"),
                    });
                }
            }
        }

        if let Some(max) = self.max_depth_for(grant) {
            match token.max_depth {
                Some(token_max) if token_max <= max => {}
                Some(token_max) => {
                    return Err(TokenError::PolicyDenied {
                        reason: format!(
                            "token max_depth {token_max} exceeds policy max_depth {max}"
                        ),
                    });
                }
                None => {
                    return Err(TokenError::PolicyDenied {
                        reason: format!("token has no max_depth; policy requires {max}"),
                    });
                }
            }
        }

        Ok(())
    }

    /// Verify `token` and confirm the call is still permitted by this policy.
    ///
    /// Routes through [`Verifier`] so an attached [`crate::AuditSink`] records
    /// exactly one [`crate::Decision`].
    pub fn check_call(
        &self,
        verifier: &Verifier<'_>,
        token: &Token,
        tool: &str,
        arg_keys: &[&str],
    ) -> Result<(), TokenError> {
        verifier.verify_call_against_policy(token, self, tool, arg_keys)
    }

    /// Like [`Policy::check_call`], including argument-value constraints.
    pub fn check_call_with_args(
        &self,
        verifier: &Verifier<'_>,
        token: &Token,
        tool: &str,
        args: &BTreeMap<String, String>,
    ) -> Result<(), TokenError> {
        verifier.verify_call_with_args_against_policy(token, self, tool, args)
    }
}

struct ResolvedGrant<'a> {
    grant: &'a ToolGrant,
    expiry: u64,
    audience: Option<String>,
    max_depth: Option<u32>,
}
