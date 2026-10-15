//! Declarative policy files describing which tools an agent may call.
//!
//! A policy is a JSON document: a version, optional defaults (audience, TTL,
//! max attenuation depth, key id), and a list of tool grants. Each grant
//! names a tool, the argument keys it may receive, optional required
//! keys that must be present on every call, and optional per-key
//! [`Constraint`](crate::Constraint)s in the same serde form used on tokens.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

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
    /// Argument keys that must be present on every call this grant mints.
    ///
    /// Each key must also appear in [`ToolGrant::arg_keys`]. Empty names
    /// are rejected. At check time the token must require at least this set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_keys: Vec<String>,
}

/// Errors from parsing or applying a [`Policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The document is not valid JSON or does not match the schema.
    InvalidJson(String),
    /// `version` is not a supported policy schema version.
    UnknownVersion { version: String },
    /// The same tool name appears in more than one grant.
    DuplicateTool { name: String },
    /// A constraint is attached to a key that is not in the grant's allowlist.
    ConstraintKeyNotAllowed { tool: String, key: String },
    /// A required key is empty or is not in the grant's allowlist.
    RequiredKeyNotAllowed { tool: String, key: String },
    /// An empty suffix, contains, matches, NotOneOf, PrefixOneOf,
    /// SuffixOneOf, ContainsAny, ContainsNone, MatchesAny, MatchesNone,
    /// PrefixNone, SuffixNone, IntOneOf, IntNone, FloatOneOf, FloatNone,
    /// LenOneOf, LenNone, CharLenOneOf, CharLenNone, NotContains,
    /// NotPrefix, NotSuffix, NotMatches, All, Any, or Not constraint is
    /// rejected.
    EmptyConstraintPattern { tool: String, key: String },
    /// An All/Any/Not tree deeper than [`crate::MAX_CONSTRAINT_NESTING`] is rejected.
    ConstraintNestingTooDeep { tool: String, key: String },
    /// A FloatRange with non-finite bounds or `min > max`, a MinFloat
    /// or MaxFloat with a non-finite bound, a FloatOneOf or FloatNone
    /// list with a non-finite member, or a LenRange or CharLenRange
    /// with `min > max`, is rejected.
    InvalidConstraintRange { tool: String, key: String },
    /// A TTL (default or per-grant) is present and zero.
    ZeroTtl {
        /// `None` when the policy default TTL is zero; otherwise the grant name.
        tool: Option<String>,
    },
    /// A grant has an empty tool name.
    EmptyToolName,
    /// No grant exists for the requested tool.
    UnknownTool { name: String },
    /// Neither the grant nor the policy default specifies a TTL.
    MissingTtl { tool: String },
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
            PolicyError::RequiredKeyNotAllowed { tool, key } => {
                write!(
                    f,
                    "required key '{key}' on tool '{tool}' is empty or not in the allowed key list"
                )
            }
            PolicyError::EmptyConstraintPattern { tool, key } => {
                write!(
                    f,
                    "empty suffix/contains/matches/not_one_of/not_contains/not_prefix/not_suffix/not_matches/all/any/not/prefix_one_of/suffix_one_of/contains_any/contains_none/matches_any/matches_none/prefix_none/suffix_none/int_one_of/int_none/float_one_of/float_none/len_one_of/len_none/char_len_one_of/char_len_none constraint for '{key}' on tool '{tool}' is rejected"
                )
            }
            PolicyError::ConstraintNestingTooDeep { tool, key } => {
                write!(
                    f,
                    "constraint nesting for '{key}' on tool '{tool}' exceeds maximum depth of {}",
                    crate::MAX_CONSTRAINT_NESTING
                )
            }
            PolicyError::InvalidConstraintRange { tool, key } => {
                write!(
                    f,
                    "invalid float_range, min_float, max_float, exclusive_min_float, exclusive_max_float, float_one_of, float_none, len_range, or char_len_range for '{key}' on tool '{tool}' is rejected (min <= max required; float bounds and list members must be finite)"
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

/// Errors from loading a file-backed [`Policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyFileError {
    /// The path could not be read.
    Io(String),
    /// The document failed to parse or validate.
    Policy(PolicyError),
}

impl std::fmt::Display for PolicyFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyFileError::Io(msg) => write!(f, "failed to read policy file: {msg}"),
            PolicyFileError::Policy(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PolicyFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PolicyFileError::Policy(err) => Some(err),
            PolicyFileError::Io(_) => None,
        }
    }
}

impl From<PolicyError> for PolicyFileError {
    fn from(err: PolicyError) -> Self {
        PolicyFileError::Policy(err)
    }
}

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

            for key in &grant.required_keys {
                if key.is_empty() || !grant.arg_keys.iter().any(|k| k == key) {
                    errors.push(PolicyError::RequiredKeyNotAllowed {
                        tool: grant.name.clone(),
                        key: key.clone(),
                    });
                }
            }

            if let Some(constraints) = &grant.constraints {
                for (key, constraint) in constraints {
                    if !grant.arg_keys.iter().any(|k| k == key) {
                        errors.push(PolicyError::ConstraintKeyNotAllowed {
                            tool: grant.name.clone(),
                            key: key.clone(),
                        });
                    }
                    if constraint.is_empty_pattern() {
                        errors.push(PolicyError::EmptyConstraintPattern {
                            tool: grant.name.clone(),
                            key: key.clone(),
                        });
                    }
                    if constraint.exceeds_max_nesting() {
                        errors.push(PolicyError::ConstraintNestingTooDeep {
                            tool: grant.name.clone(),
                            key: key.clone(),
                        });
                    }
                    if constraint.is_invalid_range() {
                        errors.push(PolicyError::InvalidConstraintRange {
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
        let ttl = self.ttl_for(grant).ok_or_else(|| PolicyError::MissingTtl {
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
    /// Expiry is `now + ttl`. Audience, max depth, required keys, and
    /// argument constraints come from the grant with policy defaults
    /// applied. `kid` is [`Policy::default_kid`].
    pub fn mint(&self, tool: &str, secret: &[u8], now: u64) -> Result<Token, PolicyError> {
        let resolved = self.resolve_grant(tool, now)?;
        Token::mint_with_required_keys(
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
            resolved.grant.required_keys.clone(),
        )
        .map_err(|err| PolicyError::RequiredKeyNotAllowed {
            tool: tool.to_string(),
            key: match err {
                TokenError::InvalidRequiredKey { key } => key,
                _ => String::new(),
            },
        })
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
            .mint_with_required_keys(
                resolved.grant.name.clone(),
                resolved.grant.arg_keys.clone(),
                resolved.expiry,
                resolved.audience,
                resolved.grant.constraints.clone(),
                false,
                None,
                resolved.max_depth,
                resolved.grant.required_keys.clone(),
            )
            .map_err(|err| match err {
                TokenError::NoActiveKey => PolicyError::NoActiveKey,
                TokenError::InvalidRequiredKey { key } => PolicyError::RequiredKeyNotAllowed {
                    tool: tool.to_string(),
                    key,
                },
                _ => PolicyError::NoActiveKey,
            })
    }

    /// True when `token`'s capabilities are within this policy.
    ///
    /// Used after mint: a later, tighter policy denies older broader tokens
    /// even if the token MAC is still valid.
    pub fn authorize_token(&self, token: &Token) -> Result<(), TokenError> {
        let grant = self
            .grant(&token.tool_name)
            .ok_or_else(|| TokenError::PolicyDenied {
                reason: format!("tool '{}' is not permitted by policy", token.tool_name),
            })?;

        for key in &token.arg_keys {
            if !grant.arg_keys.iter().any(|k| k == key) {
                return Err(TokenError::ArgKeyNotAllowed { key: key.clone() });
            }
        }

        for key in &grant.required_keys {
            if !token.required_keys.iter().any(|k| k == key) {
                return Err(TokenError::PolicyDenied {
                    reason: format!("token is missing required key '{key}'"),
                });
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
                        reason: format!(
                            "token audience '{got}' does not match policy '{expected}'"
                        ),
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

    /// Load and validate a policy JSON file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PolicyFileError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .map_err(|e| PolicyFileError::Io(format!("{}: {e}", path.display())))?;
        let policy = Self::from_json(&text)?;
        policy.validate()?;
        Ok(policy)
    }
}

/// File-backed [`Policy`] that reloads when the file's mtime changes.
///
/// The gate loads this at start and calls [`PolicyFile::reload_if_changed`]
/// before each decision. A parse/validate failure keeps the previous good
/// version and writes one warning line to stderr. No watcher thread or extra
/// crate is required.
#[derive(Debug, Clone)]
pub struct PolicyFile {
    path: PathBuf,
    policy: Policy,
    mtime: Option<SystemTime>,
}

impl PolicyFile {
    /// Read `path`, validate, and remember its modification time.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, PolicyFileError> {
        let path = path.into();
        let mtime = file_mtime(&path);
        let policy = Policy::from_file(&path)?;
        Ok(PolicyFile {
            path,
            policy,
            mtime,
        })
    }

    /// Path of the policy file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current in-memory policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Re-read the file when its modification time differs from the last load.
    ///
    /// Returns `true` when the policy was replaced. A failed parse keeps the
    /// previous policy, records the new mtime so the warning is not repeated,
    /// and writes one line to stderr.
    pub fn reload_if_changed(&mut self) -> bool {
        let mtime = file_mtime(&self.path);
        if mtime == self.mtime {
            return false;
        }
        match Policy::from_file(&self.path) {
            Ok(policy) => {
                self.policy = policy;
                self.mtime = mtime;
                true
            }
            Err(err) => {
                let _ = writeln!(
                    io::stderr(),
                    "warning: failed to reload policy file {}: {err}; keeping previous version",
                    self.path.display()
                );
                self.mtime = mtime;
                false
            }
        }
    }
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|meta| meta.modified()).ok()
}

struct ResolvedGrant<'a> {
    grant: &'a ToolGrant,
    expiry: u64,
    audience: Option<String>,
    max_depth: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{MemoryAuditSink, Outcome};
    use crate::constraint::Constraint;
    use crate::TokenError;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";
    const NOW: u64 = 1_700_000_000;

    fn sample_json() -> &'static str {
        r#"{
            "version": "1",
            "default_audience": "agent",
            "default_ttl_seconds": 3600,
            "default_max_depth": 2,
            "default_kid": "key-2025",
            "tools": [
                {
                    "name": "read_file",
                    "arg_keys": ["path", "limit"],
                    "constraints": {
                        "path": {"type": "prefix", "value": "/tmp/"},
                        "limit": {"type": "int_range", "value": {"min": 1, "max": 100}}
                    }
                },
                {
                    "name": "ping",
                    "arg_keys": [],
                    "ttl_seconds": 60,
                    "audience": "monitor",
                    "max_depth": 0
                }
            ]
        }"#
    }

    fn sample_policy() -> Policy {
        let policy = Policy::from_json(sample_json()).unwrap();
        policy.validate().unwrap();
        policy
    }

    #[test]
    fn from_json_parses_defaults_and_constraint_serde() {
        let policy = sample_policy();
        assert_eq!(policy.version, POLICY_VERSION);
        assert_eq!(policy.default_audience.as_deref(), Some("agent"));
        assert_eq!(policy.default_ttl_seconds, Some(3600));
        assert_eq!(policy.default_max_depth, Some(2));
        assert_eq!(policy.default_kid.as_deref(), Some("key-2025"));
        assert_eq!(policy.tools.len(), 2);
        let grant = policy.grant("read_file").unwrap();
        assert_eq!(grant.arg_keys, vec!["path", "limit"]);
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("path"),
            Some(&Constraint::Prefix("/tmp/".into()))
        );
    }

    #[test]
    fn from_json_rejects_malformed() {
        let err = Policy::from_json("{not json").unwrap_err();
        assert!(matches!(err, PolicyError::InvalidJson(_)));
    }

    #[test]
    fn validate_unknown_version() {
        let policy = Policy::from_json(r#"{"version":"9","tools":[]}"#).unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::UnknownVersion {
                version: "9".into()
            })
        );
    }

    #[test]
    fn validate_duplicate_tool_names() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [
                    {"name": "read_file", "arg_keys": ["path"]},
                    {"name": "read_file", "arg_keys": ["limit"]}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::DuplicateTool {
                name: "read_file".into()
            })
        );
    }

    #[test]
    fn validate_constraint_key_not_in_allowlist() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {"offset": {"type": "max_len", "value": 8}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::ConstraintKeyNotAllowed {
                tool: "read_file".into(),
                key: "offset".into()
            })
        );
    }

    #[test]
    fn validate_empty_suffix_and_contains_are_rejected() {
        let suffix = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "suffix", "value": ""}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            suffix.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "name".into()
            })
        );

        let contains = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {"path": {"type": "contains", "value": ""}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            contains.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "path".into()
            })
        );
    }

    #[test]
    fn from_json_parses_min_len_and_matches() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name", "query"],
                    "constraints": {
                        "name": {"type": "matches", "value": "*.txt"},
                        "query": {"type": "min_len", "value": 3}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("read_file").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("name"),
            Some(&Constraint::Matches("*.txt".into()))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("query"),
            Some(&Constraint::MinLen(3))
        );
    }

    #[test]
    fn validate_empty_matches_is_rejected() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "matches", "value": ""}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "name".into()
            })
        );
    }

    #[test]
    fn from_json_parses_not_equals_and_not_one_of() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["role", "mode"],
                    "constraints": {
                        "role": {"type": "not_equals", "value": "admin"},
                        "mode": {"type": "not_one_of", "value": ["admin", "root"]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("role"),
            Some(&Constraint::NotEquals("admin".into()))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("mode"),
            Some(&Constraint::NotOneOf(vec!["admin".into(), "root".into()]))
        );
    }

    #[test]
    fn from_json_parses_not_contains_and_not_prefix() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["note", "path"],
                    "constraints": {
                        "note": {"type": "not_contains", "value": "secret"},
                        "path": {"type": "not_prefix", "value": "/tmp/"}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("read_file").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("note"),
            Some(&Constraint::NotContains("secret".into()))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("path"),
            Some(&Constraint::NotPrefix("/tmp/".into()))
        );
    }

    #[test]
    fn validate_empty_not_contains_and_not_prefix_are_rejected() {
        let contains = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["note"],
                    "constraints": {"note": {"type": "not_contains", "value": ""}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            contains.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "note".into()
            })
        );

        let prefix = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {"path": {"type": "not_prefix", "value": ""}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            prefix.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "path".into()
            })
        );
    }

    #[test]
    fn from_json_parses_not_suffix_and_not_matches() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name", "file"],
                    "constraints": {
                        "name": {"type": "not_suffix", "value": ".bak"},
                        "file": {"type": "not_matches", "value": "*.tmp"}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("read_file").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("name"),
            Some(&Constraint::NotSuffix(".bak".into()))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("file"),
            Some(&Constraint::NotMatches("*.tmp".into()))
        );
    }

    #[test]
    fn validate_empty_not_suffix_and_not_matches_are_rejected() {
        let suffix = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "not_suffix", "value": ""}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            suffix.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "name".into()
            })
        );

        let matches = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["file"],
                    "constraints": {"file": {"type": "not_matches", "value": ""}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            matches.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "file".into()
            })
        );
    }

    #[test]
    fn from_json_parses_all_and_any() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path", "name"],
                    "constraints": {
                        "path": {
                            "type": "all",
                            "value": [
                                {"type": "prefix", "value": "/tmp/"},
                                {"type": "suffix", "value": ".txt"}
                            ]
                        },
                        "name": {
                            "type": "any",
                            "value": [
                                {"type": "suffix", "value": ".md"},
                                {"type": "suffix", "value": ".txt"}
                            ]
                        }
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("read_file").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("path"),
            Some(&Constraint::All(vec![
                Constraint::Prefix("/tmp/".into()),
                Constraint::Suffix(".txt".into())
            ]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("name"),
            Some(&Constraint::Any(vec![
                Constraint::Suffix(".md".into()),
                Constraint::Suffix(".txt".into())
            ]))
        );
    }

    #[test]
    fn from_json_parses_not() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {
                        "path": {
                            "type": "not",
                            "value": {"type": "prefix", "value": "/tmp/"}
                        }
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("read_file").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("path"),
            Some(&Constraint::Not(Box::new(Constraint::Prefix(
                "/tmp/".into()
            ))))
        );
    }

    #[test]
    fn from_json_parses_float_range() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "score_tool",
                    "arg_keys": ["score"],
                    "constraints": {
                        "score": {"type": "float_range", "value": {"min": 0.5, "max": 10.5}}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("score_tool").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("score"),
            Some(&Constraint::FloatRange {
                min: 0.5,
                max: 10.5
            })
        );
    }

    #[test]
    fn validate_inverted_float_range_is_rejected() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "score_tool",
                    "arg_keys": ["score"],
                    "constraints": {
                        "score": {"type": "float_range", "value": {"min": 10.5, "max": 0.5}}
                    }
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::InvalidConstraintRange {
                tool: "score_tool".into(),
                key: "score".into()
            })
        );
    }

    #[test]
    fn from_json_parses_len_range() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "search",
                    "arg_keys": ["query"],
                    "constraints": {
                        "query": {"type": "len_range", "value": {"min": 1, "max": 16}}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("search").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("query"),
            Some(&Constraint::LenRange { min: 1, max: 16 })
        );
    }

    #[test]
    fn validate_inverted_len_range_is_rejected() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "search",
                    "arg_keys": ["query"],
                    "constraints": {
                        "query": {"type": "len_range", "value": {"min": 16, "max": 1}}
                    }
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::InvalidConstraintRange {
                tool: "search".into(),
                key: "query".into()
            })
        );
    }

    #[test]
    fn from_json_parses_char_len_range() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "search",
                    "arg_keys": ["query"],
                    "constraints": {
                        "query": {"type": "char_len_range", "value": {"min": 1, "max": 16}}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("search").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("query"),
            Some(&Constraint::CharLenRange { min: 1, max: 16 })
        );
    }

    #[test]
    fn validate_inverted_char_len_range_is_rejected() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "search",
                    "arg_keys": ["query"],
                    "constraints": {
                        "query": {"type": "char_len_range", "value": {"min": 16, "max": 1}}
                    }
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::InvalidConstraintRange {
                tool: "search".into(),
                key: "query".into()
            })
        );
    }

    #[test]
    fn validate_empty_all_and_any_are_rejected() {
        let all = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {"path": {"type": "all", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            all.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "path".into()
            })
        );

        let any = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "any", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            any.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "name".into()
            })
        );
    }

    #[test]
    fn validate_empty_not_child_is_rejected() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {"path": {"type": "not", "value": {"type": "suffix", "value": ""}}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "path".into()
            })
        );
    }

    #[test]
    fn validate_all_any_nesting_too_deep_is_rejected() {
        let mut inner = serde_json::json!({"type": "prefix", "value": "/tmp/"});
        for _ in 0..9 {
            inner = serde_json::json!({"type": "all", "value": [inner]});
        }
        let doc = serde_json::json!({
            "version": "1",
            "tools": [{
                "name": "read_file",
                "arg_keys": ["path"],
                "constraints": {"path": inner}
            }]
        });
        let policy = Policy::from_json(&doc.to_string()).unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::ConstraintNestingTooDeep {
                tool: "read_file".into(),
                key: "path".into()
            })
        );
    }

    #[test]
    fn validate_not_nesting_too_deep_is_rejected() {
        let mut inner = serde_json::json!({"type": "prefix", "value": "/tmp/"});
        for _ in 0..9 {
            inner = serde_json::json!({"type": "not", "value": inner});
        }
        let doc = serde_json::json!({
            "version": "1",
            "tools": [{
                "name": "read_file",
                "arg_keys": ["path"],
                "constraints": {"path": inner}
            }]
        });
        let policy = Policy::from_json(&doc.to_string()).unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::ConstraintNestingTooDeep {
                tool: "read_file".into(),
                key: "path".into()
            })
        );
    }

    #[test]
    fn validate_empty_not_one_of_is_rejected() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["role"],
                    "constraints": {"role": {"type": "not_one_of", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "file_op".into(),
                key: "role".into()
            })
        );
    }

    #[test]
    fn from_json_parses_prefix_one_of_and_suffix_one_of() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["path", "name"],
                    "constraints": {
                        "path": {"type": "prefix_one_of", "value": ["/tmp/", "/var/"]},
                        "name": {"type": "suffix_one_of", "value": [".txt", ".md"]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("path"),
            Some(&Constraint::PrefixOneOf(vec![
                "/tmp/".into(),
                "/var/".into()
            ]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("name"),
            Some(&Constraint::SuffixOneOf(vec![".txt".into(), ".md".into()]))
        );
    }

    #[test]
    fn validate_empty_prefix_one_of_and_suffix_one_of_are_rejected() {
        let empty_list = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {"path": {"type": "prefix_one_of", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_list.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "path".into()
            })
        );

        let empty_member = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "write_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "suffix_one_of", "value": [".txt", ""]}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_member.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "write_file".into(),
                key: "name".into()
            })
        );
    }

    #[test]
    fn from_json_parses_contains_any_and_contains_none() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "note_op",
                    "arg_keys": ["note", "memo"],
                    "constraints": {
                        "note": {"type": "contains_any", "value": ["tmp", "var"]},
                        "memo": {"type": "contains_none", "value": ["secret", "password"]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("note_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("note"),
            Some(&Constraint::ContainsAny(vec!["tmp".into(), "var".into()]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("memo"),
            Some(&Constraint::ContainsNone(vec![
                "secret".into(),
                "password".into()
            ]))
        );
    }

    #[test]
    fn from_json_parses_matches_any_and_matches_none() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["file", "skip"],
                    "constraints": {
                        "file": {"type": "matches_any", "value": ["*.txt", "*.md"]},
                        "skip": {"type": "matches_none", "value": ["*.tmp", "*.bak"]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("file"),
            Some(&Constraint::MatchesAny(vec!["*.txt".into(), "*.md".into()]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("skip"),
            Some(&Constraint::MatchesNone(vec![
                "*.tmp".into(),
                "*.bak".into()
            ]))
        );
    }

    #[test]
    fn validate_empty_matches_any_and_matches_none_are_rejected() {
        let empty_list = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["file"],
                    "constraints": {"file": {"type": "matches_any", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_list.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "file".into()
            })
        );

        let empty_member = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["skip"],
                    "constraints": {"skip": {"type": "matches_none", "value": ["*.tmp", ""]}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_member.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "skip".into()
            })
        );
    }

    #[test]
    fn from_json_parses_prefix_none_and_suffix_none() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["dest", "name"],
                    "constraints": {
                        "dest": {"type": "prefix_none", "value": ["/etc/", "/root/"]},
                        "name": {"type": "suffix_none", "value": [".bak", ".tmp"]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("dest"),
            Some(&Constraint::PrefixNone(vec![
                "/etc/".into(),
                "/root/".into()
            ]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("name"),
            Some(&Constraint::SuffixNone(vec![".bak".into(), ".tmp".into()]))
        );
    }

    #[test]
    fn validate_empty_prefix_none_and_suffix_none_are_rejected() {
        let empty_list = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["dest"],
                    "constraints": {"dest": {"type": "prefix_none", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_list.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "dest".into()
            })
        );

        let empty_member = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "suffix_none", "value": [".bak", ""]}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_member.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "name".into()
            })
        );
    }

    #[test]
    fn from_json_parses_int_one_of_and_int_none() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["mode", "port"],
                    "constraints": {
                        "mode": {"type": "int_one_of", "value": [1, 2, 3]},
                        "port": {"type": "int_none", "value": [0, -1]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("mode"),
            Some(&Constraint::IntOneOf(vec![1, 2, 3]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("port"),
            Some(&Constraint::IntNone(vec![0, -1]))
        );
    }

    #[test]
    fn validate_empty_int_one_of_and_int_none_are_rejected() {
        let empty_one_of = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["mode"],
                    "constraints": {"mode": {"type": "int_one_of", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_one_of.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "mode".into()
            })
        );

        let empty_none = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["port"],
                    "constraints": {"port": {"type": "int_none", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_none.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "port".into()
            })
        );
    }

    #[test]
    fn from_json_parses_float_one_of_and_float_none() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["score", "bias"],
                    "constraints": {
                        "score": {"type": "float_one_of", "value": [0.5, 1.5, 2.5]},
                        "bias": {"type": "float_none", "value": [0.0, -1.0]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("score"),
            Some(&Constraint::FloatOneOf(vec![0.5, 1.5, 2.5]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("bias"),
            Some(&Constraint::FloatNone(vec![0.0, -1.0]))
        );
    }

    #[test]
    fn validate_empty_float_one_of_and_float_none_are_rejected() {
        let empty_one_of = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["score"],
                    "constraints": {"score": {"type": "float_one_of", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_one_of.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "score".into()
            })
        );

        let empty_none = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["bias"],
                    "constraints": {"bias": {"type": "float_none", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_none.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "bias".into()
            })
        );
    }

    #[test]
    fn from_json_parses_len_one_of_and_len_none() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["pin", "name"],
                    "constraints": {
                        "pin": {"type": "len_one_of", "value": [4, 8, 16]},
                        "name": {"type": "len_none", "value": [0, 1]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("pin"),
            Some(&Constraint::LenOneOf(vec![4, 8, 16]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("name"),
            Some(&Constraint::LenNone(vec![0, 1]))
        );
    }

    #[test]
    fn validate_empty_len_one_of_and_len_none_are_rejected() {
        let empty_one_of = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["pin"],
                    "constraints": {"pin": {"type": "len_one_of", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_one_of.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "pin".into()
            })
        );

        let empty_none = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "len_none", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_none.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "name".into()
            })
        );
    }

    #[test]
    fn from_json_parses_min_char_len_and_max_char_len() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["title", "blurb"],
                    "constraints": {
                        "title": {"type": "min_char_len", "value": 3},
                        "blurb": {"type": "max_char_len", "value": 16}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("title"),
            Some(&Constraint::MinCharLen(3))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("blurb"),
            Some(&Constraint::MaxCharLen(16))
        );
    }

    #[test]
    fn from_json_parses_min_int_and_max_int() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["limit", "offset"],
                    "constraints": {
                        "limit": {"type": "min_int", "value": 1},
                        "offset": {"type": "max_int", "value": 100}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("limit"),
            Some(&Constraint::MinInt(1))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("offset"),
            Some(&Constraint::MaxInt(100))
        );
    }

    #[test]
    fn from_json_parses_min_float_and_max_float() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "score_tool",
                    "arg_keys": ["floor", "ceiling"],
                    "constraints": {
                        "floor": {"type": "min_float", "value": 0.5},
                        "ceiling": {"type": "max_float", "value": 10.5}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("score_tool").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("floor"),
            Some(&Constraint::MinFloat(0.5))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("ceiling"),
            Some(&Constraint::MaxFloat(10.5))
        );
    }

    #[test]
    fn from_json_parses_exclusive_min_float_and_exclusive_max_float() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "score_tool",
                    "arg_keys": ["open_floor", "open_ceiling"],
                    "constraints": {
                        "open_floor": {"type": "exclusive_min_float", "value": 0.5},
                        "open_ceiling": {"type": "exclusive_max_float", "value": 10.5}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("score_tool").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("open_floor"),
            Some(&Constraint::ExclusiveMinFloat(0.5))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("open_ceiling"),
            Some(&Constraint::ExclusiveMaxFloat(10.5))
        );
    }

    #[test]
    fn from_json_parses_exclusive_min_int_and_exclusive_max_int() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["open_retries", "open_cap"],
                    "constraints": {
                        "open_retries": {"type": "exclusive_min_int", "value": 1},
                        "open_cap": {"type": "exclusive_max_int", "value": 100}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("open_retries"),
            Some(&Constraint::ExclusiveMinInt(1))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("open_cap"),
            Some(&Constraint::ExclusiveMaxInt(100))
        );
    }

    #[test]
    fn from_json_parses_exclusive_min_len_and_exclusive_max_len() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["open_query", "open_body"],
                    "constraints": {
                        "open_query": {"type": "exclusive_min_len", "value": 0},
                        "open_body": {"type": "exclusive_max_len", "value": 256}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("open_query"),
            Some(&Constraint::ExclusiveMinLen(0))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("open_body"),
            Some(&Constraint::ExclusiveMaxLen(256))
        );
    }

    #[test]
    fn validate_non_finite_min_float_is_rejected() {
        let mut policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "score_tool",
                    "arg_keys": ["score"],
                    "constraints": {
                        "score": {"type": "min_float", "value": 1.0}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.tools[0]
            .constraints
            .as_mut()
            .unwrap()
            .insert("score".to_string(), Constraint::MinFloat(f64::NAN));
        assert_eq!(
            policy.validate(),
            Err(PolicyError::InvalidConstraintRange {
                tool: "score_tool".into(),
                key: "score".into()
            })
        );
    }

    #[test]
    fn validate_non_finite_exclusive_min_float_is_rejected() {
        let mut policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "score_tool",
                    "arg_keys": ["score"],
                    "constraints": {
                        "score": {"type": "exclusive_min_float", "value": 1.0}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.tools[0]
            .constraints
            .as_mut()
            .unwrap()
            .insert("score".to_string(), Constraint::ExclusiveMinFloat(f64::NAN));
        assert_eq!(
            policy.validate(),
            Err(PolicyError::InvalidConstraintRange {
                tool: "score_tool".into(),
                key: "score".into()
            })
        );
    }

    #[test]
    fn invalid_constraint_range_message_names_exclusive_float_bounds() {
        let err = PolicyError::InvalidConstraintRange {
            tool: "score_tool".into(),
            key: "score".into(),
        };
        let message = err.to_string();
        assert!(
            message.contains("exclusive_min_float"),
            "missing exclusive_min_float: {message}"
        );
        assert!(
            message.contains("exclusive_max_float"),
            "missing exclusive_max_float: {message}"
        );
        assert!(
            message.contains("float bounds and list members must be finite"),
            "missing finite-bound guidance: {message}"
        );
    }

    #[test]
    fn from_json_parses_char_len_one_of_and_char_len_none() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "file_op",
                    "arg_keys": ["pin", "name"],
                    "constraints": {
                        "pin": {"type": "char_len_one_of", "value": [4, 8, 16]},
                        "name": {"type": "char_len_none", "value": [0, 1]}
                    }
                }]
            }"#,
        )
        .unwrap();
        policy.validate().unwrap();
        let grant = policy.grant("file_op").unwrap();
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("pin"),
            Some(&Constraint::CharLenOneOf(vec![4, 8, 16]))
        );
        assert_eq!(
            grant.constraints.as_ref().unwrap().get("name"),
            Some(&Constraint::CharLenNone(vec![0, 1]))
        );
    }

    #[test]
    fn validate_empty_char_len_one_of_and_char_len_none_are_rejected() {
        let empty_one_of = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["pin"],
                    "constraints": {"pin": {"type": "char_len_one_of", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_one_of.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "pin".into()
            })
        );

        let empty_none = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["name"],
                    "constraints": {"name": {"type": "char_len_none", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_none.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "read_file".into(),
                key: "name".into()
            })
        );
    }

    #[test]
    fn validate_empty_contains_any_and_contains_none_are_rejected() {
        let empty_list = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "search",
                    "arg_keys": ["note"],
                    "constraints": {"note": {"type": "contains_any", "value": []}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_list.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "search".into(),
                key: "note".into()
            })
        );

        let empty_member = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "write_note",
                    "arg_keys": ["memo"],
                    "constraints": {"memo": {"type": "contains_none", "value": ["secret", ""]}}
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            empty_member.validate(),
            Err(PolicyError::EmptyConstraintPattern {
                tool: "write_note".into(),
                key: "memo".into()
            })
        );
    }

    #[test]
    fn validate_zero_default_ttl() {
        let policy =
            Policy::from_json(r#"{"version":"1","default_ttl_seconds":0,"tools":[]}"#).unwrap();
        assert_eq!(policy.validate(), Err(PolicyError::ZeroTtl { tool: None }));
    }

    #[test]
    fn validate_zero_grant_ttl() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{"name": "ping", "ttl_seconds": 0}]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::ZeroTtl {
                tool: Some("ping".into())
            })
        );
    }

    #[test]
    fn validate_empty_tool_name() {
        let policy = Policy::from_json(r#"{"version":"1","tools":[{"name":""}]}"#).unwrap();
        assert_eq!(policy.validate(), Err(PolicyError::EmptyToolName));
    }

    #[test]
    fn validate_collects_multiple_errors() {
        let policy = Policy::from_json(
            r#"{
                "version": "2",
                "default_ttl_seconds": 0,
                "tools": [
                    {"name": ""},
                    {"name": "a"},
                    {"name": "a"}
                ]
            }"#,
        )
        .unwrap();
        let err = policy.validate().unwrap_err();
        match err {
            PolicyError::Multiple(errors) => {
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, PolicyError::UnknownVersion { .. })));
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, PolicyError::ZeroTtl { tool: None })));
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, PolicyError::EmptyToolName)));
                assert!(errors
                    .iter()
                    .any(|e| matches!(e, PolicyError::DuplicateTool { .. })));
            }
            other => panic!("expected Multiple, got {other:?}"),
        }
    }

    #[test]
    fn mint_applies_defaults() {
        let policy = sample_policy();
        let token = policy.mint("read_file", SECRET, NOW).unwrap();
        assert_eq!(token.tool_name, "read_file");
        assert_eq!(token.arg_keys, vec!["path", "limit"]);
        assert_eq!(token.expiry, NOW + 3600);
        assert_eq!(token.audience.as_deref(), Some("agent"));
        assert_eq!(token.max_depth, Some(2));
        assert_eq!(token.kid.as_deref(), Some("key-2025"));
        assert_eq!(
            token.constraints.as_ref().unwrap().get("path"),
            Some(&Constraint::Prefix("/tmp/".into()))
        );
        assert!(token.verify(SECRET, NOW).is_ok());
    }

    #[test]
    fn mint_grant_overrides_defaults() {
        let policy = sample_policy();
        let token = policy.mint("ping", SECRET, NOW).unwrap();
        assert_eq!(token.expiry, NOW + 60);
        assert_eq!(token.audience.as_deref(), Some("monitor"));
        assert_eq!(token.max_depth, Some(0));
        assert_eq!(token.kid.as_deref(), Some("key-2025"));
        assert!(token.arg_keys.is_empty());
    }

    #[test]
    fn mint_unknown_tool() {
        let policy = sample_policy();
        let err = policy.mint("write_file", SECRET, NOW).unwrap_err();
        assert_eq!(
            err,
            PolicyError::UnknownTool {
                name: "write_file".into()
            }
        );
    }

    #[test]
    fn mint_missing_ttl() {
        let policy =
            Policy::from_json(r#"{"version":"1","tools":[{"name":"ping","arg_keys":[]}]}"#)
                .unwrap();
        let err = policy.mint("ping", SECRET, NOW).unwrap_err();
        assert_eq!(
            err,
            PolicyError::MissingTtl {
                tool: "ping".into()
            }
        );
    }

    #[test]
    fn mint_with_keyring_uses_active_key() {
        let policy = sample_policy();
        let mut keyring = Keyring::new();
        keyring.add("active-1", SECRET.to_vec());
        let token = policy
            .mint_with_keyring("read_file", &keyring, NOW)
            .unwrap();
        assert_eq!(token.kid.as_deref(), Some("active-1"));
        assert_eq!(token.expiry, NOW + 3600);
        assert!(keyring.verify(&token, NOW).is_ok());
    }

    #[test]
    fn mint_with_keyring_requires_active_key() {
        let policy = sample_policy();
        let keyring = Keyring::new();
        let err = policy
            .mint_with_keyring("read_file", &keyring, NOW)
            .unwrap_err();
        assert_eq!(err, PolicyError::NoActiveKey);
    }

    #[test]
    fn check_call_allows_when_policy_unchanged() {
        let policy = sample_policy();
        let token = policy.mint("read_file", SECRET, NOW).unwrap();
        let mut args = BTreeMap::new();
        args.insert("path".into(), "/tmp/a.txt".into());
        args.insert("limit".into(), "10".into());
        let verifier = Verifier::new(SECRET).at(NOW);
        assert!(policy
            .check_call_with_args(&verifier, &token, "read_file", &args)
            .is_ok());
    }

    #[test]
    fn tightening_policy_denies_broader_token() {
        let broad = sample_policy();
        let token = broad.mint("read_file", SECRET, NOW).unwrap();
        assert!(token
            .verify_call(SECRET, NOW, "read_file", &["path"], None)
            .is_ok());

        let tight = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 3600,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "constraints": {
                        "path": {"type": "prefix", "value": "/tmp/"}
                    }
                }]
            }"#,
        )
        .unwrap();
        let verifier = Verifier::new(SECRET).at(NOW);
        let err = tight
            .check_call(&verifier, &token, "read_file", &["path"])
            .unwrap_err();
        assert!(matches!(err, TokenError::ArgKeyNotAllowed { key } if key == "limit"));
    }

    #[test]
    fn tightening_constraint_denies_broader_token() {
        let broad = sample_policy();
        let token = broad.mint("read_file", SECRET, NOW).unwrap();

        let tight = Policy::from_json(
            r#"{
                "version": "1",
                "default_audience": "agent",
                "default_ttl_seconds": 3600,
                "default_max_depth": 2,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path", "limit"],
                    "constraints": {
                        "path": {"type": "prefix", "value": "/tmp/subdir/"},
                        "limit": {"type": "int_range", "value": {"min": 1, "max": 100}}
                    }
                }]
            }"#,
        )
        .unwrap();
        let verifier = Verifier::new(SECRET).at(NOW);
        let err = tight
            .check_call(&verifier, &token, "read_file", &["path"])
            .unwrap_err();
        assert!(matches!(err, TokenError::PolicyDenied { .. }));
        assert_eq!(err.kind(), "policy_denied");
    }

    #[test]
    fn removing_tool_denies_old_token() {
        let policy = sample_policy();
        let token = policy.mint("ping", SECRET, NOW).unwrap();
        let empty =
            Policy::from_json(r#"{"version":"1","default_ttl_seconds":60,"tools":[]}"#).unwrap();
        let verifier = Verifier::new(SECRET).at(NOW);
        let err = empty
            .check_call(&verifier, &token, "ping", &[])
            .unwrap_err();
        assert!(matches!(err, TokenError::PolicyDenied { .. }));
    }

    #[test]
    fn check_call_records_exactly_one_allow_decision() {
        let policy = sample_policy();
        let token = policy.mint("read_file", SECRET, NOW).unwrap();
        let sink = MemoryAuditSink::new();
        let verifier = Verifier::new(SECRET).at(NOW).audit(&sink);
        policy
            .check_call(&verifier, &token, "read_file", &["path"])
            .unwrap();
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.decisions()[0].outcome, Outcome::Allow);
        assert_eq!(sink.decisions()[0].tool_name.as_deref(), Some("read_file"));
    }

    #[test]
    fn check_call_records_exactly_one_deny_decision() {
        let policy = sample_policy();
        let token = policy.mint("read_file", SECRET, NOW).unwrap();
        let tight = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 3600,
                "tools": [{"name": "read_file", "arg_keys": ["path"]}]
            }"#,
        )
        .unwrap();
        let sink = MemoryAuditSink::new();
        let verifier = Verifier::new(SECRET).at(NOW).audit(&sink);
        let err = tight
            .check_call(&verifier, &token, "read_file", &["path"])
            .unwrap_err();
        assert!(matches!(err, TokenError::ArgKeyNotAllowed { .. }));
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.decisions()[0].outcome, Outcome::Deny);
        assert_eq!(
            sink.decisions()[0].error_kind.as_deref(),
            Some("arg_key_not_allowed")
        );
    }

    fn temp_policy_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "toolgate-policy-{}-{}-{}.json",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn bump_mtime(path: &Path) {
        let meta = fs::metadata(path).unwrap();
        let newer = meta
            .modified()
            .unwrap()
            .checked_add(std::time::Duration::from_secs(2))
            .unwrap();
        let handle = fs::File::options().write(true).open(path).unwrap();
        handle.set_modified(newer).unwrap();
    }

    fn broad_policy_json() -> &'static str {
        r#"{
            "version": "1",
            "default_ttl_seconds": 3600,
            "tools": [{
                "name": "read_file",
                "arg_keys": ["path", "limit"]
            }]
        }"#
    }

    fn tight_policy_json() -> &'static str {
        r#"{
            "version": "1",
            "default_ttl_seconds": 3600,
            "tools": [{
                "name": "read_file",
                "arg_keys": ["path"]
            }]
        }"#
    }

    #[test]
    fn policy_reload_if_changed_picks_up_tightening() {
        let path = temp_policy_path("reload");
        fs::write(&path, broad_policy_json()).unwrap();
        let mut file = PolicyFile::load(&path).unwrap();
        assert!(file.policy().grant("read_file").unwrap().arg_keys.len() == 2);
        assert!(!file.reload_if_changed());

        fs::write(&path, tight_policy_json()).unwrap();
        bump_mtime(&path);

        assert!(file.reload_if_changed());
        assert_eq!(
            file.policy().grant("read_file").unwrap().arg_keys,
            vec!["path"]
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn policy_bad_reload_keeps_old() {
        let path = temp_policy_path("bad-reload");
        fs::write(&path, broad_policy_json()).unwrap();
        let mut file = PolicyFile::load(&path).unwrap();
        assert!(file.policy().grant("read_file").is_some());

        fs::write(&path, r#"{"version":"9","tools":[]}"#).unwrap();
        bump_mtime(&path);

        assert!(!file.reload_if_changed());
        assert_eq!(file.policy().version, POLICY_VERSION);
        assert!(file.policy().grant("read_file").is_some());
        assert!(!file.reload_if_changed());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn validate_required_key_not_in_allowlist() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "required_keys": ["limit"]
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::RequiredKeyNotAllowed {
                tool: "read_file".into(),
                key: "limit".into()
            })
        );
    }

    #[test]
    fn validate_empty_required_key() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path"],
                    "required_keys": [""]
                }]
            }"#,
        )
        .unwrap();
        assert_eq!(
            policy.validate(),
            Err(PolicyError::RequiredKeyNotAllowed {
                tool: "read_file".into(),
                key: "".into()
            })
        );
    }

    #[test]
    fn mint_includes_grant_required_keys() {
        let policy = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path", "limit"],
                    "required_keys": ["path"]
                }]
            }"#,
        )
        .unwrap();
        let token = policy.mint("read_file", SECRET, NOW).unwrap();
        assert_eq!(token.required_keys, vec!["path"]);
        let mut args = BTreeMap::new();
        args.insert("path".into(), "/tmp/a.txt".into());
        let verifier = Verifier::new(SECRET).at(NOW);
        assert!(policy
            .check_call_with_args(&verifier, &token, "read_file", &args)
            .is_ok());
    }

    #[test]
    fn authorize_token_requires_policy_required_keys() {
        let loose = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path", "limit"]
                }]
            }"#,
        )
        .unwrap();
        let token = loose.mint("read_file", SECRET, NOW).unwrap();
        assert!(token.required_keys.is_empty());

        let tight = Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 60,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path", "limit"],
                    "required_keys": ["path"]
                }]
            }"#,
        )
        .unwrap();
        assert!(matches!(
            tight.authorize_token(&token),
            Err(TokenError::PolicyDenied { .. })
        ));
    }
}
