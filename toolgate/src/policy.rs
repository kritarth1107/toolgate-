//! Declarative policy files describing which tools an agent may call.
//!
//! A policy is a JSON document: a version, optional defaults (audience, TTL,
//! max attenuation depth, key id), and a list of tool grants. Each grant
//! names a tool, the argument keys it may receive, and optional per-key
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
    /// A suffix or contains constraint has an empty needle.
    EmptyConstraintPattern { tool: String, key: String },
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
            PolicyError::EmptyConstraintPattern { tool, key } => {
                write!(
                    f,
                    "empty suffix/contains constraint for '{key}' on tool '{tool}' is rejected"
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
}
