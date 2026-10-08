//! Helpers for checking MCP `tools/call` JSON-RPC requests against a token.
//!
//! This module inspects the request and runs verifier checks. It does not
//! dispatch the tool.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::token::{Token, TokenError};
use crate::verifier::Verifier;

/// Parsed `tools/call` fields used by the stdio gate and [`check_tools_call`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtractedCall {
    pub tool_name: String,
    pub arg_keys: Vec<String>,
    pub arguments: BTreeMap<String, String>,
    pub nested_keys: Vec<String>,
}

/// Extracted `tools/call` name and scalar argument values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallInfo {
    /// Tool name from `params.name`.
    pub tool_name: String,
    /// Scalar arguments converted to strings for constraint checks.
    ///
    /// Nested object/array values on unconstrained keys are omitted here
    /// after the key has been checked against the token allowlist.
    pub arguments: BTreeMap<String, String>,
}

/// Return `params._meta.toolgate` when it is a string.
pub fn token_string_from_meta(request: &Value) -> Option<&str> {
    request
        .get("params")
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get("toolgate"))
        .and_then(Value::as_str)
}

/// Parse `params._meta.toolgate` as a `tg1.` string or a JSON token object.
///
/// Returns `None` when the field is absent. A present but unusable value is
/// `Some(Err(TokenError::MalformedRequest))`.
pub fn token_from_meta(request: &Value) -> Option<Result<Token, TokenError>> {
    let raw = request.get("params")?.get("_meta")?.get("toolgate")?;
    Some(parse_meta_token(raw))
}

fn parse_meta_token(raw: &Value) -> Result<Token, TokenError> {
    match raw {
        Value::String(s) => Token::from_token_string(s).map_err(|_| TokenError::MalformedRequest),
        obj if obj.is_object() => {
            serde_json::from_value(obj.clone()).map_err(|_| TokenError::MalformedRequest)
        }
        _ => Err(TokenError::MalformedRequest),
    }
}

/// Extract `params.name` and arguments from a `tools/call` request.
///
/// Does not verify a token or write an audit record.
pub(crate) fn extract_tools_call(request: &Value) -> Result<ExtractedCall, TokenError> {
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Err(TokenError::MalformedRequest);
    }

    let params = match request.get("params") {
        Some(Value::Object(map)) => map,
        _ => return Err(TokenError::MalformedRequest),
    };

    let Some(tool_name) = params.get("name").and_then(Value::as_str) else {
        return Err(TokenError::MalformedRequest);
    };

    let empty = Map::new();
    let args_obj = match params.get("arguments") {
        None => &empty,
        Some(Value::Object(map)) => map,
        Some(_) => return Err(TokenError::MalformedRequest),
    };

    let mut arguments = BTreeMap::new();
    let mut arg_keys = Vec::with_capacity(args_obj.len());
    let mut nested_keys = Vec::new();

    for (key, value) in args_obj {
        arg_keys.push(key.clone());
        match scalar_to_string(value) {
            Some(converted) => {
                arguments.insert(key.clone(), converted);
            }
            None => nested_keys.push(key.clone()),
        }
    }

    Ok(ExtractedCall {
        tool_name: tool_name.to_string(),
        arg_keys,
        arguments,
        nested_keys,
    })
}

/// Verify that `token` authorizes the MCP `tools/call` in `request`.
///
/// Scalar argument values are converted to strings: strings as-is, integers
/// in decimal, booleans as `true`/`false`. Nested object or array values are
/// allowed only on unconstrained keys (for allowlist checking). A nested
/// value on a constrained key is [`TokenError::MalformedRequest`].
pub fn check_tools_call(
    verifier: &Verifier<'_>,
    token: &Token,
    request: &Value,
) -> Result<CallInfo, TokenError> {
    let extracted = match extract_tools_call(request) {
        Ok(extracted) => extracted,
        Err(err) => {
            verifier.record(token, None, None, &Err(err.clone()));
            return Err(err);
        }
    };

    for key in &extracted.nested_keys {
        if has_constraint(token, key) {
            let err = TokenError::MalformedRequest;
            verifier.record(
                token,
                Some(extracted.tool_name.as_str()),
                None,
                &Err(err.clone()),
            );
            return Err(err);
        }
    }

    let keys: Vec<&str> = extracted.arg_keys.iter().map(String::as_str).collect();
    verifier.verify_extracted_call(token, &extracted.tool_name, &keys, &extracted.arguments)?;

    Ok(CallInfo {
        tool_name: extracted.tool_name,
        arguments: extracted.arguments,
    })
}

pub(crate) fn has_constraint(token: &Token, key: &str) -> bool {
    token
        .constraints
        .as_ref()
        .is_some_and(|constraints| constraints.contains_key(key))
}

fn scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Bool(true) => Some("true".to_string()),
        Value::Bool(false) => Some("false".to_string()),
        Value::Number(n) => n
            .as_i64()
            .map(|i| i.to_string())
            .or_else(|| n.as_u64().map(|u| u.to_string())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{MemoryAuditSink, Outcome, REDACTED};
    use crate::constraint::Constraint;
    use crate::Verifier;
    use serde_json::json;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";

    fn token_with_constraints() -> Token {
        let mut constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );
        Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into(), "meta".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        )
    }

    fn verifier() -> Verifier<'static> {
        Verifier::new(SECRET).at(1999999999)
    }

    fn tools_call(name: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        })
    }

    #[test]
    fn check_tools_call_good() {
        let token = token_with_constraints();
        let request = tools_call(
            "read_file",
            json!({
                "path": "/tmp/notes.txt",
                "limit": 50,
                "meta": {"extra": true}
            }),
        );
        let info = check_tools_call(&verifier(), &token, &request).unwrap();
        assert_eq!(info.tool_name, "read_file");
        assert_eq!(info.arguments.get("path").unwrap(), "/tmp/notes.txt");
        assert_eq!(info.arguments.get("limit").unwrap(), "50");
        assert!(!info.arguments.contains_key("meta"));
    }

    #[test]
    fn check_tools_call_wrong_method() {
        let token = token_with_constraints();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"name": "read_file", "arguments": {}}
        });
        assert_eq!(
            check_tools_call(&verifier(), &token, &request),
            Err(TokenError::MalformedRequest)
        );
    }

    #[test]
    fn check_tools_call_missing_name() {
        let token = token_with_constraints();
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {"path": "/tmp/a"}}
        });
        assert_eq!(
            check_tools_call(&verifier(), &token, &request),
            Err(TokenError::MalformedRequest)
        );
    }

    #[test]
    fn check_tools_call_wrong_tool() {
        let token = token_with_constraints();
        let request = tools_call("write_file", json!({"path": "/tmp/a"}));
        assert!(matches!(
            check_tools_call(&verifier(), &token, &request),
            Err(TokenError::ToolMismatch { .. })
        ));
    }

    #[test]
    fn check_tools_call_disallowed_key() {
        let token = token_with_constraints();
        let request = tools_call("read_file", json!({"path": "/tmp/a", "secret": "nope"}));
        assert!(matches!(
            check_tools_call(&verifier(), &token, &request),
            Err(TokenError::ArgKeyNotAllowed { key }) if key == "secret"
        ));
    }

    #[test]
    fn check_tools_call_integer_constraint_violation() {
        let token = token_with_constraints();
        let request = tools_call("read_file", json!({"path": "/tmp/a", "limit": 200}));
        assert!(matches!(
            check_tools_call(&verifier(), &token, &request),
            Err(TokenError::ConstraintViolation { key }) if key == "limit"
        ));
    }

    #[test]
    fn check_tools_call_nested_value_under_constrained_key() {
        let token = token_with_constraints();
        let request = tools_call("read_file", json!({"path": {"nested": true}, "limit": 10}));
        assert_eq!(
            check_tools_call(&verifier(), &token, &request),
            Err(TokenError::MalformedRequest)
        );
    }

    #[test]
    fn token_string_from_meta_reads_toolgate_field() {
        let request = json!({
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {},
                "_meta": {"toolgate": "tg1.abc"}
            }
        });
        assert_eq!(token_string_from_meta(&request), Some("tg1.abc"));
        assert_eq!(
            token_string_from_meta(&json!({"method": "tools/call"})),
            None
        );
    }

    #[test]
    fn check_tools_call_converts_bool_scalars() {
        let token = Token::mint(SECRET, "toggle", vec!["flag".into()], 2000000000);
        let request = tools_call("toggle", json!({"flag": true}));
        let info = check_tools_call(&verifier(), &token, &request).unwrap();
        assert_eq!(info.arguments.get("flag").unwrap(), "true");
    }

    #[test]
    fn check_tools_call_records_allow_with_redacted_args() {
        let token = token_with_constraints();
        let sink = MemoryAuditSink::new();
        let verifier = Verifier::new(SECRET).at(1999999999).audit(&sink);
        let request = tools_call("read_file", json!({"path": "/tmp/notes.txt", "limit": 50}));
        check_tools_call(&verifier, &token, &request).unwrap();
        assert_eq!(sink.len(), 1);
        let decision = &sink.decisions()[0];
        assert_eq!(decision.outcome, Outcome::Allow);
        assert_eq!(decision.tool_name.as_deref(), Some("read_file"));
        assert_eq!(decision.arguments.get("path").unwrap(), REDACTED);
        assert_eq!(decision.arguments.get("limit").unwrap(), REDACTED);
        assert!(!format!("{decision:?}").contains("/tmp/notes.txt"));
    }

    #[test]
    fn check_tools_call_records_malformed_request() {
        let token = token_with_constraints();
        let sink = MemoryAuditSink::new();
        let verifier = Verifier::new(SECRET).at(1999999999).audit(&sink);
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"name": "read_file", "arguments": {}}
        });
        assert_eq!(
            check_tools_call(&verifier, &token, &request),
            Err(TokenError::MalformedRequest)
        );
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.decisions()[0].outcome, Outcome::Deny);
        assert_eq!(
            sink.decisions()[0].error_kind.as_deref(),
            Some("malformed_request")
        );
    }

    #[test]
    fn check_tools_call_records_constraint_violation_once() {
        let token = token_with_constraints();
        let sink = MemoryAuditSink::new();
        let verifier = Verifier::new(SECRET).at(1999999999).audit(&sink);
        let request = tools_call("read_file", json!({"path": "/tmp/a", "limit": 200}));
        assert!(matches!(
            check_tools_call(&verifier, &token, &request),
            Err(TokenError::ConstraintViolation { key }) if key == "limit"
        ));
        assert_eq!(sink.len(), 1);
        assert_eq!(
            sink.decisions()[0].error_kind.as_deref(),
            Some("constraint_violation")
        );
    }
}
