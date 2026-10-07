//! Helpers for checking MCP `tools/call` JSON-RPC requests against a token.
//!
//! This module inspects the request and runs verifier checks. It does not
//! dispatch the tool.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::token::{Token, TokenError};
use crate::verifier::Verifier;

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
    let mut keys: Vec<&str> = Vec::with_capacity(args_obj.len());

    for (key, value) in args_obj {
        keys.push(key.as_str());
        match scalar_to_string(value) {
            Some(converted) => {
                arguments.insert(key.clone(), converted);
            }
            None => {
                if has_constraint(token, key) {
                    return Err(TokenError::MalformedRequest);
                }
            }
        }
    }

    verifier.verify_call(token, tool_name, &keys)?;

    if let Some(constraints) = &token.constraints {
        for (key, value) in &arguments {
            if let Some(constraint) = constraints.get(key) {
                if !constraint.check(value) {
                    return Err(TokenError::ConstraintViolation { key: key.clone() });
                }
            }
        }
    }

    Ok(CallInfo {
        tool_name: tool_name.to_string(),
        arguments,
    })
}

fn has_constraint(token: &Token, key: &str) -> bool {
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
