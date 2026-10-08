//! Line-oriented stdio MCP gate types and JSON-RPC error codes.
//!
//! [`decide`] inspects one newline-delimited JSON-RPC message. It does no I/O.

use serde_json::{json, Map, Value};

use crate::mcp::{extract_tools_call, has_constraint, token_from_meta};
use crate::policy::Policy;
use crate::token::TokenError;
use crate::verifier::Verifier;

/// JSON-RPC 2.0 parse error (`error.code`).
pub const JSONRPC_PARSE_ERROR: i64 = -32700;

/// JSON-RPC 2.0 invalid request (`error.code`). Used for unsupported batches.
pub const JSONRPC_INVALID_REQUEST: i64 = -32600;

/// Stable application `error.code` for a denied or unauthenticated `tools/call`.
pub const JSONRPC_TOOLGATE_DENIED: i64 = -32040;

/// What to do with one client JSON-RPC line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateAction {
    /// Pass this JSON-RPC text to the downstream server (no trailing newline).
    Forward(String),
    /// Write this JSON-RPC error response to the client.
    Respond(Value),
    /// Discard a denied `tools/call` notification (no `id`).
    Drop,
}

/// JSON-RPC error object with optional `data.error_kind`.
pub fn jsonrpc_error(
    id: Value,
    code: i64,
    message: impl Into<String>,
    error_kind: Option<&str>,
) -> Value {
    let mut error = Map::new();
    error.insert("code".into(), json!(code));
    error.insert("message".into(), json!(message.into()));
    if let Some(kind) = error_kind {
        error.insert("data".into(), json!({ "error_kind": kind }));
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": Value::Object(error),
    })
}

/// Parse-error response (`id` is null per JSON-RPC 2.0).
pub fn parse_error_response() -> Value {
    jsonrpc_error(Value::Null, JSONRPC_PARSE_ERROR, "Parse error", None)
}

/// Denied `tools/call` response: same `id`, stable code, `data.error_kind`.
pub fn denied_response(id: Value, err: &TokenError) -> Value {
    jsonrpc_error(
        id,
        JSONRPC_TOOLGATE_DENIED,
        err.to_string(),
        Some(err.kind()),
    )
}

/// Inspect one newline-delimited JSON-RPC message.
///
/// Non-`tools/call` objects are forwarded unchanged. A `tools/call` must
/// carry a token at `params._meta.toolgate`. Allowed calls are forwarded
/// with that field stripped. Denied calls become a JSON-RPC error with the
/// same `id` (notifications are dropped). Malformed JSON is a parse error.
/// JSON-RPC batch arrays are rejected.
///
/// When a [`Policy`] is set, the call is checked through the policy as well
/// as [`Verifier`]. An attached [`crate::AuditSink`] records exactly one
/// [`crate::Decision`] per `tools/call`.
pub fn decide(line: &str, verifier: &Verifier<'_>, policy: Option<&Policy>) -> GateAction {
    let value: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return GateAction::Respond(parse_error_response()),
    };

    if value.is_array() {
        return GateAction::Respond(jsonrpc_error(
            Value::Null,
            JSONRPC_INVALID_REQUEST,
            "batched JSON-RPC is not supported",
            None,
        ));
    }

    if value.get("method").and_then(Value::as_str) != Some("tools/call") {
        return GateAction::Forward(line.to_string());
    }

    let id = value.get("id").cloned();
    decide_tools_call(value, id, verifier, policy)
}

fn decide_tools_call(
    value: Value,
    id: Option<Value>,
    verifier: &Verifier<'_>,
    policy: Option<&Policy>,
) -> GateAction {
    let tool_hint = value
        .get("params")
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str);

    let token = match token_from_meta(&value) {
        Some(Ok(token)) => token,
        Some(Err(err)) => {
            verifier.record_unauthenticated(tool_hint, None, &err);
            return deny_action(id, &err);
        }
        None => {
            let err = TokenError::MalformedRequest;
            verifier.record_unauthenticated(tool_hint, None, &err);
            return deny_action(id, &err);
        }
    };

    let extracted = match extract_tools_call(&value) {
        Ok(extracted) => extracted,
        Err(err) => {
            verifier.record(&token, tool_hint, None, &Err(err.clone()));
            return deny_action(id, &err);
        }
    };

    for key in &extracted.nested_keys {
        if has_constraint(&token, key) {
            let err = TokenError::MalformedRequest;
            verifier.record(
                &token,
                Some(extracted.tool_name.as_str()),
                None,
                &Err(err.clone()),
            );
            return deny_action(id, &err);
        }
    }

    let keys: Vec<&str> = extracted.arg_keys.iter().map(String::as_str).collect();
    let result = match policy {
        Some(policy) => verifier.verify_extracted_call_against_policy(
            &token,
            policy,
            &extracted.tool_name,
            &keys,
            &extracted.arguments,
        ),
        None => verifier.verify_extracted_call(
            &token,
            &extracted.tool_name,
            &keys,
            &extracted.arguments,
        ),
    };

    match result {
        Ok(()) => GateAction::Forward(strip_toolgate_meta(&value).to_string()),
        Err(err) => deny_action(id, &err),
    }
}

/// Remove `params._meta.toolgate` so the downstream server never sees the token.
///
/// An empty `_meta` object is removed as well.
pub fn strip_toolgate_meta(request: &Value) -> Value {
    let mut stripped = request.clone();
    let Some(params) = stripped.get_mut("params").and_then(Value::as_object_mut) else {
        return stripped;
    };
    let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) else {
        return stripped;
    };
    meta.remove("toolgate");
    if meta.is_empty() {
        params.remove("_meta");
    }
    stripped
}

fn deny_action(id: Option<Value>, err: &TokenError) -> GateAction {
    match id {
        Some(id) => GateAction::Respond(denied_response(id, err)),
        None => GateAction::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jsonrpc_error_shape() {
        let value = denied_response(json!(1), &TokenError::Expired);
        assert_eq!(value["error"]["code"], JSONRPC_TOOLGATE_DENIED);
        assert_eq!(value["error"]["data"]["error_kind"], "expired");
        assert_eq!(value["id"], 1);
        assert_eq!(value["jsonrpc"], "2.0");
    }

    #[test]
    fn parse_error_has_null_id_and_no_kind() {
        let value = parse_error_response();
        assert_eq!(value["id"], Value::Null);
        assert_eq!(value["error"]["code"], JSONRPC_PARSE_ERROR);
        assert!(value["error"].get("data").is_none());
    }
}
