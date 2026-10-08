//! Line-oriented stdio MCP gate types and JSON-RPC error codes.
//!
//! [`decide`] inspects one newline-delimited JSON-RPC message. It does no I/O.

use serde_json::{json, Map, Value};

use crate::mcp::{extract_tools_call, has_constraint, token_from_meta};
use crate::policy::Policy;
use crate::token::{Token, TokenError};
use crate::use_store::{UseResult, UseStore};
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
    decide_with_replay(line, verifier, policy, None)
}

/// [`decide`] plus an optional per-token use limit through [`UseStore`].
///
/// `replay` is `(store, max_uses)`. Tokens without a `jti` fail with
/// [`TokenError::MissingJti`]. A second call after the limit is
/// [`TokenError::ReplayDetected`]. The use is consumed only after the
/// verifier (and optional policy) accept the call, and the sink still
/// records exactly one decision.
pub fn decide_with_replay(
    line: &str,
    verifier: &Verifier<'_>,
    policy: Option<&Policy>,
    replay: Option<(&mut dyn UseStore, u64)>,
) -> GateAction {
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
    decide_tools_call(value, id, verifier, policy, replay)
}

fn consume_use(token: &Token, store: &mut dyn UseStore, max_uses: u64) -> Result<(), TokenError> {
    match token.jti.as_deref() {
        Some(jti) => {
            if store.try_use(jti, max_uses) == UseResult::Exceeded {
                Err(TokenError::ReplayDetected {
                    jti: jti.to_string(),
                })
            } else {
                Ok(())
            }
        }
        None => Err(TokenError::MissingJti),
    }
}

fn decide_tools_call(
    value: Value,
    id: Option<Value>,
    verifier: &Verifier<'_>,
    policy: Option<&Policy>,
    mut replay: Option<(&mut dyn UseStore, u64)>,
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
    let mut result = match policy {
        Some(policy) => verifier.authorize_extracted_call_against_policy(
            &token,
            policy,
            &extracted.tool_name,
            &keys,
            &extracted.arguments,
        ),
        None => verifier.authorize_extracted_call(
            &token,
            &extracted.tool_name,
            &keys,
            &extracted.arguments,
        ),
    };
    if result.is_ok() {
        if let Some((store, max_uses)) = replay.as_mut() {
            result = consume_use(&token, *store, *max_uses);
        }
    }
    verifier.record(
        &token,
        Some(extracted.tool_name.as_str()),
        Some(&extracted.arguments),
        &result,
    );

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
    use crate::audit::{MemoryAuditSink, Outcome};
    use crate::constraint::Constraint;
    use crate::policy::Policy;
    use crate::revocation::RevocationList;
    use crate::token::Token;
    use crate::use_store::MemoryUseStore;
    use crate::Verifier;
    use serde_json::json;
    use std::collections::BTreeMap;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";
    const NOW: u64 = 1_999_999_999;

    fn verifier() -> Verifier<'static> {
        Verifier::new(SECRET).at(NOW)
    }

    fn constrained_token() -> Token {
        let mut constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );
        Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2_000_000_000,
            None,
            None,
            Some(constraints),
        )
    }

    fn basic_token() -> Token {
        Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2_000_000_000,
        )
    }

    fn tools_call(id: Option<Value>, name: &str, arguments: Value, token: Option<Value>) -> String {
        let mut params = json!({
            "name": name,
            "arguments": arguments,
        });
        if let Some(token) = token {
            params["_meta"] = json!({ "toolgate": token });
        }
        let mut msg = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": params,
        });
        if let Some(id) = id {
            msg["id"] = id;
        }
        msg.to_string()
    }

    fn tg1_token(token: &Token) -> Value {
        json!(token.to_token_string())
    }

    fn json_token(token: &Token) -> Value {
        serde_json::to_value(token).unwrap()
    }

    fn sample_policy() -> Policy {
        Policy::from_json(
            r#"{
                "version": "1",
                "default_ttl_seconds": 3600,
                "tools": [{
                    "name": "read_file",
                    "arg_keys": ["path", "limit"],
                    "constraints": {
                        "path": {"type": "prefix", "value": "/tmp/"},
                        "limit": {"type": "int_range", "value": {"min": 1, "max": 100}}
                    }
                }]
            }"#,
        )
        .unwrap()
    }

    fn forwarded(action: GateAction) -> Value {
        match action {
            GateAction::Forward(text) => serde_json::from_str(&text).unwrap(),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    fn error_of(action: GateAction) -> Value {
        match action {
            GateAction::Respond(value) => value,
            other => panic!("expected Respond, got {other:?}"),
        }
    }

    #[test]
    fn pass_through_non_tools_call() {
        let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert_eq!(
            decide(initialize, &verifier(), None),
            GateAction::Forward(initialize.to_string())
        );

        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        assert_eq!(
            decide(list, &verifier(), None),
            GateAction::Forward(list.to_string())
        );

        let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert_eq!(
            decide(note, &verifier(), None),
            GateAction::Forward(note.to_string())
        );

        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#;
        assert_eq!(
            decide(response, &verifier(), None),
            GateAction::Forward(response.to_string())
        );
    }

    #[test]
    fn allow_and_strip_tg1_token() {
        let token = constrained_token();
        let line = tools_call(
            Some(json!(1)),
            "read_file",
            json!({"path": "/tmp/a.txt", "limit": 10}),
            Some(tg1_token(&token)),
        );
        let action = decide(&line, &verifier(), None);
        let text = action_text(&action);
        let forwarded = forwarded(action);
        assert_eq!(forwarded["method"], "tools/call");
        assert_eq!(forwarded["params"]["name"], "read_file");
        assert_eq!(forwarded["params"]["arguments"]["path"], "/tmp/a.txt");
        assert!(forwarded["params"].get("_meta").is_none());
        assert!(!text.contains("toolgate"));
        assert!(!text.contains("tg1."));
    }

    #[test]
    fn allow_and_strip_json_token() {
        let token = constrained_token();
        let line = tools_call(
            Some(json!(1)),
            "read_file",
            json!({"path": "/tmp/a.txt", "limit": 10}),
            Some(json_token(&token)),
        );
        let action = decide(&line, &verifier(), None);
        let text = action_text(&action);
        let forwarded = forwarded(action);
        assert!(forwarded["params"].get("_meta").is_none());
        assert!(!text.contains("toolgate"));
    }

    #[test]
    fn strip_keeps_other_meta_fields() {
        let token = basic_token();
        let line = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/a.txt"},
                "_meta": {
                    "toolgate": token.to_token_string(),
                    "progressToken": "p1"
                }
            }
        })
        .to_string();
        let forwarded = forwarded(decide(&line, &verifier(), None));
        assert!(forwarded["params"]["_meta"].get("toolgate").is_none());
        assert_eq!(forwarded["params"]["_meta"]["progressToken"], "p1");
    }

    #[test]
    fn missing_token_is_denied() {
        let line = tools_call(
            Some(json!(7)),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            None,
        );
        let response = error_of(decide(&line, &verifier(), None));
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], JSONRPC_TOOLGATE_DENIED);
        assert_eq!(response["error"]["data"]["error_kind"], "malformed_request");
    }

    #[test]
    fn bad_mac_is_denied() {
        let token = basic_token();
        let other = Verifier::new(b"other-secret-key-32-bytes-long!").at(NOW);
        let line = tools_call(
            Some(json!("abc")),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let response = error_of(decide(&line, &other, None));
        assert_eq!(response["id"], "abc");
        assert_eq!(response["error"]["data"]["error_kind"], "invalid_mac");
        assert_eq!(response["error"]["code"], JSONRPC_TOOLGATE_DENIED);
    }

    #[test]
    fn tool_mismatch_is_denied() {
        let token = basic_token();
        let line = tools_call(
            Some(json!(2)),
            "write_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let response = error_of(decide(&line, &verifier(), None));
        assert_eq!(response["error"]["data"]["error_kind"], "tool_mismatch");
        assert_eq!(response["id"], 2);
    }

    #[test]
    fn constraint_violation_is_denied() {
        let token = constrained_token();
        let line = tools_call(
            Some(json!(3)),
            "read_file",
            json!({"path": "/etc/passwd", "limit": 10}),
            Some(tg1_token(&token)),
        );
        let response = error_of(decide(&line, &verifier(), None));
        assert_eq!(
            response["error"]["data"]["error_kind"],
            "constraint_violation"
        );
    }

    #[test]
    fn policy_deny() {
        let token = Token::mint(SECRET, "write_file", vec!["path".into()], 2_000_000_000);
        let policy = sample_policy();
        let line = tools_call(
            Some(json!(4)),
            "write_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let response = error_of(decide(&line, &verifier(), Some(&policy)));
        assert_eq!(response["error"]["data"]["error_kind"], "policy_denied");
        assert_eq!(response["id"], 4);
    }

    #[test]
    fn notification_drop() {
        let line = tools_call(None, "read_file", json!({"path": "/tmp/a.txt"}), None);
        assert_eq!(decide(&line, &verifier(), None), GateAction::Drop);
    }

    #[test]
    fn parse_error() {
        let response = error_of(decide("{not-json", &verifier(), None));
        assert_eq!(response["id"], Value::Null);
        assert_eq!(response["error"]["code"], JSONRPC_PARSE_ERROR);
        assert!(response["error"].get("data").is_none());
    }

    #[test]
    fn id_preserved_on_deny() {
        let line = tools_call(
            Some(json!("req-9")),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            None,
        );
        let response = error_of(decide(&line, &verifier(), None));
        assert_eq!(response["id"], "req-9");
        assert_eq!(response["jsonrpc"], "2.0");
    }

    fn jti_token() -> Token {
        Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2_000_000_000,
            None,
            None,
            None,
            true,
        )
    }

    #[test]
    fn revoked_jti_is_denied() {
        let token = jti_token();
        let mut list = RevocationList::new();
        list.revoke(token.jti.clone().unwrap());
        let verifier = Verifier::new(SECRET).at(NOW).revocation(&list);
        let line = tools_call(
            Some(json!(8)),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let response = error_of(decide(&line, &verifier, None));
        assert_eq!(response["id"], 8);
        assert_eq!(response["error"]["code"], JSONRPC_TOOLGATE_DENIED);
        assert_eq!(response["error"]["data"]["error_kind"], "revoked");
    }

    #[test]
    fn revocation_list_requires_jti() {
        let token = basic_token();
        let list = RevocationList::new();
        let verifier = Verifier::new(SECRET).at(NOW).revocation(&list);
        let line = tools_call(
            Some(json!(9)),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let response = error_of(decide(&line, &verifier, None));
        assert_eq!(response["error"]["data"]["error_kind"], "missing_jti");
    }

    #[test]
    fn max_uses_allows_then_denies_replay() {
        let token = jti_token();
        let line = tools_call(
            Some(json!(10)),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let mut store = MemoryUseStore::new();
        let forwarded = forwarded(decide_with_replay(
            &line,
            &verifier(),
            None,
            Some((&mut store, 1)),
        ));
        assert_eq!(forwarded["method"], "tools/call");
        assert!(forwarded["params"].get("_meta").is_none());

        let response = error_of(decide_with_replay(
            &line,
            &verifier(),
            None,
            Some((&mut store, 1)),
        ));
        assert_eq!(response["id"], 10);
        assert_eq!(response["error"]["data"]["error_kind"], "replay_detected");
        assert_eq!(response["error"]["code"], JSONRPC_TOOLGATE_DENIED);
    }

    #[test]
    fn max_uses_requires_jti() {
        let token = basic_token();
        let line = tools_call(
            Some(json!(11)),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let mut store = MemoryUseStore::new();
        let response = error_of(decide_with_replay(
            &line,
            &verifier(),
            None,
            Some((&mut store, 2)),
        ));
        assert_eq!(response["error"]["data"]["error_kind"], "missing_jti");
    }

    #[test]
    fn replay_notification_is_dropped() {
        let token = jti_token();
        let line = tools_call(
            None,
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );
        let mut store = MemoryUseStore::new();
        assert!(matches!(
            decide_with_replay(&line, &verifier(), None, Some((&mut store, 1))),
            GateAction::Forward(_)
        ));
        assert_eq!(
            decide_with_replay(&line, &verifier(), None, Some((&mut store, 1))),
            GateAction::Drop
        );
    }

    #[test]
    fn audit_records_revoked_and_replay_kinds() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2_000_000_000,
            None,
            None,
            None,
            true,
        );
        let jti = token.jti.clone().unwrap();
        let line = tools_call(
            Some(json!(1)),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            Some(tg1_token(&token)),
        );

        let sink = MemoryAuditSink::new();
        let mut list = RevocationList::new();
        list.revoke(jti.clone());
        let verifier = Verifier::new(SECRET).at(NOW).revocation(&list).audit(&sink);
        decide(&line, &verifier, None);
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.decisions()[0].outcome, Outcome::Deny);
        assert_eq!(sink.decisions()[0].error_kind.as_deref(), Some("revoked"));
        assert_eq!(sink.decisions()[0].token_id.as_deref(), Some(jti.as_str()));

        let sink = MemoryAuditSink::new();
        let verifier = Verifier::new(SECRET).at(NOW).audit(&sink);
        let mut store = MemoryUseStore::new();
        assert!(matches!(
            decide_with_replay(&line, &verifier, None, Some((&mut store, 1))),
            GateAction::Forward(_)
        ));
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.decisions()[0].outcome, Outcome::Allow);

        decide_with_replay(&line, &verifier, None, Some((&mut store, 1)));
        assert_eq!(sink.len(), 2);
        assert_eq!(sink.decisions()[1].outcome, Outcome::Deny);
        assert_eq!(
            sink.decisions()[1].error_kind.as_deref(),
            Some("replay_detected")
        );
        assert_eq!(sink.decisions()[1].token_id.as_deref(), Some(jti.as_str()));
    }

    #[test]
    fn audit_one_decision_per_tools_call() {
        let token = constrained_token();
        let sink = MemoryAuditSink::new();
        let verifier = Verifier::new(SECRET).at(NOW).audit(&sink);

        let allowed = tools_call(
            Some(json!(1)),
            "read_file",
            json!({"path": "/tmp/a.txt", "limit": 10}),
            Some(tg1_token(&token)),
        );
        assert!(matches!(
            decide(&allowed, &verifier, None),
            GateAction::Forward(_)
        ));
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.decisions()[0].outcome, Outcome::Allow);

        let denied = tools_call(
            Some(json!(2)),
            "read_file",
            json!({"path": "/tmp/a.txt"}),
            None,
        );
        decide(&denied, &verifier, None);
        assert_eq!(sink.len(), 2);
        assert_eq!(sink.decisions()[1].outcome, Outcome::Deny);
        assert_eq!(
            sink.decisions()[1].error_kind.as_deref(),
            Some("malformed_request")
        );

        let note = tools_call(None, "read_file", json!({"path": "/tmp/a.txt"}), None);
        decide(&note, &verifier, None);
        assert_eq!(sink.len(), 3);

        let pass = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
        decide(pass, &verifier, None);
        assert_eq!(sink.len(), 3);
    }

    #[test]
    fn batch_array_is_invalid_request() {
        let line = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#;
        let response = error_of(decide(line, &verifier(), None));
        assert_eq!(response["error"]["code"], JSONRPC_INVALID_REQUEST);
        assert_eq!(response["id"], Value::Null);
    }

    #[test]
    fn jsonrpc_error_shape() {
        let value = denied_response(json!(1), &TokenError::Expired);
        assert_eq!(value["error"]["code"], JSONRPC_TOOLGATE_DENIED);
        assert_eq!(value["error"]["data"]["error_kind"], "expired");
        assert_eq!(value["id"], 1);
    }

    fn action_text(action: &GateAction) -> String {
        match action {
            GateAction::Forward(text) => text.clone(),
            GateAction::Respond(value) => value.to_string(),
            GateAction::Drop => String::new(),
        }
    }
}
