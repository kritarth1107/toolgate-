use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

fn tg() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tg"))
}

fn run_json(args: &[&str], input: &Value) -> Value {
    let mut child = tg()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tg");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "tg {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json stdout")
}

fn mint_token() -> Value {
    run_json(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["path", "limit"],
            "expiry": 2000000000,
            "constraints": {
                "path": {"type": "prefix", "value": "/tmp/"},
                "limit": {"type": "int_range", "value": {"min": 1, "max": 100}}
            }
        }),
    )
    .get("token")
    .cloned()
    .expect("mint token")
}

#[test]
fn encode_emits_tg1_string() {
    let token = mint_token();
    let out = run_json(&["encode"], &token);
    let encoded = out.get("token").and_then(Value::as_str).unwrap();
    assert!(encoded.starts_with("tg1."));
    assert!(!encoded.contains('='));
}

#[test]
fn decode_returns_unverified_json_token() {
    let token = mint_token();
    let encoded = run_json(&["encode"], &json!({"token": token}))
        .get("token")
        .cloned()
        .unwrap();
    let encoded_str = encoded.as_str().unwrap();

    let mut child = tg()
        .args(["decode"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(encoded_str.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let decoded: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decoded.get("verified"), Some(&Value::Bool(false)));
    assert_eq!(decoded["token"]["tool_name"], "read_file");
}

#[test]
fn check_accepts_tg1_token_string() {
    let token = mint_token();
    let encoded = run_json(&["encode"], &token);
    let out = run_json(
        &["check"],
        &json!({
            "secret": "cli-secret",
            "token": encoded["token"],
            "current_time": 1999999999
        }),
    );
    assert_eq!(out.get("valid"), Some(&Value::Bool(true)));
}

#[test]
fn check_call_accepts_tg1_token_string() {
    let token = mint_token();
    let encoded = run_json(&["encode"], &token);
    let out = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": encoded["token"],
            "tool_name": "read_file",
            "args": {"path": "/tmp/a.txt", "limit": "10"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(out.get("authorized"), Some(&Value::Bool(true)));
}

#[test]
fn check_mcp_authorizes_tools_call() {
    let token = mint_token();
    let out = run_json(
        &["check-mcp"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "current_time": 1999999999,
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/tmp/a.txt", "limit": 10}
                }
            }
        }),
    );
    assert_eq!(out.get("authorized"), Some(&Value::Bool(true)));
}

#[test]
fn check_mcp_reports_malformed_request() {
    let token = mint_token();
    let out = run_json(
        &["check-mcp"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "current_time": 1999999999,
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {"name": "read_file"}
            }
        }),
    );
    assert_eq!(out.get("authorized"), Some(&Value::Bool(false)));
    assert_eq!(
        out.get("error_kind").and_then(Value::as_str),
        Some("malformed_request")
    );
}

#[test]
fn check_mcp_accepts_tg1_token_string() {
    let token = mint_token();
    let encoded = run_json(&["encode"], &token);
    let out = run_json(
        &["check-mcp"],
        &json!({
            "secret": "cli-secret",
            "token": encoded["token"],
            "current_time": 1999999999,
            "request": {
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/tmp/a.txt", "limit": 25}
                }
            }
        }),
    );
    assert_eq!(out.get("authorized"), Some(&Value::Bool(true)));
}
