use serde_json::{json, Value};
use std::fs;
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

fn run_with_status(args: &[&str], input: &Value) -> std::process::Output {
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
    child.wait_with_output().unwrap()
}

fn parse_jsonl_decisions(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl decision"))
        .collect()
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

#[test]
fn check_call_writes_redacted_audit_jsonl_file() {
    let token = mint_token();
    let path = std::env::temp_dir().join(format!(
        "toolgate-audit-{}-{}.jsonl",
        std::process::id(),
        "check-call"
    ));
    let _ = fs::remove_file(&path);
    let input = json!({
        "secret": "cli-secret",
        "token": token,
        "tool_name": "read_file",
        "args": {"path": "/tmp/secret.txt", "limit": "10"},
        "current_time": 1999999999
    });
    let path_str = path.to_str().unwrap();
    let out = run_json(&["check-call", "--audit-jsonl", path_str], &input);
    assert_eq!(out.get("authorized"), Some(&Value::Bool(true)));

    let text = fs::read_to_string(&path).expect("audit file");
    let decisions = parse_jsonl_decisions(&text);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["outcome"], "allow");
    assert_eq!(decisions[0]["tool_name"], "read_file");
    assert_eq!(decisions[0]["arguments"]["path"], "[REDACTED]");
    assert_eq!(decisions[0]["arguments"]["limit"], "[REDACTED]");
    assert!(!text.contains("/tmp/secret.txt"));
    let _ = fs::remove_file(&path);
}

#[test]
fn check_mcp_writes_deny_audit_to_stderr() {
    let token = mint_token();
    let input = json!({
        "secret": "cli-secret",
        "token": token,
        "current_time": 1999999999,
        "request": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"name": "read_file"}
        }
    });
    let output = run_with_status(&["check-mcp", "--audit-jsonl", "stderr"], &input);
    assert!(output.status.success());
    let stdout: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stdout.get("authorized"), Some(&Value::Bool(false)));
    let decisions = parse_jsonl_decisions(&String::from_utf8_lossy(&output.stderr));
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["outcome"], "deny");
    assert_eq!(decisions[0]["error_kind"], "malformed_request");
}

#[test]
fn check_writes_audit_jsonl_to_stdout_after_result() {
    let token = mint_token();
    let input = json!({
        "secret": "cli-secret",
        "token": token,
        "current_time": 1999999999
    });
    let output = run_with_status(&["check", "--audit-jsonl", "stdout"], &input);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last_line = stdout.lines().rev().find(|l| !l.trim().is_empty()).unwrap();
    let decision: Value = serde_json::from_str(last_line).unwrap();
    assert_eq!(decision["outcome"], "allow");
    assert_eq!(decision["tool_name"], "read_file");
    assert!(stdout.contains("\"valid\": true"));
}

#[test]
fn check_call_audit_redact_keys_keeps_unlisted_values() {
    let token = mint_token();
    let path = std::env::temp_dir().join(format!(
        "toolgate-audit-{}-{}.jsonl",
        std::process::id(),
        "redact-keys"
    ));
    let _ = fs::remove_file(&path);
    let input = json!({
        "secret": "cli-secret",
        "token": token,
        "tool_name": "read_file",
        "args": {"path": "/tmp/secret.txt", "limit": "10"},
        "current_time": 1999999999
    });
    let path_str = path.to_str().unwrap();
    let out = run_json(
        &[
            "check-call",
            "--audit-jsonl",
            path_str,
            "--audit-redact-keys",
            "path",
        ],
        &input,
    );
    assert_eq!(out.get("authorized"), Some(&Value::Bool(true)));
    let text = fs::read_to_string(&path).unwrap();
    let decisions = parse_jsonl_decisions(&text);
    assert_eq!(decisions[0]["arguments"]["path"], "[REDACTED]");
    assert_eq!(decisions[0]["arguments"]["limit"], "10");
    assert!(!text.contains("/tmp/secret.txt"));
    let _ = fs::remove_file(&path);
}
