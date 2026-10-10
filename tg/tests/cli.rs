use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use toolgate::Token;

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

fn mint_token_with_jti() -> Value {
    run_json(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["path", "limit"],
            "expiry": 2000000000,
            "generate_jti": true,
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

fn example_policy_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../examples/policy.json")
}

fn write_temp_policy(name: &str, contents: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "toolgate-policy-{}-{}-{}.json",
        std::process::id(),
        name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(&path, contents).unwrap();
    path
}

#[test]
fn policy_lint_ok_on_example() {
    let output = tg()
        .args(["policy", "lint", example_policy_path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "lint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
}

#[test]
fn policy_lint_reports_validation_errors() {
    let path = write_temp_policy(
        "dup",
        r#"{
            "version": "1",
            "tools": [
                {"name": "read_file", "arg_keys": ["path"]},
                {"name": "read_file", "arg_keys": ["limit"]}
            ]
        }"#,
    );
    let output = tg()
        .args(["policy", "lint", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("duplicate tool name"),
        "stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn mint_from_policy_file() {
    let out = run_json(
        &[
            "mint",
            "--policy",
            example_policy_path().to_str().unwrap(),
            "--tool",
            "read_file",
        ],
        &json!({
            "secret": "cli-secret",
            "current_time": 1700000000
        }),
    );
    let token = &out["token"];
    assert_eq!(token["tool_name"], "read_file");
    assert_eq!(token["expiry"], 1700003600);
    assert_eq!(token["audience"], "agent-runtime");
    assert_eq!(token["max_depth"], 2);
    assert_eq!(token["kid"], "key-2025");
    assert!(token["arg_keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k == "path"));
}

#[test]
fn mint_stdin_json_unchanged() {
    let token = mint_token();
    assert_eq!(token["tool_name"], "read_file");
    assert_eq!(token["expiry"], 2000000000);
    assert!(token.get("kid").is_none() || token["kid"].is_null());
}

#[test]
fn gate_help_lists_policy_audience_leeway() {
    let output = tg().args(["gate", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--policy"));
    assert!(stdout.contains("--audience"));
    assert!(stdout.contains("--leeway"));
    assert!(stdout.contains("SERVER"));
}

#[test]
fn gate_requires_tg_secret_env() {
    let output = tg()
        .args(["gate", "--", "cat"])
        .env_remove("TG_SECRET")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("TG_SECRET"), "stderr={stderr:?}");
}

fn write_fake_mcp_echo(log: &Path) -> PathBuf {
    let script = std::env::temp_dir().join(format!(
        "toolgate-fake-mcp-{}-{}.sh",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  printf '%s\\n' \"$line\"\ndone\n",
            log.display()
        ),
    )
    .unwrap();
    script
}

fn unique_temp(prefix: &str, ext: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "toolgate-{}-{}-{}.{}",
        prefix,
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        ext
    ))
}

#[test]
fn gate_forwards_allowed_call_without_token_and_answers_denied() {
    let token = mint_token();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let log = unique_temp("fake-mcp", "log");
    let _ = fs::remove_file(&log);
    let script = write_fake_mcp_echo(&log);

    let mut child = tg()
        .args(["gate", "--", "sh", script.to_str().unwrap()])
        .env("TG_SECRET", "cli-secret")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tg gate");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {}
    });
    writeln!(stdin, "{initialize}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let echoed: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(echoed["method"], "initialize");

    let allowed = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/a.txt", "limit": 10},
            "_meta": {"toolgate": tg1}
        }
    });
    writeln!(stdin, "{allowed}").unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");
    assert_eq!(forwarded["id"], 1);
    assert_eq!(forwarded["params"]["name"], "read_file");
    assert!(
        forwarded["params"].get("_meta").is_none()
            || forwarded["params"]["_meta"].get("toolgate").is_none()
    );
    assert!(
        !line.contains("toolgate") && !line.contains("tg1."),
        "token leaked to client/server echo: {line}"
    );

    let denied = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/a.txt", "limit": 10}
        }
    });
    writeln!(stdin, "{denied}").unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["id"], 2);
    assert_eq!(error["error"]["data"]["error_kind"], "malformed_request");
    assert!(error.get("method").is_none());

    drop(stdin);
    let mut stderr = child.stderr.take();
    let status = child.wait().unwrap();
    if !status.success() {
        let mut err = String::new();
        if let Some(mut pipe) = stderr.take() {
            let _ = std::io::Read::read_to_string(&mut pipe, &mut err);
        }
        panic!("gate exit {:?}: {err}", status.code());
    }

    let server_seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        server_seen.contains("\"method\":\"initialize\"")
            || server_seen.contains("\"method\": \"initialize\""),
        "server log missing initialize: {server_seen}"
    );
    assert!(
        server_seen.contains("read_file"),
        "server log missing allowed call: {server_seen}"
    );
    assert!(
        !server_seen.contains("toolgate") && !server_seen.contains("tg1."),
        "token reached the server: {server_seen}"
    );
    assert!(
        !server_seen.contains("\"id\":2") && !server_seen.contains("\"id\": 2"),
        "denied call reached the server: {server_seen}"
    );

    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn gate_help_lists_revoked_and_max_uses() {
    let output = tg().args(["gate", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--revoked"));
    assert!(stdout.contains("--max-uses"));
    assert!(stdout.contains("--use-store"));
}

#[test]
fn gate_use_store_requires_max_uses() {
    let store = unique_temp("use-store-only", "jsonl");
    let output = tg()
        .args(["gate", "--use-store", store.to_str().unwrap(), "--", "cat"])
        .env("TG_SECRET", "cli-secret")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--use-store") && stderr.contains("--max-uses"),
        "stderr={stderr:?}"
    );
    let _ = fs::remove_file(&store);
}

#[test]
fn revoke_appends_raw_jti() {
    let path = unique_temp("revoked", "txt");
    let _ = fs::remove_file(&path);
    let output = tg()
        .args(["revoke", "jti-from-cli", "--file", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "jti-from-cli"
    );
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text, "jti-from-cli\n");
    let _ = fs::remove_file(&path);
}

#[test]
fn revoke_extracts_jti_from_tg1_token() {
    let token = mint_token_with_jti();
    let jti = token["jti"].as_str().unwrap().to_string();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();
    let path = unique_temp("revoked-token", "txt");
    let _ = fs::remove_file(&path);
    let output = tg()
        .args(["revoke", tg1, "--file", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "revoke failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), jti);
    assert_eq!(fs::read_to_string(&path).unwrap(), format!("{jti}\n"));
    let _ = fs::remove_file(&path);
}

#[test]
fn revoke_rejects_token_without_jti() {
    let token = mint_token();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();
    let path = unique_temp("revoked-no-jti", "txt");
    let output = tg()
        .args(["revoke", tg1, "--file", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no jti"), "stderr={stderr:?}");
    let _ = fs::remove_file(&path);
}

fn tools_call_line(id: u64, tg1: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/a.txt", "limit": 10},
            "_meta": {"toolgate": tg1}
        }
    })
}

fn spawn_gate(args: &[&str], log: &Path) -> (std::process::Child, PathBuf) {
    let script = write_fake_mcp_echo(log);
    let child = tg()
        .args(args)
        .arg("--")
        .args(["sh", script.to_str().unwrap()])
        .env("TG_SECRET", "cli-secret")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tg gate");
    (child, script)
}

#[test]
fn gate_revoked_file_denies_listed_jti() {
    let token = mint_token_with_jti();
    let jti = token["jti"].as_str().unwrap();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let revoked = unique_temp("gate-revoked", "txt");
    fs::write(&revoked, format!("# denylist\n{jti}\n")).unwrap();
    let audit = unique_temp("gate-revoked-audit", "jsonl");
    let _ = fs::remove_file(&audit);
    let log = unique_temp("fake-mcp-revoked", "log");
    let _ = fs::remove_file(&log);

    let (mut child, script) = spawn_gate(
        &[
            "gate",
            "--revoked",
            revoked.to_str().unwrap(),
            "--audit-jsonl",
            audit.to_str().unwrap(),
        ],
        &log,
    );
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["id"], 1);
    assert_eq!(error["error"]["data"]["error_kind"], "revoked");

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let server_seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !server_seen.contains("read_file"),
        "revoked call reached the server: {server_seen}"
    );
    let decisions = parse_jsonl_decisions(&fs::read_to_string(&audit).unwrap());
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["outcome"], "deny");
    assert_eq!(decisions[0]["error_kind"], "revoked");
    assert_eq!(decisions[0]["token_id"], jti);

    let _ = fs::remove_file(&revoked);
    let _ = fs::remove_file(&audit);
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn gate_max_uses_denies_replay() {
    let token = mint_token_with_jti();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let audit = unique_temp("gate-replay-audit", "jsonl");
    let _ = fs::remove_file(&audit);
    let log = unique_temp("fake-mcp-replay", "log");
    let _ = fs::remove_file(&log);

    let (mut child, script) = spawn_gate(
        &[
            "gate",
            "--max-uses",
            "1",
            "--audit-jsonl",
            audit.to_str().unwrap(),
        ],
        &log,
    );
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");
    assert!(
        forwarded["params"].get("_meta").is_none()
            || forwarded["params"]["_meta"].get("toolgate").is_none()
    );

    writeln!(stdin, "{}", tools_call_line(2, tg1)).unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["id"], 2);
    assert_eq!(error["error"]["data"]["error_kind"], "replay_detected");

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let server_seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        server_seen.contains("read_file"),
        "first call never reached the server: {server_seen}"
    );
    assert!(
        !server_seen.contains("\"id\":2") && !server_seen.contains("\"id\": 2"),
        "replay reached the server: {server_seen}"
    );
    let decisions = parse_jsonl_decisions(&fs::read_to_string(&audit).unwrap());
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0]["outcome"], "allow");
    assert_eq!(decisions[1]["outcome"], "deny");
    assert_eq!(decisions[1]["error_kind"], "replay_detected");

    let _ = fs::remove_file(&audit);
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn gate_use_store_denies_replay_after_restart() {
    let token = mint_token_with_jti();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let store = unique_temp("gate-use-store", "jsonl");
    let _ = fs::remove_file(&store);
    let audit = unique_temp("gate-use-store-audit", "jsonl");
    let _ = fs::remove_file(&audit);
    let log = unique_temp("fake-mcp-use-store", "log");
    let _ = fs::remove_file(&log);

    let args = [
        "gate",
        "--max-uses",
        "1",
        "--use-store",
        store.to_str().unwrap(),
        "--audit-jsonl",
        audit.to_str().unwrap(),
    ];

    let (mut child, script) = spawn_gate(&args, &log);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");
    assert!(
        forwarded["params"].get("_meta").is_none()
            || forwarded["params"]["_meta"].get("toolgate").is_none()
    );

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());
    assert!(
        fs::read_to_string(&store)
            .unwrap()
            .contains(token["jti"].as_str().unwrap()),
        "first use was not persisted"
    );

    let (mut child, script2) = spawn_gate(&args, &log);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(2, tg1)).unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["id"], 2);
    assert_eq!(error["error"]["data"]["error_kind"], "replay_detected");

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let server_seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        server_seen.contains("read_file"),
        "first call never reached the server: {server_seen}"
    );
    assert!(
        !server_seen.contains("\"id\":2") && !server_seen.contains("\"id\": 2"),
        "replay after restart reached the server: {server_seen}"
    );
    let decisions = parse_jsonl_decisions(&fs::read_to_string(&audit).unwrap());
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0]["outcome"], "allow");
    assert_eq!(decisions[1]["outcome"], "deny");
    assert_eq!(decisions[1]["error_kind"], "replay_detected");

    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(&audit);
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
    let _ = fs::remove_file(&script2);
}

#[test]
fn gate_reloads_revoked_file_on_change() {
    let token = mint_token_with_jti();
    let jti = token["jti"].as_str().unwrap().to_string();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let revoked = unique_temp("gate-reload", "txt");
    fs::write(&revoked, "# none yet\n").unwrap();
    let log = unique_temp("fake-mcp-reload", "log");
    let _ = fs::remove_file(&log);

    let (mut child, script) = spawn_gate(&["gate", "--revoked", revoked.to_str().unwrap()], &log);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");

    let output = tg()
        .args(["revoke", &jti, "--file", revoked.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let handle = fs::File::options().write(true).open(&revoked).unwrap();
    let newer = SystemTime::now() + std::time::Duration::from_secs(2);
    handle.set_modified(newer).unwrap();
    drop(handle);

    writeln!(stdin, "{}", tools_call_line(2, tg1)).unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["id"], 2);
    assert_eq!(error["error"]["data"]["error_kind"], "revoked");

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let server_seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !server_seen.contains("\"id\":2") && !server_seen.contains("\"id\": 2"),
        "revoked-after-reload reached the server: {server_seen}"
    );

    let _ = fs::remove_file(&revoked);
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

const KEYRING_SECRET_A: &[u8] = b"cli-secret-a-32-bytes-long!!!!";
const KEYRING_SECRET_B: &[u8] = b"cli-secret-b-32-bytes-long!!!!";

fn write_temp_keyring(name: &str, contents: &str) -> PathBuf {
    let path = unique_temp(name, "json");
    fs::write(&path, contents).unwrap();
    path
}

fn mint_kid_token(secret: &[u8], kid: &str) -> String {
    let token = Token::mint_with_kid(
        secret,
        "read_file",
        vec!["path".into(), "limit".into()],
        2_000_000_000,
        None,
        Some(kid.to_string()),
    );
    token.to_token_string()
}

fn spawn_gate_keyring(args: &[&str], log: &Path) -> (std::process::Child, PathBuf) {
    let script = write_fake_mcp_echo(log);
    let child = tg()
        .args(args)
        .arg("--")
        .args(["sh", script.to_str().unwrap()])
        .env_remove("TG_SECRET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tg gate");
    (child, script)
}

#[test]
fn gate_help_lists_keyring() {
    let output = tg().args(["gate", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--keyring"));
}

#[test]
fn gate_rejects_secret_and_keyring_together() {
    let keyring = write_temp_keyring(
        "both",
        r#"{"keys":{"key-a":"cli-secret-a-32-bytes-long!!!!"}}"#,
    );
    let output = tg()
        .args(["gate", "--keyring", keyring.to_str().unwrap(), "--", "cat"])
        .env("TG_SECRET", "cli-secret")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TG_SECRET") && stderr.contains("--keyring"),
        "stderr={stderr:?}"
    );
    let _ = fs::remove_file(&keyring);
}

#[test]
fn gate_keyring_verifies_tokens_from_different_kids() {
    let hex_b = hex::encode(KEYRING_SECRET_B);
    let keyring = write_temp_keyring(
        "multi-kid",
        &format!(
            r#"{{"keys":{{"key-a":"cli-secret-a-32-bytes-long!!!!","key-b":"hex:{hex_b}"}},"active":"key-a"}}"#
        ),
    );
    let tg1_a = mint_kid_token(KEYRING_SECRET_A, "key-a");
    let tg1_b = mint_kid_token(KEYRING_SECRET_B, "key-b");
    let tg1_unknown = mint_kid_token(b"other-secret-key-32-bytes-long!", "key-missing");

    let log = unique_temp("fake-mcp-keyring", "log");
    let _ = fs::remove_file(&log);
    let (mut child, script) =
        spawn_gate_keyring(&["gate", "--keyring", keyring.to_str().unwrap()], &log);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, &tg1_a)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");
    assert_eq!(forwarded["id"], 1);
    assert!(
        forwarded["params"].get("_meta").is_none()
            || forwarded["params"]["_meta"].get("toolgate").is_none()
    );

    writeln!(stdin, "{}", tools_call_line(2, &tg1_b)).unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");
    assert_eq!(forwarded["id"], 2);

    writeln!(stdin, "{}", tools_call_line(3, &tg1_unknown)).unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["id"], 3);
    assert_eq!(error["error"]["data"]["error_kind"], "unknown_key_id");

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let server_seen = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        server_seen.contains("\"id\":1") || server_seen.contains("\"id\": 1"),
        "key-a call never reached the server: {server_seen}"
    );
    assert!(
        server_seen.contains("\"id\":2") || server_seen.contains("\"id\": 2"),
        "key-b call never reached the server: {server_seen}"
    );
    assert!(
        !server_seen.contains("\"id\":3") && !server_seen.contains("\"id\": 3"),
        "unknown kid reached the server: {server_seen}"
    );

    let _ = fs::remove_file(&keyring);
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn use_store_help_lists_stats_and_prune() {
    let top = tg().args(["--help"]).output().unwrap();
    assert!(top.status.success());
    let top_out = String::from_utf8_lossy(&top.stdout);
    assert!(
        top_out.contains("use-store"),
        "top-level help missing use-store: {top_out}"
    );

    let output = tg().args(["use-store", "--help"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stats"));
    assert!(stdout.contains("prune"));
}

#[test]
fn use_store_stats_and_prune() {
    let path = unique_temp("cli-use-store", "jsonl");
    fs::write(
        &path,
        concat!(
            r#"{"jti":"old","expiry":1}"#,
            "\n",
            r#"{"jti":"old","expiry":1}"#,
            "\n",
            r#"{"jti":"live","expiry":4000000000}"#,
            "\n"
        ),
    )
    .unwrap();

    let stats_out = tg()
        .args(["use-store", "stats", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        stats_out.status.success(),
        "stats failed: {}",
        String::from_utf8_lossy(&stats_out.stderr)
    );
    let stats: Value = serde_json::from_slice(&stats_out.stdout).unwrap();
    assert_eq!(stats["unique_jtis"], 2);
    assert_eq!(stats["total_records"], 3);
    assert_eq!(stats["expired_records"], 2);
    assert_eq!(stats["path"], path.to_str().unwrap());

    let prune_out = tg()
        .args(["use-store", "prune", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        prune_out.status.success(),
        "prune failed: {}",
        String::from_utf8_lossy(&prune_out.stderr)
    );
    let report: Value = serde_json::from_slice(&prune_out.stdout).unwrap();
    assert_eq!(report["removed"], 2);
    assert_eq!(report["remaining"], 1);
    assert_eq!(report["path"], path.to_str().unwrap());

    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains("old"));
    assert!(text.contains("live"));

    let stats_after = tg()
        .args(["use-store", "stats", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(stats_after.status.success());
    let after: Value = serde_json::from_slice(&stats_after.stdout).unwrap();
    assert_eq!(after["unique_jtis"], 1);
    assert_eq!(after["total_records"], 1);
    assert_eq!(after["expired_records"], 0);

    let _ = fs::remove_file(format!("{}.lock", path.display()));
    let _ = fs::remove_file(&path);
}

#[test]
fn use_store_stats_and_prune_fail_when_file_missing() {
    let missing = unique_temp("cli-use-store-missing", "jsonl");
    let _ = fs::remove_file(&missing);

    let stats = tg()
        .args(["use-store", "stats", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!stats.status.success());
    let stderr = String::from_utf8_lossy(&stats.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("use-store"),
        "stats stderr={stderr:?}"
    );

    let prune = tg()
        .args(["use-store", "prune", missing.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!prune.status.success());
    let stderr = String::from_utf8_lossy(&prune.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("use-store"),
        "prune stderr={stderr:?}"
    );
}

fn gate_with_env(args: &[&str], envs: &[(&str, Option<&str>)]) -> std::process::Output {
    let mut cmd = tg();
    cmd.args(args);
    for (key, value) in envs {
        match value {
            Some(value) => {
                cmd.env(key, value);
            }
            None => {
                cmd.env_remove(key);
            }
        }
    }
    cmd.output().unwrap()
}

fn spawn_gate_envs(
    args: &[&str],
    log: &Path,
    extra_env: &[(&str, &str)],
    remove_env: &[&str],
) -> (std::process::Child, PathBuf) {
    let script = write_fake_mcp_echo(log);
    let mut cmd = tg();
    cmd.args(args)
        .arg("--")
        .args(["sh", script.to_str().unwrap()])
        .env("TG_SECRET", "cli-secret")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in remove_env {
        cmd.env_remove(key);
    }
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let child = cmd.spawn().expect("spawn tg gate");
    (child, script)
}

fn mint_token_with_audience(audience: &str) -> Value {
    run_json(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["path", "limit"],
            "expiry": 2000000000,
            "audience": audience,
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
fn gate_rejects_invalid_tg_max_uses() {
    let output = gate_with_env(
        &["gate", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_MAX_USES", Some("nope")),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TG_MAX_USES") && stderr.contains("nope"),
        "stderr={stderr:?}"
    );
}

#[test]
fn gate_rejects_zero_tg_max_uses() {
    let output = gate_with_env(
        &["gate", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_MAX_USES", Some("0")),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TG_MAX_USES") && stderr.contains("positive"),
        "stderr={stderr:?}"
    );
}

#[test]
fn gate_rejects_invalid_tg_leeway() {
    let output = gate_with_env(
        &["gate", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_LEEWAY", Some("not-a-duration")),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TG_LEEWAY") && stderr.contains("not-a-duration"),
        "stderr={stderr:?}"
    );
}

#[test]
fn gate_max_uses_flag_wins_over_invalid_env() {
    let output = gate_with_env(
        &["gate", "--max-uses", "1", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_MAX_USES", Some("abc")),
        ],
    );
    assert!(
        output.status.success(),
        "flag should win over invalid TG_MAX_USES: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_leeway_flag_wins_over_invalid_env() {
    let output = gate_with_env(
        &["gate", "--leeway", "0", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_LEEWAY", Some("xyz")),
        ],
    );
    assert!(
        output.status.success(),
        "flag should win over invalid TG_LEEWAY: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_rejects_tg_secret_and_tg_keyring() {
    let keyring = write_temp_keyring(
        "env-both",
        r#"{"keys":{"key-a":"cli-secret-a-32-bytes-long!!!!"}}"#,
    );
    let output = gate_with_env(
        &["gate", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_KEYRING", Some(keyring.to_str().unwrap())),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TG_SECRET") && stderr.contains("TG_KEYRING"),
        "stderr={stderr:?}"
    );
    let _ = fs::remove_file(&keyring);
}

#[test]
fn gate_empty_env_strings_are_unset() {
    let output = gate_with_env(
        &["gate", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_KEYRING", Some("")),
            ("TG_MAX_USES", Some("")),
            ("TG_LEEWAY", Some("")),
            ("TG_POLICY", Some("")),
        ],
    );
    assert!(
        output.status.success(),
        "empty env strings should be ignored: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_use_store_env_requires_max_uses() {
    let store = unique_temp("use-store-env-only", "jsonl");
    let output = gate_with_env(
        &["gate", "--", "cat"],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_USE_STORE", Some(store.to_str().unwrap())),
            ("TG_MAX_USES", Some("")),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TG_USE_STORE") && stderr.contains("TG_MAX_USES"),
        "stderr={stderr:?}"
    );
    let _ = fs::remove_file(&store);
}

#[test]
fn gate_policy_flag_wins_over_missing_env_path() {
    let missing = unique_temp("missing-policy-env", "json");
    let _ = fs::remove_file(&missing);
    let output = gate_with_env(
        &[
            "gate",
            "--policy",
            example_policy_path().to_str().unwrap(),
            "--",
            "cat",
        ],
        &[
            ("TG_SECRET", Some("cli-secret")),
            ("TG_POLICY", Some(missing.to_str().unwrap())),
        ],
    );
    assert!(
        output.status.success(),
        "--policy should win over TG_POLICY: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_max_uses_env_denies_replay() {
    let token = mint_token_with_jti();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let log = unique_temp("fake-mcp-max-uses-env", "log");
    let _ = fs::remove_file(&log);
    let (mut child, script) = spawn_gate_envs(&["gate"], &log, &[("TG_MAX_USES", "1")], &[]);
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");

    writeln!(stdin, "{}", tools_call_line(2, tg1)).unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["id"], 2);
    assert_eq!(error["error"]["data"]["error_kind"], "replay_detected");

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn gate_max_uses_flag_wins_over_stricter_env() {
    let token = mint_token_with_jti();
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let log = unique_temp("fake-mcp-max-uses-flag", "log");
    let _ = fs::remove_file(&log);
    let (mut child, script) = spawn_gate_envs(
        &["gate", "--max-uses", "2"],
        &log,
        &[("TG_MAX_USES", "1")],
        &[],
    );
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let first: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(first["method"], "tools/call");

    writeln!(stdin, "{}", tools_call_line(2, tg1)).unwrap();
    stdin.flush().unwrap();
    line.clear();
    stdout.read_line(&mut line).unwrap();
    let second: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        second["method"], "tools/call",
        "--max-uses 2 should win over TG_MAX_USES=1: {second}"
    );

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn gate_audience_flag_wins_over_env() {
    let token = mint_token_with_audience("client-a");
    let encoded = run_json(&["encode"], &token);
    let tg1 = encoded["token"].as_str().unwrap();

    let log = unique_temp("fake-mcp-audience-flag", "log");
    let _ = fs::remove_file(&log);
    let (mut child, script) = spawn_gate_envs(
        &["gate", "--audience", "client-a"],
        &log,
        &[("TG_AUDIENCE", "other-client")],
        &[],
    );
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");
    assert_eq!(forwarded["id"], 1);

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn gate_audit_jsonl_flag_wins_over_env() {
    let flag_audit = unique_temp("gate-audit-flag", "jsonl");
    let env_audit = unique_temp("gate-audit-env", "jsonl");
    let _ = fs::remove_file(&flag_audit);
    let _ = fs::remove_file(&env_audit);
    let log = unique_temp("fake-mcp-audit-flag", "log");
    let _ = fs::remove_file(&log);

    let (mut child, script) = spawn_gate_envs(
        &["gate", "--audit-jsonl", flag_audit.to_str().unwrap()],
        &log,
        &[("TG_AUDIT_JSONL", env_audit.to_str().unwrap())],
        &[],
    );
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let denied = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/a.txt", "limit": 10}
        }
    });
    writeln!(stdin, "{denied}").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let error: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(error["error"]["data"]["error_kind"], "malformed_request");

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let flag_text = fs::read_to_string(&flag_audit).unwrap_or_default();
    assert!(
        !flag_text.is_empty(),
        "--audit-jsonl should receive the decision"
    );
    assert!(
        !env_audit.exists() || fs::read_to_string(&env_audit).unwrap().is_empty(),
        "TG_AUDIT_JSONL should be ignored when --audit-jsonl is set"
    );

    let _ = fs::remove_file(&flag_audit);
    let _ = fs::remove_file(&env_audit);
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

#[test]
fn gate_keyring_env_verifies_without_flag() {
    let keyring = write_temp_keyring(
        "env-keyring",
        r#"{"keys":{"key-a":"cli-secret-a-32-bytes-long!!!!"}}"#,
    );
    let tg1 = mint_kid_token(KEYRING_SECRET_A, "key-a");
    let log = unique_temp("fake-mcp-keyring-env", "log");
    let _ = fs::remove_file(&log);
    let (mut child, script) = spawn_gate_envs(
        &["gate"],
        &log,
        &[("TG_KEYRING", keyring.to_str().unwrap())],
        &["TG_SECRET"],
    );
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    writeln!(stdin, "{}", tools_call_line(1, &tg1)).unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let forwarded: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(forwarded["method"], "tools/call");
    assert_eq!(forwarded["id"], 1);

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    let _ = fs::remove_file(&keyring);
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&script);
}

fn mint_suffix_contains_token() -> Value {
    run_json(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["name", "path"],
            "expiry": 2000000000,
            "constraints": {
                "name": {"type": "suffix", "value": ".txt"},
                "path": {"type": "contains", "value": "tmp"}
            }
        }),
    )
    .get("token")
    .cloned()
    .expect("mint token")
}

#[test]
fn mint_accepts_suffix_and_contains_constraints() {
    let token = mint_suffix_contains_token();
    assert_eq!(token["constraints"]["name"]["type"], "suffix");
    assert_eq!(token["constraints"]["name"]["value"], ".txt");
    assert_eq!(token["constraints"]["path"]["type"], "contains");
    assert_eq!(token["constraints"]["path"]["value"], "tmp");
}

#[test]
fn check_call_enforces_suffix_and_contains() {
    let token = mint_suffix_contains_token();
    let ok = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "read_file",
            "args": {"name": "notes.txt", "path": "/var/tmp/out"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(ok.get("authorized"), Some(&Value::Bool(true)));

    let denied = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "read_file",
            "args": {"name": "notes.pdf", "path": "/var/tmp/out"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(denied.get("authorized"), Some(&Value::Bool(false)));
    assert_eq!(
        denied.get("error_kind").and_then(Value::as_str),
        Some("constraint_violation")
    );
}

#[test]
fn attenuate_can_tighten_suffix_and_contains() {
    let token = mint_suffix_contains_token();
    let out = run_json(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {
                "name": {"type": "suffix", "value": ".bak.txt"},
                "path": {"type": "contains", "value": "tmp/public"}
            }
        }),
    );
    let attenuated = &out["token"];
    assert_eq!(attenuated["constraints"]["name"]["value"], ".bak.txt");
    assert_eq!(attenuated["constraints"]["path"]["value"], "tmp/public");
}

#[test]
fn attenuate_rejects_looser_suffix_and_contains() {
    let token = mint_suffix_contains_token();
    let suffix = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {"name": {"type": "suffix", "value": ".t"}}
        }),
    );
    assert!(!suffix.status.success());
    assert!(
        String::from_utf8_lossy(&suffix.stderr).contains("attenuation"),
        "looser suffix should fail closed: {}",
        String::from_utf8_lossy(&suffix.stderr)
    );

    let contains = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {"path": {"type": "contains", "value": "tm"}}
        }),
    );
    assert!(!contains.status.success());
}

#[test]
fn mint_rejects_empty_suffix_and_contains() {
    let suffix = run_with_status(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["name"],
            "expiry": 2000000000,
            "constraints": {"name": {"type": "suffix", "value": ""}}
        }),
    );
    assert!(!suffix.status.success());
    assert!(
        String::from_utf8_lossy(&suffix.stderr).contains("empty suffix/contains"),
        "{}",
        String::from_utf8_lossy(&suffix.stderr)
    );

    let contains = run_with_status(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["path"],
            "expiry": 2000000000,
            "constraints": {"path": {"type": "contains", "value": ""}}
        }),
    );
    assert!(!contains.status.success());
}

#[test]
fn attenuate_rejects_empty_suffix_and_contains() {
    let token = mint_suffix_contains_token();
    let out = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {"name": {"type": "suffix", "value": ""}}
        }),
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("empty suffix/contains"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn mint_minlen_matches_token() -> Value {
    run_json(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["name", "query"],
            "expiry": 2000000000,
            "constraints": {
                "name": {"type": "matches", "value": "*.txt"},
                "query": {"type": "min_len", "value": 3}
            }
        }),
    )
    .get("token")
    .cloned()
    .expect("mint token")
}

#[test]
fn mint_accepts_min_len_and_matches_constraints() {
    let token = mint_minlen_matches_token();
    assert_eq!(token["constraints"]["name"]["type"], "matches");
    assert_eq!(token["constraints"]["name"]["value"], "*.txt");
    assert_eq!(token["constraints"]["query"]["type"], "min_len");
    assert_eq!(token["constraints"]["query"]["value"], 3);
}

#[test]
fn check_call_enforces_min_len_and_matches() {
    let token = mint_minlen_matches_token();
    let ok = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "read_file",
            "args": {"name": "notes.txt", "query": "abc"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(ok.get("authorized"), Some(&Value::Bool(true)));

    let denied_glob = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "read_file",
            "args": {"name": "notes.pdf", "query": "abc"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(denied_glob.get("authorized"), Some(&Value::Bool(false)));
    assert_eq!(
        denied_glob.get("error_kind").and_then(Value::as_str),
        Some("constraint_violation")
    );

    let denied_len = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "read_file",
            "args": {"name": "notes.txt", "query": "ab"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(denied_len.get("authorized"), Some(&Value::Bool(false)));
}

#[test]
fn attenuate_can_raise_min_len_and_replace_matches_with_exact() {
    let token = mint_minlen_matches_token();
    let out = run_json(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {
                "name": {"type": "exact", "value": "notes.txt"},
                "query": {"type": "min_len", "value": 8}
            }
        }),
    );
    let attenuated = &out["token"];
    assert_eq!(attenuated["constraints"]["name"]["type"], "exact");
    assert_eq!(attenuated["constraints"]["name"]["value"], "notes.txt");
    assert_eq!(attenuated["constraints"]["query"]["value"], 8);
}

#[test]
fn attenuate_rejects_looser_min_len_and_changed_matches() {
    let token = mint_minlen_matches_token();
    let min_len = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {"query": {"type": "min_len", "value": 1}}
        }),
    );
    assert!(!min_len.status.success());
    assert!(
        String::from_utf8_lossy(&min_len.stderr).contains("attenuation"),
        "looser min_len should fail closed: {}",
        String::from_utf8_lossy(&min_len.stderr)
    );

    let matches = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {"name": {"type": "matches", "value": "notes.txt"}}
        }),
    );
    assert!(!matches.status.success());
}

#[test]
fn mint_rejects_empty_matches() {
    let out = run_with_status(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "read_file",
            "arg_keys": ["name"],
            "expiry": 2000000000,
            "constraints": {"name": {"type": "matches", "value": ""}}
        }),
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("empty suffix/contains/matches"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn attenuate_rejects_empty_matches() {
    let token = mint_minlen_matches_token();
    let out = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {"name": {"type": "matches", "value": ""}}
        }),
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("empty suffix/contains/matches"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn mint_denylist_token() -> Value {
    run_json(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "file_op",
            "arg_keys": ["role", "mode"],
            "expiry": 2000000000,
            "constraints": {
                "role": {"type": "not_equals", "value": "admin"},
                "mode": {"type": "not_one_of", "value": ["admin"]}
            }
        }),
    )
    .get("token")
    .cloned()
    .expect("mint token")
}

#[test]
fn mint_accepts_not_equals_and_not_one_of_constraints() {
    let token = mint_denylist_token();
    assert_eq!(token["constraints"]["role"]["type"], "not_equals");
    assert_eq!(token["constraints"]["role"]["value"], "admin");
    assert_eq!(token["constraints"]["mode"]["type"], "not_one_of");
    assert_eq!(token["constraints"]["mode"]["value"], json!(["admin"]));
}

#[test]
fn check_call_enforces_not_equals_and_not_one_of() {
    let token = mint_denylist_token();
    let ok = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "file_op",
            "args": {"role": "user", "mode": "read"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(ok.get("authorized"), Some(&Value::Bool(true)));

    let denied_equals = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "file_op",
            "args": {"role": "admin", "mode": "read"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(denied_equals.get("authorized"), Some(&Value::Bool(false)));
    assert_eq!(
        denied_equals.get("error_kind").and_then(Value::as_str),
        Some("constraint_violation")
    );

    let denied_one_of = run_json(
        &["check-call"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "tool_name": "file_op",
            "args": {"role": "user", "mode": "admin"},
            "current_time": 1999999999
        }),
    );
    assert_eq!(denied_one_of.get("authorized"), Some(&Value::Bool(false)));
    assert_eq!(
        denied_one_of.get("error_kind").and_then(Value::as_str),
        Some("constraint_violation")
    );
}

#[test]
fn attenuate_can_tighten_not_one_of() {
    let token = mint_denylist_token();
    let out = run_json(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {
                "role": {"type": "not_one_of", "value": ["admin", "root"]},
                "mode": {"type": "not_one_of", "value": ["admin", "root"]}
            }
        }),
    );
    let attenuated = &out["token"];
    assert_eq!(attenuated["constraints"]["role"]["type"], "not_one_of");
    assert_eq!(
        attenuated["constraints"]["role"]["value"],
        json!(["admin", "root"])
    );
    assert_eq!(
        attenuated["constraints"]["mode"]["value"],
        json!(["admin", "root"])
    );
}

#[test]
fn attenuate_rejects_loosening_not_one_of() {
    let token = mint_denylist_token();
    let grown = run_json(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {
                "mode": {"type": "not_one_of", "value": ["admin", "root"]}
            }
        }),
    );
    let grown_token = grown.get("token").cloned().expect("grown token");

    let looser = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": grown_token,
            "constraints": {"mode": {"type": "not_one_of", "value": ["admin"]}}
        }),
    );
    assert!(!looser.status.success());
    assert!(
        String::from_utf8_lossy(&looser.stderr).contains("attenuation"),
        "dropping a forbidden value should fail closed: {}",
        String::from_utf8_lossy(&looser.stderr)
    );
}

#[test]
fn policy_lint_rejects_empty_not_one_of() {
    let path = write_temp_policy(
        "empty-not-one-of",
        r#"{
            "version": "1",
            "tools": [{
                "name": "file_op",
                "arg_keys": ["role"],
                "constraints": {"role": {"type": "not_one_of", "value": []}}
            }]
        }"#,
    );
    let output = tg()
        .args(["policy", "lint", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("empty suffix/contains/matches/not_one_of"),
        "stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn mint_from_policy_accepts_not_equals_and_not_one_of() {
    let path = write_temp_policy(
        "denylist-grant",
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
    );
    let out = run_json(
        &[
            "mint",
            "--policy",
            path.to_str().unwrap(),
            "--tool",
            "file_op",
        ],
        &json!({
            "secret": "cli-secret",
            "current_time": 1700000000
        }),
    );
    let token = &out["token"];
    assert_eq!(token["tool_name"], "file_op");
    assert_eq!(token["constraints"]["role"]["type"], "not_equals");
    assert_eq!(token["constraints"]["role"]["value"], "admin");
    assert_eq!(token["constraints"]["mode"]["type"], "not_one_of");
    assert_eq!(
        token["constraints"]["mode"]["value"],
        json!(["admin", "root"])
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn mint_rejects_empty_not_one_of() {
    let out = run_with_status(
        &["mint"],
        &json!({
            "secret": "cli-secret",
            "tool_name": "file_op",
            "arg_keys": ["role"],
            "expiry": 2000000000,
            "constraints": {"role": {"type": "not_one_of", "value": []}}
        }),
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("empty suffix/contains/matches/not_one_of"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn attenuate_rejects_empty_not_one_of() {
    let token = mint_denylist_token();
    let out = run_with_status(
        &["attenuate"],
        &json!({
            "secret": "cli-secret",
            "token": token,
            "constraints": {"mode": {"type": "not_one_of", "value": []}}
        }),
    );
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("empty suffix/contains/matches/not_one_of"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
