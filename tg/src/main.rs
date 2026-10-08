use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use toolgate::{
    append_revoked_jti, check_tools_call, decide, decide_with_replay, AuditSink, Constraints,
    Decision, GateAction, JsonlAuditSink, MemoryAuditSink, MemoryUseStore, Policy, Redaction,
    RevocationFile, RevocationList, Token, TokenStringError, UseStore, Verifier,
};

#[derive(Parser)]
#[command(name = "tg")]
#[command(about = "Toolgate CLI - macaroon-style capability tokens for tool calls")]
#[command(version)]
struct Cli {
    /// Write each Decision as JSONL to stdout, stderr, or a file path
    #[arg(long, global = true, value_name = "TARGET")]
    audit_jsonl: Option<String>,
    /// Comma-separated argument keys to redact in audit records (default: all values)
    #[arg(long, global = true, value_name = "KEYS")]
    audit_redact_keys: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mint a new capability token
    Mint {
        /// Mint from a policy file instead of a full stdin mint request
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        /// Tool name to mint (requires --policy)
        #[arg(long)]
        tool: Option<String>,
    },
    /// Attenuate an existing token (reduce capabilities)
    Attenuate,
    /// Check/verify a token
    Check,
    /// Verify a token authorizes a specific tool call
    CheckCall,
    /// Encode a JSON token as a compact `tg1.` string
    Encode,
    /// Decode a compact `tg1.` string to JSON (does not verify the MAC)
    Decode,
    /// Verify a token against an MCP tools/call JSON-RPC request
    CheckMcp,
    /// Inspect a declarative policy file
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Line-oriented stdio MCP gate in front of a local server
    Gate {
        /// Policy file applied to every tools/call
        #[arg(long, value_name = "FILE")]
        policy: Option<PathBuf>,
        /// Expected token audience
        #[arg(long, value_name = "A")]
        audience: Option<String>,
        /// Clock-skew leeway in seconds
        #[arg(long, value_name = "SECS")]
        leeway: Option<u64>,
        /// Revoked-jti file (one id per line; reloaded when the file changes)
        #[arg(long, value_name = "FILE")]
        revoked: Option<PathBuf>,
        /// Maximum uses per token jti
        #[arg(long, value_name = "N")]
        max_uses: Option<u64>,
        /// Downstream MCP server command (pass it after `--`)
        #[arg(
            required = true,
            num_args = 1..,
            last = true,
            value_name = "SERVER",
            allow_hyphen_values = true
        )]
        server: Vec<String>,
    },
    /// Append a token jti to a revoked-jti file
    Revoke {
        /// Compact `tg1.` token, JSON token, or raw jti
        token_or_jti: String,
        /// Revoked-jti file to append to
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Validate a policy file
    Lint {
        /// Path to the policy JSON file
        file: PathBuf,
    },
}

#[derive(Deserialize)]
struct MintInput {
    secret: String,
    tool_name: String,
    arg_keys: Vec<String>,
    expiry: u64,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    constraints: Option<Constraints>,
    #[serde(default)]
    generate_jti: bool,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    max_depth: Option<u32>,
}

#[derive(Deserialize)]
struct PolicyMintInput {
    secret: String,
    #[serde(default)]
    current_time: Option<u64>,
}

#[derive(Serialize)]
struct MintOutput {
    token: Token,
}

#[derive(Deserialize)]
struct AttenuateInput {
    secret: String,
    token: Token,
    #[serde(default)]
    arg_keys: Option<Vec<String>>,
    #[serde(default)]
    expiry: Option<u64>,
    #[serde(default)]
    constraints: Option<Constraints>,
}

#[derive(Serialize)]
struct AttenuateOutput {
    token: Token,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TokenArg {
    Object(Box<Token>),
    String(String),
}

impl TokenArg {
    fn into_token(self) -> Result<Token, TokenStringError> {
        match self {
            TokenArg::Object(token) => Ok(*token),
            TokenArg::String(s) => Token::from_token_string(&s),
        }
    }
}

#[derive(Deserialize)]
struct CheckInput {
    secret: String,
    token: TokenArg,
    #[serde(default)]
    current_time: Option<u64>,
    #[serde(default)]
    audience: Option<String>,
    /// Clock-skew leeway in seconds applied to expiry and nbf.
    #[serde(default)]
    leeway: Option<u64>,
}

#[derive(Deserialize)]
struct CheckCallInput {
    secret: String,
    token: TokenArg,
    tool_name: String,
    #[serde(default)]
    arg_keys: Vec<String>,
    #[serde(default)]
    args: Option<BTreeMap<String, String>>,
    #[serde(default)]
    current_time: Option<u64>,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    revoked: Option<Vec<String>>,
    /// Clock-skew leeway in seconds applied to expiry and nbf.
    #[serde(default)]
    leeway: Option<u64>,
}

#[derive(Serialize)]
struct CheckCallOutput {
    authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_kind: Option<String>,
}

#[derive(Serialize)]
struct CheckOutput {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EncodeInput {
    Wrapped { token: Token },
    Raw(Token),
}

#[derive(Serialize)]
struct EncodeOutput {
    token: String,
}

#[derive(Serialize)]
struct DecodeOutput {
    token: Token,
    /// Decode does not check the MAC.
    verified: bool,
}

#[derive(Deserialize)]
struct CheckMcpInput {
    secret: String,
    token: TokenArg,
    request: serde_json::Value,
    #[serde(default)]
    audience: Option<String>,
    #[serde(default)]
    leeway: Option<u64>,
    #[serde(default)]
    current_time: Option<u64>,
    #[serde(default)]
    revoked: Option<Vec<String>>,
}

fn read_stdin() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok(input)
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs()
}

fn decode_secret(s: &str) -> Vec<u8> {
    if let Some(hex_str) = s.strip_prefix("hex:") {
        hex::decode(hex_str).expect("invalid hex in secret")
    } else {
        s.as_bytes().to_vec()
    }
}

struct AuditOpts {
    target: Option<String>,
    redaction: Redaction,
}

impl AuditOpts {
    fn from_cli(cli: &Cli) -> Self {
        let redaction = match &cli.audit_redact_keys {
            Some(keys) => Redaction::keys(keys.split(',').map(str::trim).filter(|s| !s.is_empty())),
            None => Redaction::all_values(),
        };
        AuditOpts {
            target: cli.audit_jsonl.clone(),
            redaction,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let audit = AuditOpts::from_cli(&cli);

    let result = match cli.command {
        Commands::Mint { policy, tool } => handle_mint(policy, tool),
        Commands::Attenuate => handle_attenuate(),
        Commands::Check => handle_check(&audit),
        Commands::CheckCall => handle_check_call(&audit),
        Commands::Encode => handle_encode(),
        Commands::Decode => handle_decode(),
        Commands::CheckMcp => handle_check_mcp(&audit),
        Commands::Policy { command } => match command {
            PolicyCommands::Lint { file } => handle_policy_lint(file),
        },
        Commands::Gate {
            policy,
            audience,
            leeway,
            revoked,
            max_uses,
            server,
        } => handle_gate(policy, audience, leeway, revoked, max_uses, server, &audit),
        Commands::Revoke { token_or_jti, file } => handle_revoke(token_or_jti, file),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn handle_mint(
    policy_path: Option<PathBuf>,
    tool: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match (policy_path, tool) {
        (Some(path), Some(tool)) => handle_mint_from_policy(path, tool),
        (None, None) => handle_mint_from_stdin(),
        (Some(_), None) => Err("--tool is required with --policy".into()),
        (None, Some(_)) => Err("--policy is required with --tool".into()),
    }
}

fn handle_mint_from_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let input: MintInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);

    let token = Token::mint_complete(
        &secret,
        input.tool_name,
        input.arg_keys,
        input.expiry,
        input.audience,
        None,
        input.constraints,
        input.generate_jti,
        input.nbf,
        input.max_depth,
    );

    let output = MintOutput { token };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn handle_mint_from_policy(path: PathBuf, tool: String) -> Result<(), Box<dyn std::error::Error>> {
    let policy = load_policy(&path)?;
    let input: PolicyMintInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let now = input.current_time.unwrap_or_else(current_unix_time);
    let token = policy.mint(&tool, &secret, now)?;
    let output = MintOutput { token };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn load_policy(path: &std::path::Path) -> Result<Policy, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let policy = Policy::from_json(&contents)?;
    policy.validate()?;
    Ok(policy)
}

fn handle_policy_lint(file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(&file)?;
    match Policy::from_json(&contents).and_then(|p| p.validate()) {
        Ok(()) => {
            println!("ok");
            Ok(())
        }
        Err(err) => {
            println!("{err}");
            std::process::exit(1);
        }
    }
}

fn handle_attenuate() -> Result<(), Box<dyn std::error::Error>> {
    let input: AttenuateInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);

    let attenuated = input.token.attenuate_with_constraints(
        &secret,
        input.arg_keys,
        input.expiry,
        input.constraints,
    )?;

    let output = AttenuateOutput { token: attenuated };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn handle_encode() -> Result<(), Box<dyn std::error::Error>> {
    let input: EncodeInput = serde_json::from_str(&read_stdin()?)?;
    let token = match input {
        EncodeInput::Wrapped { token } | EncodeInput::Raw(token) => token,
    };
    let output = EncodeOutput {
        token: token.to_token_string(),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn handle_decode() -> Result<(), Box<dyn std::error::Error>> {
    let raw = read_stdin()?;
    let token_string = parse_token_string_input(&raw)?;
    let token = Token::from_token_string(&token_string)?;
    let output = DecodeOutput {
        token,
        verified: false,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn parse_token_string_input(raw: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = raw.trim();
    if trimmed.starts_with("tg1.") {
        return Ok(trimmed.to_string());
    }
    if let Ok(s) = serde_json::from_str::<String>(trimmed) {
        return Ok(s);
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)?;
    if let Some(s) = value.get("token").and_then(|t| t.as_str()) {
        return Ok(s.to_string());
    }
    Err("decode expects a tg1. string, a JSON string, or {\"token\":\"tg1....\"}".into())
}

fn handle_check(audit: &AuditOpts) -> Result<(), Box<dyn std::error::Error>> {
    let input: CheckInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let token = input.token.into_token()?;
    let current_time = input.current_time.unwrap_or_else(current_unix_time);
    let leeway = Duration::from_secs(input.leeway.unwrap_or(0));
    let sink = MemoryAuditSink::new();
    let mut verifier = Verifier::new(&secret).at(current_time).leeway(leeway);
    if let Some(ref audience) = input.audience {
        verifier = verifier.audience(audience);
    }
    if audit.target.is_some() {
        verifier = verifier.audit(&sink).redaction(&audit.redaction);
    }

    let output = match verifier.verify(&token) {
        Ok(()) => CheckOutput {
            valid: true,
            error: None,
        },
        Err(e) => CheckOutput {
            valid: false,
            error: Some(e.kind().to_string()),
        },
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    emit_audit(audit, &sink)?;
    Ok(())
}

fn handle_check_call(audit: &AuditOpts) -> Result<(), Box<dyn std::error::Error>> {
    let input: CheckCallInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let token = input.token.into_token()?;
    let current_time = input.current_time.unwrap_or_else(current_unix_time);
    let leeway = Duration::from_secs(input.leeway.unwrap_or(0));
    let revocation_list = input
        .revoked
        .map(|jtis| jtis.into_iter().collect::<RevocationList>());
    let sink = MemoryAuditSink::new();
    let mut verifier = Verifier::new(&secret).at(current_time).leeway(leeway);
    if let Some(ref audience) = input.audience {
        verifier = verifier.audience(audience);
    }
    if let Some(ref list) = revocation_list {
        verifier = verifier.revocation(list);
    }
    if audit.target.is_some() {
        verifier = verifier.audit(&sink).redaction(&audit.redaction);
    }

    let result = if let Some(ref args) = input.args {
        verifier.verify_call_with_args(&token, &input.tool_name, args)
    } else {
        let arg_keys_refs: Vec<&str> = input.arg_keys.iter().map(|s| s.as_str()).collect();
        verifier.verify_call(&token, &input.tool_name, &arg_keys_refs)
    };

    let output = match result {
        Ok(()) => CheckCallOutput {
            authorized: true,
            error: None,
            error_kind: None,
        },
        Err(e) => CheckCallOutput {
            authorized: false,
            error: Some(e.to_string()),
            error_kind: Some(e.kind().to_string()),
        },
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    emit_audit(audit, &sink)?;
    Ok(())
}

fn handle_check_mcp(audit: &AuditOpts) -> Result<(), Box<dyn std::error::Error>> {
    let input: CheckMcpInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let token = input.token.into_token()?;
    let current_time = input.current_time.unwrap_or_else(current_unix_time);
    let leeway = Duration::from_secs(input.leeway.unwrap_or(0));
    let revocation_list = input
        .revoked
        .map(|jtis| jtis.into_iter().collect::<RevocationList>());
    let sink = MemoryAuditSink::new();

    let mut verifier = Verifier::new(&secret).at(current_time).leeway(leeway);
    if let Some(ref audience) = input.audience {
        verifier = verifier.audience(audience);
    }
    if let Some(ref list) = revocation_list {
        verifier = verifier.revocation(list);
    }
    if audit.target.is_some() {
        verifier = verifier.audit(&sink).redaction(&audit.redaction);
    }

    let result = check_tools_call(&verifier, &token, &input.request);
    let output = match result {
        Ok(_) => CheckCallOutput {
            authorized: true,
            error: None,
            error_kind: None,
        },
        Err(e) => CheckCallOutput {
            authorized: false,
            error: Some(e.to_string()),
            error_kind: Some(e.kind().to_string()),
        },
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    emit_audit(audit, &sink)?;
    Ok(())
}

fn emit_audit(audit: &AuditOpts, sink: &MemoryAuditSink) -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = audit.target.as_deref() else {
        return Ok(());
    };
    write_audit_jsonl(target, &sink.decisions())?;
    Ok(())
}

fn write_audit_jsonl(
    target: &str,
    decisions: &[Decision],
) -> Result<(), Box<dyn std::error::Error>> {
    match target {
        "stdout" => write_jsonl(io::stdout(), decisions),
        "stderr" => write_jsonl(io::stderr(), decisions),
        path => {
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            write_jsonl(file, decisions)
        }
    }
}

fn write_jsonl<W: Write>(
    writer: W,
    decisions: &[Decision],
) -> Result<(), Box<dyn std::error::Error>> {
    let sink = JsonlAuditSink::new(writer);
    for decision in decisions {
        sink.record(decision)?;
    }
    Ok(())
}

fn handle_revoke(token_or_jti: String, file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let jti = jti_from_token_or_id(&token_or_jti)?;
    append_revoked_jti(&file, &jti)?;
    println!("{jti}");
    Ok(())
}

fn jti_from_token_or_id(input: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("token or jti must not be empty".into());
    }
    if trimmed.starts_with(toolgate::TOKEN_STRING_PREFIX) {
        let token = Token::from_token_string(trimmed)?;
        return token.jti.ok_or_else(|| "token has no jti".into());
    }
    if trimmed.starts_with('{') {
        let token: Token = serde_json::from_str(trimmed)?;
        return token.jti.ok_or_else(|| "token has no jti".into());
    }
    if trimmed.contains(char::is_whitespace) {
        return Err("jti must be a single token identifier".into());
    }
    Ok(trimmed.to_string())
}

const TG_SECRET_ENV: &str = "TG_SECRET";

fn handle_gate(
    policy_path: Option<PathBuf>,
    audience: Option<String>,
    leeway: Option<u64>,
    revoked_path: Option<PathBuf>,
    max_uses: Option<u64>,
    server: Vec<String>,
    audit: &AuditOpts,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret_raw = std::env::var(TG_SECRET_ENV).map_err(|_| {
        format!("{TG_SECRET_ENV} is required (do not pass the secret on the command line)")
    })?;
    let secret = decode_secret(&secret_raw);
    let policy = match policy_path {
        Some(path) => Some(load_policy(&path)?),
        None => None,
    };
    if let Some(0) = max_uses {
        return Err("--max-uses must be greater than 0".into());
    }
    let mut revoked_file = match revoked_path {
        Some(path) => Some(RevocationFile::load(path)?),
        None => None,
    };
    let mut use_store = MemoryUseStore::new();
    let leeway = Duration::from_secs(leeway.unwrap_or(0));
    let sink = MemoryAuditSink::new();
    let code = run_gate_pump(server, |line| {
        if let Some(file) = revoked_file.as_mut() {
            file.reload_if_changed()?;
        }
        let mut verifier = Verifier::new(&secret).leeway(leeway);
        if let Some(ref audience) = audience {
            verifier = verifier.audience(audience);
        }
        if let Some(ref file) = revoked_file {
            verifier = verifier.revocation(file.list());
        }
        if audit.target.is_some() {
            verifier = verifier.audit(&sink).redaction(&audit.redaction);
        }
        let action = match max_uses {
            Some(n) => decide_with_replay(
                line,
                &verifier,
                policy.as_ref(),
                Some((&mut use_store as &mut dyn UseStore, n)),
            ),
            None => decide(line, &verifier, policy.as_ref()),
        };
        if audit.target.is_some() {
            emit_audit(audit, &sink)?;
            sink.clear();
        }
        Ok(action)
    })?;

    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn run_gate_pump(
    mut server: Vec<String>,
    mut on_line: impl FnMut(&str) -> Result<GateAction, Box<dyn std::error::Error>>,
) -> Result<i32, Box<dyn std::error::Error>> {
    if server.is_empty() {
        return Err("server command is required (pass it after --)".into());
    }
    let program = server.remove(0);
    let mut child = Command::new(&program)
        .args(&server)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("failed to spawn {program}: {e}"))?;

    let mut child_stdin = child.stdin.take().ok_or("child stdin is not piped")?;
    let mut child_stdout = child.stdout.take().ok_or("child stdout is not piped")?;
    let client_stdout = Arc::new(Mutex::new(io::stdout()));
    let thread_stdout = client_stdout.clone();

    let out_thread = thread::spawn(move || -> io::Result<()> {
        let mut buf = [0u8; 8192];
        loop {
            let n = match child_stdout.read(&mut buf) {
                Ok(n) => n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            };
            if n == 0 {
                break;
            }
            let mut out = thread_stdout
                .lock()
                .map_err(|_| io::Error::other("client stdout lock poisoned"))?;
            out.write_all(&buf[..n])?;
            out.flush()?;
        }
        Ok(())
    });

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match on_line(&line)? {
            GateAction::Forward(msg) => {
                if writeln!(child_stdin, "{msg}").is_err() || child_stdin.flush().is_err() {
                    break;
                }
            }
            GateAction::Respond(value) => {
                let mut out = client_stdout
                    .lock()
                    .map_err(|_| "client stdout lock poisoned")?;
                writeln!(out, "{}", serde_json::to_string(&value)?)?;
                out.flush()?;
            }
            GateAction::Drop => {}
        }
    }
    drop(child_stdin);

    if let Err(err) = out_thread.join().unwrap_or(Ok(())) {
        return Err(err.into());
    }

    let status = child.wait()?;
    Ok(status.code().unwrap_or(1))
}
