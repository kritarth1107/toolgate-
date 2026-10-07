use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use toolgate::{
    check_tools_call, Constraints, RevocationList, Token, TokenError, TokenStringError, Verifier,
    VerifyTime,
};

#[derive(Parser)]
#[command(name = "tg")]
#[command(about = "Toolgate CLI - macaroon-style capability tokens for tool calls")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mint a new capability token
    Mint,
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

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Mint => handle_mint(),
        Commands::Attenuate => handle_attenuate(),
        Commands::Check => handle_check(),
        Commands::CheckCall => handle_check_call(),
        Commands::Encode => handle_encode(),
        Commands::Decode => handle_decode(),
        Commands::CheckMcp => handle_check_mcp(),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn handle_mint() -> Result<(), Box<dyn std::error::Error>> {
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

fn handle_check() -> Result<(), Box<dyn std::error::Error>> {
    let input: CheckInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let token = input.token.into_token()?;
    let current_time = input.current_time.unwrap_or_else(current_unix_time);
    let leeway = Duration::from_secs(input.leeway.unwrap_or(0));
    let time = VerifyTime::unix_with_leeway(current_time, leeway);

    let output = match token.verify_at(&secret, &time, input.audience.as_deref()) {
        Ok(()) => CheckOutput {
            valid: true,
            error: None,
        },
        Err(e) => CheckOutput {
            valid: false,
            error: Some(error_to_string(&e)),
        },
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn handle_check_call() -> Result<(), Box<dyn std::error::Error>> {
    let input: CheckCallInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let token = input.token.into_token()?;
    let current_time = input.current_time.unwrap_or_else(current_unix_time);
    let leeway = Duration::from_secs(input.leeway.unwrap_or(0));
    let time = VerifyTime::unix_with_leeway(current_time, leeway);

    // Build revocation list if provided
    let revocation_list = input
        .revoked
        .map(|jtis| jtis.into_iter().collect::<RevocationList>());

    // If args provided, use verify_call_with_args_at for constraint checking
    // Otherwise fall back to verify_call_at with just arg_keys
    let result = if let Some(ref args) = input.args {
        token.verify_call_with_args_at(
            &secret,
            &time,
            &input.tool_name,
            args,
            input.audience.as_deref(),
        )
    } else {
        let arg_keys_refs: Vec<&str> = input.arg_keys.iter().map(|s| s.as_str()).collect();
        token.verify_call_at(
            &secret,
            &time,
            &input.tool_name,
            &arg_keys_refs,
            input.audience.as_deref(),
        )
    };

    // Check revocation if list provided and basic verification passed
    let result = match (result, &revocation_list) {
        (Ok(()), Some(list)) => {
            // Check against revocation list
            match &token.jti {
                Some(jti) if list.is_revoked(jti) => Err(TokenError::Revoked { jti: jti.clone() }),
                Some(_) => Ok(()),
                None => Err(TokenError::MissingJti),
            }
        }
        (result, _) => result,
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
            error_kind: Some(error_to_kind(&e)),
        },
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn handle_check_mcp() -> Result<(), Box<dyn std::error::Error>> {
    let input: CheckMcpInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let token = input.token.into_token()?;
    let current_time = input.current_time.unwrap_or_else(current_unix_time);
    let leeway = Duration::from_secs(input.leeway.unwrap_or(0));
    let revocation_list = input
        .revoked
        .map(|jtis| jtis.into_iter().collect::<RevocationList>());

    let mut verifier = Verifier::new(&secret).at(current_time).leeway(leeway);
    if let Some(ref audience) = input.audience {
        verifier = verifier.audience(audience);
    }
    if let Some(ref list) = revocation_list {
        verifier = verifier.revocation(list);
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
            error_kind: Some(error_to_kind(&e)),
        },
    };

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn error_to_string(e: &TokenError) -> String {
    match e {
        TokenError::InvalidMac => "invalid_mac".to_string(),
        TokenError::Expired => "expired".to_string(),
        TokenError::AttenuationWidens => "attenuation_widens".to_string(),
        TokenError::AudienceMismatch => "audience_mismatch".to_string(),
        TokenError::ToolMismatch { .. } => "tool_mismatch".to_string(),
        TokenError::ArgKeyNotAllowed { .. } => "arg_key_not_allowed".to_string(),
        TokenError::UnknownKeyId { .. } => "unknown_key_id".to_string(),
        TokenError::NoActiveKey => "no_active_key".to_string(),
        TokenError::MissingKeyId => "missing_key_id".to_string(),
        TokenError::ConstraintViolation { .. } => "constraint_violation".to_string(),
        TokenError::Revoked { .. } => "revoked".to_string(),
        TokenError::ReplayDetected { .. } => "replay_detected".to_string(),
        TokenError::MissingJti => "missing_jti".to_string(),
        TokenError::NotYetValid => "not_yet_valid".to_string(),
        TokenError::MaxDepthExceeded { .. } => "max_depth_exceeded".to_string(),
        TokenError::MalformedRequest => "malformed_request".to_string(),
    }
}

fn error_to_kind(e: &TokenError) -> String {
    match e {
        TokenError::InvalidMac => "invalid_mac".to_string(),
        TokenError::Expired => "expired".to_string(),
        TokenError::AttenuationWidens => "attenuation_widens".to_string(),
        TokenError::AudienceMismatch => "audience_mismatch".to_string(),
        TokenError::ToolMismatch { .. } => "tool_mismatch".to_string(),
        TokenError::ArgKeyNotAllowed { .. } => "arg_key_not_allowed".to_string(),
        TokenError::UnknownKeyId { .. } => "unknown_key_id".to_string(),
        TokenError::NoActiveKey => "no_active_key".to_string(),
        TokenError::MissingKeyId => "missing_key_id".to_string(),
        TokenError::ConstraintViolation { .. } => "constraint_violation".to_string(),
        TokenError::Revoked { .. } => "revoked".to_string(),
        TokenError::ReplayDetected { .. } => "replay_detected".to_string(),
        TokenError::MissingJti => "missing_jti".to_string(),
        TokenError::NotYetValid => "not_yet_valid".to_string(),
        TokenError::MaxDepthExceeded { .. } => "max_depth_exceeded".to_string(),
        TokenError::MalformedRequest => "malformed_request".to_string(),
    }
}
