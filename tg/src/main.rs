use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};
use toolgate::{Token, TokenError};

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
}

#[derive(Deserialize)]
struct MintInput {
    secret: String,
    tool_name: String,
    arg_keys: Vec<String>,
    expiry: u64,
    #[serde(default)]
    audience: Option<String>,
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
}

#[derive(Serialize)]
struct AttenuateOutput {
    token: Token,
}

#[derive(Deserialize)]
struct CheckInput {
    secret: String,
    token: Token,
    #[serde(default)]
    current_time: Option<u64>,
    #[serde(default)]
    audience: Option<String>,
}

#[derive(Deserialize)]
struct CheckCallInput {
    secret: String,
    token: Token,
    tool_name: String,
    #[serde(default)]
    arg_keys: Vec<String>,
    #[serde(default)]
    current_time: Option<u64>,
    #[serde(default)]
    audience: Option<String>,
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
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn handle_mint() -> Result<(), Box<dyn std::error::Error>> {
    let input: MintInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);

    let token = Token::mint_with_audience(
        &secret,
        input.tool_name,
        input.arg_keys,
        input.expiry,
        input.audience,
    );

    let output = MintOutput { token };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn handle_attenuate() -> Result<(), Box<dyn std::error::Error>> {
    let input: AttenuateInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);

    let attenuated = input
        .token
        .attenuate(&secret, input.arg_keys, input.expiry)?;

    let output = AttenuateOutput { token: attenuated };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn handle_check() -> Result<(), Box<dyn std::error::Error>> {
    let input: CheckInput = serde_json::from_str(&read_stdin()?)?;
    let secret = decode_secret(&input.secret);
    let current_time = input.current_time.unwrap_or_else(current_unix_time);

    let output =
        match input
            .token
            .verify_with_audience(&secret, current_time, input.audience.as_deref())
        {
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
    let current_time = input.current_time.unwrap_or_else(current_unix_time);

    let arg_keys_refs: Vec<&str> = input.arg_keys.iter().map(|s| s.as_str()).collect();

    let output = match input.token.verify_call(
        &secret,
        current_time,
        &input.tool_name,
        &arg_keys_refs,
        input.audience.as_deref(),
    ) {
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

fn error_to_string(e: &TokenError) -> String {
    match e {
        TokenError::InvalidMac => "invalid_mac".to_string(),
        TokenError::Expired => "expired".to_string(),
        TokenError::AttenuationWidens => "attenuation_widens".to_string(),
        TokenError::AudienceMismatch => "audience_mismatch".to_string(),
        TokenError::ToolMismatch { .. } => "tool_mismatch".to_string(),
        TokenError::ArgKeyNotAllowed { .. } => "arg_key_not_allowed".to_string(),
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
    }
}
