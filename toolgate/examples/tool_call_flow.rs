//! Example demonstrating the complete token flow:
//! mint → attenuate → verify_call (with value constraints)
//!
//! Run with: cargo run --example tool_call_flow

use std::collections::BTreeMap;
use toolgate::{Constraint, Token};

fn main() {
    let secret = b"example-secret-key-32-bytes-!!";
    let current_time = 1700000000u64;
    let expiry = 1700100000u64;

    println!("=== Toolgate Token Flow Example ===\n");

    // Step 1: Server mints a token with constraints
    println!("1. Minting token for read_file tool with constraints...");

    let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
    constraints.insert("path".to_string(), Constraint::Prefix("/data/".to_string()));
    constraints.insert(
        "limit".to_string(),
        Constraint::IntRange { min: 1, max: 1000 },
    );

    let token = Token::mint_full(
        secret,
        "read_file",
        vec!["path".into(), "limit".into(), "format".into()],
        expiry,
        Some("client-abc".to_string()),
        None,
        Some(constraints),
    );

    println!("   Tool: {}", token.tool_name);
    println!("   Allowed args: {:?}", token.arg_keys);
    println!("   Constraints: {:?}", token.constraints);
    println!("   Audience: {:?}", token.audience);
    println!();

    // Step 2: Token is attenuated to tighten constraints
    println!("2. Attenuating token (tightening path constraint to /data/public/)...");

    let mut tighter: BTreeMap<String, Constraint> = BTreeMap::new();
    tighter.insert(
        "path".to_string(),
        Constraint::Prefix("/data/public/".to_string()),
    );
    tighter.insert(
        "limit".to_string(),
        Constraint::IntRange { min: 1, max: 100 },
    );

    let attenuated = token
        .attenuate_with_constraints(
            secret,
            Some(vec!["path".into(), "limit".into()]),
            None,
            Some(tighter),
        )
        .expect("attenuation should succeed");

    println!("   Args after attenuation: {:?}", attenuated.arg_keys);
    println!(
        "   Constraints after attenuation: {:?}",
        attenuated.constraints
    );
    println!();

    // Step 3: Verify calls with argument values
    println!("3. Verifying tool calls with argument values...\n");

    // Allowed: path in /data/public/, limit within range
    let mut args = BTreeMap::new();
    args.insert("path".to_string(), "/data/public/file.txt".to_string());
    args.insert("limit".to_string(), "50".to_string());

    let result = attenuated.verify_call_with_args(
        secret,
        current_time,
        "read_file",
        &args,
        Some("client-abc"),
    );
    println!(
        "   /data/public/file.txt, limit=50: {}",
        format_result(&result)
    );

    // Denied: path outside allowed prefix
    let mut bad_path = BTreeMap::new();
    bad_path.insert("path".to_string(), "/etc/passwd".to_string());
    bad_path.insert("limit".to_string(), "10".to_string());

    let result = attenuated.verify_call_with_args(
        secret,
        current_time,
        "read_file",
        &bad_path,
        Some("client-abc"),
    );
    println!("   /etc/passwd, limit=10: {}", format_result(&result));

    // Denied: limit exceeds constraint
    let mut bad_limit = BTreeMap::new();
    bad_limit.insert("path".to_string(), "/data/public/file.txt".to_string());
    bad_limit.insert("limit".to_string(), "500".to_string());

    let result = attenuated.verify_call_with_args(
        secret,
        current_time,
        "read_file",
        &bad_limit,
        Some("client-abc"),
    );
    println!(
        "   /data/public/file.txt, limit=500: {}",
        format_result(&result)
    );

    // Denied: wrong audience
    let result = attenuated.verify_call_with_args(
        secret,
        current_time,
        "read_file",
        &args,
        Some("client-xyz"),
    );
    println!("   valid args, wrong audience: {}", format_result(&result));

    println!();
    println!("=== Wire Format ===\n");

    // Demonstrate wire encoding (includes constraints)
    let wire = attenuated.to_wire();
    let json = serde_json::to_string(&attenuated).unwrap();
    println!("   Wire format: {} bytes", wire.len());
    println!("   JSON format: {} bytes", json.len());
    println!(
        "   Space savings: {}%",
        (json.len() - wire.len()) * 100 / json.len()
    );

    let decoded = Token::from_wire(&wire).expect("wire decode should succeed");
    println!(
        "   Constraints preserved after roundtrip: {}",
        decoded.constraints == attenuated.constraints
    );
}

fn format_result(result: &Result<(), toolgate::TokenError>) -> String {
    match result {
        Ok(()) => "✓ ALLOWED".to_string(),
        Err(e) => format!("✗ DENIED ({})", e),
    }
}
