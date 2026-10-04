//! Example demonstrating the complete token flow:
//! mint → attenuate → verify_call
//!
//! Run with: cargo run --example tool_call_flow

use toolgate::Token;

fn main() {
    let secret = b"example-secret-key-32-bytes-!!";
    let current_time = 1700000000u64;
    let expiry = 1700100000u64;

    println!("=== Toolgate Token Flow Example ===\n");

    // Step 1: Server mints a token for a client
    println!("1. Minting token for file_manager tool...");
    let token = Token::mint_with_audience(
        secret,
        "file_manager",
        vec!["read".into(), "write".into(), "delete".into()],
        expiry,
        Some("client-abc".to_string()),
    );
    println!("   Tool: {}", token.tool_name);
    println!("   Allowed args: {:?}", token.arg_keys);
    println!("   Audience: {:?}", token.audience);
    println!("   Expiry: {}", token.expiry);
    println!();

    // Step 2: Token is attenuated to reduce capabilities
    println!("2. Attenuating token (removing 'delete' permission)...");
    let attenuated = token
        .attenuate(secret, Some(vec!["read".into(), "write".into()]), None)
        .expect("attenuation should succeed");
    println!(
        "   Allowed args after attenuation: {:?}",
        attenuated.arg_keys
    );
    println!("   Audience preserved: {:?}", attenuated.audience);
    println!();

    // Step 3: Client attempts various tool calls
    println!("3. Verifying tool calls...\n");

    // Allowed call: read operation
    let result = attenuated.verify_call(
        secret,
        current_time,
        "file_manager",
        &["read"],
        Some("client-abc"),
    );
    println!("   read operation: {}", format_result(&result));

    // Allowed call: write operation
    let result = attenuated.verify_call(
        secret,
        current_time,
        "file_manager",
        &["write"],
        Some("client-abc"),
    );
    println!("   write operation: {}", format_result(&result));

    // Denied: delete was attenuated away
    let result = attenuated.verify_call(
        secret,
        current_time,
        "file_manager",
        &["delete"],
        Some("client-abc"),
    );
    println!("   delete operation: {}", format_result(&result));

    // Denied: wrong tool
    let result = attenuated.verify_call(
        secret,
        current_time,
        "database_manager",
        &["read"],
        Some("client-abc"),
    );
    println!("   database_manager: {}", format_result(&result));

    // Denied: wrong audience
    let result = attenuated.verify_call(
        secret,
        current_time,
        "file_manager",
        &["read"],
        Some("client-xyz"),
    );
    println!("   wrong audience: {}", format_result(&result));

    println!();
    println!("=== Wire Format ===\n");

    // Demonstrate wire encoding
    let wire = attenuated.to_wire();
    let json = serde_json::to_string(&attenuated).unwrap();
    println!("   Wire format: {} bytes", wire.len());
    println!("   JSON format: {} bytes", json.len());
    println!(
        "   Space savings: {}%",
        (json.len() - wire.len()) * 100 / json.len()
    );

    let decoded = Token::from_wire(&wire).expect("wire decode should succeed");
    println!("   Roundtrip verified: {}", decoded == attenuated);
}

fn format_result(result: &Result<(), toolgate::TokenError>) -> String {
    match result {
        Ok(()) => "✓ ALLOWED".to_string(),
        Err(e) => format!("✗ DENIED ({})", e),
    }
}
