//! Example demonstrating the complete token flow:
//! mint → attenuate → verify_call (with value constraints)
//! And: revocation, replay prevention, nbf, leeway, and max attenuation depth
//!
//! Run with: cargo run --example tool_call_flow

use std::collections::BTreeMap;
use std::time::Duration;
use toolgate::{
    Constraint, FixedClock, MemoryUseStore, RevocationList, Token, TokenError, VerifyTime,
};

fn main() {
    let secret = b"example-secret-key-32-bytes-!!";
    let current_time = 1700000000u64;
    let expiry = 1700100000u64;

    println!("=== Toolgate Token Flow Example ===\n");

    // Step 1: Server mints a token with constraints and jti for tracking
    println!("1. Minting token for read_file tool with constraints and jti...");

    let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
    constraints.insert("path".to_string(), Constraint::Prefix("/data/".to_string()));
    constraints.insert(
        "limit".to_string(),
        Constraint::IntRange { min: 1, max: 1000 },
    );

    let token = Token::mint_with_jti(
        secret,
        "read_file",
        vec!["path".into(), "limit".into(), "format".into()],
        expiry,
        Some("client-abc".to_string()),
        None,
        Some(constraints),
        true, // generate jti for revocation/replay tracking
    );

    println!("   Tool: {}", token.tool_name);
    println!("   Allowed args: {:?}", token.arg_keys);
    println!("   Constraints: {:?}", token.constraints);
    println!("   Audience: {:?}", token.audience);
    println!("   JTI: {:?}", token.jti);
    println!();

    // Step 2: Token is attenuated to tighten constraints (jti preserved)
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
    println!("   JTI preserved: {}", attenuated.jti == token.jti);
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
    println!("=== Revocation and Replay Prevention ===\n");

    // Mint a single-use token
    println!("4. Single-use token (replay prevention)...");
    let single_use_token = Token::mint_with_jti(
        secret,
        "sensitive_op",
        vec!["action".into()],
        expiry,
        None,
        None,
        None,
        true,
    );
    println!("   JTI: {:?}", single_use_token.jti);

    let mut use_store = MemoryUseStore::new();

    let result = single_use_token.verify_single_use(secret, current_time, &mut use_store);
    println!("   First use: {}", format_result(&result));

    let result = single_use_token.verify_single_use(secret, current_time, &mut use_store);
    println!("   Second use (replay): {}", format_result(&result));

    println!();
    println!("5. Token revocation...");

    let revocable_token = Token::mint_with_jti(
        secret,
        "revocable_op",
        vec![],
        expiry,
        None,
        None,
        None,
        true,
    );
    println!("   JTI: {:?}", revocable_token.jti);

    let mut revocation_list = RevocationList::new();

    let result = revocable_token.verify_with_revocation(secret, current_time, &revocation_list);
    println!("   Before revocation: {}", format_result(&result));

    revocation_list.revoke(revocable_token.jti.clone().unwrap());

    let result = revocable_token.verify_with_revocation(secret, current_time, &revocation_list);
    println!("   After revocation: {}", format_result(&result));

    println!();
    println!("=== Wire Format ===\n");

    // Demonstrate wire encoding (includes constraints and jti)
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
    println!(
        "   JTI preserved after roundtrip: {}",
        decoded.jti == attenuated.jti
    );

    println!();
    println!("=== Clock, Not-Before, Leeway, and Depth ===\n");

    println!("6. Not-before (nbf) and injected FixedClock...");
    let timed = Token::mint_complete(
        secret,
        "scheduled_op",
        vec!["action".into()],
        expiry,
        None,
        None,
        None,
        false,
        Some(current_time + 60),
        Some(1),
    );
    println!("   nbf: {:?}", timed.nbf);
    println!("   max_depth: {:?}", timed.max_depth);

    let too_early = FixedClock::at(current_time);
    println!(
        "   Before nbf: {}",
        format_result(&timed.verify_with_clock(secret, &too_early, Duration::ZERO))
    );

    let on_time = FixedClock::at(current_time + 60);
    println!(
        "   At nbf: {}",
        format_result(&timed.verify_with_clock(secret, &on_time, Duration::ZERO))
    );

    println!();
    println!("7. Clock-skew leeway...");
    let expired = Token::mint(secret, "skew_op", vec![], current_time);
    let late = VerifyTime::unix_with_leeway(current_time + 20, Duration::from_secs(30));
    println!(
        "   20s past expiry, 30s leeway: {}",
        format_result(&expired.verify_at(secret, &late, None))
    );
    let too_late = VerifyTime::unix_with_leeway(current_time + 40, Duration::from_secs(30));
    println!(
        "   40s past expiry, 30s leeway: {}",
        format_result(&expired.verify_at(secret, &too_late, None))
    );

    println!();
    println!("8. Max attenuation depth...");
    let first = timed
        .attenuate(secret, None, Some(expiry - 1))
        .expect("first attenuation within max_depth=1");
    println!("   After 1 attenuate: depth={}", first.depth);
    let second = first.attenuate(secret, None, Some(expiry - 2));
    match second {
        Ok(_) => println!("   Second attenuate: unexpectedly succeeded"),
        Err(TokenError::MaxDepthExceeded { depth, max }) => {
            println!(
                "   Second attenuate: rejected (depth {} > max {})",
                depth, max
            );
        }
        Err(e) => println!("   Second attenuate: unexpected error ({})", e),
    }
}

fn format_result(result: &Result<(), toolgate::TokenError>) -> String {
    match result {
        Ok(()) => "✓ ALLOWED".to_string(),
        Err(e) => format!("✗ DENIED ({})", e),
    }
}
