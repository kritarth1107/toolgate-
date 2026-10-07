# toolgate

A small, fast Rust library for issuing macaroon-style capability tokens for tool calls.

## What It Does

toolgate issues capability tokens that bind:
- **Tool name**: which tool the token authorizes
- **Argument keys**: an allowlist of permitted argument names
- **Argument constraints** (optional): restrict argument values (prefix, exact, one-of, max length, int range)
- **Expiry**: unix timestamp when the token becomes invalid
- **Not-before (`nbf`)** (optional): unix timestamp before which the token is rejected
- **Audience** (optional): restrict token to a specific client/service
- **Token ID (jti)** (optional): unique identifier for revocation and replay detection
- **Max attenuation depth** (optional): how many times the token may be narrowed
- **Nonce**: random bytes for uniqueness

Tokens are signed with HMAC-SHA256 over a canonical byte encoding. They can be **attenuated** (capabilities reduced) but never widened—you can drop argument keys, shorten expiry, or tighten constraints, but never add keys, extend expiry, or loosen constraints. Audience binding, key ID, token ID, not-before, and max depth are preserved during attenuation. Each attenuation increments a `depth` counter; if `max_depth` is set, further narrowing is rejected.

Expiry and not-before checks take a swappable [`Clock`](#clocks-and-leeway) plus optional clock-skew leeway, so library paths do not call `SystemTime` directly.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
toolgate = "0.9"
```

Or install the CLI:

```bash
cargo install --path tg
```

## Library Usage

```rust
use toolgate::Token;

let secret = b"your-256-bit-secret-key-here!!";

// Mint a token
let token = Token::mint(
    secret,
    "read_file",
    vec!["path".into(), "offset".into()],
    1700000000, // expiry unix seconds
);

// Mint with audience binding
let bound_token = Token::mint_with_audience(
    secret,
    "read_file",
    vec!["path".into()],
    1700000000,
    Some("client-123".to_string()),
);

// Verify a token
let current_time = 1699999999;
token.verify(secret, current_time)?; // Ok(())

// Verify with audience check
bound_token.verify_with_audience(secret, current_time, Some("client-123"))?;

// Verify a specific tool call (checks MAC, expiry, audience, tool name, arg keys)
token.verify_call(
    secret,
    current_time,
    "read_file",
    &["path", "offset"],
    None, // no audience check
)?;

// Same checks through the Verifier builder
use toolgate::Verifier;
Verifier::new(secret)
    .at(current_time)
    .verify_call(&token, "read_file", &["path", "offset"])?;

// Attenuate: drop keys or shorten expiry
let restricted = token.attenuate(
    secret,
    Some(vec!["path".into()]), // only allow "path" arg
    Some(1699500000),          // shorter expiry
)?;
```

## Clocks and Leeway

Verification uses a `Clock` instead of calling `SystemTime` in library paths. Pass an explicit unix timestamp (wrapped as `FixedClock`) or inject a test clock:

```rust
use std::time::Duration;
use toolgate::{FixedClock, Token, VerifyTime};

let secret = b"your-256-bit-secret-key-here!!";
let token = Token::mint(secret, "read_file", vec!["path".into()], 1700000000);

// Existing API: current_time is a FixedClock with zero leeway
token.verify(secret, 1699999999)?;

// Inject a clock (useful in tests)
let clock = FixedClock::at(1699999999);
token.verify_with_clock(secret, &clock, Duration::ZERO)?;

// Allow 30s of clock skew on expiry (and nbf, if set)
token.verify_with_leeway(secret, 1700000020, Duration::from_secs(30))?;

// Bundle clock + leeway
let time = VerifyTime::unix_with_leeway(1700000020, Duration::from_secs(30));
token.verify_at(secret, &time, None)?;
```

Leeway is applied symmetrically:
- Expired if `now > expiry + leeway`
- Not yet valid if `now + leeway < nbf`

## Not-Before and Max Attenuation Depth

```rust
use toolgate::Token;

let secret = b"your-256-bit-secret-key-here!!";

let token = Token::mint_complete(
    secret,
    "read_file",
    vec!["path".into(), "limit".into()],
    1700100000,          // expiry
    None,                // audience
    None,                // kid
    None,                // constraints
    false,               // generate_jti
    Some(1700000000),    // nbf
    Some(2),             // max_depth: at most two attenuations
);

// Too early
assert!(token.verify(secret, 1699999999).is_err());
// On or after nbf
assert!(token.verify(secret, 1700000000).is_ok());

let once = token.attenuate(secret, Some(vec!["path".into()]), None)?;
assert_eq!(once.depth, 1);
let twice = once.attenuate(secret, None, Some(1700050000))?;
assert_eq!(twice.depth, 2);
assert!(twice.attenuate(secret, None, None).is_err()); // MaxDepthExceeded
```

`nbf`, `depth`, and `max_depth` are covered by the MAC. Tokens minted without them encode identically to v0.5.

## Argument Value Constraints

Tokens can restrict not just which argument keys are allowed, but also what values those arguments may have:

```rust
use toolgate::{Token, Constraint};
use std::collections::BTreeMap;

let secret = b"your-256-bit-secret-key-here!!";

// Create constraints
let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
constraints.insert("mode".to_string(), Constraint::OneOf(vec!["read".into(), "list".into()]));
constraints.insert("limit".to_string(), Constraint::IntRange { min: 1, max: 100 });
constraints.insert("query".to_string(), Constraint::MaxLen(256));

// Mint token with constraints
let token = Token::mint_full(
    secret,
    "file_op",
    vec!["path".into(), "mode".into(), "limit".into(), "query".into()],
    2000000000,
    None,  // audience
    None,  // kid
    Some(constraints),
);

// Verify with actual argument values
let mut args = BTreeMap::new();
args.insert("path".to_string(), "/tmp/test.txt".to_string());
args.insert("mode".to_string(), "read".to_string());
args.insert("limit".to_string(), "50".to_string());

token.verify_call_with_args(
    secret,
    1999999999,
    "file_op",
    &args,
    None,
)?; // Ok - all constraints satisfied
```

### Constraint Types

| Type | Description | Example |
|------|-------------|---------|
| `Exact(String)` | Value must match exactly | `Exact("read".into())` |
| `OneOf(Vec<String>)` | Value must be one of the allowed values | `OneOf(vec!["read".into(), "write".into()])` |
| `Prefix(String)` | Value must start with the prefix | `Prefix("/tmp/".into())` |
| `MaxLen(usize)` | Value must have at most N bytes | `MaxLen(256)` |
| `IntRange { min, max }` | Value must parse as integer in range | `IntRange { min: 1, max: 100 }` |

### Attenuating Constraints

Constraints can only be tightened during attenuation, never loosened:

```rust
// Tighten prefix: /tmp/ → /tmp/subdir/
let mut tighter: BTreeMap<String, Constraint> = BTreeMap::new();
tighter.insert("path".to_string(), Constraint::Prefix("/tmp/subdir/".to_string()));

let attenuated = token.attenuate_with_constraints(
    secret,
    None,  // keep same arg keys
    None,  // keep same expiry
    Some(tighter),
)?;
```

Valid attenuation rules:
- **Prefix**: new prefix must extend the old one (`/tmp/` → `/tmp/sub/`)
- **OneOf**: new set must be a subset of the old set
- **MaxLen**: new max must be ≤ old max
- **IntRange**: new range must be within old range
- **Exact**: can replace any constraint if the exact value satisfies it

## Key Rotation

The `Keyring` type manages multiple signing keys for seamless key rotation:

```rust
use toolgate::Keyring;

let mut keyring = Keyring::new();

// Add keys - first key becomes active automatically
keyring.add("key-2024", b"old-secret-key-32-bytes-here!!".to_vec());
keyring.add("key-2025", b"new-secret-key-32-bytes-here!!".to_vec());

// Set the newer key as active for minting
keyring.set_active("key-2025").unwrap();

// Mint with the active key - token includes kid field
let token = keyring.mint("read_file", vec!["path".into()], 2000000000).unwrap();
assert_eq!(token.kid, Some("key-2025".to_string()));

// Verify through keyring (looks up key by kid)
keyring.verify(&token, 1999999999).unwrap();

// Old tokens still verify until their key is retired
let old_token = Token::mint_with_kid(
    b"old-secret-key-32-bytes-here!!",
    "read_file",
    vec!["path".into()],
    2000000000,
    None,
    Some("key-2024".to_string()),
);
keyring.verify(&old_token, 1999999999).unwrap();

// Retire old key when ready - old tokens will fail with UnknownKeyId
keyring.retire("key-2024");
```

Key points:
- Tokens carry an optional `kid` (key identifier) covered by the MAC
- `Keyring::verify` looks up the signing key by `kid`
- Attenuation preserves the original `kid`
- Tokens without `kid` cannot be verified through a keyring (use `Token::verify` directly)

## Revocation and Replay Prevention

Tokens can carry a unique identifier (`jti`) for revocation tracking and replay prevention:

```rust
use toolgate::{Token, RevocationList, MemoryUseStore};

let secret = b"your-256-bit-secret-key-here!!";

// Mint a token with jti for tracking
let token = Token::mint_with_jti(
    secret,
    "sensitive_op",
    vec!["action".into()],
    2000000000,
    None,  // audience
    None,  // kid
    None,  // constraints
    true,  // generate_jti
);
assert!(token.jti.is_some()); // 16 random bytes, hex-encoded

// ===== Revocation =====
let mut revocation_list = RevocationList::new();

// Token is valid
assert!(token.verify_with_revocation(secret, 1999999999, &revocation_list).is_ok());

// Revoke the token
revocation_list.revoke(token.jti.clone().unwrap());

// Token is now rejected
assert!(token.verify_with_revocation(secret, 1999999999, &revocation_list).is_err());

// ===== Replay Prevention (single-use) =====
let single_use_token = Token::mint_with_jti(
    secret,
    "one_time_op",
    vec![],
    2000000000,
    None, None, None,
    true,
);

let mut use_store = MemoryUseStore::new();

// First use succeeds
assert!(single_use_token.verify_single_use(secret, 1999999999, &mut use_store).is_ok());

// Second use (replay) fails
assert!(single_use_token.verify_single_use(secret, 1999999999, &mut use_store).is_err());

// ===== Max-uses (e.g., allow 3 uses) =====
let multi_use_token = Token::mint_with_jti(
    secret,
    "limited_op",
    vec![],
    2000000000,
    None, None, None,
    true,
);

let mut store = MemoryUseStore::new();
for _ in 0..3 {
    assert!(multi_use_token.verify_with_max_uses(secret, 1999999999, &mut store, 3, None).is_ok());
}
// Fourth use fails
assert!(multi_use_token.verify_with_max_uses(secret, 1999999999, &mut store, 3, None).is_err());
```

Key points:
- `jti` is a 16-byte random identifier (hex-encoded, 32 chars) covered by the MAC
- Attenuated tokens inherit their parent's `jti`
- `RevocationList` tracks explicitly revoked token IDs
- `UseStore` trait enables pluggable use-count tracking (in-memory impl provided)
- Tokens without `jti` cannot be checked against revocation lists or use stores

## Policy Files

Operators describe which tools an agent may call in one JSON document. toolgate mints tokens from a grant (defaults applied) and re-checks calls against the current file, so tightening the policy denies older broader tokens.

```rust
use std::collections::BTreeMap;
use toolgate::{MemoryAuditSink, Policy, Verifier};

let secret = b"your-256-bit-secret-key-here!!";
let json = std::fs::read_to_string("examples/policy.json")?;
let policy = Policy::from_json(&json)?;
policy.validate()?;

// Mint: expiry is now + ttl; audience / max_depth / constraints come from
// the grant with policy defaults applied.
let now = 1_700_000_000;
let token = policy.mint("read_file", secret, now)?;

// Or mint with the keyring's active key (token kid is the active key id).
// policy.mint_with_keyring("read_file", &keyring, now)?;

let mut args = BTreeMap::new();
args.insert("path".to_string(), "/tmp/a.txt".to_string());
args.insert("limit".to_string(), "10".to_string());

let sink = MemoryAuditSink::new();
let verifier = Verifier::new(secret).at(now).audit(&sink);
policy.check_call_with_args(&verifier, &token, "read_file", &args)?;
assert_eq!(sink.len(), 1); // one Decision, even when the policy check fails
```

`examples/policy.json` is a complete sample. Schema:

| Field | Where | Description |
|-------|--------|-------------|
| `version` | policy | Must be `"1"` |
| `default_audience` / `default_ttl_seconds` / `default_max_depth` / `default_kid` | policy | Optional defaults |
| `tools[]` | policy | Grants; each `name` may appear once |
| `name` / `arg_keys` | grant | Tool name and allowed argument keys |
| `constraints` | grant | Per-key [`Constraint`](#argument-value-constraints) (same serde form as tokens) |
| `ttl_seconds` / `audience` / `max_depth` | grant | Optional overrides of the defaults |

`Policy::validate()` rejects unknown versions, duplicate tool names, empty tool names, zero TTLs, and constraints on keys that are not in the grant's allowlist. Minting an unknown tool, or a grant with no TTL and no default TTL, is an error.

`check_call` / `check_call_with_args` verify the token through [`Verifier`](#verifier) **and** confirm the token is still within the current policy (argument keys, constraints, audience, and max depth). An attached `AuditSink` still records exactly one `Decision`.

## CLI Usage

The `tg` binary accepts JSON on stdin and outputs JSON.

### Mint

```bash
echo '{
  "secret": "my-secret",
  "tool_name": "read_file",
  "arg_keys": ["path", "limit"],
  "expiry": 2000000000,
  "audience": "client-123",
  "constraints": {
    "path": {"type": "prefix", "value": "/tmp/"},
    "limit": {"type": "int_range", "value": {"min": 1, "max": 100}}
  },
  "generate_jti": true,
  "nbf": 1699990000,
  "max_depth": 2
}' | tg mint
```

The `audience`, `constraints`, `generate_jti`, `nbf`, and `max_depth` fields are optional. Set `generate_jti: true` to generate a unique token identifier for revocation/replay tracking.

Mint from a policy file instead of a full mint request. Stdin still supplies the secret (and optional `current_time`); expiry is `now + ttl` from the grant.

```bash
echo '{"secret": "my-secret", "current_time": 1700000000}' | tg mint --policy examples/policy.json --tool read_file
```

Existing stdin JSON minting is unchanged when `--policy` is omitted.

### Policy lint

Validate a policy file. Prints `ok` or the validation errors; exits nonzero on error.

```bash
tg policy lint examples/policy.json
```

### Attenuate

```bash
echo '{
  "secret": "my-secret",
  "token": { ... },
  "arg_keys": ["path"],
  "expiry": 1900000000,
  "constraints": {
    "path": {"type": "prefix", "value": "/tmp/subdir/"}
  }
}' | tg attenuate
```

The `constraints` field can add new constraints or tighten existing ones (never loosen).

### Check

```bash
echo '{
  "secret": "my-secret",
  "token": { ... },
  "current_time": 1699999999,
  "audience": "client-123",
  "leeway": 30
}' | tg check
```

Omit `current_time` to use the system clock. The `audience` and `leeway` (seconds of clock-skew grace) fields are optional.

### Check-Call

Verify a token authorizes a specific tool call:

```bash
# Check with just arg keys (no value validation)
echo '{
  "secret": "my-secret",
  "token": { ... },
  "tool_name": "read_file",
  "arg_keys": ["path"],
  "audience": "client-123"
}' | tg check-call

# Check with actual argument values (validates constraints)
echo '{
  "secret": "my-secret",
  "token": { ... },
  "tool_name": "read_file",
  "args": {"path": "/tmp/test.txt", "limit": "50"},
  "audience": "client-123"
}' | tg check-call

# Check with revocation list and clock-skew leeway
echo '{
  "secret": "my-secret",
  "token": { ... },
  "tool_name": "read_file",
  "args": {"path": "/tmp/test.txt"},
  "revoked": ["abc123...", "def456..."],
  "leeway": 30
}' | tg check-call
```

The `token` field on `check` and `check-call` may be a JSON token object or a `tg1.` string.

Returns `{"authorized": true}` or `{"authorized": false, "error": "...", "error_kind": "..."}`.

### Encode

Convert a JSON token (raw object or `{"token": {...}}`) to a compact string:

```bash
echo '{"token": { ... }}' | tg encode
# {"token":"tg1...."}
```

### Decode

Convert a `tg1.` string to JSON. The MAC is not checked; the output always includes `"verified": false`.

```bash
echo 'tg1....' | tg decode
```

### Check-Mcp

Verify a token against an MCP `tools/call` JSON-RPC request:

```bash
echo '{
  "secret": "my-secret",
  "token": "tg1....",
  "request": {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "read_file", "arguments": {"path": "/tmp/a.txt", "limit": 10}}
  },
  "audience": "client-123",
  "leeway": 30,
  "current_time": 1699999999,
  "revoked": []
}' | tg check-mcp
```

`token` may be a JSON token or a `tg1.` string. Returns `{"authorized": true}` or `{"authorized": false, "error": "...", "error_kind": "..."}`.

Error kinds: `invalid_mac`, `expired`, `not_yet_valid`, `audience_mismatch`, `tool_mismatch`, `arg_key_not_allowed`, `constraint_violation`, `revoked`, `missing_jti`, `max_depth_exceeded`, `malformed_request`, `policy_denied`.

### Audit JSONL

`tg check`, `tg check-call`, and `tg check-mcp` accept `--audit-jsonl TARGET` to write one `Decision` per line after the command JSON. `TARGET` is `stdout`, `stderr`, or a file path (created/appended). Argument values are redacted by default. Pass `--audit-redact-keys path,token` to redact only those keys.

```bash
echo '{ ... }' | tg check-call --audit-jsonl stderr
echo '{ ... }' | tg check-mcp --audit-jsonl /tmp/decisions.jsonl
echo '{ ... }' | tg check --audit-jsonl stdout --audit-redact-keys path
```

Secrets can be hex-encoded with `"secret": "hex:deadbeef..."`.

## Canonical Byte Encoding (v6)

For cross-implementation compatibility, tokens are signed over this exact byte layout (all integers big-endian):

| Field | Encoding |
|-------|----------|
| tool_name | u16 length + UTF-8 bytes |
| arg_keys_count | u16 |
| arg_keys | for each key (sorted lexicographically): u16 length + UTF-8 bytes |
| expiry | u64 (unix seconds) |
| nonce | u16 length + raw bytes |
| audience | u16 length + UTF-8 bytes (0 = unbound) |
| kid | u16 length + UTF-8 bytes (0 = no key id) |
| constraints_count | u16 (only if > 0) |
| constraints | for each (sorted by key): key + type (u8) + type-specific data |
| jti | u16 length + UTF-8 bytes (only if present) |
| flags | u8 (only if nbf, depth>0, or max_depth is set; bit0=nbf, bit1=depth, bit2=max_depth) |
| nbf | u64 (only if bit0 is set) |
| depth | u32 (only if bit1 is set) |
| max_depth | u32 (only if bit2 is set) |

Constraint type encoding:
- `0` Exact: u16 length + UTF-8 value
- `1` OneOf: u16 count + (for each, sorted: u16 length + UTF-8 value)
- `2` Prefix: u16 length + UTF-8 prefix
- `3` MaxLen: u64 max
- `4` IntRange: i64 min + i64 max

**Example without constraints, jti, nbf, or depth** (identical to v5/v4/v3):

```
00 04 r e a d           # tool_name: len=4, "read"
00 02                   # 2 arg keys
00 01 a                 # key "a"
00 01 b                 # key "b"
00 00 00 00 00 00 03 e8 # expiry = 1000
00 02 ab cd             # nonce: len=2, bytes
00 00                   # audience: len=0 (unbound)
00 00                   # kid: len=0 (none)
```

Tokens without nbf/depth/max_depth encode identically to v5. Tokens without jti encode identically to v4. Tokens without constraints and without jti encode identically to v3, ensuring backward compatibility.

The HMAC-SHA256 is computed over these concatenated bytes.

## Compact Wire Format

For efficient transmission, tokens can be encoded to a compact binary format:

```rust
let wire_bytes = token.to_wire();
let decoded = Token::from_wire(&wire_bytes)?;
```

Wire format is typically smaller than JSON and suitable for constrained channels.

## String Tokens

`Token::to_token_string()` encodes the wire bytes as `tg1.` plus unpadded base64url. `Token::from_token_string()` (and `FromStr`) decode that form. The string is suitable for an HTTP header or an MCP `_meta` field.

```rust
use toolgate::Token;

let compact = token.to_token_string(); // "tg1...."
let parsed = Token::from_token_string(&compact)?;
assert_eq!(parsed, token);
```

Decoding rejects a wrong prefix, invalid base64url, trailing garbage after the wire payload, and input longer than `MAX_TOKEN_STRING_LEN` (8192 bytes). Parsing a string does not verify the MAC.

## Verifier

`Verifier` consolidates the `verify_*` variants. Existing `Token` and `Keyring` methods keep their behaviour and delegate to it.

```rust
use std::time::Duration;
use toolgate::{FixedClock, Verifier};

let clock = FixedClock::at(1699999999);
Verifier::new(secret)
    .clock(&clock)          // or .at(unix)
    .leeway(Duration::from_secs(30))
    .audience("client-123")
    .revocation(&revocation_list)
    .keyring(&keyring)      // looks up the secret by kid
    .audit(&sink)           // optional Decision sink
    .verify(&token)?;

Verifier::new(secret)
    .at(1699999999)
    .verify_call(&token, "read_file", &["path"])?;

Verifier::new(secret)
    .at(1699999999)
    .verify_call_with_args(&token, "read_file", &args)?;
```

`.keyring()` overrides the constructor secret and looks up the signing key by `kid`. Single-use and max-uses checks stay on `Token::verify_single_use` / `Token::verify_with_max_uses` (and the matching `Keyring` methods); threading a `&mut UseStore` through the builder would make every check require a mutable borrow.

Attach `.audit(&sink)` to record each verify/check as a [`Decision`]. Argument values are redacted by default (keys kept, values replaced with `[REDACTED]`). Use `.redaction(&Redaction::keys(["token"]))` to redact only listed keys.

## Audit Decisions

Every `Verifier` check can emit a structured, serializable `Decision` to a pluggable `AuditSink`. The record includes allow/deny, reason/`error_kind`, token id (`jti`), tool name, audience, a timestamp from the verifier `Clock`, delegation `depth`, and the call arguments after redaction.

```rust
use std::collections::BTreeMap;
use toolgate::{MemoryAuditSink, Outcome, Redaction, Token, Verifier, REDACTED};

let secret = b"your-256-bit-secret-key-here!!";
let token = Token::mint_with_jti(
    secret,
    "read_file",
    vec!["path".into()],
    2000000000,
    None, None, None,
    true,
);
let sink = MemoryAuditSink::new();
let mut args = BTreeMap::new();
args.insert("path".to_string(), "/tmp/secret.txt".to_string());

Verifier::new(secret)
    .at(1999999999)
    .audit(&sink)
    .verify_call_with_args(&token, "read_file", &args)?;

let decision = &sink.decisions()[0];
assert_eq!(decision.outcome, Outcome::Allow);
assert_eq!(decision.arguments.get("path").unwrap(), REDACTED);
```

Built-in sinks:
- `MemoryAuditSink`: in-process `Vec` of decisions (useful for tests)
- `JsonlAuditSink<W>`: one JSON object per line on any `io::Write`

`check_tools_call` records through the same verifier, including `malformed_request` parse failures. Existing `Token` / `Keyring` verify methods stay unchanged when no sink is attached.

To keep selected values (for example a non-secret `limit`) while still redacting secrets:

```rust
use toolgate::Redaction;
let redaction = Redaction::keys(["path", "token"]);
Verifier::new(secret).audit(&sink).redaction(&redaction);
```

## MCP tools/call

The `mcp` feature (on by default, pulls `serde_json`) checks a JSON-RPC `tools/call` request against a token:

```rust
use toolgate::{check_tools_call, token_string_from_meta, Verifier};

let compact = token_string_from_meta(&request); // params._meta.toolgate, if present
let info = check_tools_call(&verifier, &token, &request)?;
```

`check_tools_call` extracts `params.name` and `params.arguments`. Scalar values become strings (strings as-is, integers in decimal, bools as `true`/`false`) for constraint checks. Nested object or array values are allowed on unconstrained keys for allowlist checking, and rejected as `MalformedRequest` when the key has a constraint. Non-`tools/call` methods and a missing name are also `MalformedRequest`. The helper inspects the request only; it does not dispatch the tool.

## Limits

- **Shared secret**: This is a symmetric-key system. All parties that mint or verify tokens share the same secret.
- **Not a public-key system**: Tokens cannot be verified without the secret.
- **Not a full MCP gateway**: This library only handles token issuance and verification. The MCP helper inspects a `tools/call` request and does not dispatch tools, validate transport, or implement a server.
- **Nonce is random, not sequential**: Each mint/attenuate generates a fresh random nonce.

## Version History

- **0.9.0**: Declarative policy files (`Policy`), mint/check from grants, CLI `policy lint` and `mint --policy`
- **0.8.0**: Structured audit `Decision` records, `AuditSink` (memory + JSONL), argument redaction, optional `Verifier` sink, CLI `--audit-jsonl`
- **0.7.0**: Compact `tg1.` string tokens, `Verifier` builder, MCP `tools/call` check (`mcp` feature), CLI `encode` / `decode` / `check-mcp`
- **0.6.0**: Add swappable `Clock`, expiry/nbf leeway, optional `nbf`, attenuation `depth`/`max_depth`, canonical encoding v6, wire format v5
- **0.5.0**: Add token identifiers (`jti`), revocation lists, and replay prevention (`UseStore` trait), canonical encoding v5, wire format v4
- **0.4.0**: Add argument value constraints (`Constraint` type), `verify_call_with_args` API, canonical encoding v4, wire format v3
- **0.3.0**: Add key identifiers (`kid`) and `Keyring` type for key rotation
- **0.2.0**: Add audience binding, verify_call API, compact wire codec, CLI check-call command
- **0.1.0**: Initial release with mint, attenuate, verify

## License

MIT
