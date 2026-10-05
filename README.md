# toolgate

A small, fast Rust library for issuing macaroon-style capability tokens for tool calls.

## What It Does

toolgate issues capability tokens that bind:
- **Tool name**: which tool the token authorizes
- **Argument keys**: an allowlist of permitted argument names
- **Argument constraints** (optional): restrict argument values (prefix, exact, one-of, max length, int range)
- **Expiry**: unix timestamp when the token becomes invalid
- **Audience** (optional): restrict token to a specific client/service
- **Nonce**: random bytes for uniqueness

Tokens are signed with HMAC-SHA256 over a canonical byte encoding. They can be **attenuated** (capabilities reduced) but never widened—you can drop argument keys, shorten expiry, or tighten constraints, but never add keys, extend expiry, or loosen constraints. Audience binding is preserved during attenuation.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
toolgate = "0.4"
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

// Attenuate: drop keys or shorten expiry
let restricted = token.attenuate(
    secret,
    Some(vec!["path".into()]), // only allow "path" arg
    Some(1699500000),          // shorter expiry
)?;
```

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
  }
}' | tg mint
```

The `audience` and `constraints` fields are optional. Omit them for an unbound token without constraints.

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
  "audience": "client-123"
}' | tg check
```

Omit `current_time` to use the system clock. The `audience` field is optional.

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
```

Returns `{"authorized": true}` or `{"authorized": false, "error": "...", "error_kind": "..."}`.

Error kinds: `invalid_mac`, `expired`, `audience_mismatch`, `tool_mismatch`, `arg_key_not_allowed`, `constraint_violation`.

Secrets can be hex-encoded with `"secret": "hex:deadbeef..."`.

## Canonical Byte Encoding (v4)

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

Constraint type encoding:
- `0` Exact: u16 length + UTF-8 value
- `1` OneOf: u16 count + (for each, sorted: u16 length + UTF-8 value)
- `2` Prefix: u16 length + UTF-8 prefix
- `3` MaxLen: u64 max
- `4` IntRange: i64 min + i64 max

**Example without constraints** (identical to v3):

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

Tokens without constraints encode identically to v3, ensuring backward compatibility.

The HMAC-SHA256 is computed over these concatenated bytes.

## Compact Wire Format

For efficient transmission, tokens can be encoded to a compact binary format:

```rust
let wire_bytes = token.to_wire();
let decoded = Token::from_wire(&wire_bytes)?;
```

Wire format is typically smaller than JSON and suitable for constrained channels.

## Limits

- **Shared secret**: This is a symmetric-key system. All parties that mint or verify tokens share the same secret.
- **Not a public-key system**: Tokens cannot be verified without the secret.
- **Not a full MCP gateway**: This library only handles token issuance and verification. It does not implement tool dispatch, argument validation, or network transport.
- **Nonce is random, not sequential**: Each mint/attenuate generates a fresh random nonce.

## Version History

- **0.4.0**: Add argument value constraints (`Constraint` type), `verify_call_with_args` API, canonical encoding v4, wire format v3
- **0.3.0**: Add key identifiers (`kid`) and `Keyring` type for key rotation
- **0.2.0**: Add audience binding, verify_call API, compact wire codec, CLI check-call command
- **0.1.0**: Initial release with mint, attenuate, verify

## License

MIT
