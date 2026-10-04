# toolgate

A small, fast Rust library for issuing macaroon-style capability tokens for tool calls.

## What It Does

toolgate issues capability tokens that bind:
- **Tool name**: which tool the token authorizes
- **Argument keys**: an allowlist of permitted argument names
- **Expiry**: unix timestamp when the token becomes invalid
- **Nonce**: random bytes for uniqueness

Tokens are signed with HMAC-SHA256 over a canonical byte encoding. They can be **attenuated** (capabilities reduced) but never widened—you can drop argument keys or shorten expiry, but never add keys or extend expiry.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
toolgate = "0.1"
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

// Verify a token
let current_time = 1699999999;
token.verify(secret, current_time)?; // Ok(())

// Attenuate: drop keys or shorten expiry
let restricted = token.attenuate(
    secret,
    Some(vec!["path".into()]), // only allow "path" arg
    Some(1699500000),          // shorter expiry
)?;
```

## CLI Usage

The `tg` binary accepts JSON on stdin and outputs JSON.

### Mint

```bash
echo '{
  "secret": "my-secret",
  "tool_name": "read_file",
  "arg_keys": ["path", "limit"],
  "expiry": 2000000000
}' | tg mint
```

### Attenuate

```bash
echo '{
  "secret": "my-secret",
  "token": { ... },
  "arg_keys": ["path"],
  "expiry": 1900000000
}' | tg attenuate
```

### Check

```bash
echo '{
  "secret": "my-secret",
  "token": { ... },
  "current_time": 1699999999
}' | tg check
```

Omit `current_time` to use the system clock.

Secrets can be hex-encoded with `"secret": "hex:deadbeef..."`.

## Canonical Byte Encoding

For cross-implementation compatibility, tokens are signed over this exact byte layout (all integers big-endian):

| Field | Encoding |
|-------|----------|
| tool_name | u16 length + UTF-8 bytes |
| arg_keys_count | u16 |
| arg_keys | for each key (sorted lexicographically): u16 length + UTF-8 bytes |
| expiry | u64 (unix seconds) |
| nonce | u16 length + raw bytes |

**Example**: `encode("read", ["a", "b"], 1000, [0xAB, 0xCD])` produces:

```
00 04 r e a d           # tool_name: len=4, "read"
00 02                   # 2 arg keys
00 01 a                 # key "a"
00 01 b                 # key "b"
00 00 00 00 00 00 03 e8 # expiry = 1000
00 02 ab cd             # nonce: len=2, bytes
```

The HMAC-SHA256 is computed over these concatenated bytes.

## Limits

- **Shared secret**: This is a symmetric-key system. All parties that mint or verify tokens share the same secret.
- **Not a public-key system**: Tokens cannot be verified without the secret.
- **Not a full MCP gateway**: This library only handles token issuance and verification. It does not implement tool dispatch, argument validation, or network transport.
- **Nonce is random, not sequential**: Each mint/attenuate generates a fresh random nonce.

## License

MIT
