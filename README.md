# toolgate

A small, fast Rust library for issuing macaroon-style capability tokens for tool calls.

## What It Does

toolgate issues capability tokens that bind:
- **Tool name**: which tool the token authorizes
- **Argument keys**: an allowlist of permitted argument names
- **Argument constraints** (optional): restrict argument values (prefix, suffix, contains, exact, one-of, not-equals, not-one-of, not-contains, not-prefix, min/max length, int range, simple glob)
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
toolgate = "0.19"
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
constraints.insert("name".to_string(), Constraint::Suffix(".txt".to_string()));
constraints.insert("note".to_string(), Constraint::Contains("draft".to_string()));
constraints.insert("mode".to_string(), Constraint::OneOf(vec!["read".into(), "list".into()]));
constraints.insert("limit".to_string(), Constraint::IntRange { min: 1, max: 100 });
constraints.insert("query".to_string(), Constraint::MaxLen(256));
constraints.insert("label".to_string(), Constraint::MinLen(3));
constraints.insert("file".to_string(), Constraint::Matches("*.txt".to_string()));
constraints.insert("role".to_string(), Constraint::NotEquals("admin".to_string()));
constraints.insert("actor".to_string(), Constraint::NotOneOf(vec!["admin".into(), "root".into()]));
constraints.insert("memo".to_string(), Constraint::NotContains("secret".to_string()));
constraints.insert("dest".to_string(), Constraint::NotPrefix("/tmp/".to_string()));

// Mint token with constraints
let token = Token::mint_full(
    secret,
    "file_op",
    vec!["path".into(), "name".into(), "note".into(), "mode".into(), "limit".into(), "query".into(), "label".into(), "file".into(), "role".into(), "actor".into(), "memo".into(), "dest".into()],
    2000000000,
    None,  // audience
    None,  // kid
    Some(constraints),
);

// Verify with actual argument values
let mut args = BTreeMap::new();
args.insert("path".to_string(), "/tmp/test.txt".to_string());
args.insert("name".to_string(), "test.txt".to_string());
args.insert("note".to_string(), "draft-notes".to_string());
args.insert("mode".to_string(), "read".to_string());
args.insert("limit".to_string(), "50".to_string());
args.insert("label".to_string(), "abc".to_string());
args.insert("file".to_string(), "notes.txt".to_string());
args.insert("role".to_string(), "user".to_string());
args.insert("actor".to_string(), "user".to_string());
args.insert("memo".to_string(), "ok".to_string());
args.insert("dest".to_string(), "/var/out".to_string());

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
| `Suffix(String)` | Value must end with the suffix | `Suffix(".txt".into())` |
| `Contains(String)` | Value must contain the UTF-8 substring | `Contains("tmp".into())` |
| `MaxLen(usize)` | Value must have at most N bytes | `MaxLen(256)` |
| `MinLen(usize)` | Value must have at least N bytes | `MinLen(3)` |
| `Matches(String)` | Value must match a simple `*` / `?` glob over Unicode scalars | `Matches("*.txt".into())` |
| `NotEquals(String)` | Value must not equal the forbidden string | `NotEquals("admin".into())` |
| `NotOneOf(Vec<String>)` | Value must not be any of the forbidden values | `NotOneOf(vec!["admin".into(), "root".into()])` |
| `NotContains(String)` | Value must not contain the UTF-8 substring | `NotContains("secret".into())` |
| `NotPrefix(String)` | Value must not start with the prefix | `NotPrefix("/tmp/".into())` |
| `IntRange { min, max }` | Value must parse as integer in range | `IntRange { min: 1, max: 100 }` |

JSON forms match the Rust names: `{"type":"not_contains","value":"secret"}` and `{"type":"not_prefix","value":"/tmp/"}`. `MinLen(0)` is valid and accepts the empty string. Empty suffix, contains, matches, not-contains, or not-prefix patterns, and empty NotOneOf denylists, are rejected at mint/validate and never match a value.

`Matches` is not a regex: only `*` (any sequence, including empty) and `?` (exactly one Unicode scalar) are special. `.` `[` `]` and every other character match literally. There are no character classes, `**` path semantics, or escape sequences.

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
- **Suffix**: new suffix must end with the old suffix (`.txt` → `.bak.txt`)
- **Contains**: new needle must contain the old needle (`tmp` → `tmp/public`)
- **OneOf**: new set must be a subset of the old set
- **MaxLen**: new max must be ≤ old max
- **MinLen**: new min must be ≥ old min
- **Matches**: new pattern must equal the old pattern; tighten by replacing with Exact
- **NotEquals**: new forbidden value must equal the old; may become NotOneOf if the new denylist still contains that value
- **NotOneOf**: new denylist must be a **superset** of the old (more denials = tighter); dropping a forbidden value is rejected
- **NotContains**: new forbidden needle must be a **substring of** the old needle (shorter/equal forbids more)
- **NotPrefix**: new forbidden prefix must be a **prefix of** the old forbidden prefix (shorter/equal forbids more)
- **IntRange**: new range must be within old range
- **Exact**: can replace any constraint if the exact value satisfies it (for denylists, the exact value must not be forbidden)

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

### Keyring files

A JSON keyring file maps key ids to secrets. Secrets accept the same `hex:` prefix as `TG_SECRET`. Optional `active` names the key used for minting; when omitted, the first key (sorted by kid) becomes active.

```json
{
  "keys": {
    "key-2024": "old-secret-key-32-bytes-here!!",
    "key-2025": "hex:6e65772d7365637265742d6b65792d33322d62797465732d686572652121"
  },
  "active": "key-2025"
}
```

```rust
use toolgate::{parse_keyring_file, Keyring, KeyringFile};

let keyring = parse_keyring_file(r#"{"keys":{"key-2025":"hex:616263"}}"#)?;
assert_eq!(keyring.active_kid(), Some("key-2025"));

let mut file = KeyringFile::load("/tmp/keyring.json")?;
file.reload_if_changed();
```

`Keyring::from_file` / `parse_keyring_file` reject an empty `keys` object, an empty kid, invalid hex, and an `active` that is not in `keys`. `KeyringFile` remembers mtime and reloads when the file changes. A reload that fails to parse keeps the previous good keyring and writes one warning line to stderr — it never fails open.

`tg gate --keyring FILE` verifies tokens through this keyring. Tokens minted with different `kid`s verify when that kid is present. An unknown kid is still `unknown_key_id`. Do not set `TG_SECRET` when `--keyring` is given; secrets are never taken from argv.

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

A revoked-jti file is one identifier per line (`#` comments and blank lines ignored). `RevocationList::from_file` / `parse_revoked_jtis` load it; `RevocationFile` remembers mtime and reloads when the file changes; `append_revoked_jti` (and `tg revoke`) append one id.

```rust
use toolgate::{parse_revoked_jtis, RevocationFile};

let list = parse_revoked_jtis("# denylist\nabc123\n");
assert!(list.is_revoked("abc123"));

let mut file = RevocationFile::load("/tmp/revoked-jtis.txt")?;
file.reload_if_changed()?;
```

`MemoryUseStore` keeps counts in process. `FileUseStore` is an append-only JSONL log (one `UseRecord` per accepted use: `jti` plus the token `expiry`). On open it rebuilds counts from the file, skips a torn or garbage trailing line with one stderr warning, and drops records whose token has already expired. Each accepted use is appended and `fsync`ed before the caller treats it as recorded. A write failure is `UseResult::StoreError` / `use_store_failed` — the call is denied, never failed open.

Open/rebuild, each accepted use, and `prune_expired` take an exclusive advisory lock (`flock`) on a sibling `<path>.lock` file so two `tg gate` processes cannot race counts. The lock is held for that critical section only (reload, the use check, append/`fsync`, or rewrite), not for the lifetime of the store. Contended callers wait. A lock or I/O error is denied — the store never fails open. `inspect` loads without rewriting; `stats(now)` reports unique jtis, total records, expired records, and the path; `prune_expired(now)` rewrites the log without expired records so a later single-use check can succeed for that `jti` after expiry GC.

```rust
use toolgate::{FileUseStore, UseStore};

let mut store = FileUseStore::open("/tmp/toolgate-uses.jsonl")?;
assert!(single_use_token.verify_single_use(secret, 1999999999, &mut store).is_ok());
// After a process restart, the same path still has the count:
let mut store = FileUseStore::open("/tmp/toolgate-uses.jsonl")?;
assert!(single_use_token.verify_single_use(secret, 1999999999, &mut store).is_err());

let inspect = FileUseStore::inspect("/tmp/toolgate-uses.jsonl")?;
let stats = inspect.stats(1999999999);
let _ = stats.unique_jtis;
let report = FileUseStore::new("/tmp/toolgate-uses.jsonl").prune_expired(2_000_000_001)?;
let _ = report.removed;
```

Key points:
- `jti` is a 16-byte random identifier (hex-encoded, 32 chars) covered by the MAC
- Attenuated tokens inherit their parent's `jti`
- `RevocationList` tracks explicitly revoked token IDs
- `UseStore` trait enables pluggable use-count tracking (`MemoryUseStore` and `FileUseStore`)
- `FileUseStore` serializes open/append/prune with an exclusive sibling `.lock` file (`flock`)
- `FileUseStore::stats` / `prune_expired` inspect or compact a log without restarting the gate
- Tokens without `jti` cannot be checked against revocation lists or use stores
- `tg gate --revoked` / `--max-uses` / `--use-store` apply the same checks on each `tools/call`
- `tg use-store stats|prune FILE` inspects or compacts a `FileUseStore` log

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

`PolicyFile` loads a policy JSON path, remembers mtime, and reloads when the file changes (`tg gate --policy` uses this). A failed reload keeps the previous good policy and writes one warning line to stderr, so tightening takes effect without a restart and a bad edit does not fail open.

## CLI Usage

The `tg` binary accepts JSON on stdin and outputs JSON.

### Mint

```bash
echo '{
  "secret": "my-secret",
  "tool_name": "read_file",
  "arg_keys": ["path", "limit", "name", "role", "memo", "dest"],
  "expiry": 2000000000,
  "audience": "client-123",
  "constraints": {
    "path": {"type": "prefix", "value": "/tmp/"},
    "limit": {"type": "int_range", "value": {"min": 1, "max": 100}},
    "name": {"type": "matches", "value": "*.txt"},
    "role": {"type": "not_equals", "value": "admin"},
    "memo": {"type": "not_contains", "value": "secret"},
    "dest": {"type": "not_prefix", "value": "/tmp/"}
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

Error kinds: `invalid_mac`, `expired`, `not_yet_valid`, `audience_mismatch`, `tool_mismatch`, `arg_key_not_allowed`, `constraint_violation`, `revoked`, `replay_detected`, `missing_jti`, `max_depth_exceeded`, `malformed_request`, `policy_denied`, `use_store_failed`.

### Gate (stdio MCP)

`tg gate` sits in front of a local stdio MCP server. It reads newline-delimited JSON-RPC from the client, forwards everything that is not `tools/call`, and checks `tools/call` against a token at `params._meta.toolgate` (`tg1.` string or JSON token). Allowed calls are forwarded with `_meta.toolgate` stripped so the child never sees the secret. Denied calls are answered by the gate with a JSON-RPC error (same `id`, stable `error.code`, `data.error_kind`). Denied notifications (no `id`) are dropped.

The shared secret comes from `TG_SECRET` (the existing `hex:` form is accepted) **or** from `tg gate --keyring FILE` / `TG_KEYRING`. Giving both is an error. The secret is never taken from argv.

When a `tg gate` flag is omitted, the matching environment variable is used. An explicit flag always wins. An empty env string is treated as unset.

| Flag | Env |
|------|-----|
| `--policy` | `TG_POLICY` |
| `--keyring` | `TG_KEYRING` |
| `--revoked` | `TG_REVOKED` |
| `--use-store` | `TG_USE_STORE` |
| `--max-uses` | `TG_MAX_USES` (positive integer; invalid values are a hard error) |
| `--audience` | `TG_AUDIENCE` |
| `--leeway` | `TG_LEEWAY` (seconds; invalid values are a hard error) |
| `--audit-jsonl` | `TG_AUDIT_JSONL` |

`--use-store` / `TG_USE_STORE` still requires `--max-uses` or `TG_MAX_USES`. mtime reload of policy, keyring, and revoked files is unchanged.

```bash
export TG_SECRET=my-shared-secret

# Mint a compact token for the client to place in params._meta.toolgate
echo '{
  "secret": "my-shared-secret",
  "tool_name": "read_file",
  "arg_keys": ["path", "limit"],
  "expiry": 2000000000
}' | tg mint | jq '{token}' | tg encode
# {"token":"tg1...."}

# Front a local stdio MCP server
tg gate --policy examples/policy.json --audience agent-runtime --leeway 30 \
  --revoked /tmp/revoked-jtis.txt --max-uses 1 --use-store /tmp/toolgate-uses.jsonl \
  --audit-jsonl /tmp/decisions.jsonl -- \
  ./my-mcp-server

# Same options from the environment (flags still override)
export TG_POLICY=examples/policy.json
export TG_AUDIENCE=agent-runtime
export TG_LEEWAY=30
export TG_REVOKED=/tmp/revoked-jtis.txt
export TG_MAX_USES=1
export TG_USE_STORE=/tmp/toolgate-uses.jsonl
export TG_AUDIT_JSONL=/tmp/decisions.jsonl
tg gate -- ./my-mcp-server

# Or verify with a keyring file instead of TG_SECRET
tg gate --keyring /tmp/keyring.json --policy examples/policy.json -- \
  ./my-mcp-server
```

`--revoked FILE` is a revoked-jti list: one token id per line, `#` comments and blank lines ignored. The gate loads it at start and reloads when the file's mtime changes. `--max-uses N` counts uses per `jti` through `UseStore` (tokens without a `jti` are denied as `missing_jti`). Without `--use-store` the counts live in `MemoryUseStore` and reset when the process exits. `--use-store FILE` (only valid with `--max-uses` or `TG_MAX_USES`) uses `FileUseStore`: the same append-only log, rebuilt on start, so a single-use token cannot be replayed by restarting the gate. Concurrent `tg gate` processes sharing that file serialize on `<FILE>.lock`. A persist or lock failure denies the call as `use_store_failed` and is recorded in the audit; the gate never fails open. Revocation and replay denials are recorded as `revoked` and `replay_detected`.

### Use store

Inspect or compact a `FileUseStore` log without restarting a gate.

```bash
tg use-store stats /tmp/toolgate-uses.jsonl
# {"unique_jtis":1,"total_records":1,"expired_records":0,"path":"/tmp/toolgate-uses.jsonl"}

tg use-store prune /tmp/toolgate-uses.jsonl
# {"removed":0,"remaining":1,"path":"/tmp/toolgate-uses.jsonl"}
```

`stats` prints JSON and does not rewrite the file. `prune` drops records whose token expiry is already in the past (same rule as open compaction) and prints a short JSON report. Both exit nonzero if the file is missing or the operation fails.

`--keyring FILE` and `--policy FILE` use the same mtime-check reload as the revoked-jti file: no watcher thread and no extra crate. A keyring or policy reload that fails to parse or validate keeps the previous good version and writes one warning line to stderr; the gate does not fail open. Unknown kids stay `unknown_key_id`.

### Revoke

Append a jti to a revoked-jti file. The argument may be a raw identifier, a `tg1.` string, or a JSON token (the token must carry a `jti`).

```bash
tg revoke "$JTI" --file /tmp/revoked-jtis.txt
tg revoke 'tg1....' --file /tmp/revoked-jtis.txt
```

A client `tools/call` looks like:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {"path": "/tmp/a.txt", "limit": 10},
    "_meta": {"toolgate": "tg1...."}
  }
}
```

The child receives the same request with `_meta.toolgate` removed. A missing or invalid token is not forwarded; the client gets:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32040,
    "message": "malformed request",
    "data": {"error_kind": "malformed_request"}
  }
}
```

Library path (same rules, no I/O) is `toolgate::decide`:

```rust
use toolgate::{decide, GateAction, Verifier};

let action = decide(&line, &verifier, Some(&policy));
// or decide_with_replay(&line, &verifier, Some(&policy), Some((&mut use_store, 1)))
match action {
    GateAction::Forward(msg) => { /* write msg to the server */ }
    GateAction::Respond(err) => { /* write err to the client */ }
    GateAction::Drop => {}
}
```

#### JSON-RPC error codes

| `error.code` | When | `error.data.error_kind` |
|--------------|------|-------------------------|
| `-32700` | Client line is not JSON | omitted |
| `-32600` | JSON-RPC batch (array); not supported | omitted |
| `-32040` | `tools/call` missing a token, or the token/policy/revocation/replay check failed | existing kinds: `malformed_request`, `invalid_mac`, `expired`, `not_yet_valid`, `audience_mismatch`, `tool_mismatch`, `arg_key_not_allowed`, `constraint_violation`, `revoked`, `replay_detected`, `missing_jti`, `max_depth_exceeded`, `policy_denied`, … |

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
- `5` Suffix: u16 length + UTF-8 suffix
- `6` Contains: u16 length + UTF-8 needle
- `7` MinLen: u64 min
- `8` Matches: u16 length + UTF-8 pattern
- `9` NotEquals: u16 length + UTF-8 value
- `10` NotOneOf: u16 count + (for each, sorted unique: u16 length + UTF-8 value)
- `11` NotContains: u16 length + UTF-8 needle
- `12` NotPrefix: u16 length + UTF-8 prefix

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
use toolgate::{check_tools_call, token_from_meta, token_string_from_meta, Verifier};

let compact = token_string_from_meta(&request); // params._meta.toolgate, if a string
let token = token_from_meta(&request);          // tg1. string or JSON token object
let info = check_tools_call(&verifier, &token, &request)?;
```

`check_tools_call` extracts `params.name` and `params.arguments`. Scalar values become strings (strings as-is, integers in decimal, bools as `true`/`false`) for constraint checks. Nested object or array values are allowed on unconstrained keys for allowlist checking, and rejected as `MalformedRequest` when the key has a constraint. Non-`tools/call` methods and a missing name are also `MalformedRequest`. The helper inspects the request only; it does not dispatch the tool.

[`decide`](#gate-stdio-mcp) is the stdio gate: one client line in, `Forward` / `Respond` / `Drop` out. It uses the same verifier, optional policy, and audit sink. `decide_with_replay` adds a `UseStore` max-uses check after the verifier accepts the call, including `FileUseStore` when `tg gate --use-store` is set.

## Limits

- **Shared secret**: This is a symmetric-key system. All parties that mint or verify tokens share the same secret. The stdio gate reads that secret from `TG_SECRET` or a `--keyring` / `TG_KEYRING` file; the model is unchanged.
- **Not a public-key system**: Tokens cannot be verified without the secret.
- **Line-oriented stdio gate only**: `tg gate` / `decide` sit in front of a local child process. They inspect newline-delimited JSON-RPC (one object per line). There is no HTTP or SSE transport. JSON-RPC batch arrays are rejected (`-32600`). Server responses are copied through and not validated. JSON strings must not contain raw newlines.
- **Not a hosted gateway**: The gate does not dispatch tools, open a network listener, or run as a service. `check_tools_call` still only inspects a request.
- **Nonce is random, not sequential**: Each mint/attenuate generates a fresh random nonce.
- **Local advisory lock only**: `FileUseStore` uses `flock` on a sibling `.lock` file. That serializes processes on one machine (and filesystems that honor `flock`). It is not a distributed lock. Lock or I/O errors deny the call; they never fail open.

## Version History

- **0.19.0**: `Constraint::NotContains` and `Constraint::NotPrefix` inverted argument constraints, with fail-closed empty needles and tighten-only attenuation
- **0.18.0**: `Constraint::NotEquals` and `Constraint::NotOneOf` denylist argument constraints, with fail-closed empty NotOneOf and tighten-only attenuation
- **0.17.0**: `Constraint::MinLen` and `Constraint::Matches` (`*` / `?` glob), with fail-closed empty patterns and tighten-only attenuation
- **0.16.0**: `Constraint::Suffix` and `Constraint::Contains`, with fail-closed empty needles and tighten-only attenuation
- **0.15.0**: `tg gate` falls back to `TG_POLICY`, `TG_KEYRING`, `TG_REVOKED`, `TG_USE_STORE`, `TG_MAX_USES`, `TG_AUDIENCE`, `TG_LEEWAY`, and `TG_AUDIT_JSONL` when the matching flag is omitted
- **0.14.0**: Concurrent-safe `FileUseStore` (advisory lock), `stats` / `prune_expired`, `tg use-store stats|prune`
- **0.13.0**: Persistent use-count store (`FileUseStore`, `tg gate --use-store`)
- **0.12.0**: Gate keyring files and policy/keyring hot-reload (`tg gate --keyring`, `KeyringFile`, `PolicyFile`)
- **0.11.0**: Gate revocation and replay (`tg gate --revoked` / `--max-uses`, `tg revoke`, `RevocationFile`, `decide_with_replay`)
- **0.10.0**: Line-oriented stdio MCP gate (`decide` / `tg gate`): pass-through of non-`tools/call`, token at `_meta.toolgate`, strip before the child, JSON-RPC errors with a stable code and `data.error_kind`
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
