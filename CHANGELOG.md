# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.19.0] - 2026-10-10

### Added
- **`Constraint::NotContains(String)`**: value must not contain the forbidden UTF-8 substring (byte/UTF-8 contains check, same spirit as Contains)
- **`Constraint::NotPrefix(String)`**: value must not start with the forbidden prefix (same spirit as Prefix)
- CLI JSON forms `{"type":"not_contains","value":"..."}` and `{"type":"not_prefix","value":"..."}` on `tg mint`, `tg attenuate`, and `tg check-call`

### Changed
- Canonical and wire constraint type tags: Exact=0, OneOf=1, Prefix=2, MaxLen=3, IntRange=4, Suffix=5, Contains=6, MinLen=7, Matches=8, NotEquals=9, NotOneOf=10, NotContains=11, NotPrefix=12
- Tokens without the new types still encode identically to 0.18.0

### Notes
- Attenuation only tightens: a new NotContains needle must be a substring of the old needle (shorter/equal forbids more); a new NotPrefix prefix must be a prefix of the old forbidden prefix
- Exact may replace NotContains when the exact value does not contain the old needle, and may replace NotPrefix when the exact value does not start with the old forbidden prefix
- Empty NotContains needles and empty NotPrefix prefixes are rejected at mint/validate and never match a value (fail closed)

## [0.18.0] - 2026-10-10

### Added
- **`Constraint::NotEquals(String)`**: value must not equal the forbidden string (byte/UTF-8 exact, same spirit as Exact)
- **`Constraint::NotOneOf(Vec<String>)`**: value must not be any of the forbidden values (stored and encoded as sorted unique strings, same spirit as OneOf)
- CLI JSON forms `{"type":"not_equals","value":"..."}` and `{"type":"not_one_of","value":["a","b"]}` on `tg mint`, `tg attenuate`, and `tg check-call`

### Changed
- Canonical and wire constraint type tags: Exact=0, OneOf=1, Prefix=2, MaxLen=3, IntRange=4, Suffix=5, Contains=6, MinLen=7, Matches=8, NotEquals=9, NotOneOf=10
- Tokens without the new types still encode identically to 0.17.0

### Notes
- Attenuation only tightens: NotEquals may stay the same forbidden value or become a NotOneOf that still contains it; NotOneOf may only grow (more denials)
- Exact may replace NotEquals when the exact value is not the forbidden string, and may replace NotOneOf when the exact value is not in the old denylist
- Empty NotOneOf denylists are rejected at mint/validate and never match a value (fail closed)

## [0.17.0] - 2026-10-10

### Added
- **`Constraint::MinLen(usize)`**: value byte length must be at least N (`MinLen(0)` is valid and accepts the empty string)
- **`Constraint::Matches(String)`**: simple glob over Unicode scalars (`*` any sequence, `?` exactly one scalar; all other characters are literal)
- CLI JSON forms `{"type":"min_len","value":N}` and `{"type":"matches","value":"..."}` on `tg mint`, `tg attenuate`, and `tg check-call`

### Changed
- Canonical and wire constraint type tags: Exact=0, OneOf=1, Prefix=2, MaxLen=3, IntRange=4, Suffix=5, Contains=6, MinLen=7, Matches=8
- Tokens without the new types still encode identically to 0.16.0

### Notes
- Attenuation only tightens: a new MinLen must be ≥ the old minimum; Matches may only stay the same pattern
- Exact may replace MinLen when the exact value's length meets the previous min, and may replace Matches when the exact value satisfies the previous glob
- Empty Matches patterns are rejected at mint/validate and never match a value (fail closed)

## [0.16.0] - 2026-10-09

### Added
- **`Constraint::Suffix(String)`**: value must end with the given suffix
- **`Constraint::Contains(String)`**: value must contain the given UTF-8 substring
- CLI JSON forms `{"type":"suffix","value":"..."}` and `{"type":"contains","value":"..."}` on `tg mint`, `tg attenuate`, and `tg check-call`

### Changed
- Canonical and wire constraint type tags: Exact=0, OneOf=1, Prefix=2, MaxLen=3, IntRange=4, Suffix=5, Contains=6
- Tokens without the new types still encode identically to 0.15.0

### Notes
- Attenuation only tightens: a new suffix must end with the old suffix, and a new contains needle must contain the old needle
- Exact may replace Suffix or Contains when the exact value satisfies the previous constraint
- Empty suffix/contains needles are rejected at mint/validate and never match a value (fail closed)

## [0.15.0] - 2026-10-09

### Added
- **Stdio MCP gate env fallbacks**: omitted `tg gate` flags read matching environment variables
  - `TG_POLICY`, `TG_KEYRING`, `TG_REVOKED`, `TG_USE_STORE`, `TG_MAX_USES`, `TG_AUDIENCE`, `TG_LEEWAY`, `TG_AUDIT_JSONL`
  - Explicit flags always win; an empty env string is treated as unset
  - `TG_MAX_USES` must be a positive integer and `TG_LEEWAY` must be seconds; invalid values are a hard error (never fail open)
  - `--use-store` / `TG_USE_STORE` still requires `--max-uses` or `TG_MAX_USES`

### Notes
- `TG_SECRET` behavior is unchanged, including mutual exclusion with `--keyring` / `TG_KEYRING`
- Secrets are still never taken from argv
- Policy, keyring, and revoked-file mtime reload is unchanged

## [0.14.0] - 2026-10-09

### Added
- **Concurrent-safe FileUseStore**: exclusive advisory lock (`flock`) on a sibling `<path>.lock`
  - Held only for open/rebuild, each accepted use (reload, check, append, `fsync`), and `prune_expired`
  - Contended callers wait; lock or I/O errors deny the call (`UseResult::StoreError` / `use_store_failed`)
- **Inspect and compact APIs**: `FileUseStore::inspect`, `FileUseStore::stats` (`UseStoreStats`), `FileUseStore::prune_expired` (`PruneReport`)
  - `stats` reports unique jtis, total records, expired records, and path without rewriting
  - `prune_expired` rewrites the log without expired records under the same lock (callable without restart)
- **CLI**: `tg use-store stats FILE` and `tg use-store prune FILE`
  - JSON on stdout; nonzero exit if the file is missing or the operation fails
  - `tg gate --use-store` is unchanged

### Notes
- Shared-secret model is unchanged
- The lock is local `flock`, not a distributed lock
- Open still compacts expired records once at start; `prune_expired` makes that explicit on a live store

## [0.13.0] - 2026-10-08

### Added
- **File-backed use store**: `FileUseStore` persists per-`jti` use counts across process restarts
  - Append-only JSONL log: one `UseRecord` (`jti` + token `expiry`) per accepted use
  - `open` / `open_at` rebuild counts; a torn or garbage trailing line is skipped with one stderr warning
  - Expired records are compacted on open (rewrite + fsync); no extra crate or background thread
  - Each accepted use is appended and `fsync`ed before the call is forwarded
- **Stdio MCP gate**: `tg gate --use-store FILE` (requires `--max-uses`)
  - Without the flag the gate still uses `MemoryUseStore`
  - A persist failure denies the call as `use_store_failed` (never fail open) and records one audit `Decision`

### Notes
- Shared-secret model is unchanged
- A single-use token cannot be replayed by restarting `tg gate` when `--use-store` points at the same file

## [0.12.0] - 2026-10-08

### Added
- **Keyring file**: JSON document mapping `kid` → secret, plus optional `active`
  - `parse_keyring_file` / `Keyring::from_json` / `Keyring::from_file`
  - Secrets accept the same `hex:` prefix as `TG_SECRET`
  - `KeyringFile` loads at start and reloads when the file mtime changes
- **Stdio MCP gate**: `tg gate --keyring FILE` verifies tokens through the existing `Keyring` / `Verifier` path
  - Tokens minted with different `kid`s verify when that key is present
  - `TG_SECRET` still works when no keyring is given; setting both is an error
  - Secrets are never taken from argv
- **Policy hot-reload**: `PolicyFile` reloads `--policy` when the file mtime changes
  - Tightening the policy denies older broader tokens on the next `tools/call`

### Notes
- Reloading the keyring or policy file is an mtime check; no watcher thread or extra crate
- A reload that fails to parse or validate keeps the previous good version and writes one warning line to stderr; the gate never fails open
- Unknown kids stay `unknown_key_id`; no new error kinds

## [0.11.0] - 2026-10-08

### Added
- **Revoked-jti file**: one token id per line (`#` comments and blank lines ignored)
  - `parse_revoked_jtis` / `RevocationList::from_file`
  - `RevocationFile` loads at start and reloads when the file mtime changes
  - `append_revoked_jti` appends one id, creating the file if needed
- **Stdio MCP gate**: `tg gate --revoked FILE` denies `tools/call` whose token `jti` is listed
- **Replay limit**: `tg gate --max-uses N` counts uses per `jti` through `UseStore`
  - `decide_with_replay` applies the limit after verifier/policy accept
  - Tokens without a `jti` are denied as `missing_jti`
- **CLI**: `tg revoke <token-or-jti> --file FILE` appends a jti (raw id, `tg1.` string, or JSON token)
- Denied revocation/replay calls emit one `Decision` with `revoked` or `replay_detected`

### Notes
- Reloading the revoked-jti file is an mtime check; no watcher thread or extra crate
- Shared-secret model is unchanged

## [0.10.0] - 2026-10-08

### Added
- **Stdio MCP gate** (behind the existing `mcp` feature): a local, I/O-free decision function plus `tg gate`
  - `decide(line, &Verifier, Option<&Policy>)` → `GateAction::{Forward, Respond, Drop}`
  - Non-`tools/call` messages (initialize, `tools/list`, notifications, responses) pass through unchanged
  - `tools/call` must carry a token at `params._meta.toolgate` (`tg1.` string or JSON token), verified through `Verifier` and an optional `Policy`
  - Allowed calls are forwarded with `_meta.toolgate` stripped so the downstream server never sees the token
  - Denied or token-less calls get a JSON-RPC error with the same `id`, code `-32040`, and `data.error_kind` matching existing `TokenError::kind()` values
  - Malformed JSON is JSON-RPC parse error `-32700`; batch arrays are rejected with `-32600`
  - Denied `tools/call` notifications (no `id`) are dropped, not answered
  - An attached `AuditSink` records exactly one `Decision` per `tools/call`
- **CLI**: `tg gate [--policy FILE] [--audience A] [--leeway SECS] [--audit-jsonl TARGET] -- <server> [args...]`
  - Secret from `TG_SECRET` (supports `hex:`); never argv
  - Spawns the server, pumps client stdin → gate → child stdin, child stdout → client stdout unchanged, child stderr inherited
  - Exits with the child's status; std threads only (no async runtime)
- **Helpers**: `token_from_meta` (string or JSON token), JSON-RPC error constructors, `strip_toolgate_meta`

### Notes
- The gate is line-oriented stdio only: no HTTP/SSE, no batching, no validation of server responses
- Shared-secret model is unchanged

## [0.9.0] - 2026-10-07

### Added
- **Declarative policy files**: operators describe which tools an agent may call in one JSON document
  - `Policy` / `ToolGrant` (serde): `version`, optional `default_audience` / `default_ttl_seconds` / `default_max_depth` / `default_kid`, and a list of grants
  - Each grant: tool `name`, `arg_keys`, optional per-key `Constraint`s (existing serde form), optional `ttl_seconds` / `audience` / `max_depth` overrides
  - `Policy::from_json` / `validate()` with `PolicyError`: unknown version, duplicate tool names, constraints on keys not in the allowlist, zero TTL, empty tool name
  - `Policy::mint(tool, secret, now)` and `mint_with_keyring` (active key): token fields come from the grant with defaults applied
  - `Policy::check_call` / `check_call_with_args`: verify through `Verifier` **and** confirm the token is still permitted by the current policy (tightening denies older broader tokens). An attached `AuditSink` records exactly one `Decision`
- **New error variant**: `TokenError::PolicyDenied` (`policy_denied`)
- **CLI**:
  - `tg policy lint <file>`: prints `ok` or the validation errors; nonzero exit on error
  - `tg mint --policy <file> --tool <name>`: mint from a grant; stdin still supplies `secret` (and optional `current_time`). Existing stdin JSON minting is unchanged
- **Example**: `examples/policy.json`

### Notes
- Policy version `"1"` is the only accepted schema version
- Grant TTL (or `default_ttl_seconds`) is required to mint; expiry is `now + ttl`

## [0.8.0] - 2026-10-07

### Added
- **Audit decisions**: every verify/check can emit a structured, serializable `Decision`
  - Fields: `outcome` (allow/deny), `reason` / `error_kind`, `token_id` (`jti`), `tool_name`, `audience`, `timestamp` (from the verifier `Clock`), `depth`, and call `arguments`
  - `TokenError::kind()` returns the stable machine-readable kind used by CLI `error_kind`
- **`AuditSink` trait** plus two built-ins:
  - `MemoryAuditSink`: in-process collection for tests
  - `JsonlAuditSink<W>`: one JSON object per line on any `io::Write`
- **Argument redaction**: `Redaction` keeps keys and replaces values with `[REDACTED]` by default, or only a configured key list
- **`Verifier`**: optional `.audit(&sink)` and `.redaction(&policy)`
  - `verify`, `verify_call`, and `verify_call_with_args` each emit one record when a sink is attached
  - Existing `Token` / `Keyring` verify APIs stay unchanged when no sink is set
- **MCP `tools/call`**: `check_tools_call` records through the verifier, including `malformed_request`
- **CLI**:
  - `--audit-jsonl stdout|stderr|<path>` on `check`, `check-call`, and `check-mcp`
  - `--audit-redact-keys key1,key2` to redact only listed argument keys

### Notes
- `serde_json` is now a required dependency (used by `JsonlAuditSink`); the default `mcp` feature still gates the MCP module
- Audit write failures do not change the verification result

## [0.7.0] - 2026-10-07

### Added
- **Compact string tokens**: `tg1.` + unpadded base64url of the existing wire bytes
  - `Token::to_token_string()` / `Token::from_token_string()` / `FromStr`
  - Rejects wrong prefix, invalid base64url, trailing garbage, and oversized input (`MAX_TOKEN_STRING_LEN`)
- **`Verifier` builder**: consolidates `verify_*` variants
  - `Verifier::new(secret)` with `.clock()` / `.at()`, `.leeway()`, `.audience()`, `.revocation()`, `.keyring()`
  - `.verify()`, `.verify_call()`, `.verify_call_with_args()`
  - Existing `Token` and `Keyring` verify APIs keep their behaviour and delegate to `Verifier`
  - Single-use / `UseStore` checks stay on the existing methods
- **MCP `tools/call` check**: `mcp` module behind a default-on `mcp` feature (`serde_json`)
  - `check_tools_call(&Verifier, &Token, &Value)` extracts tool name and arguments
  - Scalars convert to strings; nested values on constrained keys are `MalformedRequest`
  - `token_string_from_meta()` reads `params._meta.toolgate`
- **CLI**:
  - `tg encode`: JSON token → `{"token":"tg1...."}`
  - `tg decode`: string → JSON token with `"verified": false` (no MAC check)
  - `tg check-mcp`: verify a token against a JSON-RPC `tools/call` request
  - `tg check` / `tg check-call` accept a `tg1.` string in `token`
- **New error variant**: `TokenError::MalformedRequest` (`malformed_request`)

### Notes
- The MCP helper inspects the request only and does not dispatch tools
- No new crate dependencies; `serde_json` is optional and enabled by the default `mcp` feature

## [0.6.0] - 2026-10-06

### Added
- **Swappable clocks**: Verification no longer hard-depends on `SystemTime`
  - `Clock` trait: `now_unix()` source used for expiry and not-before checks
  - `SystemClock`: wall-clock implementation
  - `FixedClock`: frozen unix timestamp for tests and explicit times
  - `InstantClock`: starts at a unix origin and advances with `Instant`
  - `VerifyTime<C>`: bundles a clock with clock-skew leeway
  - `Token::verify_with_clock()` / `verify_with_leeway()` / `verify_at()`
  - `Token::verify_call_at()` / `verify_call_with_args_at()`
  - `Keyring::verify_with_clock()` / `verify_with_leeway()` / `verify_at()`
- **Expiry leeway**: Configurable `Duration` grace applied to expiry and `nbf`
- **Not-before (`nbf`)**: Optional unix timestamp covered by the MAC
  - `Token::mint_complete()`: mint with `nbf` and `max_depth`
  - Verification returns `TokenError::NotYetValid` when `now + leeway < nbf`
- **Attenuation depth**: Optional maximum delegation depth
  - Each `attenuate` increments `depth` (covered by the MAC)
  - `max_depth` is set at mint time and preserved
  - Exceeding the limit returns `TokenError::MaxDepthExceeded`
- **New error variants**: `NotYetValid`, `MaxDepthExceeded`
- **CLI updates**:
  - `tg mint`: `nbf` and `max_depth` fields
  - `tg check` / `tg check-call`: `leeway` field (seconds)

### Changed
- **Canonical encoding bumped to v6**: Adds nbf/depth/max_depth after jti. Tokens without those fields encode identically to v5.
- **Wire format bumped to v5**: Adds nbf/depth/max_depth. Tokens without those fields still encode as v4 (identical to v0.5). Decoding supports v1–v5.

### Notes
- Existing `verify(secret, current_time)` wraps the timestamp in `FixedClock` with zero leeway
- `depth` starts at 0; tokens with no `max_depth` may be attenuated without limit
- No new crate dependencies

## [0.5.0] - 2026-10-06

### Added
- **Token identifiers (`jti`)**: Optional unique identifier (16 random bytes, hex-encoded) covered by MAC
  - `Token::mint_with_jti()`: Mint tokens with unique identifier for tracking
  - Attenuated tokens inherit their parent's `jti`
- **Revocation support**: Explicitly revoke tokens by identifier
  - `RevocationList` type: revoke by jti, check membership, iterate
  - `Token::verify_with_revocation()` / `verify_with_revocation_and_audience()`
  - `Keyring::verify_with_revocation()` / `verify_with_revocation_and_audience()`
- **Replay prevention**: Track and limit token uses
  - `UseStore` trait: pluggable interface for use-count tracking
  - `MemoryUseStore`: in-process HashMap-based implementation
  - `Token::verify_single_use()` / `verify_with_max_uses()`
  - `Token::verify_with_revocation_and_use_store()`: combined protection
  - `Keyring::verify_single_use()` / `verify_with_max_uses()` / `verify_with_revocation_and_use_store()`
- **New error variants**:
  - `TokenError::Revoked`: token jti found in revocation list
  - `TokenError::ReplayDetected`: token use count exceeded
  - `TokenError::MissingJti`: operation requires jti but token has none
- **CLI updates**:
  - `tg mint`: Add `generate_jti` field to request unique identifier
  - `tg check-call`: Add `revoked` field (list of jti strings) for revocation checking

### Changed
- **Canonical encoding bumped to v5**: Adds jti after constraints. Tokens without jti encode identically to v4 for backward compatibility.
- **Wire format bumped to v4**: Adds jti. Decoding supports v1, v2, v3, and v4.

### Notes
- `jti` is 32 hex characters (16 bytes)
- No new dependencies added; `UseStore` implementations are in-process only
- `MemoryUseStore` is suitable for single-process verification scenarios

## [0.4.0] - 2026-10-05

### Added
- **Argument value constraints**: Tokens can now restrict argument values, not just keys
  - `Constraint::Exact(String)`: value must match exactly
  - `Constraint::OneOf(Vec<String>)`: value must be one of allowed values
  - `Constraint::Prefix(String)`: value must start with prefix
  - `Constraint::MaxLen(usize)`: value must have at most N bytes
  - `Constraint::IntRange { min, max }`: value must parse as integer in range
- **`Token::mint_full()`**: Mint tokens with all parameters including constraints
- **`Token::attenuate_with_constraints()`**: Attenuate with constraint tightening
- **`Token::verify_call_with_args()`**: Verify calls with actual argument values
- **`Keyring::verify_call_with_args()`**: Same via keyring for key rotation
- **`ConstraintViolation` error variant**: Returned when argument value fails constraint
- **CLI constraints support**: `tg mint`, `tg attenuate` accept `constraints` field; `tg check-call` accepts `args` field for value validation

### Changed
- **Canonical encoding bumped to v4**: Adds constraints after kid field. Tokens without constraints encode identically to v3 for backward compatibility.
- **Wire format bumped to v3**: Adds constraints. Decoding supports v1, v2, and v3.

### Notes
- Constraints use deterministic encoding: keys sorted, OneOf values sorted
- Attenuation can only tighten constraints (longer prefix, subset of values, smaller max, narrower range)
- Empty constraints map is normalized to None

## [0.3.0] - 2026-10-05

### Added
- **Key identifiers (`kid`)**: Tokens can now carry an optional key identifier that is covered by the MAC, enabling verifiers to look up the correct signing key.
- **`Keyring` type**: A new type for managing multiple signing keys with rotation support:
  - `add(kid, secret)`: Add a key to the keyring
  - `retire(kid)` / `remove(kid)`: Remove a key from the keyring
  - `set_active(kid)`: Set which key is used for minting new tokens
  - `mint()` / `mint_with_audience()`: Mint tokens using the active key
  - `verify()` / `verify_with_audience()` / `verify_call()`: Verify tokens by looking up the key by `kid`
  - `attenuate()`: Attenuate tokens (preserves `kid`)
- **`Token::mint_with_kid()`**: New method to mint tokens with explicit key identifier
- **New error variants**: `UnknownKeyId`, `NoActiveKey`, `MissingKeyId`

### Changed
- **Canonical encoding bumped to v3**: Adds `kid` field after `audience` (length 0 for no key id). Backward compatible - tokens without `kid` encode identically to v2.
- **Wire format bumped to v2**: Adds `kid` field. Decoding supports both v1 (no kid) and v2 for backward compatibility.

## [0.2.0] - 2026-10-04

### Added
- **Audience binding**: Tokens can be bound to a specific audience (client/service identifier)
- **`verify_call()` API**: Verify a token authorizes a specific tool call in one step
- **Compact wire format**: Binary encoding for efficient transmission (`to_wire()` / `from_wire()`)
- **CLI `check-call` command**: Verify token authorization for specific tool calls

### Changed
- Canonical encoding bumped to v2 (adds audience field)

## [0.1.0] - 2026-10-04

### Added
- Initial release
- `Token::mint()`: Create capability tokens with tool name, argument keys, and expiry
- `Token::verify()`: Verify token MAC and expiry
- `Token::attenuate()`: Reduce token capabilities (drop keys or shorten expiry)
- HMAC-SHA256 signing over canonical byte encoding
- JSON serialization support
- `tg` CLI with mint, attenuate, and check commands
