# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
