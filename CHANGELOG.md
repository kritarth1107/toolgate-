# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
