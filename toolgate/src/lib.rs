//! toolgate: Macaroon-style capability tokens for tool calls.
//!
//! A token binds a tool name, an allowlist of argument keys, an expiry
//! (unix seconds), an optional audience, and a random nonce. Tokens can
//! be attenuated (drop argument keys or shorten expiry) but never widened.
//!
//! # Example
//!
//! ```
//! use toolgate::Token;
//!
//! let secret = b"your-256-bit-secret-key-here!!";
//!
//! // Mint a token for the read_file tool
//! let token = Token::mint(
//!     secret,
//!     "read_file",
//!     vec!["path".into(), "offset".into()],
//!     2000000000, // expiry unix seconds
//! );
//!
//! // Verify the token
//! assert!(token.verify(secret, 1999999999).is_ok());
//!
//! // Attenuate: restrict to only "path" argument
//! let restricted = token.attenuate(
//!     secret,
//!     Some(vec!["path".into()]),
//!     None,
//! ).unwrap();
//!
//! assert_eq!(restricted.arg_keys, vec!["path"]);
//!
//! // Verify a specific tool call
//! assert!(token.verify_call(
//!     secret,
//!     1999999999,
//!     "read_file",
//!     &["path"],
//!     None,
//! ).is_ok());
//! ```
//!
//! # Key Rotation with Keyring
//!
//! ```
//! use toolgate::Keyring;
//!
//! let mut keyring = Keyring::new();
//! keyring.add("key-2024", b"secret-key-2024-bytes-here!!!!!".to_vec());
//! keyring.add("key-2025", b"secret-key-2025-bytes-here!!!!!".to_vec());
//! keyring.set_active("key-2025").unwrap();
//!
//! // Mint with the active key
//! let token = keyring.mint("read_file", vec!["path".into()], 2000000000).unwrap();
//! assert_eq!(token.kid, Some("key-2025".to_string()));
//!
//! // Verify through keyring (looks up key by kid)
//! assert!(keyring.verify(&token, 1999999999).is_ok());
//! ```

pub mod clock;
pub mod constraint;
pub mod encoding;
pub mod keyring;
pub mod revocation;
pub mod token;
pub mod use_store;
pub mod wire;

pub use clock::{Clock, FixedClock, InstantClock, SystemClock, VerifyTime};
pub use constraint::{Constraint, Constraints};
pub use keyring::Keyring;
pub use revocation::RevocationList;
pub use token::{Token, TokenError};
pub use use_store::{MemoryUseStore, UseResult, UseStore};
pub use wire::WireError;
