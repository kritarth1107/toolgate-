//! toolgate: Macaroon-style capability tokens for tool calls.
//!
//! A token binds a tool name, an allowlist of argument keys, an expiry
//! (unix seconds), and a random nonce. Tokens can be attenuated (drop
//! argument keys or shorten expiry) but never widened.
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
//! ```

pub mod encoding;
pub mod token;

pub use token::{Token, TokenError};
