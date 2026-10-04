//! toolgate: Macaroon-style capability tokens for tool calls.
//!
//! A token binds a tool name, an allowlist of argument keys, an expiry
//! (unix seconds), and a random nonce. Tokens can be attenuated (drop
//! argument keys or shorten expiry) but never widened.

pub mod encoding;
pub mod token;

pub use token::{Token, TokenError};
