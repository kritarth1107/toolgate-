//! Compact binary wire format for Token serialization.
//!
//! This module provides a space-efficient binary encoding for tokens,
//! suitable for transmission over constrained channels.
//!
//! ## Wire Format (all integers big-endian)
//!
//! | Field | Encoding |
//! |-------|----------|
//! | version | u8 (currently 1) |
//! | tool_name | u16 length + UTF-8 bytes |
//! | arg_keys_count | u16 |
//! | arg_keys | for each: u16 length + UTF-8 bytes |
//! | expiry | u64 (unix seconds) |
//! | nonce | u8 length + bytes |
//! | mac | u8 length + bytes |
//! | audience | u16 length + UTF-8 bytes (0 = none) |

use crate::Token;

/// Wire format version
const WIRE_VERSION: u8 = 1;

/// Errors that can occur during wire encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    UnsupportedVersion(u8),
    UnexpectedEof,
    InvalidUtf8,
    BufferTooSmall,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::UnsupportedVersion(v) => write!(f, "unsupported wire version: {}", v),
            WireError::UnexpectedEof => write!(f, "unexpected end of data"),
            WireError::InvalidUtf8 => write!(f, "invalid UTF-8 in token data"),
            WireError::BufferTooSmall => write!(f, "buffer too small for encoding"),
        }
    }
}

impl std::error::Error for WireError {}

impl Token {
    /// Encode this token to compact binary wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Version
        buf.push(WIRE_VERSION);

        // Tool name
        let name_bytes = self.tool_name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        // Arg keys
        buf.extend_from_slice(&(self.arg_keys.len() as u16).to_be_bytes());
        for key in &self.arg_keys {
            let key_bytes = key.as_bytes();
            buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(key_bytes);
        }

        // Expiry
        buf.extend_from_slice(&self.expiry.to_be_bytes());

        // Nonce (u8 length since nonce is typically 16 bytes)
        buf.push(self.nonce.len() as u8);
        buf.extend_from_slice(&self.nonce);

        // MAC (u8 length since MAC is typically 32 bytes)
        buf.push(self.mac.len() as u8);
        buf.extend_from_slice(&self.mac);

        // Audience (optional)
        match &self.audience {
            Some(aud) => {
                let aud_bytes = aud.as_bytes();
                buf.extend_from_slice(&(aud_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(aud_bytes);
            }
            None => {
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        buf
    }

    /// Decode a token from compact binary wire format.
    pub fn from_wire(data: &[u8]) -> Result<Token, WireError> {
        let mut pos = 0;

        // Helper to read bytes
        let read_bytes = |pos: &mut usize, len: usize| -> Result<&[u8], WireError> {
            if *pos + len > data.len() {
                return Err(WireError::UnexpectedEof);
            }
            let slice = &data[*pos..*pos + len];
            *pos += len;
            Ok(slice)
        };

        // Version
        let version = *read_bytes(&mut pos, 1)?.first().unwrap();
        if version != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }

        // Tool name
        let name_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let name_bytes = read_bytes(&mut pos, name_len)?;
        let tool_name =
            String::from_utf8(name_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?;

        // Arg keys
        let keys_count = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let mut arg_keys = Vec::with_capacity(keys_count);
        for _ in 0..keys_count {
            let key_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            let key_bytes = read_bytes(&mut pos, key_len)?;
            let key = String::from_utf8(key_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?;
            arg_keys.push(key);
        }

        // Expiry
        let expiry = u64::from_be_bytes(read_bytes(&mut pos, 8)?.try_into().unwrap());

        // Nonce
        let nonce_len = *read_bytes(&mut pos, 1)?.first().unwrap() as usize;
        let nonce = read_bytes(&mut pos, nonce_len)?.to_vec();

        // MAC
        let mac_len = *read_bytes(&mut pos, 1)?.first().unwrap() as usize;
        let mac = read_bytes(&mut pos, mac_len)?.to_vec();

        // Audience
        let aud_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let audience = if aud_len > 0 {
            let aud_bytes = read_bytes(&mut pos, aud_len)?;
            Some(String::from_utf8(aud_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?)
        } else {
            None
        };

        Ok(Token {
            tool_name,
            arg_keys,
            expiry,
            nonce,
            mac,
            audience,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";

    #[test]
    fn wire_roundtrip_basic() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.tool_name, token.tool_name);
        assert_eq!(decoded.arg_keys, token.arg_keys);
        assert_eq!(decoded.expiry, token.expiry);
        assert_eq!(decoded.nonce, token.nonce);
        assert_eq!(decoded.mac, token.mac);
        assert_eq!(decoded.audience, token.audience);
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_with_audience() {
        let token = Token::mint_with_audience(
            SECRET,
            "write_file",
            vec!["path".into(), "data".into()],
            2000000000,
            Some("client-xyz".to_string()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.audience, Some("client-xyz".to_string()));
        assert!(decoded
            .verify_with_audience(SECRET, 1999999999, Some("client-xyz"))
            .is_ok());
    }

    #[test]
    fn wire_roundtrip_empty_keys() {
        let token = Token::mint(SECRET, "ping", vec![], 2000000000);

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.arg_keys.len(), 0);
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_format_version() {
        let token = Token::mint(SECRET, "test", vec![], 1000);
        let wire = token.to_wire();

        assert_eq!(wire[0], WIRE_VERSION);
    }

    #[test]
    fn wire_unsupported_version() {
        let mut data = vec![99u8]; // Invalid version
        data.extend_from_slice(&[0, 4]); // tool name length
        data.extend_from_slice(b"test");

        let result = Token::from_wire(&data);
        assert_eq!(result, Err(WireError::UnsupportedVersion(99)));
    }

    #[test]
    fn wire_truncated_data() {
        let token = Token::mint(SECRET, "test", vec![], 1000);
        let wire = token.to_wire();

        let truncated = &wire[..wire.len() / 2];
        let result = Token::from_wire(truncated);
        assert_eq!(result, Err(WireError::UnexpectedEof));
    }

    #[test]
    fn wire_is_compact() {
        let token = Token::mint(SECRET, "read", vec!["a".into()], 1000);

        let wire = token.to_wire();
        let json = serde_json::to_string(&token).unwrap();

        assert!(
            wire.len() < json.len(),
            "wire format should be smaller than JSON"
        );
    }
}
