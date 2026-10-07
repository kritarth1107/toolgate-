//! Compact string encoding for tokens (`tg1.` + unpadded base64url).
//!
//! The payload is the existing compact wire format. The string form is
//! intended for HTTP headers and MCP `_meta` fields.

use std::fmt;
use std::str::FromStr;

use crate::wire::WireError;
use crate::Token;

/// Prefix for compact token strings.
pub const TOKEN_STRING_PREFIX: &str = "tg1.";

/// Maximum accepted length of a compact token string, including the prefix.
///
/// Large enough for typical tokens (including constraints) while bounding
/// decode work when the value arrives from an HTTP header or `_meta` field.
pub const MAX_TOKEN_STRING_LEN: usize = 8192;

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Errors from parsing a compact token string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenStringError {
    /// Input exceeds [`MAX_TOKEN_STRING_LEN`].
    InputTooLong,
    /// Missing or incorrect `tg1.` prefix.
    WrongPrefix,
    /// Payload is not valid unpadded base64url.
    InvalidBase64,
    /// Extra characters or leftover bits after a complete payload.
    TrailingGarbage,
    /// Wire payload could not be decoded.
    Wire(WireError),
}

impl fmt::Display for TokenStringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenStringError::InputTooLong => write!(
                f,
                "token string exceeds maximum length of {MAX_TOKEN_STRING_LEN}"
            ),
            TokenStringError::WrongPrefix => {
                write!(f, "token string must start with '{TOKEN_STRING_PREFIX}'")
            }
            TokenStringError::InvalidBase64 => {
                write!(f, "token string payload is not valid base64url")
            }
            TokenStringError::TrailingGarbage => {
                write!(f, "token string contains trailing garbage")
            }
            TokenStringError::Wire(err) => write!(f, "token string wire payload: {err}"),
        }
    }
}

impl std::error::Error for TokenStringError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TokenStringError::Wire(err) => Some(err),
            _ => None,
        }
    }
}

impl From<WireError> for TokenStringError {
    fn from(err: WireError) -> Self {
        TokenStringError::Wire(err)
    }
}

impl Token {
    /// Encode this token as `tg1.` plus unpadded base64url of the wire bytes.
    pub fn to_token_string(&self) -> String {
        let mut out = String::from(TOKEN_STRING_PREFIX);
        encode_base64url(&self.to_wire(), &mut out);
        out
    }

    /// Decode a compact token string.
    ///
    /// Rejects the wrong prefix, invalid base64url, trailing garbage after
    /// the wire payload, and input longer than [`MAX_TOKEN_STRING_LEN`].
    /// This does not verify the MAC.
    pub fn from_token_string(s: &str) -> Result<Self, TokenStringError> {
        if s.len() > MAX_TOKEN_STRING_LEN {
            return Err(TokenStringError::InputTooLong);
        }
        let payload = s
            .strip_prefix(TOKEN_STRING_PREFIX)
            .ok_or(TokenStringError::WrongPrefix)?;
        let bytes = decode_base64url(payload)?;
        let (token, consumed) = Token::from_wire_consumed(&bytes)?;
        if consumed != bytes.len() {
            return Err(TokenStringError::TrailingGarbage);
        }
        Ok(token)
    }
}

impl FromStr for Token {
    type Err = TokenStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Token::from_token_string(s)
    }
}

fn encode_base64url(input: &[u8], out: &mut String) {
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        out.push(B64URL[((n >> 6) & 63) as usize] as char);
        out.push(B64URL[(n & 63) as usize] as char);
        i += 3;
    }
    if i < input.len() {
        let rem = input.len() - i;
        let mut n = (input[i] as u32) << 16;
        if rem == 2 {
            n |= (input[i + 1] as u32) << 8;
        }
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        if rem == 2 {
            out.push(B64URL[((n >> 6) & 63) as usize] as char);
        }
    }
}

fn decode_base64url(s: &str) -> Result<Vec<u8>, TokenStringError> {
    if s.as_bytes()
        .iter()
        .any(|b| decode_b64url_digit(*b).is_none())
    {
        return Err(TokenStringError::InvalidBase64);
    }
    if s.len() % 4 == 1 {
        return Err(TokenStringError::InvalidBase64);
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let n = (b64_digit(bytes[i])? << 18)
            | (b64_digit(bytes[i + 1])? << 12)
            | (b64_digit(bytes[i + 2])? << 6)
            | b64_digit(bytes[i + 3])?;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }

    let rem = bytes.len() - i;
    if rem == 2 {
        let d0 = b64_digit(bytes[i])?;
        let d1 = b64_digit(bytes[i + 1])?;
        if d1 & 0x0F != 0 {
            return Err(TokenStringError::TrailingGarbage);
        }
        out.push(((d0 << 2) | (d1 >> 4)) as u8);
    } else if rem == 3 {
        let d0 = b64_digit(bytes[i])?;
        let d1 = b64_digit(bytes[i + 1])?;
        let d2 = b64_digit(bytes[i + 2])?;
        if d2 & 0x03 != 0 {
            return Err(TokenStringError::TrailingGarbage);
        }
        out.push(((d0 << 2) | (d1 >> 4)) as u8);
        out.push(((d1 << 4) | (d2 >> 2)) as u8);
    }

    Ok(out)
}

fn decode_b64url_digit(b: u8) -> Option<u32> {
    match b {
        b'A'..=b'Z' => Some((b - b'A') as u32),
        b'a'..=b'z' => Some((b - b'a' + 26) as u32),
        b'0'..=b'9' => Some((b - b'0' + 52) as u32),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn b64_digit(b: u8) -> Result<u32, TokenStringError> {
    decode_b64url_digit(b).ok_or(TokenStringError::InvalidBase64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraint::Constraint;
    use std::collections::BTreeMap;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";

    fn sample_token() -> Token {
        Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
        )
    }

    #[test]
    fn token_string_roundtrip() {
        let token = sample_token();
        let encoded = token.to_token_string();
        assert!(encoded.starts_with(TOKEN_STRING_PREFIX));
        assert!(!encoded.contains('='));
        assert!(!encoded[TOKEN_STRING_PREFIX.len()..].contains('+'));
        assert!(!encoded[TOKEN_STRING_PREFIX.len()..].contains('/'));

        let decoded = Token::from_token_string(&encoded).unwrap();
        assert_eq!(decoded, token);
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn token_string_from_str() {
        let token = sample_token();
        let encoded = token.to_token_string();
        let parsed: Token = encoded.parse().unwrap();
        assert_eq!(parsed, token);
    }

    #[test]
    fn token_string_roundtrip_with_constraints_and_jti() {
        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client".into()),
            Some("key-1".into()),
            Some(constraints),
            true,
            Some(1_900_000_000),
            Some(2),
        );
        let decoded = Token::from_token_string(&token.to_token_string()).unwrap();
        assert_eq!(decoded, token);
        assert!(decoded.verify(SECRET, 1_950_000_000).is_ok());
    }

    #[test]
    fn token_string_matches_wire_bytes() {
        let token = sample_token();
        let encoded = token.to_token_string();
        let payload = encoded.strip_prefix(TOKEN_STRING_PREFIX).unwrap();
        let bytes = decode_base64url(payload).unwrap();
        assert_eq!(bytes, token.to_wire());
    }

    #[test]
    fn token_string_rejects_wrong_prefix() {
        let token = sample_token();
        let encoded = token.to_token_string();
        let payload = encoded.strip_prefix(TOKEN_STRING_PREFIX).unwrap();

        assert_eq!(
            Token::from_token_string(payload),
            Err(TokenStringError::WrongPrefix)
        );
        assert_eq!(
            Token::from_token_string(&format!("tg2.{payload}")),
            Err(TokenStringError::WrongPrefix)
        );
        assert_eq!(
            Token::from_token_string(&format!("TG1.{payload}")),
            Err(TokenStringError::WrongPrefix)
        );
    }

    #[test]
    fn token_string_rejects_invalid_base64() {
        assert_eq!(
            Token::from_token_string("tg1.@@@"),
            Err(TokenStringError::InvalidBase64)
        );
        assert_eq!(
            Token::from_token_string("tg1.abc+def"),
            Err(TokenStringError::InvalidBase64)
        );
        assert_eq!(
            Token::from_token_string("tg1.abc/def"),
            Err(TokenStringError::InvalidBase64)
        );
        assert_eq!(
            Token::from_token_string("tg1.abcd="),
            Err(TokenStringError::InvalidBase64)
        );
        // One leftover character cannot form a byte.
        assert_eq!(
            Token::from_token_string("tg1.a"),
            Err(TokenStringError::InvalidBase64)
        );
    }

    #[test]
    fn token_string_rejects_trailing_garbage() {
        let token = sample_token();
        let encoded = token.to_token_string();

        assert_eq!(
            Token::from_token_string(&format!("{encoded} extra")),
            Err(TokenStringError::InvalidBase64)
        );

        // Extra decoded wire bytes after a complete token.
        let mut padded = token.to_wire();
        padded.push(0xFF);
        let mut s = String::from(TOKEN_STRING_PREFIX);
        encode_base64url(&padded, &mut s);
        assert_eq!(
            Token::from_token_string(&s),
            Err(TokenStringError::TrailingGarbage)
        );

        // Non-zero leftover bits in the final base64url character.
        assert_eq!(
            Token::from_token_string("tg1.ab"),
            Err(TokenStringError::TrailingGarbage)
        );
    }

    #[test]
    fn token_string_rejects_oversized_input() {
        let mut s = String::from(TOKEN_STRING_PREFIX);
        s.push_str(&"A".repeat(MAX_TOKEN_STRING_LEN));
        assert!(s.len() > MAX_TOKEN_STRING_LEN);
        assert_eq!(
            Token::from_token_string(&s),
            Err(TokenStringError::InputTooLong)
        );
    }

    #[test]
    fn token_string_rejects_empty_payload() {
        let result = Token::from_token_string(TOKEN_STRING_PREFIX);
        assert!(matches!(result, Err(TokenStringError::Wire(_))));
    }
}
