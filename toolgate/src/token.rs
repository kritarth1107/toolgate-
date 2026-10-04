//! Token creation, attenuation, and verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::encoding::encode_canonical_v2;

type HmacSha256 = Hmac<Sha256>;

/// A capability token for a tool call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub tool_name: String,
    pub arg_keys: Vec<String>,
    pub expiry: u64,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mac: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
}

/// Errors that can occur during token operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidMac,
    Expired,
    AttenuationWidens,
    AudienceMismatch,
    ToolMismatch { expected: String, got: String },
    ArgKeyNotAllowed { key: String },
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::InvalidMac => write!(f, "invalid MAC"),
            TokenError::Expired => write!(f, "token expired"),
            TokenError::AttenuationWidens => write!(f, "attenuation cannot widen capabilities"),
            TokenError::AudienceMismatch => write!(f, "audience mismatch"),
            TokenError::ToolMismatch { expected, got } => {
                write!(f, "tool mismatch: expected '{}', got '{}'", expected, got)
            }
            TokenError::ArgKeyNotAllowed { key } => {
                write!(f, "argument key '{}' not in token allowlist", key)
            }
        }
    }
}

impl std::error::Error for TokenError {}

impl Token {
    /// Mint a new token with the given parameters.
    ///
    /// Use `mint_with_audience` to create a token bound to a specific audience.
    pub fn mint(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
    ) -> Self {
        Self::mint_with_audience(secret, tool_name, arg_keys, expiry, None)
    }

    /// Mint a new token with an optional audience binding.
    ///
    /// When `audience` is `Some(value)`, the token is bound to that audience
    /// and verification will fail if a different audience is expected.
    /// When `audience` is `None`, the token is unbound.
    pub fn mint_with_audience(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
    ) -> Self {
        let tool_name = tool_name.into();
        let nonce: [u8; 16] = rand::random();

        let canonical =
            encode_canonical_v2(&tool_name, &arg_keys, expiry, &nonce, audience.as_deref());
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let mac = hmac.finalize().into_bytes().to_vec();

        Token {
            tool_name,
            arg_keys,
            expiry,
            nonce: nonce.to_vec(),
            mac,
            audience,
        }
    }

    /// Verify the token's MAC and check expiry.
    /// Uses constant-time comparison for the MAC.
    ///
    /// This does not check audience. Use `verify_with_audience` if you need
    /// to verify that the token is bound to a specific audience.
    pub fn verify(&self, secret: &[u8], current_time: u64) -> Result<(), TokenError> {
        self.verify_with_audience(secret, current_time, None)
    }

    /// Verify the token's MAC, expiry, and optionally audience.
    ///
    /// If `expected_audience` is `Some(aud)`:
    /// - Token must have a matching audience, or
    /// - Token must be unbound (audience=None), which matches any expected audience
    ///
    /// If `expected_audience` is `None`, audience is not checked.
    pub fn verify_with_audience(
        &self,
        secret: &[u8],
        current_time: u64,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        // Check expiry first
        if current_time > self.expiry {
            return Err(TokenError::Expired);
        }

        // Check audience if required
        if let Some(expected) = expected_audience {
            if let Some(ref token_aud) = self.audience {
                if token_aud != expected {
                    return Err(TokenError::AudienceMismatch);
                }
            }
            // Token with no audience (unbound) matches any expected audience
        }

        // Recompute MAC
        let canonical = encode_canonical_v2(
            &self.tool_name,
            &self.arg_keys,
            self.expiry,
            &self.nonce,
            self.audience.as_deref(),
        );
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let expected = hmac.finalize().into_bytes();

        // Constant-time comparison
        if expected.ct_eq(&self.mac).into() {
            Ok(())
        } else {
            Err(TokenError::InvalidMac)
        }
    }

    /// Verify that this token authorizes a specific tool call.
    ///
    /// This performs full verification:
    /// 1. MAC validity
    /// 2. Expiry check
    /// 3. Audience match (if `expected_audience` is provided)
    /// 4. Tool name must match exactly
    /// 5. All requested argument keys must be in the token's allowlist
    ///
    /// Returns `Ok(())` if the call is authorized, or a specific error.
    pub fn verify_call(
        &self,
        secret: &[u8],
        current_time: u64,
        tool_name: &str,
        requested_arg_keys: &[&str],
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        // First verify MAC, expiry, and audience
        self.verify_with_audience(secret, current_time, expected_audience)?;

        // Check tool name matches
        if self.tool_name != tool_name {
            return Err(TokenError::ToolMismatch {
                expected: tool_name.to_string(),
                got: self.tool_name.clone(),
            });
        }

        // Check all requested arg keys are in the allowlist
        for key in requested_arg_keys {
            if !self.arg_keys.iter().any(|k| k == *key) {
                return Err(TokenError::ArgKeyNotAllowed {
                    key: (*key).to_string(),
                });
            }
        }

        Ok(())
    }

    /// Attenuate the token by removing argument keys or shortening expiry.
    /// Cannot add keys or extend expiry. Audience is preserved unchanged.
    pub fn attenuate(
        &self,
        secret: &[u8],
        new_arg_keys: Option<Vec<String>>,
        new_expiry: Option<u64>,
    ) -> Result<Token, TokenError> {
        // Validate attenuation doesn't widen
        let final_arg_keys = match new_arg_keys {
            Some(ref keys) => {
                // Check all new keys exist in original
                for key in keys {
                    if !self.arg_keys.contains(key) {
                        return Err(TokenError::AttenuationWidens);
                    }
                }
                keys.clone()
            }
            None => self.arg_keys.clone(),
        };

        let final_expiry = match new_expiry {
            Some(exp) => {
                if exp > self.expiry {
                    return Err(TokenError::AttenuationWidens);
                }
                exp
            }
            None => self.expiry,
        };

        // Generate new nonce and MAC for the attenuated token
        // Audience is preserved unchanged
        let nonce: [u8; 16] = rand::random();
        let canonical = encode_canonical_v2(
            &self.tool_name,
            &final_arg_keys,
            final_expiry,
            &nonce,
            self.audience.as_deref(),
        );
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let mac = hmac.finalize().into_bytes().to_vec();

        Ok(Token {
            tool_name: self.tool_name.clone(),
            arg_keys: final_arg_keys,
            expiry: final_expiry,
            nonce: nonce.to_vec(),
            mac,
            audience: self.audience.clone(),
        })
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";

    #[test]
    fn mint_and_verify_happy_path() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "offset".into()],
            2000000000,
        );

        assert_eq!(token.tool_name, "read_file");
        assert_eq!(token.arg_keys, vec!["path", "offset"]);
        assert_eq!(token.expiry, 2000000000);
        assert_eq!(token.nonce.len(), 16);
        assert_eq!(token.mac.len(), 32);
        assert_eq!(token.audience, None);

        // Verify with time before expiry
        assert!(token.verify(SECRET, 1999999999).is_ok());
        assert!(token.verify(SECRET, 2000000000).is_ok());
    }

    #[test]
    fn expired_token_fails() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1700000000);

        // Time after expiry
        let result = token.verify(SECRET, 1700000001);
        assert_eq!(result, Err(TokenError::Expired));
    }

    #[test]
    fn tampered_mac_fails() {
        let mut token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        // Tamper with MAC
        token.mac[0] ^= 0xFF;

        let result = token.verify(SECRET, 1999999999);
        assert_eq!(result, Err(TokenError::InvalidMac));
    }

    #[test]
    fn wrong_secret_fails() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.verify(b"wrong-secret", 1999999999);
        assert_eq!(result, Err(TokenError::InvalidMac));
    }

    #[test]
    fn attenuate_can_drop_keys() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "offset".into(), "limit".into()],
            2000000000,
        );

        let attenuated = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.tool_name, "read_file");
        assert_eq!(attenuated.arg_keys, vec!["path"]);
        assert_eq!(attenuated.expiry, 2000000000);
        assert!(attenuated.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn attenuate_can_shorten_expiry() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let attenuated = token.attenuate(SECRET, None, Some(1900000000)).unwrap();

        assert_eq!(attenuated.expiry, 1900000000);
        assert!(attenuated.verify(SECRET, 1899999999).is_ok());
    }

    #[test]
    fn attenuation_cannot_add_keys() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.attenuate(SECRET, Some(vec!["path".into(), "offset".into()]), None);
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn attenuation_cannot_extend_expiry() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.attenuate(SECRET, None, Some(2100000000));
        assert_eq!(result, Err(TokenError::AttenuationWidens));
    }

    #[test]
    fn token_json_roundtrip() {
        let token = Token::mint(
            SECRET,
            "write_file",
            vec!["path".into(), "data".into()],
            2000000000,
        );

        let json = serde_json::to_string(&token).unwrap();
        let parsed: Token = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.tool_name, token.tool_name);
        assert_eq!(parsed.arg_keys, token.arg_keys);
        assert_eq!(parsed.expiry, token.expiry);
        assert_eq!(parsed.nonce, token.nonce);
        assert_eq!(parsed.mac, token.mac);
        assert!(parsed.verify(SECRET, 1999999999).is_ok());
    }

    // ===== Audience tests =====

    #[test]
    fn mint_with_audience() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        assert_eq!(token.audience, Some("client-abc".to_string()));
        assert!(token.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn audience_match_succeeds() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        assert!(token
            .verify_with_audience(SECRET, 1999999999, Some("client-abc"))
            .is_ok());
    }

    #[test]
    fn audience_mismatch_fails() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        let result = token.verify_with_audience(SECRET, 1999999999, Some("client-xyz"));
        assert_eq!(result, Err(TokenError::AudienceMismatch));
    }

    #[test]
    fn unbound_token_matches_any_audience() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        assert!(token
            .verify_with_audience(SECRET, 1999999999, Some("any-client"))
            .is_ok());
        assert!(token
            .verify_with_audience(SECRET, 1999999999, Some("other-client"))
            .is_ok());
    }

    #[test]
    fn audience_preserved_after_attenuation() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        let attenuated = token
            .attenuate(SECRET, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.audience, Some("client-abc".to_string()));
        assert!(attenuated
            .verify_with_audience(SECRET, 1999999999, Some("client-abc"))
            .is_ok());
    }

    #[test]
    fn audience_json_roundtrip() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-123".to_string()),
        );

        let json = serde_json::to_string(&token).unwrap();
        let parsed: Token = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.audience, Some("client-123".to_string()));
        assert!(parsed
            .verify_with_audience(SECRET, 1999999999, Some("client-123"))
            .is_ok());
    }

    #[test]
    fn no_audience_omitted_from_json() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("audience"));
    }

    // ===== verify_call tests =====

    #[test]
    fn verify_call_happy_path() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
        );

        assert!(token
            .verify_call(SECRET, 1999999999, "read_file", &["path", "limit"], None)
            .is_ok());
    }

    #[test]
    fn verify_call_subset_of_keys() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into(), "offset".into()],
            2000000000,
        );

        assert!(token
            .verify_call(SECRET, 1999999999, "read_file", &["path"], None)
            .is_ok());
    }

    #[test]
    fn verify_call_tool_mismatch() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.verify_call(SECRET, 1999999999, "write_file", &["path"], None);
        assert!(matches!(result, Err(TokenError::ToolMismatch { .. })));

        if let Err(TokenError::ToolMismatch { expected, got }) = result {
            assert_eq!(expected, "write_file");
            assert_eq!(got, "read_file");
        }
    }

    #[test]
    fn verify_call_arg_key_not_allowed() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let result = token.verify_call(SECRET, 1999999999, "read_file", &["path", "limit"], None);
        assert!(matches!(result, Err(TokenError::ArgKeyNotAllowed { .. })));

        if let Err(TokenError::ArgKeyNotAllowed { key }) = result {
            assert_eq!(key, "limit");
        }
    }

    #[test]
    fn verify_call_with_audience() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );

        assert!(token
            .verify_call(SECRET, 1999999999, "read_file", &["path"], Some("client-abc"))
            .is_ok());

        let result =
            token.verify_call(SECRET, 1999999999, "read_file", &["path"], Some("client-xyz"));
        assert_eq!(result, Err(TokenError::AudienceMismatch));
    }

    #[test]
    fn verify_call_expired() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1700000000);

        let result = token.verify_call(SECRET, 1700000001, "read_file", &["path"], None);
        assert_eq!(result, Err(TokenError::Expired));
    }

    #[test]
    fn verify_call_invalid_mac() {
        let mut token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        token.mac[0] ^= 0xFF;

        let result = token.verify_call(SECRET, 1999999999, "read_file", &["path"], None);
        assert_eq!(result, Err(TokenError::InvalidMac));
    }

    #[test]
    fn verify_call_empty_keys() {
        let token = Token::mint(SECRET, "ping", vec![], 2000000000);

        assert!(token
            .verify_call(SECRET, 1999999999, "ping", &[], None)
            .is_ok());

        let result = token.verify_call(SECRET, 1999999999, "ping", &["extra"], None);
        assert!(matches!(result, Err(TokenError::ArgKeyNotAllowed { .. })));
    }
}
