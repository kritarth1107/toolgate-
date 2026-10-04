//! Token creation, attenuation, and verification.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::encoding::encode_canonical;

type HmacSha256 = Hmac<Sha256>;

/// A capability token for a tool call.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub tool_name: String,
    pub arg_keys: Vec<String>,
    pub expiry: u64,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub mac: Vec<u8>,
}

/// Errors that can occur during token operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    InvalidMac,
    Expired,
    AttenuationWidens,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::InvalidMac => write!(f, "invalid MAC"),
            TokenError::Expired => write!(f, "token expired"),
            TokenError::AttenuationWidens => write!(f, "attenuation cannot widen capabilities"),
        }
    }
}

impl std::error::Error for TokenError {}

impl Token {
    /// Mint a new token with the given parameters.
    pub fn mint(
        secret: &[u8],
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
    ) -> Self {
        let tool_name = tool_name.into();
        let nonce: [u8; 16] = rand::random();

        let canonical = encode_canonical(&tool_name, &arg_keys, expiry, &nonce);
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let mac = hmac.finalize().into_bytes().to_vec();

        Token {
            tool_name,
            arg_keys,
            expiry,
            nonce: nonce.to_vec(),
            mac,
        }
    }

    /// Verify the token's MAC and check expiry.
    /// Uses constant-time comparison for the MAC.
    pub fn verify(&self, secret: &[u8], current_time: u64) -> Result<(), TokenError> {
        // Check expiry first
        if current_time > self.expiry {
            return Err(TokenError::Expired);
        }

        // Recompute MAC
        let canonical = encode_canonical(&self.tool_name, &self.arg_keys, self.expiry, &self.nonce);
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

    /// Attenuate the token by removing argument keys or shortening expiry.
    /// Cannot add keys or extend expiry.
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
        let nonce: [u8; 16] = rand::random();
        let canonical = encode_canonical(&self.tool_name, &final_arg_keys, final_expiry, &nonce);
        let mut hmac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
        hmac.update(&canonical);
        let mac = hmac.finalize().into_bytes().to_vec();

        Ok(Token {
            tool_name: self.tool_name.clone(),
            arg_keys: final_arg_keys,
            expiry: final_expiry,
            nonce: nonce.to_vec(),
            mac,
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
