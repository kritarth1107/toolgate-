//! Key management and rotation support.
//!
//! The `Keyring` type manages multiple signing keys, enabling key rotation
//! without immediately invalidating existing tokens.

use std::collections::HashMap;
use std::time::Duration;

use crate::clock::{Clock, VerifyTime};
use crate::constraint::Constraints;
use crate::revocation::RevocationList;
use crate::token::Token;
use crate::use_store::UseStore;
use crate::TokenError;

/// A collection of signing keys with rotation support.
///
/// The keyring tracks multiple keys by ID. One key is designated as "active"
/// and used for minting new tokens. Verification looks up the key by the
/// token's `kid` field, allowing old tokens to verify until their key is retired.
///
/// # Example
///
/// ```
/// use toolgate::Keyring;
///
/// let mut keyring = Keyring::new();
///
/// // Add keys
/// keyring.add("key-2024", b"secret-key-2024-32-bytes-here!".to_vec());
/// keyring.add("key-2025", b"secret-key-2025-32-bytes-here!".to_vec());
///
/// // Set active key for minting
/// keyring.set_active("key-2025").unwrap();
///
/// // Mint with the active key
/// let token = keyring.mint("read_file", vec!["path".into()], 2000000000).unwrap();
/// assert_eq!(token.kid, Some("key-2025".to_string()));
///
/// // Verify (looks up key by kid)
/// assert!(keyring.verify(&token, 1999999999).is_ok());
///
/// // Retire old key - tokens signed with it will no longer verify
/// keyring.retire("key-2024");
/// ```
#[derive(Debug, Clone)]
pub struct Keyring {
    keys: HashMap<String, Vec<u8>>,
    active_kid: Option<String>,
}

impl Default for Keyring {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyring {
    /// Create an empty keyring.
    pub fn new() -> Self {
        Keyring {
            keys: HashMap::new(),
            active_kid: None,
        }
    }

    /// Add a key to the keyring.
    ///
    /// If this is the first key added, it becomes the active key automatically.
    pub fn add(&mut self, kid: impl Into<String>, secret: Vec<u8>) {
        let kid = kid.into();
        let is_first = self.keys.is_empty();
        self.keys.insert(kid.clone(), secret);
        if is_first {
            self.active_kid = Some(kid);
        }
    }

    /// Retire (remove) a key from the keyring.
    ///
    /// Tokens signed with this key will fail verification with `UnknownKeyId`.
    /// If the retired key was the active key, there will be no active key until
    /// `set_active` is called.
    pub fn retire(&mut self, kid: &str) {
        self.keys.remove(kid);
        if self.active_kid.as_deref() == Some(kid) {
            self.active_kid = None;
        }
    }

    /// Remove a key from the keyring (alias for `retire`).
    pub fn remove(&mut self, kid: &str) {
        self.retire(kid);
    }

    /// Set the active key used for minting new tokens.
    ///
    /// Returns an error if the key ID is not in the keyring.
    pub fn set_active(&mut self, kid: &str) -> Result<(), TokenError> {
        if !self.keys.contains_key(kid) {
            return Err(TokenError::UnknownKeyId {
                kid: kid.to_string(),
            });
        }
        self.active_kid = Some(kid.to_string());
        Ok(())
    }

    /// Get the active key ID, if set.
    pub fn active_kid(&self) -> Option<&str> {
        self.active_kid.as_deref()
    }

    /// Check if a key ID exists in the keyring.
    pub fn contains_key(&self, kid: &str) -> bool {
        self.keys.contains_key(kid)
    }

    /// Get the secret for a key ID, if it exists.
    pub fn get_secret(&self, kid: &str) -> Option<&[u8]> {
        self.keys.get(kid).map(|v| v.as_slice())
    }

    /// List all key IDs in the keyring.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(|s| s.as_str())
    }

    /// Mint a new token using the active key.
    ///
    /// The token's `kid` field will be set to the active key ID.
    /// Returns an error if no active key is set.
    pub fn mint(
        &self,
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
    ) -> Result<Token, TokenError> {
        self.mint_with_audience(tool_name, arg_keys, expiry, None)
    }

    /// Mint a new token with audience binding using the active key.
    pub fn mint_with_audience(
        &self,
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
    ) -> Result<Token, TokenError> {
        let kid = self.active_kid.as_ref().ok_or(TokenError::NoActiveKey)?;
        let secret = self.keys.get(kid).ok_or(TokenError::NoActiveKey)?;

        Ok(Token::mint_with_kid(
            secret,
            tool_name,
            arg_keys,
            expiry,
            audience,
            Some(kid.clone()),
        ))
    }

    /// Mint a token with optional jti, not-before, and max attenuation depth.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_complete(
        &self,
        tool_name: impl Into<String>,
        arg_keys: Vec<String>,
        expiry: u64,
        audience: Option<String>,
        constraints: Option<Constraints>,
        generate_jti: bool,
        nbf: Option<u64>,
        max_depth: Option<u32>,
    ) -> Result<Token, TokenError> {
        let kid = self.active_kid.as_ref().ok_or(TokenError::NoActiveKey)?;
        let secret = self.keys.get(kid).ok_or(TokenError::NoActiveKey)?;

        Ok(Token::mint_complete(
            secret,
            tool_name,
            arg_keys,
            expiry,
            audience,
            Some(kid.clone()),
            constraints,
            generate_jti,
            nbf,
            max_depth,
        ))
    }

    /// Verify a token using the keyring.
    ///
    /// Looks up the signing key by the token's `kid` field.
    /// Tokens without a `kid` cannot be verified through a keyring - use
    /// `Token::verify` with an explicit secret instead.
    pub fn verify(&self, token: &Token, current_time: u64) -> Result<(), TokenError> {
        self.verify_with_audience(token, current_time, None)
    }

    /// Verify a token with audience checking using the keyring.
    pub fn verify_with_audience(
        &self,
        token: &Token,
        current_time: u64,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_with_audience(secret, current_time, expected_audience)
    }

    /// Verify a token using an explicit unix timestamp and clock-skew leeway.
    pub fn verify_with_leeway(
        &self,
        token: &Token,
        current_time: u64,
        leeway: Duration,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_with_leeway(secret, current_time, leeway)
    }

    /// Verify a token using a swappable [`Clock`] and leeway.
    pub fn verify_with_clock<C: Clock>(
        &self,
        token: &Token,
        clock: &C,
        leeway: Duration,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_with_clock(secret, clock, leeway)
    }

    /// Verify a token using a bundled clock and leeway.
    pub fn verify_at<C: Clock>(
        &self,
        token: &Token,
        time: &VerifyTime<C>,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_at(secret, time, expected_audience)
    }

    /// Verify a token with revocation list checking using the keyring.
    ///
    /// The token must have a jti to be checked against the revocation list.
    pub fn verify_with_revocation(
        &self,
        token: &Token,
        current_time: u64,
        revocation_list: &RevocationList,
    ) -> Result<(), TokenError> {
        self.verify_with_revocation_and_audience(token, current_time, revocation_list, None)
    }

    /// Verify a token with revocation list and audience checking using the keyring.
    ///
    /// The token must have a jti to be checked against the revocation list.
    pub fn verify_with_revocation_and_audience(
        &self,
        token: &Token,
        current_time: u64,
        revocation_list: &RevocationList,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_with_revocation_and_audience(
            secret,
            current_time,
            revocation_list,
            expected_audience,
        )
    }

    /// Verify a single-use token using the keyring.
    ///
    /// The token must have a jti to be tracked by the use store.
    pub fn verify_single_use<S: UseStore>(
        &self,
        token: &Token,
        current_time: u64,
        use_store: &mut S,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_single_use(secret, current_time, use_store)
    }

    /// Verify a token with max-uses limit using the keyring.
    ///
    /// The token must have a jti to be tracked by the use store.
    pub fn verify_with_max_uses<S: UseStore>(
        &self,
        token: &Token,
        current_time: u64,
        use_store: &mut S,
        max_uses: u64,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_with_max_uses(secret, current_time, use_store, max_uses, expected_audience)
    }

    /// Verify a token with both revocation list and use store checking.
    ///
    /// Provides comprehensive replay prevention using the keyring.
    pub fn verify_with_revocation_and_use_store<S: UseStore>(
        &self,
        token: &Token,
        current_time: u64,
        revocation_list: &RevocationList,
        use_store: &mut S,
        max_uses: u64,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_with_revocation_and_use_store(
            secret,
            current_time,
            revocation_list,
            use_store,
            max_uses,
            expected_audience,
        )
    }

    /// Verify that a token authorizes a specific tool call.
    pub fn verify_call(
        &self,
        token: &Token,
        current_time: u64,
        tool_name: &str,
        requested_arg_keys: &[&str],
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_call(
            secret,
            current_time,
            tool_name,
            requested_arg_keys,
            expected_audience,
        )
    }

    /// Verify that a token authorizes a specific tool call with argument values.
    ///
    /// This performs full verification including constraint checking on argument values.
    pub fn verify_call_with_args(
        &self,
        token: &Token,
        current_time: u64,
        tool_name: &str,
        args: &std::collections::BTreeMap<String, String>,
        expected_audience: Option<&str>,
    ) -> Result<(), TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.verify_call_with_args(secret, current_time, tool_name, args, expected_audience)
    }

    /// Attenuate a token using the keyring.
    ///
    /// The attenuated token preserves the original `kid`.
    pub fn attenuate(
        &self,
        token: &Token,
        new_arg_keys: Option<Vec<String>>,
        new_expiry: Option<u64>,
    ) -> Result<Token, TokenError> {
        let secret = self.get_secret_for_token(token)?;
        token.attenuate(secret, new_arg_keys, new_expiry)
    }

    fn get_secret_for_token(&self, token: &Token) -> Result<&[u8], TokenError> {
        match &token.kid {
            Some(kid) => self
                .keys
                .get(kid)
                .map(|v| v.as_slice())
                .ok_or_else(|| TokenError::UnknownKeyId { kid: kid.clone() }),
            None => Err(TokenError::MissingKeyId),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_1: &[u8] = b"test-secret-key-1-32-bytes-!!";
    const SECRET_2: &[u8] = b"test-secret-key-2-32-bytes-!!";

    #[test]
    fn keyring_mint_and_verify() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        let token = keyring
            .mint("read_file", vec!["path".into()], 2000000000)
            .unwrap();

        assert_eq!(token.kid, Some("key-1".to_string()));
        assert!(keyring.verify(&token, 1999999999).is_ok());
    }

    #[test]
    fn keyring_rotation() {
        let mut keyring = Keyring::new();
        keyring.add("key-old", SECRET_1.to_vec());

        // Mint with old key
        let old_token = keyring
            .mint("read_file", vec!["path".into()], 2000000000)
            .unwrap();
        assert_eq!(old_token.kid, Some("key-old".to_string()));

        // Add new key and set it active
        keyring.add("key-new", SECRET_2.to_vec());
        keyring.set_active("key-new").unwrap();

        // Mint with new key
        let new_token = keyring
            .mint("read_file", vec!["path".into()], 2000000000)
            .unwrap();
        assert_eq!(new_token.kid, Some("key-new".to_string()));

        // Both tokens verify
        assert!(keyring.verify(&old_token, 1999999999).is_ok());
        assert!(keyring.verify(&new_token, 1999999999).is_ok());

        // Retire old key
        keyring.retire("key-old");

        // Old token fails, new token still works
        let result = keyring.verify(&old_token, 1999999999);
        assert!(matches!(result, Err(TokenError::UnknownKeyId { .. })));
        assert!(keyring.verify(&new_token, 1999999999).is_ok());
    }

    #[test]
    fn unknown_kid_error() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        // Create a token with a different kid
        let token = Token::mint_with_kid(
            SECRET_2,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            Some("unknown-key".to_string()),
        );

        let result = keyring.verify(&token, 1999999999);
        assert!(matches!(result, Err(TokenError::UnknownKeyId { kid }) if kid == "unknown-key"));
    }

    #[test]
    fn attenuation_preserves_kid() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        let token = keyring
            .mint("read_file", vec!["path".into(), "limit".into()], 2000000000)
            .unwrap();

        let attenuated = keyring
            .attenuate(&token, Some(vec!["path".into()]), None)
            .unwrap();

        assert_eq!(attenuated.kid, Some("key-1".to_string()));
        assert_eq!(attenuated.arg_keys, vec!["path"]);
        assert!(keyring.verify(&attenuated, 1999999999).is_ok());
    }

    #[test]
    fn mint_without_active_key_fails() {
        let keyring = Keyring::new();
        let result = keyring.mint("read_file", vec!["path".into()], 2000000000);
        assert!(matches!(result, Err(TokenError::NoActiveKey)));
    }

    #[test]
    fn set_active_unknown_key_fails() {
        let mut keyring = Keyring::new();
        let result = keyring.set_active("nonexistent");
        assert!(matches!(result, Err(TokenError::UnknownKeyId { .. })));
    }

    #[test]
    fn first_key_becomes_active() {
        let mut keyring = Keyring::new();
        assert!(keyring.active_kid().is_none());

        keyring.add("key-1", SECRET_1.to_vec());
        assert_eq!(keyring.active_kid(), Some("key-1"));

        // Second key does not auto-activate
        keyring.add("key-2", SECRET_2.to_vec());
        assert_eq!(keyring.active_kid(), Some("key-1"));
    }

    #[test]
    fn retire_active_key_clears_active() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());
        assert_eq!(keyring.active_kid(), Some("key-1"));

        keyring.retire("key-1");
        assert!(keyring.active_kid().is_none());
    }

    #[test]
    fn verify_token_without_kid_fails() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        // Old-style token without kid
        let token = Token::mint(SECRET_1, "read_file", vec!["path".into()], 2000000000);
        assert!(token.kid.is_none());

        let result = keyring.verify(&token, 1999999999);
        assert!(matches!(result, Err(TokenError::MissingKeyId)));
    }

    #[test]
    fn verify_call_through_keyring() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        let token = keyring
            .mint("read_file", vec!["path".into(), "limit".into()], 2000000000)
            .unwrap();

        assert!(keyring
            .verify_call(&token, 1999999999, "read_file", &["path"], None)
            .is_ok());

        let result = keyring.verify_call(&token, 1999999999, "write_file", &["path"], None);
        assert!(matches!(result, Err(TokenError::ToolMismatch { .. })));
    }

    #[test]
    fn mint_with_audience_through_keyring() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        let token = keyring
            .mint_with_audience(
                "read_file",
                vec!["path".into()],
                2000000000,
                Some("client-abc".to_string()),
            )
            .unwrap();

        assert_eq!(token.kid, Some("key-1".to_string()));
        assert_eq!(token.audience, Some("client-abc".to_string()));

        assert!(keyring
            .verify_with_audience(&token, 1999999999, Some("client-abc"))
            .is_ok());
    }

    #[test]
    fn key_ids_iteration() {
        let mut keyring = Keyring::new();
        keyring.add("key-a", SECRET_1.to_vec());
        keyring.add("key-b", SECRET_2.to_vec());

        let mut ids: Vec<_> = keyring.key_ids().collect();
        ids.sort();
        assert_eq!(ids, vec!["key-a", "key-b"]);
    }

    #[test]
    fn verify_call_with_args_through_keyring() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET_1,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            Some("key-1".to_string()),
            Some(constraints),
        );

        // Valid args
        let mut args = BTreeMap::new();
        args.insert("path".to_string(), "/tmp/test.txt".to_string());

        assert!(keyring
            .verify_call_with_args(&token, 1999999999, "read_file", &args, None)
            .is_ok());

        // Invalid args
        let mut bad_args = BTreeMap::new();
        bad_args.insert("path".to_string(), "/etc/passwd".to_string());

        let result =
            keyring.verify_call_with_args(&token, 1999999999, "read_file", &bad_args, None);
        assert!(matches!(
            result,
            Err(TokenError::ConstraintViolation { key }) if key == "path"
        ));
    }

    #[test]
    fn keyring_mint_complete_nbf_and_depth() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        let token = keyring
            .mint_complete(
                "read_file",
                vec!["path".into()],
                2000000000,
                None,
                None,
                false,
                Some(1_900_000_000),
                Some(1),
            )
            .unwrap();

        assert_eq!(token.kid, Some("key-1".to_string()));
        assert_eq!(token.nbf, Some(1_900_000_000));
        assert_eq!(token.max_depth, Some(1));
        assert!(keyring.verify(&token, 1_950_000_000).is_ok());
        assert_eq!(
            keyring.verify(&token, 1_899_999_999),
            Err(TokenError::NotYetValid)
        );

        let attenuated = keyring.attenuate(&token, None, Some(1950000000)).unwrap();
        assert_eq!(attenuated.depth, 1);
        let result = keyring.attenuate(&attenuated, None, Some(1900000000));
        assert_eq!(
            result,
            Err(TokenError::MaxDepthExceeded { depth: 2, max: 1 })
        );
    }

    #[test]
    fn keyring_verify_with_clock_and_leeway() {
        use crate::clock::FixedClock;

        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET_1.to_vec());

        let token = keyring
            .mint("read_file", vec!["path".into()], 1000)
            .unwrap();

        let clock = FixedClock::at(1010);
        assert_eq!(
            keyring.verify_with_clock(&token, &clock, Duration::ZERO),
            Err(TokenError::Expired)
        );
        assert!(keyring
            .verify_with_leeway(&token, 1010, Duration::from_secs(30))
            .is_ok());

        let time = VerifyTime::unix_with_leeway(1010, Duration::from_secs(15));
        assert!(keyring.verify_at(&token, &time, None).is_ok());
    }
}
