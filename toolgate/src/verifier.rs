//! Builder that consolidates the `verify_*` variants on [`Token`] and [`Keyring`].
//!
//! Single-use and max-uses checks stay on [`Token::verify_single_use`] and
//! [`Token::verify_with_max_uses`]. Threading a `&mut impl UseStore` through
//! this builder would force every `Verifier` to be mutably borrowed for
//! otherwise read-only checks.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::clock::{Clock, SystemClock};
use crate::keyring::Keyring;
use crate::revocation::RevocationList;
use crate::token::{Token, TokenError};

/// Configurable token verifier.
///
/// Start with [`Verifier::new`] and chain optional checks. When a [`Keyring`]
/// is attached, the token's `kid` selects the secret and the constructor
/// secret is ignored.
///
/// ```
/// use std::time::Duration;
/// use toolgate::{FixedClock, Token, Verifier};
///
/// let secret = b"your-256-bit-secret-key-here!!";
/// let token = Token::mint(secret, "read_file", vec!["path".into()], 2000000000);
/// let clock = FixedClock::at(1999999999);
///
/// Verifier::new(secret)
///     .clock(&clock)
///     .leeway(Duration::from_secs(30))
///     .verify(&token)
///     .unwrap();
/// ```
#[derive(Clone, Copy)]
pub struct Verifier<'a> {
    secret: &'a [u8],
    time: TimeSource<'a>,
    leeway: Duration,
    audience: Option<&'a str>,
    revocation: Option<&'a RevocationList>,
    keyring: Option<&'a Keyring>,
}

#[derive(Clone, Copy)]
enum TimeSource<'a> {
    System,
    Unix(u64),
    Clock(&'a dyn Clock),
}

impl<'a> Verifier<'a> {
    /// Create a verifier for `secret`.
    ///
    /// Time defaults to [`SystemClock`] with zero leeway until `.at()` or
    /// `.clock()` is set. Attach `.keyring()` to look up the secret by `kid`
    /// instead of using this value.
    pub fn new(secret: &'a [u8]) -> Self {
        Verifier {
            secret,
            time: TimeSource::System,
            leeway: Duration::ZERO,
            audience: None,
            revocation: None,
            keyring: None,
        }
    }

    /// Use a swappable clock for expiry and not-before checks.
    pub fn clock(mut self, clock: &'a dyn Clock) -> Self {
        self.time = TimeSource::Clock(clock);
        self
    }

    /// Use an explicit unix timestamp for expiry and not-before checks.
    pub fn at(mut self, unix: u64) -> Self {
        self.time = TimeSource::Unix(unix);
        self
    }

    /// Allow this much clock skew on expiry and not-before.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    /// Require the token audience to match `audience` (unbound tokens still pass).
    pub fn audience(mut self, audience: &'a str) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Reject tokens whose `jti` is in the revocation list.
    ///
    /// Tokens without a `jti` fail with [`TokenError::MissingJti`].
    pub fn revocation(mut self, list: &'a RevocationList) -> Self {
        self.revocation = Some(list);
        self
    }

    /// Look up the signing secret from `keyring` by the token's `kid`.
    ///
    /// Overrides the secret passed to [`Verifier::new`].
    pub fn keyring(mut self, keyring: &'a Keyring) -> Self {
        self.keyring = Some(keyring);
        self
    }

    /// Verify MAC, time window, optional audience, and optional revocation.
    pub fn verify(&self, token: &Token) -> Result<(), TokenError> {
        let secret = self.resolve_secret(token)?;
        token.verify_mac_audience(secret, self.now_unix(), self.leeway, self.audience)?;
        self.check_revocation(token)
    }

    /// Verify that `token` authorizes `tool` with the given argument keys.
    pub fn verify_call(
        &self,
        token: &Token,
        tool: &str,
        arg_keys: &[&str],
    ) -> Result<(), TokenError> {
        self.verify(token)?;
        token.check_call_keys(tool, arg_keys)
    }

    /// Verify a tool call including argument-value constraints.
    pub fn verify_call_with_args(
        &self,
        token: &Token,
        tool: &str,
        args: &BTreeMap<String, String>,
    ) -> Result<(), TokenError> {
        let keys: Vec<&str> = args.keys().map(|s| s.as_str()).collect();
        self.verify_call(token, tool, &keys)?;
        token.check_arg_constraints(args)
    }

    fn now_unix(&self) -> u64 {
        match self.time {
            TimeSource::System => SystemClock.now_unix(),
            TimeSource::Unix(t) => t,
            TimeSource::Clock(clock) => clock.now_unix(),
        }
    }

    fn resolve_secret(&self, token: &Token) -> Result<&'a [u8], TokenError> {
        let Some(keyring) = self.keyring else {
            return Ok(self.secret);
        };
        match token.kid.as_deref() {
            Some(kid) => keyring
                .get_secret(kid)
                .ok_or_else(|| TokenError::UnknownKeyId {
                    kid: kid.to_string(),
                }),
            None => Err(TokenError::MissingKeyId),
        }
    }

    fn check_revocation(&self, token: &Token) -> Result<(), TokenError> {
        let Some(list) = self.revocation else {
            return Ok(());
        };
        match &token.jti {
            Some(jti) => {
                if list.is_revoked(jti) {
                    Err(TokenError::Revoked { jti: jti.clone() })
                } else {
                    Ok(())
                }
            }
            None => Err(TokenError::MissingJti),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::constraint::Constraint;
    use crate::use_store::MemoryUseStore;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";
    const SECRET_2: &[u8] = b"other-secret-key-32-bytes-long!";

    fn basic_token() -> Token {
        Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
        )
    }

    #[test]
    fn verifier_matches_verify_happy_path() {
        let token = basic_token();
        let expected = token.verify(SECRET, 1999999999);
        let got = Verifier::new(SECRET).at(1999999999).verify(&token);
        assert_eq!(got, expected);
        assert!(got.is_ok());
    }

    #[test]
    fn verifier_matches_expired() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1700000000);
        let expected = token.verify(SECRET, 1700000001);
        let got = Verifier::new(SECRET).at(1700000001).verify(&token);
        assert_eq!(got, expected);
        assert_eq!(got, Err(TokenError::Expired));
    }

    #[test]
    fn verifier_matches_nbf() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            None,
        );
        let too_early = token.verify(SECRET, 1_899_999_999);
        let on_time = token.verify(SECRET, 1_900_000_000);
        assert_eq!(
            Verifier::new(SECRET).at(1_899_999_999).verify(&token),
            too_early
        );
        assert_eq!(
            Verifier::new(SECRET).at(1_900_000_000).verify(&token),
            on_time
        );
        assert_eq!(too_early, Err(TokenError::NotYetValid));
        assert!(on_time.is_ok());
    }

    #[test]
    fn verifier_matches_audience() {
        let token = Token::mint_with_audience(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
        );
        let ok = token.verify_with_audience(SECRET, 1999999999, Some("client-abc"));
        let bad = token.verify_with_audience(SECRET, 1999999999, Some("client-xyz"));
        assert_eq!(
            Verifier::new(SECRET)
                .at(1999999999)
                .audience("client-abc")
                .verify(&token),
            ok
        );
        assert_eq!(
            Verifier::new(SECRET)
                .at(1999999999)
                .audience("client-xyz")
                .verify(&token),
            bad
        );
        assert_eq!(bad, Err(TokenError::AudienceMismatch));
    }

    #[test]
    fn verifier_matches_revoked() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );
        let mut list = RevocationList::new();
        assert_eq!(
            Verifier::new(SECRET)
                .at(1999999999)
                .revocation(&list)
                .verify(&token),
            token.verify_with_revocation(SECRET, 1999999999, &list)
        );
        list.revoke(token.jti.clone().unwrap());
        let expected = token.verify_with_revocation(SECRET, 1999999999, &list);
        let got = Verifier::new(SECRET)
            .at(1999999999)
            .revocation(&list)
            .verify(&token);
        assert_eq!(got, expected);
        assert!(matches!(got, Err(TokenError::Revoked { .. })));
    }

    #[test]
    fn verifier_matches_constraints() {
        let mut constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );
        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let mut good = BTreeMap::new();
        good.insert("path".to_string(), "/tmp/a.txt".to_string());
        good.insert("limit".to_string(), "50".to_string());
        let mut bad = BTreeMap::new();
        bad.insert("path".to_string(), "/etc/passwd".to_string());
        bad.insert("limit".to_string(), "50".to_string());

        assert_eq!(
            Verifier::new(SECRET)
                .at(1999999999)
                .verify_call_with_args(&token, "read_file", &good),
            token.verify_call_with_args(SECRET, 1999999999, "read_file", &good, None)
        );
        assert_eq!(
            Verifier::new(SECRET)
                .at(1999999999)
                .verify_call_with_args(&token, "read_file", &bad),
            token.verify_call_with_args(SECRET, 1999999999, "read_file", &bad, None)
        );
    }

    #[test]
    fn verifier_matches_keyring() {
        let mut keyring = Keyring::new();
        keyring.add("key-1", SECRET.to_vec());
        let token = keyring
            .mint("read_file", vec!["path".into()], 2000000000)
            .unwrap();

        assert_eq!(
            Verifier::new(SECRET_2)
                .keyring(&keyring)
                .at(1999999999)
                .verify(&token),
            keyring.verify(&token, 1999999999)
        );

        keyring.retire("key-1");
        assert_eq!(
            Verifier::new(SECRET_2)
                .keyring(&keyring)
                .at(1999999999)
                .verify(&token),
            keyring.verify(&token, 1999999999)
        );
    }

    #[test]
    fn verifier_clock_and_leeway_match_legacy() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 1000);
        let clock = FixedClock::at(1010);
        assert_eq!(
            Verifier::new(SECRET)
                .clock(&clock)
                .leeway(Duration::from_secs(30))
                .verify(&token),
            token.verify_with_clock(SECRET, &clock, Duration::from_secs(30))
        );
        assert_eq!(
            Verifier::new(SECRET)
                .clock(&clock)
                .leeway(Duration::ZERO)
                .verify(&token),
            token.verify_with_clock(SECRET, &clock, Duration::ZERO)
        );
    }

    #[test]
    fn verifier_verify_call_matches_legacy() {
        let token = basic_token();
        assert_eq!(
            Verifier::new(SECRET)
                .at(1999999999)
                .verify_call(&token, "read_file", &["path"]),
            token.verify_call(SECRET, 1999999999, "read_file", &["path"], None)
        );
        assert_eq!(
            Verifier::new(SECRET)
                .at(1999999999)
                .verify_call(&token, "write_file", &["path"]),
            token.verify_call(SECRET, 1999999999, "write_file", &["path"], None)
        );
        assert_eq!(
            Verifier::new(SECRET).at(1999999999).verify_call(
                &token,
                "read_file",
                &["path", "extra"]
            ),
            token.verify_call(SECRET, 1999999999, "read_file", &["path", "extra"], None)
        );
    }

    #[test]
    fn verifier_does_not_consume_use_store() {
        // UseStore remains on the existing Token methods.
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );
        let mut store = MemoryUseStore::new();
        assert!(Verifier::new(SECRET).at(1999999999).verify(&token).is_ok());
        assert!(token
            .verify_single_use(SECRET, 1999999999, &mut store)
            .is_ok());
        assert!(matches!(
            token.verify_single_use(SECRET, 1999999999, &mut store),
            Err(TokenError::ReplayDetected { .. })
        ));
    }
}
