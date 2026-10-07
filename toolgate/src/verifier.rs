//! Builder that consolidates the `verify_*` variants on [`Token`] and [`Keyring`].
//!
//! Single-use and max-uses checks stay on [`Token::verify_single_use`] and
//! [`Token::verify_with_max_uses`]. Threading a `&mut impl UseStore` through
//! this builder would force every `Verifier` to be mutably borrowed for
//! otherwise read-only checks.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::clock::{Clock, SystemClock, VerifyTime};
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
        let time = VerifyTime::unix_with_leeway(self.now_unix(), self.leeway);
        token.verify_at(secret, &time, self.audience)?;
        self.check_revocation(token)
    }

    /// Verify that `token` authorizes `tool` with the given argument keys.
    pub fn verify_call(
        &self,
        token: &Token,
        tool: &str,
        arg_keys: &[&str],
    ) -> Result<(), TokenError> {
        let secret = self.resolve_secret(token)?;
        let time = VerifyTime::unix_with_leeway(self.now_unix(), self.leeway);
        token.verify_call_at(secret, &time, tool, arg_keys, self.audience)?;
        self.check_revocation(token)
    }

    /// Verify a tool call including argument-value constraints.
    pub fn verify_call_with_args(
        &self,
        token: &Token,
        tool: &str,
        args: &BTreeMap<String, String>,
    ) -> Result<(), TokenError> {
        let secret = self.resolve_secret(token)?;
        let time = VerifyTime::unix_with_leeway(self.now_unix(), self.leeway);
        token.verify_call_with_args_at(secret, &time, tool, args, self.audience)?;
        self.check_revocation(token)
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
