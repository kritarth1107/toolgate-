//! Swappable clocks for token expiry and not-before checks.
//!
//! Library verification paths take a [`Clock`] (or a unix timestamp that is
//! wrapped in [`FixedClock`]) instead of calling `SystemTime::now()` directly.
//! Tests can inject [`FixedClock`] or [`InstantClock`].

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// A source of unix timestamps (seconds since the epoch).
pub trait Clock {
    /// Current unix time in seconds.
    fn now_unix(&self) -> u64;
}

/// Wall-clock time from `SystemTime`.
///
/// Prefer injecting this (or a test clock) rather than calling `SystemTime`
/// from verification logic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before the unix epoch")
            .as_secs()
    }
}

/// A clock that always reports a fixed unix timestamp.
///
/// Intended for tests and for wrapping an explicit `current_time` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock {
    now: u64,
}

impl FixedClock {
    /// Create a clock frozen at `now` unix seconds.
    pub fn at(now: u64) -> Self {
        FixedClock { now }
    }

    /// Update the frozen timestamp.
    pub fn set(&mut self, now: u64) {
        self.now = now;
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.now
    }
}

/// A clock that starts at a unix timestamp and advances with [`Instant`].
///
/// Useful when tests need time to move forward from a known origin without
/// depending on the wall clock.
#[derive(Debug, Clone)]
pub struct InstantClock {
    origin: Instant,
    origin_unix: u64,
}

impl InstantClock {
    /// Create a clock that reports `origin_unix` at construction and then
    /// advances with monotonic time.
    pub fn new(origin_unix: u64) -> Self {
        InstantClock {
            origin: Instant::now(),
            origin_unix,
        }
    }
}

impl Clock for InstantClock {
    fn now_unix(&self) -> u64 {
        self.origin_unix
            .saturating_add(self.origin.elapsed().as_secs())
    }
}

/// Clock plus optional clock-skew leeway used during verification.
#[derive(Debug, Clone)]
pub struct VerifyTime<C: Clock> {
    /// Time source consulted for expiry and not-before checks.
    pub clock: C,
    /// Grace period applied to both expiry and not-before.
    pub leeway: Duration,
}

impl VerifyTime<FixedClock> {
    /// Verify at an explicit unix timestamp with no leeway.
    pub fn unix(now: u64) -> Self {
        VerifyTime {
            clock: FixedClock::at(now),
            leeway: Duration::ZERO,
        }
    }

    /// Verify at an explicit unix timestamp with clock-skew leeway.
    pub fn unix_with_leeway(now: u64, leeway: Duration) -> Self {
        VerifyTime {
            clock: FixedClock::at(now),
            leeway,
        }
    }
}

impl VerifyTime<SystemClock> {
    /// Verify using the system wall clock with no leeway.
    pub fn system() -> Self {
        VerifyTime {
            clock: SystemClock,
            leeway: Duration::ZERO,
        }
    }

    /// Verify using the system wall clock with clock-skew leeway.
    pub fn system_with_leeway(leeway: Duration) -> Self {
        VerifyTime {
            clock: SystemClock,
            leeway,
        }
    }
}

impl<C: Clock> VerifyTime<C> {
    /// Bundle a clock with a leeway duration.
    pub fn new(clock: C, leeway: Duration) -> Self {
        VerifyTime { clock, leeway }
    }

    /// Current unix time from the inner clock.
    pub fn now_unix(&self) -> u64 {
        self.clock.now_unix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_returns_set_time() {
        let mut clock = FixedClock::at(1_700_000_000);
        assert_eq!(clock.now_unix(), 1_700_000_000);
        clock.set(1_700_000_100);
        assert_eq!(clock.now_unix(), 1_700_000_100);
    }

    #[test]
    fn instant_clock_starts_at_origin() {
        let clock = InstantClock::new(5_000);
        let now = clock.now_unix();
        assert!(now >= 5_000);
        assert!(now <= 5_000 + 2);
    }

    #[test]
    fn system_clock_is_plausible() {
        let now = SystemClock.now_unix();
        // After 2020-01-01 and well before year 2100.
        assert!(now > 1_577_836_800);
        assert!(now < 4_102_444_800);
    }

    #[test]
    fn verify_time_unix_wraps_fixed_clock() {
        let time = VerifyTime::unix(42);
        assert_eq!(time.now_unix(), 42);
        assert_eq!(time.leeway, Duration::ZERO);

        let time = VerifyTime::unix_with_leeway(42, Duration::from_secs(30));
        assert_eq!(time.now_unix(), 42);
        assert_eq!(time.leeway, Duration::from_secs(30));
    }
}
