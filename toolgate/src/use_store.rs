//! Token use-count tracking for replay prevention.
//!
//! The `UseStore` trait defines an interface for tracking how many times a token
//! has been used. Implementations can enforce single-use or max-uses policies
//! to prevent token replay attacks.

use std::collections::HashMap;

/// Result of attempting to consume a token use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseResult {
    /// The use was accepted.
    Accepted,
    /// The token has exceeded its maximum uses.
    Exceeded,
}

/// Trait for tracking token usage counts.
///
/// Implementations track how many times each token (by jti) has been used
/// and can enforce maximum use limits.
pub trait UseStore {
    /// Record a use of the token and check if it's allowed.
    ///
    /// Returns `UseResult::Accepted` if the use is allowed, or
    /// `UseResult::Exceeded` if the token has exceeded its maximum uses.
    ///
    /// The `max_uses` parameter specifies the maximum number of times this
    /// token can be used. A value of 1 means single-use.
    fn try_use(&mut self, jti: &str, max_uses: u64) -> UseResult;

    /// Get the current use count for a token.
    fn get_count(&self, jti: &str) -> u64;

    /// Reset the use count for a token (e.g., for testing).
    fn reset(&mut self, jti: &str);
}

/// In-memory implementation of `UseStore`.
///
/// This is a simple in-process implementation that tracks use counts in a HashMap.
/// Suitable for single-process verification scenarios.
///
/// # Example
///
/// ```
/// use toolgate::use_store::{MemoryUseStore, UseStore, UseResult};
///
/// let mut store = MemoryUseStore::new();
///
/// // Single-use token
/// assert_eq!(store.try_use("token-1", 1), UseResult::Accepted);
/// assert_eq!(store.try_use("token-1", 1), UseResult::Exceeded);
///
/// // Multi-use token (max 3 uses)
/// assert_eq!(store.try_use("token-2", 3), UseResult::Accepted);
/// assert_eq!(store.try_use("token-2", 3), UseResult::Accepted);
/// assert_eq!(store.try_use("token-2", 3), UseResult::Accepted);
/// assert_eq!(store.try_use("token-2", 3), UseResult::Exceeded);
/// ```
#[derive(Debug, Clone, Default)]
pub struct MemoryUseStore {
    counts: HashMap<String, u64>,
}

impl MemoryUseStore {
    /// Create a new empty in-memory use store.
    pub fn new() -> Self {
        MemoryUseStore {
            counts: HashMap::new(),
        }
    }

    /// Clear all use counts.
    pub fn clear(&mut self) {
        self.counts.clear();
    }

    /// Get the number of tracked tokens.
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

impl UseStore for MemoryUseStore {
    fn try_use(&mut self, jti: &str, max_uses: u64) -> UseResult {
        let count = self.counts.entry(jti.to_string()).or_insert(0);
        if *count >= max_uses {
            UseResult::Exceeded
        } else {
            *count += 1;
            UseResult::Accepted
        }
    }

    fn get_count(&self, jti: &str) -> u64 {
        *self.counts.get(jti).unwrap_or(&0)
    }

    fn reset(&mut self, jti: &str) {
        self.counts.remove(jti);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_use_token() {
        let mut store = MemoryUseStore::new();

        assert_eq!(store.try_use("jti-1", 1), UseResult::Accepted);
        assert_eq!(store.get_count("jti-1"), 1);
        assert_eq!(store.try_use("jti-1", 1), UseResult::Exceeded);
        assert_eq!(store.get_count("jti-1"), 1); // Count not incremented on failure
    }

    #[test]
    fn multi_use_token() {
        let mut store = MemoryUseStore::new();

        assert_eq!(store.try_use("jti-1", 3), UseResult::Accepted);
        assert_eq!(store.try_use("jti-1", 3), UseResult::Accepted);
        assert_eq!(store.try_use("jti-1", 3), UseResult::Accepted);
        assert_eq!(store.get_count("jti-1"), 3);
        assert_eq!(store.try_use("jti-1", 3), UseResult::Exceeded);
    }

    #[test]
    fn independent_tokens() {
        let mut store = MemoryUseStore::new();

        assert_eq!(store.try_use("jti-1", 1), UseResult::Accepted);
        assert_eq!(store.try_use("jti-2", 1), UseResult::Accepted);
        assert_eq!(store.try_use("jti-1", 1), UseResult::Exceeded);
        assert_eq!(store.try_use("jti-2", 1), UseResult::Exceeded);
    }

    #[test]
    fn reset_count() {
        let mut store = MemoryUseStore::new();

        assert_eq!(store.try_use("jti-1", 1), UseResult::Accepted);
        assert_eq!(store.try_use("jti-1", 1), UseResult::Exceeded);

        store.reset("jti-1");
        assert_eq!(store.get_count("jti-1"), 0);
        assert_eq!(store.try_use("jti-1", 1), UseResult::Accepted);
    }

    #[test]
    fn clear_all() {
        let mut store = MemoryUseStore::new();

        store.try_use("jti-1", 1);
        store.try_use("jti-2", 1);
        assert_eq!(store.len(), 2);

        store.clear();
        assert!(store.is_empty());
        assert_eq!(store.get_count("jti-1"), 0);
    }

    #[test]
    fn unknown_token_count_is_zero() {
        let store = MemoryUseStore::new();
        assert_eq!(store.get_count("unknown"), 0);
    }
}
