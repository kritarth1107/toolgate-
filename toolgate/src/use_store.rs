//! Token use-count tracking for replay prevention.
//!
//! The `UseStore` trait defines an interface for tracking how many times a token
//! has been used. Implementations can enforce single-use or max-uses policies
//! to prevent token replay attacks. [`MemoryUseStore`] keeps counts in process;
//! [`FileUseStore`] is the durable, file-backed implementation.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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

    /// Record a use together with the token expiry (unix seconds).
    ///
    /// Persistent stores keep `expiry` so expired entries can be dropped later.
    /// The default implementation ignores expiry and calls [`UseStore::try_use`].
    fn try_use_with_expiry(&mut self, jti: &str, max_uses: u64, expiry: u64) -> UseResult {
        let _ = expiry;
        self.try_use(jti, max_uses)
    }

    /// Get the current use count for a token.
    fn get_count(&self, jti: &str) -> u64;

    /// Reset the use count for a token (e.g., for testing).
    fn reset(&mut self, jti: &str);
}

/// One accepted use recorded by a [`FileUseStore`].
///
/// The log is JSONL: one of these objects per line. `expiry` is the token's
/// unix-second expiry so a later open can drop records that can no longer
/// be presented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseRecord {
    pub jti: String,
    pub expiry: u64,
}

/// Parse one JSONL use-store line into a [`UseRecord`].
pub fn parse_use_record(line: &str) -> Result<UseRecord, serde_json::Error> {
    serde_json::from_str(line.trim())
}

/// Load records from a use-store log.
///
/// A torn or garbage trailing line (typical after a crash mid-write) is
/// skipped and produces one warning on stderr. A bad line anywhere else
/// is a hard error so a corrupt log cannot silently lose earlier uses.
pub fn parse_use_log(text: &str) -> io::Result<Vec<UseRecord>> {
    let mut records = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for (index, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match parse_use_record(line) {
            Ok(record) => records.push(record),
            Err(err) => {
                if index + 1 == lines.len() {
                    let _ = writeln!(io::stderr(), "warning: skipping torn use-store tail: {err}");
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("corrupt use-store record: {err}"),
                    ));
                }
            }
        }
    }
    Ok(records)
}

/// File-backed [`UseStore`].
///
/// Counts are keyed by `jti`. Each accepted use is represented as a
/// [`UseRecord`] so a durable log can rebuild the same counts after a restart.
/// Persistence (load, append, compaction) is layered on this type.
pub struct FileUseStore {
    path: PathBuf,
    counts: HashMap<String, u64>,
    records: Vec<UseRecord>,
}

impl std::fmt::Debug for FileUseStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileUseStore")
            .field("path", &self.path)
            .field("tracked", &self.counts.len())
            .finish()
    }
}

impl FileUseStore {
    /// Create an empty store associated with `path`.
    ///
    /// The file is not read or created until a later open/append step.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileUseStore {
            path: path.into(),
            counts: HashMap::new(),
            records: Vec::new(),
        }
    }

    /// Open `path` and rebuild in-memory counts from existing records.
    ///
    /// A missing file starts empty. A torn or garbage trailing line is
    /// skipped with one stderr warning; other corrupt lines fail the open.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => String::new(),
            Err(err) => return Err(err),
        };
        let records = parse_use_log(&text)?;
        let mut store = FileUseStore {
            path,
            counts: HashMap::new(),
            records,
        };
        store.rebuild_counts();
        Ok(store)
    }

    fn rebuild_counts(&mut self) {
        self.counts.clear();
        for record in &self.records {
            *self.counts.entry(record.jti.clone()).or_insert(0) += 1;
        }
    }

    /// Path this store will persist to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepted-use records currently held in memory.
    pub fn records(&self) -> &[UseRecord] {
        &self.records
    }

    /// Number of distinct tracked token ids.
    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Whether any token id is tracked.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    /// Drop every in-memory count and record.
    pub fn clear(&mut self) {
        self.counts.clear();
        self.records.clear();
    }

    fn accept(&mut self, jti: &str, max_uses: u64, expiry: u64) -> UseResult {
        let count = self.counts.entry(jti.to_string()).or_insert(0);
        if *count >= max_uses {
            UseResult::Exceeded
        } else {
            *count += 1;
            self.records.push(UseRecord {
                jti: jti.to_string(),
                expiry,
            });
            UseResult::Accepted
        }
    }
}

impl UseStore for FileUseStore {
    fn try_use(&mut self, jti: &str, max_uses: u64) -> UseResult {
        self.try_use_with_expiry(jti, max_uses, u64::MAX)
    }

    fn try_use_with_expiry(&mut self, jti: &str, max_uses: u64, expiry: u64) -> UseResult {
        self.accept(jti, max_uses, expiry)
    }

    fn get_count(&self, jti: &str) -> u64 {
        *self.counts.get(jti).unwrap_or(&0)
    }

    fn reset(&mut self, jti: &str) {
        self.counts.remove(jti);
        self.records.retain(|record| record.jti != jti);
    }
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
