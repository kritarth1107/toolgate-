//! Token revocation support.
//!
//! The `RevocationList` type maintains a set of revoked token identifiers (jti values).
//! When verifying tokens, the revocation list can be checked to reject tokens that
//! have been explicitly revoked. A revoked-jti file is one identifier per line;
//! blank lines and `#` comments are ignored.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// A list of revoked token identifiers.
///
/// Tokens with a jti present in the revocation list will be rejected during
/// verification when checked against this list.
///
/// # Example
///
/// ```
/// use toolgate::RevocationList;
///
/// let mut revocation_list = RevocationList::new();
///
/// // Add a revoked token identifier
/// revocation_list.revoke("abc123def456".to_string());
///
/// // Check if a token is revoked
/// assert!(revocation_list.is_revoked("abc123def456"));
/// assert!(!revocation_list.is_revoked("other-token"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct RevocationList {
    revoked: HashSet<String>,
}

impl RevocationList {
    /// Create an empty revocation list.
    pub fn new() -> Self {
        RevocationList {
            revoked: HashSet::new(),
        }
    }

    /// Revoke a token by its jti.
    pub fn revoke(&mut self, jti: String) {
        self.revoked.insert(jti);
    }

    /// Check if a jti is revoked.
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains(jti)
    }

    /// Remove a jti from the revocation list (un-revoke).
    pub fn remove(&mut self, jti: &str) {
        self.revoked.remove(jti);
    }

    /// Get the number of revoked tokens.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Check if the revocation list is empty.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Iterate over all revoked jtis.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.revoked.iter().map(|s| s.as_str())
    }

    /// Clear all revoked tokens.
    pub fn clear(&mut self) {
        self.revoked.clear();
    }

    /// Load revoked identifiers from a file (see [`parse_revoked_jtis`]).
    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Ok(parse_revoked_jtis(&text))
    }
}

/// Parse a revoked-jti file: one token id per line.
///
/// Empty lines and lines whose first non-whitespace character is `#` are ignored.
/// Other lines are trimmed and treated as jti values.
pub fn parse_revoked_jtis(text: &str) -> RevocationList {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                None
            } else {
                Some(line.to_string())
            }
        })
        .collect()
}

/// File-backed [`RevocationList`] that reloads when the file's mtime changes.
///
/// The gate loads this at start and calls [`RevocationFile::reload_if_changed`]
/// before each decision. No watcher thread or extra crate is required.
#[derive(Debug, Clone)]
pub struct RevocationFile {
    path: PathBuf,
    list: RevocationList,
    mtime: Option<SystemTime>,
}

impl RevocationFile {
    /// Read `path` and remember its modification time.
    pub fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let mtime = file_mtime(&path);
        let list = RevocationList::from_file(&path)?;
        Ok(RevocationFile { path, list, mtime })
    }

    /// Path of the revoked-jti file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current in-memory list.
    pub fn list(&self) -> &RevocationList {
        &self.list
    }

    /// Re-read the file when its modification time differs from the last load.
    ///
    /// Returns `true` when the list was replaced.
    pub fn reload_if_changed(&mut self) -> io::Result<bool> {
        let mtime = file_mtime(&self.path);
        if mtime == self.mtime {
            return Ok(false);
        }
        self.list = RevocationList::from_file(&self.path)?;
        self.mtime = mtime;
        Ok(true)
    }
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|meta| meta.modified()).ok()
}

/// Append one jti to a revoked-jti file, creating the file if needed.
pub fn append_revoked_jti(path: impl AsRef<Path>, jti: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{jti}")?;
    Ok(())
}

impl<I: IntoIterator<Item = String>> From<I> for RevocationList {
    fn from(iter: I) -> Self {
        RevocationList {
            revoked: iter.into_iter().collect(),
        }
    }
}

impl FromIterator<String> for RevocationList {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        RevocationList {
            revoked: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_list_is_empty() {
        let list = RevocationList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn revoke_and_check() {
        let mut list = RevocationList::new();
        assert!(!list.is_revoked("abc123"));

        list.revoke("abc123".to_string());
        assert!(list.is_revoked("abc123"));
        assert!(!list.is_revoked("xyz789"));
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn remove_revoked() {
        let mut list = RevocationList::new();
        list.revoke("abc123".to_string());
        assert!(list.is_revoked("abc123"));

        list.remove("abc123");
        assert!(!list.is_revoked("abc123"));
        assert!(list.is_empty());
    }

    #[test]
    fn from_iter() {
        let list: RevocationList = vec!["jti1".to_string(), "jti2".to_string()]
            .into_iter()
            .collect();
        assert!(list.is_revoked("jti1"));
        assert!(list.is_revoked("jti2"));
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn iterate() {
        let mut list = RevocationList::new();
        list.revoke("a".to_string());
        list.revoke("b".to_string());

        let mut jtis: Vec<&str> = list.iter().collect();
        jtis.sort();
        assert_eq!(jtis, vec!["a", "b"]);
    }

    #[test]
    fn clear() {
        let mut list = RevocationList::new();
        list.revoke("a".to_string());
        list.revoke("b".to_string());
        assert_eq!(list.len(), 2);

        list.clear();
        assert!(list.is_empty());
    }

    fn temp_revoked_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "toolgate-revoked-{}-{}-{}.txt",
            std::process::id(),
            name,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn parse_ignores_blank_lines_and_comments() {
        let list = parse_revoked_jtis("# heading\nabc123\n\n  def456  \n# another\nghi789\n");
        assert!(list.is_revoked("abc123"));
        assert!(list.is_revoked("def456"));
        assert!(list.is_revoked("ghi789"));
        assert!(!list.is_revoked("# heading"));
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn from_file_reads_jtis() {
        let path = temp_revoked_path("from-file");
        fs::write(&path, "# revoked\njti-one\n\njti-two\n").unwrap();
        let list = RevocationList::from_file(&path).unwrap();
        assert!(list.is_revoked("jti-one"));
        assert!(list.is_revoked("jti-two"));
        assert_eq!(list.len(), 2);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reload_if_changed_picks_up_new_jti() {
        let path = temp_revoked_path("reload");
        fs::write(&path, "keep-me\n").unwrap();
        let mut file = RevocationFile::load(&path).unwrap();
        assert!(file.list().is_revoked("keep-me"));
        assert!(!file.list().is_revoked("later"));
        assert!(!file.reload_if_changed().unwrap());

        fs::write(&path, "keep-me\nlater\n").unwrap();
        let newer = file
            .mtime
            .unwrap()
            .checked_add(std::time::Duration::from_secs(2))
            .unwrap();
        let handle = fs::File::options().write(true).open(&path).unwrap();
        handle.set_modified(newer).unwrap();
        drop(handle);

        assert!(file.reload_if_changed().unwrap());
        assert!(file.list().is_revoked("keep-me"));
        assert!(file.list().is_revoked("later"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn append_revoked_jti_creates_and_appends() {
        let path = temp_revoked_path("append");
        let _ = fs::remove_file(&path);
        append_revoked_jti(&path, "first").unwrap();
        append_revoked_jti(&path, "second").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, "first\nsecond\n");
        let list = RevocationList::from_file(&path).unwrap();
        assert!(list.is_revoked("first"));
        assert!(list.is_revoked("second"));
        let _ = fs::remove_file(&path);
    }
}
