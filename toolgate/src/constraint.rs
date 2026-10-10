//! Argument value constraints for capability tokens.
//!
//! Constraints allow tokens to restrict not just which argument keys are allowed,
//! but also what values those arguments may have.

use std::collections::BTreeMap;

/// A constraint on an argument's value.
///
/// When a token has a constraint attached to an argument key, any call using
/// that key must provide a value that satisfies the constraint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Constraint {
    /// Value must match exactly.
    Exact(String),
    /// Value must be one of the specified values.
    #[serde(rename = "one_of")]
    OneOf(Vec<String>),
    /// Value must start with the given prefix.
    Prefix(String),
    /// Value must have at most this many bytes (UTF-8 length).
    #[serde(rename = "max_len")]
    MaxLen(usize),
    /// Value must be a parseable integer in the given range (inclusive).
    #[serde(rename = "int_range")]
    IntRange { min: i64, max: i64 },
    /// Value must end with the given suffix.
    Suffix(String),
    /// Value must contain the given UTF-8 substring.
    Contains(String),
    /// Value must have at least this many bytes (UTF-8 length).
    ///
    /// `MinLen(0)` is valid and accepts every value, including the empty string.
    #[serde(rename = "min_len")]
    MinLen(usize),
    /// Value must match a simple glob over Unicode scalars.
    ///
    /// Only `*` (any sequence, including empty) and `?` (exactly one scalar)
    /// are special. Every other character, including `.` `[` `]`, is literal.
    /// An empty pattern is rejected at mint/validate and never matches.
    Matches(String),
    /// Value must not equal the forbidden string (byte/UTF-8 exact).
    #[serde(rename = "not_equals")]
    NotEquals(String),
    /// Value must not be any of the forbidden values.
    ///
    /// Stored and encoded as sorted unique strings, the same spirit as [`OneOf`].
    /// An empty denylist is rejected at mint/validate and never matches.
    #[serde(rename = "not_one_of")]
    NotOneOf(Vec<String>),
}

impl Constraint {
    /// Check if a value satisfies this constraint.
    pub fn check(&self, value: &str) -> bool {
        match self {
            Constraint::Exact(expected) => value == expected,
            Constraint::OneOf(allowed) => allowed.iter().any(|s| s == value),
            Constraint::Prefix(prefix) => value.starts_with(prefix),
            Constraint::MaxLen(max) => value.len() <= *max,
            Constraint::IntRange { min, max } => {
                if let Ok(n) = value.parse::<i64>() {
                    n >= *min && n <= *max
                } else {
                    false
                }
            }
            // Empty suffix/contains would match every string; fail closed.
            Constraint::Suffix(suffix) => !suffix.is_empty() && value.ends_with(suffix),
            Constraint::Contains(needle) => !needle.is_empty() && value.contains(needle),
            Constraint::MinLen(min) => value.len() >= *min,
            // Empty glob would be a wildcard; fail closed, same as Suffix/Contains.
            Constraint::Matches(pattern) => !pattern.is_empty() && glob_match(pattern, value),
            Constraint::NotEquals(forbidden) => value != forbidden,
            // Empty denylist would forbid nothing; fail closed.
            Constraint::NotOneOf(denied) => !denied.is_empty() && denied.iter().all(|s| s != value),
        }
    }

    /// Empty suffix/contains/matches needles and empty NotOneOf denylists
    /// match nothing and must not be treated as wildcards.
    pub fn is_empty_pattern(&self) -> bool {
        match self {
            Constraint::Suffix(value)
            | Constraint::Contains(value)
            | Constraint::Matches(value) => value.is_empty(),
            Constraint::NotOneOf(denied) => denied.is_empty(),
            _ => false,
        }
    }

    /// Check if `self` is at least as restrictive as `other`.
    ///
    /// Returns `true` if any value satisfying `self` would also satisfy `other`.
    /// This is used during attenuation to ensure constraints only become tighter.
    pub fn is_subset_of(&self, other: &Constraint) -> bool {
        match (self, other) {
            // Exact is subset of Exact only if they match
            (Constraint::Exact(a), Constraint::Exact(b)) => a == b,

            // Exact is subset of OneOf if the value is in the list
            (Constraint::Exact(a), Constraint::OneOf(allowed)) => allowed.contains(a),

            // Exact is subset of Prefix if the value starts with the prefix
            (Constraint::Exact(a), Constraint::Prefix(prefix)) => a.starts_with(prefix),

            // Exact is subset of MaxLen if the value length is within bounds
            (Constraint::Exact(a), Constraint::MaxLen(max)) => a.len() <= *max,

            // Exact is subset of MinLen if the value length meets the minimum
            (Constraint::Exact(a), Constraint::MinLen(min)) => a.len() >= *min,

            // Exact is subset of Matches if the exact value satisfies the glob
            (Constraint::Exact(a), Constraint::Matches(pattern)) => glob_match(pattern, a),

            // Exact is subset of IntRange if the value parses and is in range
            (Constraint::Exact(a), Constraint::IntRange { min, max }) => {
                if let Ok(n) = a.parse::<i64>() {
                    n >= *min && n <= *max
                } else {
                    false
                }
            }

            // Exact is subset of Suffix if the value ends with the suffix
            (Constraint::Exact(a), Constraint::Suffix(suffix)) => {
                !suffix.is_empty() && a.ends_with(suffix)
            }

            // Exact is subset of Contains if the value contains the needle
            (Constraint::Exact(a), Constraint::Contains(needle)) => {
                !needle.is_empty() && a.contains(needle)
            }

            // Exact is subset of NotEquals if the exact value is not forbidden
            (Constraint::Exact(a), Constraint::NotEquals(forbidden)) => a != forbidden,

            // Exact is subset of NotOneOf if the exact value is not in the denylist
            (Constraint::Exact(a), Constraint::NotOneOf(denied)) => {
                !denied.is_empty() && !denied.contains(a)
            }

            // OneOf is subset of OneOf if new set is subset of old set
            (Constraint::OneOf(new), Constraint::OneOf(old)) => new.iter().all(|v| old.contains(v)),

            // OneOf is subset of Prefix if all values start with the prefix
            (Constraint::OneOf(values), Constraint::Prefix(prefix)) => {
                values.iter().all(|v| v.starts_with(prefix))
            }

            // OneOf is subset of MaxLen if all values are within bounds
            (Constraint::OneOf(values), Constraint::MaxLen(max)) => {
                values.iter().all(|v| v.len() <= *max)
            }

            // OneOf is subset of MinLen if all values meet the minimum
            (Constraint::OneOf(values), Constraint::MinLen(min)) => {
                values.iter().all(|v| v.len() >= *min)
            }

            // OneOf is subset of IntRange if all values parse and are in range
            (Constraint::OneOf(values), Constraint::IntRange { min, max }) => {
                values.iter().all(|v| {
                    if let Ok(n) = v.parse::<i64>() {
                        n >= *min && n <= *max
                    } else {
                        false
                    }
                })
            }

            // OneOf is subset of Suffix if every allowed value ends with the suffix
            (Constraint::OneOf(values), Constraint::Suffix(suffix)) => {
                !suffix.is_empty() && values.iter().all(|v| v.ends_with(suffix))
            }

            // OneOf is subset of Contains if every allowed value contains the needle
            (Constraint::OneOf(values), Constraint::Contains(needle)) => {
                !needle.is_empty() && values.iter().all(|v| v.contains(needle))
            }

            // Prefix is subset of Prefix if new prefix starts with (extends) old prefix
            (Constraint::Prefix(new), Constraint::Prefix(old)) => new.starts_with(old),

            // Prefix is subset of Contains if every value with that prefix contains the needle
            (Constraint::Prefix(prefix), Constraint::Contains(needle)) => {
                !needle.is_empty() && prefix.contains(needle)
            }

            // Prefix is subset of MaxLen if... well, prefix doesn't constrain length
            // Any prefix could have values exceeding max, so this is NOT a subset
            (Constraint::Prefix(_), Constraint::MaxLen(_)) => false,

            // MaxLen is subset of MaxLen if new max <= old max
            (Constraint::MaxLen(new), Constraint::MaxLen(old)) => new <= old,

            // MinLen is subset of MinLen if new min >= old min (raise only)
            (Constraint::MinLen(new), Constraint::MinLen(old)) => new >= old,

            // Matches→Matches only allows an identical pattern. Narrowing to
            // Exact is the supported tightening path.
            (Constraint::Matches(new), Constraint::Matches(old)) => {
                !new.is_empty() && !old.is_empty() && new == old
            }

            // MaxLen is NOT a subset of Prefix (can have values not starting with prefix)
            (Constraint::MaxLen(_), Constraint::Prefix(_)) => false,

            // IntRange is subset of IntRange if new range is within old range
            (
                Constraint::IntRange {
                    min: new_min,
                    max: new_max,
                },
                Constraint::IntRange {
                    min: old_min,
                    max: old_max,
                },
            ) => new_min >= old_min && new_max <= old_max,

            // IntRange to MaxLen: all integers in range must fit in max length
            (Constraint::IntRange { min, max }, Constraint::MaxLen(max_len)) => {
                let min_str = min.to_string();
                let max_str = max.to_string();
                min_str.len() <= *max_len && max_str.len() <= *max_len
            }

            // Cross-type comparisons that don't make sense as subsets
            (Constraint::OneOf(_), Constraint::Exact(_)) => false,
            (Constraint::Prefix(_), Constraint::Exact(_)) => false,
            (Constraint::Prefix(_), Constraint::OneOf(_)) => false,
            (Constraint::Prefix(_), Constraint::IntRange { .. }) => false,
            (Constraint::MaxLen(_), Constraint::Exact(_)) => false,
            (Constraint::MaxLen(_), Constraint::OneOf(_)) => false,
            (Constraint::MaxLen(_), Constraint::IntRange { .. }) => false,
            (Constraint::IntRange { .. }, Constraint::Exact(_)) => false,
            (Constraint::IntRange { .. }, Constraint::OneOf(_)) => false,
            (Constraint::IntRange { .. }, Constraint::Prefix(_)) => false,

            // Suffix is subset of Suffix if new suffix ends with (extends) old suffix
            (Constraint::Suffix(new), Constraint::Suffix(old)) => {
                !new.is_empty() && !old.is_empty() && new.ends_with(old)
            }

            // Suffix is subset of Contains if every value with that suffix contains the needle
            (Constraint::Suffix(suffix), Constraint::Contains(needle)) => {
                !needle.is_empty() && suffix.contains(needle)
            }

            // Contains is subset of Contains if new needle contains (specializes) old needle
            (Constraint::Contains(new), Constraint::Contains(old)) => {
                !new.is_empty() && !old.is_empty() && new.contains(old)
            }

            // NotEquals → NotEquals only if the forbidden value is unchanged
            (Constraint::NotEquals(new), Constraint::NotEquals(old)) => new == old,

            // NotEquals may become NotOneOf when the new denylist still forbids that value
            (Constraint::NotOneOf(new), Constraint::NotEquals(old)) => {
                !new.is_empty() && new.contains(old)
            }

            // NotOneOf → NotOneOf only if the new denylist is a superset (more denials)
            (Constraint::NotOneOf(new), Constraint::NotOneOf(old)) => {
                !new.is_empty() && !old.is_empty() && old.iter().all(|v| new.contains(v))
            }

            // Remaining cross-type pairs cannot be shown to be subsets
            _ => false,
        }
    }
}

/// Simple glob over Unicode scalars. `*` matches any sequence (including
/// empty); `?` matches exactly one scalar; every other pattern character
/// matches itself. An empty pattern never matches.
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let pat: Vec<char> = pattern.chars().collect();
    let val: Vec<char> = value.chars().collect();
    let (n, m) = (pat.len(), val.len());
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[0][0] = true;
    for i in 1..=n {
        if pat[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        } else {
            break;
        }
    }
    for i in 1..=n {
        for j in 1..=m {
            dp[i][j] = match pat[i - 1] {
                '*' => dp[i][j - 1] || dp[i - 1][j],
                '?' => dp[i - 1][j - 1],
                c => c == val[j - 1] && dp[i - 1][j - 1],
            };
        }
    }
    dp[n][m]
}

/// A map from argument keys to their constraints.
pub type Constraints = BTreeMap<String, Constraint>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_check() {
        let c = Constraint::Exact("foo".to_string());
        assert!(c.check("foo"));
        assert!(!c.check("bar"));
        assert!(!c.check("foobar"));
    }

    #[test]
    fn oneof_check() {
        let c = Constraint::OneOf(vec!["read".to_string(), "list".to_string()]);
        assert!(c.check("read"));
        assert!(c.check("list"));
        assert!(!c.check("write"));
    }

    #[test]
    fn prefix_check() {
        let c = Constraint::Prefix("/tmp/".to_string());
        assert!(c.check("/tmp/foo"));
        assert!(c.check("/tmp/"));
        assert!(!c.check("/var/tmp"));
        assert!(!c.check("tmp/"));
    }

    #[test]
    fn maxlen_check() {
        let c = Constraint::MaxLen(5);
        assert!(c.check("hello"));
        assert!(c.check("hi"));
        assert!(c.check(""));
        assert!(!c.check("hello!"));
    }

    #[test]
    fn minlen_check() {
        let c = Constraint::MinLen(5);
        assert!(c.check("hello"));
        assert!(c.check("hello!"));
        assert!(!c.check("hi"));
        assert!(!c.check(""));
    }

    #[test]
    fn minlen_zero_allows_empty() {
        let c = Constraint::MinLen(0);
        assert!(c.check(""));
        assert!(c.check("x"));
        assert!(c.check("hello"));
    }

    #[test]
    fn minlen_uses_byte_length() {
        // "é" is one Unicode scalar and two UTF-8 bytes.
        let c = Constraint::MinLen(2);
        assert!(c.check("é"));
        assert!(!Constraint::MinLen(3).check("é"));
    }

    #[test]
    fn intrange_check() {
        let c = Constraint::IntRange { min: 1, max: 100 };
        assert!(c.check("1"));
        assert!(c.check("50"));
        assert!(c.check("100"));
        assert!(!c.check("0"));
        assert!(!c.check("101"));
        assert!(!c.check("-1"));
        assert!(!c.check("abc"));
        assert!(!c.check("10.5"));
    }

    #[test]
    fn suffix_check() {
        let c = Constraint::Suffix(".txt".to_string());
        assert!(c.check("notes.txt"));
        assert!(c.check(".txt"));
        assert!(!c.check("notes.txt.bak"));
        assert!(!c.check("txt"));
        assert!(!c.check(""));
    }

    #[test]
    fn contains_check() {
        let c = Constraint::Contains("tmp".to_string());
        assert!(c.check("/tmp/file"));
        assert!(c.check("tmp"));
        assert!(c.check("atmpb"));
        assert!(!c.check("/var/file"));
        assert!(!c.check("TMP"));
        assert!(!c.check(""));
    }

    #[test]
    fn empty_suffix_and_contains_fail_closed() {
        let suffix = Constraint::Suffix(String::new());
        let contains = Constraint::Contains(String::new());
        assert!(!suffix.check(""));
        assert!(!suffix.check("anything"));
        assert!(!contains.check(""));
        assert!(!contains.check("anything"));
    }

    #[test]
    fn matches_star_and_question() {
        let c = Constraint::Matches("*.txt".to_string());
        assert!(c.check("notes.txt"));
        assert!(c.check(".txt"));
        assert!(c.check("a.txt"));
        assert!(!c.check("notes.txt.bak"));
        assert!(!c.check("txt"));
        assert!(!c.check(""));

        let q = Constraint::Matches("file?.rs".to_string());
        assert!(q.check("file1.rs"));
        assert!(q.check("filex.rs"));
        assert!(!q.check("file.rs"));
        assert!(!q.check("file12.rs"));
    }

    #[test]
    fn matches_literals_are_not_regex() {
        let dot = Constraint::Matches("a.b".to_string());
        assert!(dot.check("a.b"));
        assert!(!dot.check("axb"));
        assert!(!dot.check("ab"));

        let class = Constraint::Matches("a[bc]".to_string());
        assert!(class.check("a[bc]"));
        assert!(!class.check("ab"));
        assert!(!class.check("ac"));
    }

    #[test]
    fn matches_unicode_scalars() {
        let star = Constraint::Matches("*".to_string());
        assert!(star.check("日本語"));
        assert!(star.check(""));

        let one = Constraint::Matches("?".to_string());
        assert!(one.check("漢"));
        assert!(one.check("é"));
        assert!(!one.check(""));
        assert!(!one.check("漢字"));

        let cafe = Constraint::Matches("caf?".to_string());
        assert!(cafe.check("café"));
        assert!(cafe.check("cafe"));
        assert!(!cafe.check("caf"));
        assert!(!cafe.check("cafée"));
    }

    #[test]
    fn empty_matches_fail_closed() {
        let empty = Constraint::Matches(String::new());
        assert!(empty.is_empty_pattern());
        assert!(!empty.check(""));
        assert!(!empty.check("anything"));
        assert!(!empty.check("*"));
    }

    #[test]
    fn not_equals_check() {
        let c = Constraint::NotEquals("admin".to_string());
        assert!(c.check("user"));
        assert!(c.check("Admin"));
        assert!(c.check("admin "));
        assert!(!c.check("admin"));
        assert!(!Constraint::NotEquals(String::new()).check(""));
        assert!(Constraint::NotEquals(String::new()).check("x"));
    }

    #[test]
    fn not_one_of_check() {
        let c = Constraint::NotOneOf(vec!["admin".to_string(), "root".to_string()]);
        assert!(c.check("user"));
        assert!(c.check("Admin"));
        assert!(!c.check("admin"));
        assert!(!c.check("root"));
    }

    #[test]
    fn empty_not_one_of_fail_closed() {
        let empty = Constraint::NotOneOf(vec![]);
        assert!(empty.is_empty_pattern());
        assert!(!empty.check(""));
        assert!(!empty.check("anything"));
        assert!(!empty.check("admin"));
    }

    #[test]
    fn exact_subset_of_exact() {
        let a = Constraint::Exact("foo".to_string());
        let b = Constraint::Exact("foo".to_string());
        let c = Constraint::Exact("bar".to_string());
        assert!(a.is_subset_of(&b));
        assert!(!a.is_subset_of(&c));
    }

    #[test]
    fn exact_subset_of_oneof() {
        let exact = Constraint::Exact("read".to_string());
        let oneof = Constraint::OneOf(vec!["read".to_string(), "write".to_string()]);
        let oneof2 = Constraint::OneOf(vec!["write".to_string()]);
        assert!(exact.is_subset_of(&oneof));
        assert!(!exact.is_subset_of(&oneof2));
    }

    #[test]
    fn exact_subset_of_prefix() {
        let exact = Constraint::Exact("/tmp/foo".to_string());
        let prefix = Constraint::Prefix("/tmp/".to_string());
        let prefix2 = Constraint::Prefix("/var/".to_string());
        assert!(exact.is_subset_of(&prefix));
        assert!(!exact.is_subset_of(&prefix2));
    }

    #[test]
    fn oneof_subset_of_oneof() {
        let small = Constraint::OneOf(vec!["read".to_string()]);
        let large = Constraint::OneOf(vec!["read".to_string(), "write".to_string()]);
        assert!(small.is_subset_of(&large));
        assert!(!large.is_subset_of(&small));
    }

    #[test]
    fn prefix_subset_of_prefix() {
        let long = Constraint::Prefix("/tmp/subdir/".to_string());
        let short = Constraint::Prefix("/tmp/".to_string());
        assert!(long.is_subset_of(&short));
        assert!(!short.is_subset_of(&long));
    }

    #[test]
    fn exact_subset_of_suffix_and_contains() {
        let exact = Constraint::Exact("report.txt".to_string());
        let suffix = Constraint::Suffix(".txt".to_string());
        let contains = Constraint::Contains("port".to_string());
        assert!(exact.is_subset_of(&suffix));
        assert!(exact.is_subset_of(&contains));
        assert!(!exact.is_subset_of(&Constraint::Suffix(".pdf".to_string())));
        assert!(!exact.is_subset_of(&Constraint::Contains("csv".to_string())));
        assert!(!Constraint::Exact("notes.txt".to_string())
            .is_subset_of(&Constraint::Suffix(String::new())));
        assert!(!Constraint::Exact("notes.txt".to_string())
            .is_subset_of(&Constraint::Contains(String::new())));
    }

    #[test]
    fn suffix_subset_of_suffix() {
        let long = Constraint::Suffix("/public.txt".to_string());
        let short = Constraint::Suffix(".txt".to_string());
        assert!(long.is_subset_of(&short));
        assert!(!short.is_subset_of(&long));
        assert!(!Constraint::Suffix(String::new()).is_subset_of(&short));
        assert!(!long.is_subset_of(&Constraint::Suffix(String::new())));
    }

    #[test]
    fn contains_subset_of_contains() {
        let specific = Constraint::Contains("tmp/public".to_string());
        let general = Constraint::Contains("tmp".to_string());
        assert!(specific.is_subset_of(&general));
        assert!(!general.is_subset_of(&specific));
        assert!(!Constraint::Contains(String::new()).is_subset_of(&general));
        assert!(!specific.is_subset_of(&Constraint::Contains(String::new())));
    }

    #[test]
    fn prefix_and_suffix_subset_of_contains() {
        let prefix = Constraint::Prefix("/tmp/".to_string());
        let suffix = Constraint::Suffix("/tmp/out".to_string());
        let needle = Constraint::Contains("tmp".to_string());
        assert!(prefix.is_subset_of(&needle));
        assert!(suffix.is_subset_of(&needle));
        assert!(!prefix.is_subset_of(&Constraint::Contains("var".to_string())));
        assert!(!Constraint::Contains("tmp".to_string()).is_subset_of(&prefix));
        assert!(!Constraint::Contains("out".to_string()).is_subset_of(&suffix));
    }

    #[test]
    fn maxlen_subset_of_maxlen() {
        let small = Constraint::MaxLen(5);
        let large = Constraint::MaxLen(10);
        assert!(small.is_subset_of(&large));
        assert!(!large.is_subset_of(&small));
    }

    #[test]
    fn minlen_subset_of_minlen() {
        let higher = Constraint::MinLen(8);
        let lower = Constraint::MinLen(3);
        assert!(higher.is_subset_of(&lower));
        assert!(!lower.is_subset_of(&higher));
        assert!(Constraint::MinLen(0).is_subset_of(&Constraint::MinLen(0)));
    }

    #[test]
    fn exact_subset_of_minlen() {
        let exact = Constraint::Exact("hello".to_string());
        assert!(exact.is_subset_of(&Constraint::MinLen(5)));
        assert!(exact.is_subset_of(&Constraint::MinLen(0)));
        assert!(!exact.is_subset_of(&Constraint::MinLen(6)));
        assert!(Constraint::Exact(String::new()).is_subset_of(&Constraint::MinLen(0)));
        assert!(!Constraint::Exact(String::new()).is_subset_of(&Constraint::MinLen(1)));
    }

    #[test]
    fn matches_subset_of_matches_only_identical() {
        let glob = Constraint::Matches("*.txt".to_string());
        assert!(glob.is_subset_of(&Constraint::Matches("*.txt".to_string())));
        assert!(!glob.is_subset_of(&Constraint::Matches("*.rs".to_string())));
        assert!(!glob.is_subset_of(&Constraint::Matches("notes.txt".to_string())));
        assert!(!Constraint::Matches("notes.txt".to_string()).is_subset_of(&glob));
        assert!(!Constraint::Matches(String::new()).is_subset_of(&glob));
        assert!(!glob.is_subset_of(&Constraint::Matches(String::new())));
    }

    #[test]
    fn exact_subset_of_matches() {
        let exact = Constraint::Exact("notes.txt".to_string());
        assert!(exact.is_subset_of(&Constraint::Matches("*.txt".to_string())));
        assert!(exact.is_subset_of(&Constraint::Matches("notes.txt".to_string())));
        assert!(!exact.is_subset_of(&Constraint::Matches("*.rs".to_string())));
        assert!(!exact.is_subset_of(&Constraint::Matches(String::new())));
    }

    #[test]
    fn not_equals_subset_of_not_equals() {
        let deny = Constraint::NotEquals("admin".to_string());
        assert!(deny.is_subset_of(&Constraint::NotEquals("admin".to_string())));
        assert!(!deny.is_subset_of(&Constraint::NotEquals("root".to_string())));
    }

    #[test]
    fn not_one_of_may_replace_not_equals() {
        let deny = Constraint::NotEquals("admin".to_string());
        let wider = Constraint::NotOneOf(vec!["admin".to_string(), "root".to_string()]);
        let missing = Constraint::NotOneOf(vec!["root".to_string()]);
        assert!(wider.is_subset_of(&deny));
        assert!(!missing.is_subset_of(&deny));
        assert!(!Constraint::NotOneOf(vec![]).is_subset_of(&deny));
    }

    #[test]
    fn not_one_of_subset_of_not_one_of_is_superset() {
        let small = Constraint::NotOneOf(vec!["admin".to_string()]);
        let large = Constraint::NotOneOf(vec!["admin".to_string(), "root".to_string()]);
        assert!(large.is_subset_of(&small));
        assert!(!small.is_subset_of(&large));
        assert!(!Constraint::NotOneOf(vec![]).is_subset_of(&small));
        assert!(!large.is_subset_of(&Constraint::NotOneOf(vec![])));
    }

    #[test]
    fn exact_subset_of_not_equals_and_not_one_of() {
        let exact = Constraint::Exact("user".to_string());
        assert!(exact.is_subset_of(&Constraint::NotEquals("admin".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotEquals("user".to_string())));
        assert!(exact.is_subset_of(&Constraint::NotOneOf(vec![
            "admin".to_string(),
            "root".to_string()
        ])));
        assert!(!exact.is_subset_of(&Constraint::NotOneOf(vec!["user".to_string()])));
        assert!(!exact.is_subset_of(&Constraint::NotOneOf(vec![])));
    }

    #[test]
    fn intrange_subset_of_intrange() {
        let inner = Constraint::IntRange { min: 10, max: 50 };
        let outer = Constraint::IntRange { min: 1, max: 100 };
        assert!(inner.is_subset_of(&outer));
        assert!(!outer.is_subset_of(&inner));
    }

    // ===== JSON serde tests =====

    #[test]
    fn json_exact() {
        let c = Constraint::Exact("hello".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"exact\""));
        assert!(json.contains("\"value\":\"hello\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn json_oneof() {
        let c = Constraint::OneOf(vec!["a".to_string(), "b".to_string()]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"one_of\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn json_prefix() {
        let c = Constraint::Prefix("/tmp/".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"prefix\""));
        assert!(json.contains("\"value\":\"/tmp/\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn json_maxlen() {
        let c = Constraint::MaxLen(256);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"max_len\""));
        assert!(json.contains("\"value\":256"));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn json_intrange() {
        let c = Constraint::IntRange { min: -10, max: 100 };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"int_range\""));
        assert!(json.contains("\"min\":-10"));
        assert!(json.contains("\"max\":100"));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn json_suffix() {
        let c = Constraint::Suffix(".txt".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"suffix\""));
        assert!(json.contains("\"value\":\".txt\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"suffix","value":".log"}"#).unwrap();
        assert_eq!(from_cli, Constraint::Suffix(".log".to_string()));
    }

    #[test]
    fn json_contains() {
        let c = Constraint::Contains("secret".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"contains\""));
        assert!(json.contains("\"value\":\"secret\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"contains","value":"tmp"}"#).unwrap();
        assert_eq!(from_cli, Constraint::Contains("tmp".to_string()));
    }

    #[test]
    fn json_minlen() {
        let c = Constraint::MinLen(8);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"min_len\""));
        assert!(json.contains("\"value\":8"));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint = serde_json::from_str(r#"{"type":"min_len","value":0}"#).unwrap();
        assert_eq!(from_cli, Constraint::MinLen(0));
    }

    #[test]
    fn json_matches() {
        let c = Constraint::Matches("pat*tern".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"matches\""));
        assert!(json.contains("\"value\":\"pat*tern\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"matches","value":"*.txt"}"#).unwrap();
        assert_eq!(from_cli, Constraint::Matches("*.txt".to_string()));
    }

    #[test]
    fn json_not_equals() {
        let c = Constraint::NotEquals("admin".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"not_equals\""));
        assert!(json.contains("\"value\":\"admin\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"not_equals","value":"root"}"#).unwrap();
        assert_eq!(from_cli, Constraint::NotEquals("root".to_string()));
    }

    #[test]
    fn json_not_one_of() {
        let c = Constraint::NotOneOf(vec!["admin".to_string(), "root".to_string()]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"not_one_of\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"not_one_of","value":["a","b"]}"#).unwrap();
        assert_eq!(
            from_cli,
            Constraint::NotOneOf(vec!["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn json_constraints_map() {
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["r".to_string(), "w".to_string()]),
        );
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let json = serde_json::to_string(&constraints).unwrap();
        let parsed: Constraints = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, constraints);
    }
}
