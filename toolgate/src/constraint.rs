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

            // Remaining cross-type pairs cannot be shown to be subsets
            _ => false,
        }
    }
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
    fn maxlen_subset_of_maxlen() {
        let small = Constraint::MaxLen(5);
        let large = Constraint::MaxLen(10);
        assert!(small.is_subset_of(&large));
        assert!(!large.is_subset_of(&small));
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
