//! Argument value constraints for capability tokens.
//!
//! Constraints allow tokens to restrict not just which argument keys are allowed,
//! but also what values those arguments may have. [`Constraint::All`],
//! [`Constraint::Any`], and [`Constraint::Not`] compose children as AND / OR /
//! NOT. [`Constraint::FloatRange`] restricts a value to a finite inclusive
//! `f64` interval. [`Constraint::LenRange`] restricts a value's byte length
//! to an inclusive `usize` interval. [`Constraint::CharLenRange`] restricts
//! a value's Unicode scalar count (`chars().count()`) to an inclusive
//! `usize` interval. Serde JSON forms are
//! `{"type":"all","value":[...]}`, `{"type":"any","value":[...]}`,
//! `{"type":"not","value":{...}}`,
//! `{"type":"float_range","value":{"min":...,"max":...}}`,
//! `{"type":"len_range","value":{"min":...,"max":...}}`,
//! `{"type":"char_len_range","value":{"min":...,"max":...}}`,
//! `{"type":"prefix_one_of","value":["/tmp/","/var/"]}`,
//! `{"type":"suffix_one_of","value":[".txt",".md"]}`,
//! `{"type":"contains_any","value":["tmp","var"]}`, and
//! `{"type":"contains_none","value":["secret","password"]}`.
//! [`Constraint::PrefixOneOf`] requires the value to start with at least
//! one listed UTF-8 prefix. [`Constraint::SuffixOneOf`] requires the value
//! to end with at least one listed UTF-8 suffix. [`Constraint::ContainsAny`]
//! requires the value to contain at least one listed UTF-8 needle.
//! [`Constraint::ContainsNone`] requires the value to contain none of the
//! listed UTF-8 needles. Empty lists and empty members are rejected at
//! mint/validate and never match (fail closed).

use std::collections::BTreeMap;

/// A constraint on an argument's value.
///
/// When a token has a constraint attached to an argument key, any call using
/// that key must provide a value that satisfies the constraint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// Value must not contain the forbidden UTF-8 substring.
    ///
    /// Same spirit as [`Contains`], inverted. An empty needle is rejected at
    /// mint/validate and never matches a value (fail closed).
    #[serde(rename = "not_contains")]
    NotContains(String),
    /// Value must not start with the forbidden prefix.
    ///
    /// Same spirit as [`Prefix`], inverted. An empty prefix is rejected at
    /// mint/validate and never matches a value (fail closed).
    #[serde(rename = "not_prefix")]
    NotPrefix(String),
    /// Value must not end with the forbidden suffix.
    ///
    /// Same spirit as [`Suffix`], inverted. An empty suffix is rejected at
    /// mint/validate and never matches a value (fail closed).
    #[serde(rename = "not_suffix")]
    NotSuffix(String),
    /// Value must not match a simple glob over Unicode scalars.
    ///
    /// Same glob rules as [`Matches`] (`*` and `?` only; other characters
    /// are literal), inverted. An empty pattern is rejected at mint/validate
    /// and never matches a value (fail closed).
    #[serde(rename = "not_matches")]
    NotMatches(String),
    /// Value must satisfy every child constraint (AND).
    ///
    /// Nested [`All`] / [`Any`] / [`Not`] trees are allowed up to
    /// [`MAX_CONSTRAINT_NESTING`]. An empty `All` is rejected at
    /// mint/validate and never matches a value (fail closed).
    ///
    /// JSON: `{"type":"all","value":[...]}` where each child is an
    /// existing constraint object.
    #[serde(rename = "all")]
    All(Vec<Constraint>),
    /// Value must satisfy at least one child constraint (OR).
    ///
    /// Nested [`All`] / [`Any`] / [`Not`] trees are allowed up to
    /// [`MAX_CONSTRAINT_NESTING`]. An empty `Any` is rejected at
    /// mint/validate and never matches a value (fail closed).
    ///
    /// JSON: `{"type":"any","value":[...]}` where each child is an
    /// existing constraint object.
    #[serde(rename = "any")]
    Any(Vec<Constraint>),
    /// Value must not satisfy the child constraint (NOT).
    ///
    /// Nested [`All`] / [`Any`] / [`Not`] trees are allowed up to
    /// [`MAX_CONSTRAINT_NESTING`]. There is no empty `Not` (always one
    /// child). A `Not` whose child is an empty pattern is rejected at
    /// mint/validate and never matches a value (fail closed).
    ///
    /// JSON: `{"type":"not","value":{...}}` where the child is an
    /// existing constraint object.
    #[serde(rename = "not")]
    Not(Box<Constraint>),
    /// Value must parse as a finite `f64` in the given range (inclusive).
    ///
    /// `min` and `max` must themselves be finite and satisfy `min <= max`;
    /// inverted or non-finite bounds are rejected at mint/validate and
    /// never match a value (fail closed). NaN, ±inf, and non-numeric
    /// strings are rejected at check time.
    #[serde(rename = "float_range")]
    FloatRange { min: f64, max: f64 },
    /// Value byte length must satisfy `min <= len <= max` (inclusive).
    ///
    /// `min` and `max` are UTF-8 byte lengths, the same unit as
    /// [`MaxLen`] and [`MinLen`]. Inverted bounds (`min > max`) are
    /// rejected at mint/validate and never match a value (fail closed).
    /// `LenRange { min: 0, max: N }` is valid and accepts the empty
    /// string when `N` allows it.
    #[serde(rename = "len_range")]
    LenRange { min: usize, max: usize },
    /// Value Unicode scalar count must satisfy `min <= count <= max`
    /// (inclusive).
    ///
    /// Count is `value.chars().count()`, not UTF-8 byte length. That is
    /// a different unit from [`LenRange`], [`MaxLen`], and [`MinLen`].
    /// Inverted bounds (`min > max`) are rejected at mint/validate and
    /// never match a value (fail closed). `CharLenRange { min: 0, max: N }`
    /// is valid and accepts the empty string when `N` allows it.
    #[serde(rename = "char_len_range")]
    CharLenRange { min: usize, max: usize },
    /// Value must start with at least one of the listed UTF-8 prefixes.
    ///
    /// Stored and encoded as sorted unique strings, the same spirit as [`OneOf`].
    /// An empty list is rejected at mint/validate and never matches a
    /// value (fail closed). An empty string in the list is rejected at
    /// mint/validate and never matches (fail closed); an empty prefix
    /// would otherwise be a wildcard.
    ///
    /// JSON: `{"type":"prefix_one_of","value":["/tmp/","/var/"]}`
    #[serde(rename = "prefix_one_of")]
    PrefixOneOf(Vec<String>),
    /// Value must end with at least one of the listed UTF-8 suffixes.
    ///
    /// Stored and encoded as sorted unique strings, the same spirit as [`OneOf`].
    /// An empty list is rejected at mint/validate and never matches a
    /// value (fail closed). An empty string in the list is rejected at
    /// mint/validate and never matches (fail closed), the same spirit
    /// as an empty [`Suffix`].
    ///
    /// JSON: `{"type":"suffix_one_of","value":[".txt",".md"]}`
    #[serde(rename = "suffix_one_of")]
    SuffixOneOf(Vec<String>),
    /// Value must contain at least one of the listed UTF-8 substrings.
    ///
    /// Stored and encoded as sorted unique strings, the same spirit as [`OneOf`].
    /// An empty list is rejected at mint/validate and never matches a
    /// value (fail closed). An empty string in the list is rejected at
    /// mint/validate and never matches (fail closed); an empty needle
    /// would otherwise be a wildcard, the same spirit as [`Contains`].
    ///
    /// JSON: `{"type":"contains_any","value":["tmp","var"]}`
    #[serde(rename = "contains_any")]
    ContainsAny(Vec<String>),
    /// Value must contain none of the listed UTF-8 substrings.
    ///
    /// Stored and encoded as sorted unique strings, the same spirit as [`NotOneOf`].
    /// An empty list is rejected at mint/validate and never matches a
    /// value (fail closed). An empty string in the list is rejected at
    /// mint/validate and never matches (fail closed); an empty needle
    /// would otherwise forbid nothing, the same spirit as [`NotContains`].
    ///
    /// JSON: `{"type":"contains_none","value":["secret","password"]}`
    #[serde(rename = "contains_none")]
    ContainsNone(Vec<String>),
}

impl PartialEq for Constraint {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Constraint::Exact(a), Constraint::Exact(b)) => a == b,
            (Constraint::OneOf(a), Constraint::OneOf(b)) => a == b,
            (Constraint::Prefix(a), Constraint::Prefix(b)) => a == b,
            (Constraint::MaxLen(a), Constraint::MaxLen(b)) => a == b,
            (
                Constraint::IntRange {
                    min: a_min,
                    max: a_max,
                },
                Constraint::IntRange {
                    min: b_min,
                    max: b_max,
                },
            ) => a_min == b_min && a_max == b_max,
            (Constraint::Suffix(a), Constraint::Suffix(b)) => a == b,
            (Constraint::Contains(a), Constraint::Contains(b)) => a == b,
            (Constraint::MinLen(a), Constraint::MinLen(b)) => a == b,
            (Constraint::Matches(a), Constraint::Matches(b)) => a == b,
            (Constraint::NotEquals(a), Constraint::NotEquals(b)) => a == b,
            (Constraint::NotOneOf(a), Constraint::NotOneOf(b)) => a == b,
            (Constraint::NotContains(a), Constraint::NotContains(b)) => a == b,
            (Constraint::NotPrefix(a), Constraint::NotPrefix(b)) => a == b,
            (Constraint::NotSuffix(a), Constraint::NotSuffix(b)) => a == b,
            (Constraint::NotMatches(a), Constraint::NotMatches(b)) => a == b,
            (Constraint::All(a), Constraint::All(b)) => a == b,
            (Constraint::Any(a), Constraint::Any(b)) => a == b,
            (Constraint::Not(a), Constraint::Not(b)) => a == b,
            // Compare IEEE-754 bit patterns so Eq is reflexive even if a
            // non-finite bound is constructed in memory (those values are
            // still rejected at mint/validate).
            (
                Constraint::FloatRange {
                    min: a_min,
                    max: a_max,
                },
                Constraint::FloatRange {
                    min: b_min,
                    max: b_max,
                },
            ) => a_min.to_bits() == b_min.to_bits() && a_max.to_bits() == b_max.to_bits(),
            (
                Constraint::LenRange {
                    min: a_min,
                    max: a_max,
                },
                Constraint::LenRange {
                    min: b_min,
                    max: b_max,
                },
            ) => a_min == b_min && a_max == b_max,
            (
                Constraint::CharLenRange {
                    min: a_min,
                    max: a_max,
                },
                Constraint::CharLenRange {
                    min: b_min,
                    max: b_max,
                },
            ) => a_min == b_min && a_max == b_max,
            (Constraint::PrefixOneOf(a), Constraint::PrefixOneOf(b)) => a == b,
            (Constraint::SuffixOneOf(a), Constraint::SuffixOneOf(b)) => a == b,
            (Constraint::ContainsAny(a), Constraint::ContainsAny(b)) => a == b,
            (Constraint::ContainsNone(a), Constraint::ContainsNone(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Constraint {}

/// Maximum nesting depth of [`Constraint::All`] / [`Constraint::Any`] /
/// [`Constraint::Not`] trees.
///
/// Depth is 1 for a single composite wrapping atomic constraints, and
/// increases by one for each nested All/Any/Not. Trees deeper than this
/// are rejected at mint/validate to avoid pathological compositions.
pub const MAX_CONSTRAINT_NESTING: usize = 8;

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
            // Empty needle would forbid nothing; fail closed, same as Contains.
            Constraint::NotContains(needle) => !needle.is_empty() && !value.contains(needle),
            // Empty prefix would forbid nothing; fail closed, same as Prefix inverted.
            Constraint::NotPrefix(prefix) => !prefix.is_empty() && !value.starts_with(prefix),
            // Empty suffix would forbid nothing; fail closed, same as Suffix inverted.
            Constraint::NotSuffix(suffix) => !suffix.is_empty() && !value.ends_with(suffix),
            // Empty glob would forbid nothing; fail closed, same as Matches inverted.
            Constraint::NotMatches(pattern) => !pattern.is_empty() && !glob_match(pattern, value),
            // Empty All/Any would match nothing / everything; fail closed.
            Constraint::All(children) => {
                !children.is_empty() && children.iter().all(|c| c.check(value))
            }
            Constraint::Any(children) => {
                !children.is_empty() && children.iter().any(|c| c.check(value))
            }
            // Empty-pattern children would invert into a wildcard; fail closed.
            Constraint::Not(child) => !child.is_empty_pattern() && !child.check(value),
            // Non-finite bounds or min > max never match; values must parse
            // as a finite f64 inside the inclusive interval.
            Constraint::FloatRange { min, max } => match parse_finite_f64(value) {
                Some(n) if float_range_is_valid(*min, *max) => n >= *min && n <= *max,
                _ => false,
            },
            // Inverted bounds never match; otherwise require min <= len <= max.
            Constraint::LenRange { min, max } => {
                len_range_is_valid(*min, *max) && value.len() >= *min && value.len() <= *max
            }
            // Unicode scalar count, not bytes. Inverted bounds never match.
            Constraint::CharLenRange { min, max } => {
                let count = value.chars().count();
                len_range_is_valid(*min, *max) && count >= *min && count <= *max
            }
            // Empty list or empty member would be a wildcard / match
            // nothing; fail closed, same spirit as Prefix/Suffix.
            Constraint::PrefixOneOf(prefixes) => {
                string_list_is_valid(prefixes) && prefixes.iter().any(|p| value.starts_with(p))
            }
            Constraint::SuffixOneOf(suffixes) => {
                string_list_is_valid(suffixes) && suffixes.iter().any(|s| value.ends_with(s))
            }
            Constraint::ContainsAny(needles) => {
                string_list_is_valid(needles) && needles.iter().any(|n| value.contains(n))
            }
            Constraint::ContainsNone(needles) => {
                string_list_is_valid(needles) && needles.iter().all(|n| !value.contains(n))
            }
        }
    }

    /// Empty suffix/contains/matches/not_contains/not_prefix/not_suffix/
    /// not_matches needles, empty NotOneOf denylists, empty PrefixOneOf,
    /// SuffixOneOf, ContainsAny, or ContainsNone lists (or a list
    /// containing an empty member), empty All/Any composites, and a
    /// `Not` whose child is an empty pattern match nothing and must not
    /// be treated as wildcards. A composite that contains an empty child
    /// is also empty.
    pub fn is_empty_pattern(&self) -> bool {
        match self {
            Constraint::Suffix(value)
            | Constraint::Contains(value)
            | Constraint::Matches(value)
            | Constraint::NotContains(value)
            | Constraint::NotPrefix(value)
            | Constraint::NotSuffix(value)
            | Constraint::NotMatches(value) => value.is_empty(),
            Constraint::NotOneOf(denied) => denied.is_empty(),
            Constraint::PrefixOneOf(values)
            | Constraint::SuffixOneOf(values)
            | Constraint::ContainsAny(values)
            | Constraint::ContainsNone(values) => !string_list_is_valid(values),
            Constraint::All(children) | Constraint::Any(children) => {
                children.is_empty() || children.iter().any(|c| c.is_empty_pattern())
            }
            Constraint::Not(child) => child.is_empty_pattern(),
            _ => false,
        }
    }

    /// True when a [`Constraint::FloatRange`], [`Constraint::LenRange`],
    /// or [`Constraint::CharLenRange`] (or a composite containing one)
    /// has inverted bounds, or when a FloatRange has non-finite bounds.
    /// Rejected at mint/validate and never matches a value (fail closed).
    pub fn is_invalid_range(&self) -> bool {
        match self {
            Constraint::FloatRange { min, max } => !float_range_is_valid(*min, *max),
            Constraint::LenRange { min, max } | Constraint::CharLenRange { min, max } => {
                !len_range_is_valid(*min, *max)
            }
            Constraint::All(children) | Constraint::Any(children) => {
                children.iter().any(Constraint::is_invalid_range)
            }
            Constraint::Not(child) => child.is_invalid_range(),
            _ => false,
        }
    }

    /// Nesting depth of All/Any/Not composition. Atomic constraints are 0.
    pub fn nesting_depth(&self) -> usize {
        match self {
            Constraint::All(children) | Constraint::Any(children) => {
                1 + children
                    .iter()
                    .map(Constraint::nesting_depth)
                    .max()
                    .unwrap_or(0)
            }
            Constraint::Not(child) => 1 + child.nesting_depth(),
            _ => 0,
        }
    }

    /// True when All/Any/Not nesting exceeds [`MAX_CONSTRAINT_NESTING`].
    pub fn exceeds_max_nesting(&self) -> bool {
        self.nesting_depth() > MAX_CONSTRAINT_NESTING
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

            // Exact is subset of FloatRange if the value parses as a finite
            // f64 inside the inclusive interval.
            (Constraint::Exact(a), Constraint::FloatRange { min, max }) => {
                match parse_finite_f64(a) {
                    Some(n) if float_range_is_valid(*min, *max) => n >= *min && n <= *max,
                    _ => false,
                }
            }

            // Exact is subset of LenRange if the value's byte length lies
            // inside the inclusive interval.
            (Constraint::Exact(a), Constraint::LenRange { min, max }) => {
                len_range_is_valid(*min, *max) && a.len() >= *min && a.len() <= *max
            }

            // Exact is subset of CharLenRange if the value's Unicode
            // scalar count lies inside the inclusive interval.
            (Constraint::Exact(a), Constraint::CharLenRange { min, max }) => {
                let count = a.chars().count();
                len_range_is_valid(*min, *max) && count >= *min && count <= *max
            }

            // Exact is subset of PrefixOneOf if the value starts with
            // at least one listed prefix.
            (Constraint::Exact(a), Constraint::PrefixOneOf(prefixes)) => {
                string_list_is_valid(prefixes) && prefixes.iter().any(|p| a.starts_with(p))
            }

            // Exact is subset of SuffixOneOf if the value ends with
            // at least one listed suffix.
            (Constraint::Exact(a), Constraint::SuffixOneOf(suffixes)) => {
                string_list_is_valid(suffixes) && suffixes.iter().any(|s| a.ends_with(s))
            }

            // Exact is subset of ContainsAny if the value contains
            // at least one listed needle.
            (Constraint::Exact(a), Constraint::ContainsAny(needles)) => {
                string_list_is_valid(needles) && needles.iter().any(|n| a.contains(n))
            }

            // Exact is subset of ContainsNone if the value contains
            // none of the listed needles.
            (Constraint::Exact(a), Constraint::ContainsNone(needles)) => {
                string_list_is_valid(needles) && needles.iter().all(|n| !a.contains(n))
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

            // Exact is subset of NotContains if the exact value does not contain the needle
            (Constraint::Exact(a), Constraint::NotContains(needle)) => {
                !needle.is_empty() && !a.contains(needle)
            }

            // Exact is subset of NotPrefix if the exact value does not start with the prefix
            (Constraint::Exact(a), Constraint::NotPrefix(prefix)) => {
                !prefix.is_empty() && !a.starts_with(prefix)
            }

            // Exact is subset of NotSuffix if the exact value does not end with the suffix
            (Constraint::Exact(a), Constraint::NotSuffix(suffix)) => {
                !suffix.is_empty() && !a.ends_with(suffix)
            }

            // Exact is subset of NotMatches if the exact value does not match the glob
            (Constraint::Exact(a), Constraint::NotMatches(pattern)) => {
                !pattern.is_empty() && !glob_match(pattern, a)
            }

            // Exact is subset of All if it satisfies every child
            (Constraint::Exact(a), Constraint::All(children)) => {
                !children.is_empty()
                    && children
                        .iter()
                        .all(|c| Constraint::Exact(a.clone()).is_subset_of(c))
            }

            // Exact is subset of Any if it satisfies at least one child
            (Constraint::Exact(a), Constraint::Any(children)) => {
                !children.is_empty()
                    && children
                        .iter()
                        .any(|c| Constraint::Exact(a.clone()).is_subset_of(c))
            }

            // Exact is subset of Not if the exact value does not satisfy
            // the child. Empty-pattern children fail closed.
            (Constraint::Exact(a), Constraint::Not(child)) => {
                !child.is_empty_pattern() && !Constraint::Exact(a.clone()).is_subset_of(child)
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

            // OneOf is subset of FloatRange if every allowed value parses as
            // a finite f64 inside the inclusive interval.
            (Constraint::OneOf(values), Constraint::FloatRange { min, max }) => {
                float_range_is_valid(*min, *max)
                    && !values.is_empty()
                    && values.iter().all(|v| match parse_finite_f64(v) {
                        Some(n) => n >= *min && n <= *max,
                        None => false,
                    })
            }

            // OneOf is subset of LenRange if every allowed value's length
            // lies inside the inclusive interval.
            (Constraint::OneOf(values), Constraint::LenRange { min, max }) => {
                len_range_is_valid(*min, *max)
                    && !values.is_empty()
                    && values.iter().all(|v| v.len() >= *min && v.len() <= *max)
            }

            // OneOf is subset of CharLenRange if every allowed value's
            // Unicode scalar count lies inside the inclusive interval.
            (Constraint::OneOf(values), Constraint::CharLenRange { min, max }) => {
                len_range_is_valid(*min, *max)
                    && !values.is_empty()
                    && values.iter().all(|v| {
                        let count = v.chars().count();
                        count >= *min && count <= *max
                    })
            }

            // OneOf is subset of PrefixOneOf if every allowed value
            // starts with at least one listed prefix.
            (Constraint::OneOf(values), Constraint::PrefixOneOf(prefixes)) => {
                string_list_is_valid(prefixes)
                    && !values.is_empty()
                    && values
                        .iter()
                        .all(|v| prefixes.iter().any(|p| v.starts_with(p)))
            }

            // OneOf is subset of SuffixOneOf if every allowed value
            // ends with at least one listed suffix.
            (Constraint::OneOf(values), Constraint::SuffixOneOf(suffixes)) => {
                string_list_is_valid(suffixes)
                    && !values.is_empty()
                    && values
                        .iter()
                        .all(|v| suffixes.iter().any(|s| v.ends_with(s)))
            }

            // OneOf is subset of ContainsAny if every allowed value
            // contains at least one listed needle.
            (Constraint::OneOf(values), Constraint::ContainsAny(needles)) => {
                string_list_is_valid(needles)
                    && !values.is_empty()
                    && values.iter().all(|v| needles.iter().any(|n| v.contains(n)))
            }

            // OneOf is subset of ContainsNone if every allowed value
            // avoids every listed needle.
            (Constraint::OneOf(values), Constraint::ContainsNone(needles)) => {
                string_list_is_valid(needles)
                    && !values.is_empty()
                    && values
                        .iter()
                        .all(|v| needles.iter().all(|n| !v.contains(n)))
            }

            // OneOf is subset of Suffix if every allowed value ends with the suffix
            (Constraint::OneOf(values), Constraint::Suffix(suffix)) => {
                !suffix.is_empty() && values.iter().all(|v| v.ends_with(suffix))
            }

            // OneOf is subset of Contains if every allowed value contains the needle
            (Constraint::OneOf(values), Constraint::Contains(needle)) => {
                !needle.is_empty() && values.iter().all(|v| v.contains(needle))
            }

            // OneOf is subset of NotContains if every allowed value avoids the needle
            (Constraint::OneOf(values), Constraint::NotContains(needle)) => {
                !needle.is_empty() && values.iter().all(|v| !v.contains(needle))
            }

            // OneOf is subset of NotPrefix if every allowed value avoids the prefix
            (Constraint::OneOf(values), Constraint::NotPrefix(prefix)) => {
                !prefix.is_empty() && values.iter().all(|v| !v.starts_with(prefix))
            }

            // OneOf is subset of NotSuffix if every allowed value avoids the suffix
            (Constraint::OneOf(values), Constraint::NotSuffix(suffix)) => {
                !suffix.is_empty() && values.iter().all(|v| !v.ends_with(suffix))
            }

            // OneOf is subset of NotMatches if every allowed value avoids the glob
            (Constraint::OneOf(values), Constraint::NotMatches(pattern)) => {
                !pattern.is_empty() && values.iter().all(|v| !glob_match(pattern, v))
            }

            // OneOf is subset of All if every allowed value satisfies every child
            (Constraint::OneOf(values), Constraint::All(children)) => {
                !values.is_empty()
                    && !children.is_empty()
                    && values.iter().all(|v| {
                        children
                            .iter()
                            .all(|c| Constraint::Exact(v.clone()).is_subset_of(c))
                    })
            }

            // OneOf is subset of Any if every allowed value satisfies some child
            (Constraint::OneOf(values), Constraint::Any(children)) => {
                !values.is_empty()
                    && !children.is_empty()
                    && values.iter().all(|v| {
                        children
                            .iter()
                            .any(|c| Constraint::Exact(v.clone()).is_subset_of(c))
                    })
            }

            // OneOf is subset of Not if every allowed value avoids the child
            (Constraint::OneOf(values), Constraint::Not(child)) => {
                !values.is_empty()
                    && !child.is_empty_pattern()
                    && values
                        .iter()
                        .all(|v| !Constraint::Exact(v.clone()).is_subset_of(child))
            }

            // Prefix is subset of Prefix if new prefix starts with (extends) old prefix
            (Constraint::Prefix(new), Constraint::Prefix(old)) => new.starts_with(old),

            // Prefix is subset of PrefixOneOf if it equals or extends
            // some listed parent prefix (no new starting region).
            (Constraint::Prefix(prefix), Constraint::PrefixOneOf(old)) => {
                !prefix.is_empty()
                    && string_list_is_valid(old)
                    && old.iter().any(|p| prefix.starts_with(p))
            }

            // PrefixOneOf may replace Prefix when every child prefix
            // equals or extends the old prefix.
            (Constraint::PrefixOneOf(new), Constraint::Prefix(old)) => {
                !old.is_empty()
                    && string_list_is_valid(new)
                    && new.iter().all(|p| p.starts_with(old))
            }

            // PrefixOneOf → PrefixOneOf: every child prefix must equal
            // some parent prefix or be a strict extension of one.
            // The child may only shrink/narrow the allowed set.
            (Constraint::PrefixOneOf(new), Constraint::PrefixOneOf(old)) => {
                prefix_one_of_tightens(new, old)
            }

            // Prefix is subset of Contains if every value with that prefix contains the needle
            (Constraint::Prefix(prefix), Constraint::Contains(needle)) => {
                !needle.is_empty() && prefix.contains(needle)
            }

            // PrefixOneOf is subset of Contains if every listed prefix
            // already contains the needle.
            (Constraint::PrefixOneOf(prefixes), Constraint::Contains(needle)) => {
                string_list_is_valid(prefixes)
                    && !needle.is_empty()
                    && prefixes.iter().all(|p| p.contains(needle))
            }

            // Prefix is subset of ContainsAny if the prefix already
            // contains at least one listed needle.
            (Constraint::Prefix(prefix), Constraint::ContainsAny(needles)) => {
                !prefix.is_empty()
                    && string_list_is_valid(needles)
                    && needles.iter().any(|n| prefix.contains(n))
            }

            // PrefixOneOf is subset of ContainsAny if every listed prefix
            // already contains at least one listed needle.
            (Constraint::PrefixOneOf(prefixes), Constraint::ContainsAny(needles)) => {
                string_list_is_valid(prefixes)
                    && string_list_is_valid(needles)
                    && prefixes
                        .iter()
                        .all(|p| needles.iter().any(|n| p.contains(n)))
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

            // FloatRange is subset of FloatRange if the new interval is
            // within the old one. Invalid (non-finite or inverted) bounds
            // fail closed.
            (
                Constraint::FloatRange {
                    min: new_min,
                    max: new_max,
                },
                Constraint::FloatRange {
                    min: old_min,
                    max: old_max,
                },
            ) => {
                float_range_is_valid(*new_min, *new_max)
                    && float_range_is_valid(*old_min, *old_max)
                    && *new_min >= *old_min
                    && *new_max <= *old_max
            }

            // IntRange may replace FloatRange when every integer in the
            // new range converts exactly to f64 and lies inside the old
            // interval. Endpoints that cannot be represented exactly in
            // f64 are unclear and fail closed.
            (
                Constraint::IntRange {
                    min: new_min,
                    max: new_max,
                },
                Constraint::FloatRange {
                    min: old_min,
                    max: old_max,
                },
            ) => {
                if !float_range_is_valid(*old_min, *old_max) || new_min > new_max {
                    false
                } else {
                    match (i64_as_exact_f64(*new_min), i64_as_exact_f64(*new_max)) {
                        (Some(lo), Some(hi)) => lo >= *old_min && hi <= *old_max,
                        _ => false,
                    }
                }
            }

            // IntRange to MaxLen: all integers in range must fit in max length
            (Constraint::IntRange { min, max }, Constraint::MaxLen(max_len)) => {
                let min_str = min.to_string();
                let max_str = max.to_string();
                min_str.len() <= *max_len && max_str.len() <= *max_len
            }

            // LenRange is subset of LenRange if the new interval is within
            // the old one. Inverted bounds fail closed.
            (
                Constraint::LenRange {
                    min: new_min,
                    max: new_max,
                },
                Constraint::LenRange {
                    min: old_min,
                    max: old_max,
                },
            ) => {
                len_range_is_valid(*new_min, *new_max)
                    && len_range_is_valid(*old_min, *old_max)
                    && *new_min >= *old_min
                    && *new_max <= *old_max
            }

            // LenRange may replace MinLen by adding an upper bound while
            // keeping or raising the minimum.
            (
                Constraint::LenRange {
                    min: new_min,
                    max: new_max,
                },
                Constraint::MinLen(old),
            ) => len_range_is_valid(*new_min, *new_max) && *new_min >= *old,

            // LenRange may replace MaxLen by adding a lower bound while
            // keeping or lowering the maximum.
            (
                Constraint::LenRange {
                    min: new_min,
                    max: new_max,
                },
                Constraint::MaxLen(old),
            ) => len_range_is_valid(*new_min, *new_max) && *new_max <= *old,

            // MinLen may replace LenRange when the new min is at least the
            // old min and the old max is still respected (only when the
            // old max is usize::MAX, i.e. equivalent to an unbounded max).
            // Otherwise fold the raise into a tighter LenRange.
            (
                Constraint::MinLen(new),
                Constraint::LenRange {
                    min: old_min,
                    max: old_max,
                },
            ) => {
                len_range_is_valid(*old_min, *old_max) && *new >= *old_min && *old_max == usize::MAX
            }

            // MaxLen may replace LenRange when the old min is 0 (still
            // respected by MaxLen) and the new max is within the old max.
            (
                Constraint::MaxLen(new),
                Constraint::LenRange {
                    min: old_min,
                    max: old_max,
                },
            ) => len_range_is_valid(*old_min, *old_max) && *old_min == 0 && *new <= *old_max,

            // CharLenRange is subset of CharLenRange if the new interval
            // is within the old one. Inverted bounds fail closed.
            (
                Constraint::CharLenRange {
                    min: new_min,
                    max: new_max,
                },
                Constraint::CharLenRange {
                    min: old_min,
                    max: old_max,
                },
            ) => {
                len_range_is_valid(*new_min, *new_max)
                    && len_range_is_valid(*old_min, *old_max)
                    && *new_min >= *old_min
                    && *new_max <= *old_max
            }

            // CharLenRange vs LenRange/MinLen/MaxLen is not a safe subset
            // in general (byte length vs Unicode scalar count). Fail closed
            // unless the replacement is Exact/OneOf, handled above.

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

            // Suffix is subset of SuffixOneOf if it equals or extends
            // some listed parent suffix (no new ending region).
            (Constraint::Suffix(suffix), Constraint::SuffixOneOf(old)) => {
                !suffix.is_empty()
                    && string_list_is_valid(old)
                    && old.iter().any(|s| suffix.ends_with(s))
            }

            // SuffixOneOf may replace Suffix when every child suffix
            // equals or extends the old suffix.
            (Constraint::SuffixOneOf(new), Constraint::Suffix(old)) => {
                !old.is_empty() && string_list_is_valid(new) && new.iter().all(|s| s.ends_with(old))
            }

            // SuffixOneOf → SuffixOneOf: every child suffix must equal
            // some parent suffix or be a strict extension of one.
            // The child may only shrink/narrow the allowed set.
            (Constraint::SuffixOneOf(new), Constraint::SuffixOneOf(old)) => {
                suffix_one_of_tightens(new, old)
            }

            // Suffix is subset of Contains if every value with that suffix contains the needle
            (Constraint::Suffix(suffix), Constraint::Contains(needle)) => {
                !needle.is_empty() && suffix.contains(needle)
            }

            // SuffixOneOf is subset of Contains if every listed suffix
            // already contains the needle.
            (Constraint::SuffixOneOf(suffixes), Constraint::Contains(needle)) => {
                string_list_is_valid(suffixes)
                    && !needle.is_empty()
                    && suffixes.iter().all(|s| s.contains(needle))
            }

            // Suffix is subset of ContainsAny if the suffix already
            // contains at least one listed needle.
            (Constraint::Suffix(suffix), Constraint::ContainsAny(needles)) => {
                !suffix.is_empty()
                    && string_list_is_valid(needles)
                    && needles.iter().any(|n| suffix.contains(n))
            }

            // SuffixOneOf is subset of ContainsAny if every listed suffix
            // already contains at least one listed needle.
            (Constraint::SuffixOneOf(suffixes), Constraint::ContainsAny(needles)) => {
                string_list_is_valid(suffixes)
                    && string_list_is_valid(needles)
                    && suffixes
                        .iter()
                        .all(|s| needles.iter().any(|n| s.contains(n)))
            }

            // Contains is subset of Contains if new needle contains (specializes) old needle
            (Constraint::Contains(new), Constraint::Contains(old)) => {
                !new.is_empty() && !old.is_empty() && new.contains(old)
            }

            // Contains is subset of ContainsAny if the needle specializes
            // some listed parent needle.
            (Constraint::Contains(needle), Constraint::ContainsAny(old)) => {
                !needle.is_empty()
                    && string_list_is_valid(old)
                    && old.iter().any(|parent| needle.contains(parent))
            }

            // ContainsAny may replace Contains when every child needle
            // specializes the old needle.
            (Constraint::ContainsAny(new), Constraint::Contains(old)) => {
                !old.is_empty()
                    && string_list_is_valid(new)
                    && new.iter().all(|child| child.contains(old))
            }

            // ContainsAny → ContainsAny: every child needle must contain
            // (specialize) some parent needle. The child may only
            // shrink/narrow the allowed set.
            (Constraint::ContainsAny(new), Constraint::ContainsAny(old)) => {
                contains_any_tightens(new, old)
            }

            // ContainsNone → ContainsNone: every old needle must be
            // covered by a new needle that is a substring of it
            // (shorter/equal forbids more). Extra needles (more denials)
            // are allowed.
            (Constraint::ContainsNone(new), Constraint::ContainsNone(old)) => {
                contains_none_tightens(new, old)
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

            // NotContains → NotContains if the new needle is a substring of the old
            // (shorter/equal needle forbids more values)
            (Constraint::NotContains(new), Constraint::NotContains(old)) => {
                !new.is_empty() && !old.is_empty() && old.contains(new)
            }

            // NotContains is subset of ContainsNone when avoiding the
            // needle still forbids every listed parent needle.
            (Constraint::NotContains(needle), Constraint::ContainsNone(old)) => {
                !needle.is_empty()
                    && string_list_is_valid(old)
                    && old.iter().all(|parent| parent.contains(needle))
            }

            // ContainsNone may replace NotContains when some new needle
            // is a substring of the old (covers that denial); extra
            // needles tighten further.
            (Constraint::ContainsNone(new), Constraint::NotContains(old)) => {
                !old.is_empty()
                    && string_list_is_valid(new)
                    && new.iter().any(|child| old.contains(child))
            }

            // NotPrefix → NotPrefix if the new prefix is a prefix of the old
            // (shorter/equal prefix forbids more values)
            (Constraint::NotPrefix(new), Constraint::NotPrefix(old)) => {
                !new.is_empty() && !old.is_empty() && old.starts_with(new)
            }

            // Prefix is subset of NotPrefix when the required prefix and the
            // forbidden prefix cannot both hold (incomparable prefixes).
            (Constraint::Prefix(prefix), Constraint::NotPrefix(forbidden)) => {
                !forbidden.is_empty()
                    && !prefix.starts_with(forbidden)
                    && !forbidden.starts_with(prefix)
            }

            // PrefixOneOf is subset of NotPrefix when every listed prefix
            // is incomparable with the forbidden prefix.
            (Constraint::PrefixOneOf(prefixes), Constraint::NotPrefix(forbidden)) => {
                string_list_is_valid(prefixes)
                    && !forbidden.is_empty()
                    && prefixes
                        .iter()
                        .all(|p| !p.starts_with(forbidden) && !forbidden.starts_with(p))
            }

            // NotContains may replace NotEquals when avoiding the needle still
            // forbids that exact value (the forbidden string contains the needle).
            (Constraint::NotContains(needle), Constraint::NotEquals(forbidden)) => {
                !needle.is_empty() && forbidden.contains(needle)
            }

            // NotPrefix may replace NotEquals when avoiding the prefix still
            // forbids that exact value.
            (Constraint::NotPrefix(prefix), Constraint::NotEquals(forbidden)) => {
                !prefix.is_empty() && forbidden.starts_with(prefix)
            }

            // NotContains may replace NotOneOf when every denied value contains
            // the needle, so avoiding it still forbids the whole denylist.
            (Constraint::NotContains(needle), Constraint::NotOneOf(denied)) => {
                !needle.is_empty()
                    && !denied.is_empty()
                    && denied.iter().all(|v| v.contains(needle))
            }

            // ContainsNone may replace NotEquals when avoiding some
            // needle still forbids that exact value.
            (Constraint::ContainsNone(needles), Constraint::NotEquals(forbidden)) => {
                string_list_is_valid(needles) && needles.iter().any(|n| forbidden.contains(n))
            }

            // ContainsNone may replace NotOneOf when every denied value
            // contains at least one needle.
            (Constraint::ContainsNone(needles), Constraint::NotOneOf(denied)) => {
                string_list_is_valid(needles)
                    && !denied.is_empty()
                    && denied.iter().all(|v| needles.iter().any(|n| v.contains(n)))
            }

            // NotPrefix may replace NotOneOf when every denied value starts
            // with the prefix.
            (Constraint::NotPrefix(prefix), Constraint::NotOneOf(denied)) => {
                !prefix.is_empty()
                    && !denied.is_empty()
                    && denied.iter().all(|v| v.starts_with(prefix))
            }

            // NotSuffix → NotSuffix if the new suffix is a suffix of the old
            // (shorter/equal suffix forbids more values)
            (Constraint::NotSuffix(new), Constraint::NotSuffix(old)) => {
                !new.is_empty() && !old.is_empty() && old.ends_with(new)
            }

            // NotMatches→NotMatches only allows an identical pattern. Narrowing
            // to Exact is the supported tightening path, same as Matches.
            (Constraint::NotMatches(new), Constraint::NotMatches(old)) => {
                !new.is_empty() && !old.is_empty() && new == old
            }

            // Suffix is subset of NotSuffix when the required suffix and the
            // forbidden suffix cannot both hold (incomparable suffixes).
            (Constraint::Suffix(suffix), Constraint::NotSuffix(forbidden)) => {
                !forbidden.is_empty()
                    && !suffix.ends_with(forbidden)
                    && !forbidden.ends_with(suffix)
            }

            // SuffixOneOf is subset of NotSuffix when every listed suffix
            // is incomparable with the forbidden suffix.
            (Constraint::SuffixOneOf(suffixes), Constraint::NotSuffix(forbidden)) => {
                string_list_is_valid(suffixes)
                    && !forbidden.is_empty()
                    && suffixes
                        .iter()
                        .all(|s| !s.ends_with(forbidden) && !forbidden.ends_with(s))
            }

            // NotSuffix may replace NotEquals when avoiding the suffix still
            // forbids that exact value.
            (Constraint::NotSuffix(suffix), Constraint::NotEquals(forbidden)) => {
                !suffix.is_empty() && forbidden.ends_with(suffix)
            }

            // NotMatches may replace NotEquals when avoiding the glob still
            // forbids that exact value.
            (Constraint::NotMatches(pattern), Constraint::NotEquals(forbidden)) => {
                !pattern.is_empty() && glob_match(pattern, forbidden)
            }

            // NotSuffix may replace NotOneOf when every denied value ends
            // with the suffix.
            (Constraint::NotSuffix(suffix), Constraint::NotOneOf(denied)) => {
                !suffix.is_empty()
                    && !denied.is_empty()
                    && denied.iter().all(|v| v.ends_with(suffix))
            }

            // NotMatches may replace NotOneOf when every denied value matches
            // the glob, so avoiding it still forbids the whole denylist.
            (Constraint::NotMatches(pattern), Constraint::NotOneOf(denied)) => {
                !pattern.is_empty()
                    && !denied.is_empty()
                    && denied.iter().all(|v| glob_match(pattern, v))
            }

            // Not → Not: widening the inner constraint strengthens the
            // outer negation. Tightening the inner would loosen Not.
            (Constraint::Not(new), Constraint::Not(old)) => {
                !new.is_empty_pattern() && !old.is_empty_pattern() && old.is_subset_of(new)
            }

            // All → All: each old child must still be covered by an
            // equal-or-tighter new child. Extra children (more ANDs) are
            // allowed and make the constraint stronger.
            (Constraint::All(new), Constraint::All(old)) => {
                !new.is_empty()
                    && !old.is_empty()
                    && old.iter().all(|o| new.iter().any(|n| n.is_subset_of(o)))
            }

            // Any → Any: each new child must tighten some old child
            // (fewer ORs or tighter alternatives). Adding a new
            // alternative is a widening.
            (Constraint::Any(new), Constraint::Any(old)) => {
                !new.is_empty()
                    && !old.is_empty()
                    && new.iter().all(|n| old.iter().any(|o| n.is_subset_of(o)))
            }

            // All may become Any only when every new alternative is as
            // strong as the whole old All (no OR-widening).
            (Constraint::Any(new), Constraint::All(old)) => {
                !new.is_empty()
                    && !old.is_empty()
                    && new.iter().all(|n| old.iter().all(|o| n.is_subset_of(o)))
            }

            // Any may become All when the conjunction still implies at
            // least one old alternative (AND is stronger than OR).
            (Constraint::All(new), Constraint::Any(old)) => {
                !new.is_empty()
                    && !old.is_empty()
                    && new.iter().any(|n| old.iter().any(|o| n.is_subset_of(o)))
            }

            // All may become a single child when that child alone covers
            // every old child (as strong as the conjunction).
            (new, Constraint::All(old)) => {
                !old.is_empty() && old.iter().all(|o| new.is_subset_of(o))
            }

            // Any may become a single child when that child tightens
            // some old alternative.
            (new, Constraint::Any(old)) => {
                !old.is_empty() && old.iter().any(|o| new.is_subset_of(o))
            }

            // A single constraint may become All when at least one new
            // child is a tightening of the old constraint (more ANDs).
            (Constraint::All(new), old) => {
                !new.is_empty() && new.iter().any(|n| n.is_subset_of(old))
            }

            // A single constraint may become Any when every new
            // alternative is a tightening of the old constraint.
            (Constraint::Any(new), old) => {
                !new.is_empty() && new.iter().all(|n| n.is_subset_of(old))
            }

            // Remaining cross-type pairs cannot be shown to be subsets
            _ => false,
        }
    }
}

/// Parse `value` as a finite `f64`. Rejects non-numeric strings, NaN, and ±inf.
fn parse_finite_f64(value: &str) -> Option<f64> {
    let n: f64 = value.parse().ok()?;
    n.is_finite().then_some(n)
}

/// Inclusive float bounds are valid only when both ends are finite and ordered.
fn float_range_is_valid(min: f64, max: f64) -> bool {
    min.is_finite() && max.is_finite() && min <= max
}

/// Inclusive length bounds are valid only when they are ordered.
fn len_range_is_valid(min: usize, max: usize) -> bool {
    min <= max
}

/// PrefixOneOf / SuffixOneOf / ContainsAny / ContainsNone lists are
/// valid only when non-empty and every member is a non-empty string
/// (empty members are wildcards or empty denials).
fn string_list_is_valid(values: &[String]) -> bool {
    !values.is_empty() && values.iter().all(|s| !s.is_empty())
}

/// Every child needle contains (specializes) some parent needle.
/// Empty lists fail closed.
fn contains_any_tightens(new: &[String], old: &[String]) -> bool {
    string_list_is_valid(new)
        && string_list_is_valid(old)
        && new
            .iter()
            .all(|child| old.iter().any(|parent| child.contains(parent)))
}

/// Every old needle is covered by a new needle that is a substring of
/// it (shorter/equal forbids more). Extra new needles are allowed.
/// Empty lists fail closed.
fn contains_none_tightens(new: &[String], old: &[String]) -> bool {
    string_list_is_valid(new)
        && string_list_is_valid(old)
        && old
            .iter()
            .all(|parent| new.iter().any(|child| parent.contains(child)))
}

/// Every child prefix equals some parent prefix or is a strict
/// extension that starts with one. Empty lists fail closed.
fn prefix_one_of_tightens(new: &[String], old: &[String]) -> bool {
    string_list_is_valid(new)
        && string_list_is_valid(old)
        && new
            .iter()
            .all(|child| old.iter().any(|parent| child.starts_with(parent)))
}

/// Every child suffix equals some parent suffix or is a strict
/// extension that ends with one. Empty lists fail closed.
fn suffix_one_of_tightens(new: &[String], old: &[String]) -> bool {
    string_list_is_valid(new)
        && string_list_is_valid(old)
        && new
            .iter()
            .all(|child| old.iter().any(|parent| child.ends_with(parent)))
}

/// Convert `n` to `f64` only when the integer is exactly representable.
fn i64_as_exact_f64(n: i64) -> Option<f64> {
    let f = n as f64;
    if f.is_finite() && f as i64 == n {
        Some(f)
    } else {
        None
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
    fn prefix_one_of_check() {
        let c = Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()]);
        assert!(c.check("/tmp/foo"));
        assert!(c.check("/tmp/"));
        assert!(c.check("/var/log"));
        assert!(c.check("/var/"));
        assert!(!c.check("/home/x"));
        assert!(!c.check("tmp/foo"));
        assert!(!c.check("/tmp"));
        assert!(!c.check(""));
    }

    #[test]
    fn suffix_one_of_check() {
        let c = Constraint::SuffixOneOf(vec![".txt".to_string(), ".md".to_string()]);
        assert!(c.check("notes.txt"));
        assert!(c.check(".txt"));
        assert!(c.check("README.md"));
        assert!(c.check(".md"));
        assert!(!c.check("notes.txt.bak"));
        assert!(!c.check("notes"));
        assert!(!c.check(""));
    }

    #[test]
    fn contains_any_check() {
        let c = Constraint::ContainsAny(vec!["tmp".to_string(), "var".to_string()]);
        assert!(c.check("/tmp/file"));
        assert!(c.check("tmp"));
        assert!(c.check("/var/log"));
        assert!(c.check("atmpb"));
        assert!(!c.check("/home/file"));
        assert!(!c.check("TMP"));
        assert!(!c.check(""));
    }

    #[test]
    fn contains_none_check() {
        let c = Constraint::ContainsNone(vec!["secret".to_string(), "password".to_string()]);
        assert!(c.check("/var/file"));
        assert!(c.check("ok"));
        assert!(c.check(""));
        assert!(c.check("SECRET"));
        assert!(!c.check("has-secret"));
        assert!(!c.check("password"));
        assert!(!c.check("my-password-here"));
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
    fn floatrange_check() {
        let c = Constraint::FloatRange {
            min: 0.5,
            max: 10.5,
        };
        assert!(c.check("0.5"));
        assert!(c.check("10.5"));
        assert!(c.check("1"));
        assert!(c.check("1.0"));
        assert!(c.check("1e1"));
        assert!(!c.check("0.49"));
        assert!(!c.check("10.51"));
        assert!(!c.check("abc"));
        assert!(!c.check(""));
        assert!(!c.check("NaN"));
        assert!(!c.check("nan"));
        assert!(!c.check("inf"));
        assert!(!c.check("-inf"));
        assert!(!c.check("Infinity"));
        assert!(!c.check("+inf"));
    }

    #[test]
    fn floatrange_invalid_bounds_fail_closed() {
        let inverted = Constraint::FloatRange {
            min: 10.0,
            max: 1.0,
        };
        let nan = Constraint::FloatRange {
            min: f64::NAN,
            max: 1.0,
        };
        let inf = Constraint::FloatRange {
            min: 0.0,
            max: f64::INFINITY,
        };
        assert!(inverted.is_invalid_range());
        assert!(nan.is_invalid_range());
        assert!(inf.is_invalid_range());
        assert!(!inverted.check("5"));
        assert!(!nan.check("1"));
        assert!(!inf.check("1"));
        assert!(!Constraint::FloatRange {
            min: 0.5,
            max: 10.5
        }
        .is_invalid_range());
    }

    #[test]
    fn lenrange_check() {
        let c = Constraint::LenRange { min: 2, max: 5 };
        assert!(c.check("hi"));
        assert!(c.check("hello"));
        assert!(!c.check("h"));
        assert!(!c.check("hello!"));
        assert!(!c.check(""));
    }

    #[test]
    fn lenrange_zero_min_allows_empty() {
        let c = Constraint::LenRange { min: 0, max: 3 };
        assert!(c.check(""));
        assert!(c.check("x"));
        assert!(c.check("abc"));
        assert!(!c.check("abcd"));
    }

    #[test]
    fn lenrange_uses_byte_length() {
        // "é" is one Unicode scalar and two UTF-8 bytes.
        let c = Constraint::LenRange { min: 2, max: 2 };
        assert!(c.check("é"));
        assert!(!Constraint::LenRange { min: 1, max: 1 }.check("é"));
        assert!(!Constraint::LenRange { min: 3, max: 4 }.check("é"));
    }

    #[test]
    fn lenrange_invalid_bounds_fail_closed() {
        let inverted = Constraint::LenRange { min: 10, max: 1 };
        assert!(inverted.is_invalid_range());
        assert!(!inverted.check(""));
        assert!(!inverted.check("hello"));
        assert!(!inverted.check("abcdefghij"));
        assert!(!Constraint::LenRange { min: 1, max: 16 }.is_invalid_range());
        assert!(!Constraint::LenRange { min: 0, max: 0 }.is_invalid_range());
        assert!(Constraint::LenRange { min: 0, max: 0 }.check(""));
        assert!(!Constraint::LenRange { min: 0, max: 0 }.check("x"));
    }

    #[test]
    fn charlenrange_check() {
        let c = Constraint::CharLenRange { min: 2, max: 5 };
        assert!(c.check("hi"));
        assert!(c.check("hello"));
        assert!(!c.check("h"));
        assert!(!c.check("hello!"));
        assert!(!c.check(""));
    }

    #[test]
    fn charlenrange_zero_min_allows_empty() {
        let c = Constraint::CharLenRange { min: 0, max: 3 };
        assert!(c.check(""));
        assert!(c.check("x"));
        assert!(c.check("abc"));
        assert!(!c.check("abcd"));
    }

    #[test]
    fn charlenrange_uses_scalar_count_not_bytes() {
        // "é" is one Unicode scalar and two UTF-8 bytes.
        let c = Constraint::CharLenRange { min: 1, max: 1 };
        assert!(c.check("é"));
        assert!(!Constraint::CharLenRange { min: 2, max: 2 }.check("é"));
        assert!(!Constraint::CharLenRange { min: 0, max: 0 }.check("é"));
        // "日本語" is three scalars and nine UTF-8 bytes.
        assert!(Constraint::CharLenRange { min: 3, max: 3 }.check("日本語"));
        assert!(!Constraint::CharLenRange { min: 9, max: 9 }.check("日本語"));
        // "café" is four scalars; byte length is five.
        assert!(Constraint::CharLenRange { min: 4, max: 4 }.check("café"));
        assert!(!Constraint::CharLenRange { min: 5, max: 5 }.check("café"));
    }

    #[test]
    fn charlenrange_invalid_bounds_fail_closed() {
        let inverted = Constraint::CharLenRange { min: 10, max: 1 };
        assert!(inverted.is_invalid_range());
        assert!(!inverted.check(""));
        assert!(!inverted.check("hello"));
        assert!(!inverted.check("abcdefghij"));
        assert!(!Constraint::CharLenRange { min: 1, max: 16 }.is_invalid_range());
        assert!(!Constraint::CharLenRange { min: 0, max: 0 }.is_invalid_range());
        assert!(Constraint::CharLenRange { min: 0, max: 0 }.check(""));
        assert!(!Constraint::CharLenRange { min: 0, max: 0 }.check("x"));
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
    fn empty_prefix_one_of_fail_closed() {
        let empty_list = Constraint::PrefixOneOf(vec![]);
        let empty_member = Constraint::PrefixOneOf(vec![String::new()]);
        let mixed = Constraint::PrefixOneOf(vec!["/tmp/".to_string(), String::new()]);
        for c in [&empty_list, &empty_member, &mixed] {
            assert!(c.is_empty_pattern());
            assert!(!c.check(""));
            assert!(!c.check("/tmp/foo"));
            assert!(!c.check("anything"));
        }
        assert!(!Constraint::PrefixOneOf(vec!["/tmp/".to_string()]).is_empty_pattern());
    }

    #[test]
    fn empty_suffix_one_of_fail_closed() {
        let empty_list = Constraint::SuffixOneOf(vec![]);
        let empty_member = Constraint::SuffixOneOf(vec![String::new()]);
        let mixed = Constraint::SuffixOneOf(vec![".txt".to_string(), String::new()]);
        for c in [&empty_list, &empty_member, &mixed] {
            assert!(c.is_empty_pattern());
            assert!(!c.check(""));
            assert!(!c.check("notes.txt"));
            assert!(!c.check("anything"));
        }
        assert!(!Constraint::SuffixOneOf(vec![".txt".to_string()]).is_empty_pattern());
    }

    #[test]
    fn empty_contains_any_fail_closed() {
        let empty_list = Constraint::ContainsAny(vec![]);
        let empty_member = Constraint::ContainsAny(vec![String::new()]);
        let mixed = Constraint::ContainsAny(vec!["tmp".to_string(), String::new()]);
        for c in [&empty_list, &empty_member, &mixed] {
            assert!(c.is_empty_pattern());
            assert!(!c.check(""));
            assert!(!c.check("/tmp/foo"));
            assert!(!c.check("anything"));
        }
        assert!(!Constraint::ContainsAny(vec!["tmp".to_string()]).is_empty_pattern());
    }

    #[test]
    fn empty_contains_none_fail_closed() {
        let empty_list = Constraint::ContainsNone(vec![]);
        let empty_member = Constraint::ContainsNone(vec![String::new()]);
        let mixed = Constraint::ContainsNone(vec!["secret".to_string(), String::new()]);
        for c in [&empty_list, &empty_member, &mixed] {
            assert!(c.is_empty_pattern());
            assert!(!c.check(""));
            assert!(!c.check("ok"));
            assert!(!c.check("anything"));
        }
        assert!(!Constraint::ContainsNone(vec!["secret".to_string()]).is_empty_pattern());
    }

    #[test]
    fn not_contains_check() {
        let c = Constraint::NotContains("tmp".to_string());
        assert!(c.check("/var/file"));
        assert!(c.check("TMP"));
        assert!(c.check(""));
        assert!(!c.check("/tmp/file"));
        assert!(!c.check("tmp"));
        assert!(!c.check("atmpb"));
    }

    #[test]
    fn not_prefix_check() {
        let c = Constraint::NotPrefix("/tmp/".to_string());
        assert!(c.check("/var/tmp"));
        assert!(c.check("tmp/"));
        assert!(c.check("/tmp"));
        assert!(c.check(""));
        assert!(!c.check("/tmp/"));
        assert!(!c.check("/tmp/foo"));
    }

    #[test]
    fn empty_not_contains_and_not_prefix_fail_closed() {
        let contains = Constraint::NotContains(String::new());
        let prefix = Constraint::NotPrefix(String::new());
        assert!(contains.is_empty_pattern());
        assert!(prefix.is_empty_pattern());
        assert!(!contains.check(""));
        assert!(!contains.check("anything"));
        assert!(!prefix.check(""));
        assert!(!prefix.check("anything"));
    }

    #[test]
    fn not_suffix_check() {
        let c = Constraint::NotSuffix(".txt".to_string());
        assert!(c.check("notes.txt.bak"));
        assert!(c.check("txt"));
        assert!(c.check(""));
        assert!(!c.check("notes.txt"));
        assert!(!c.check(".txt"));
    }

    #[test]
    fn not_matches_star_and_question() {
        let c = Constraint::NotMatches("*.txt".to_string());
        assert!(c.check("notes.txt.bak"));
        assert!(c.check("txt"));
        assert!(c.check(""));
        assert!(!c.check("notes.txt"));
        assert!(!c.check(".txt"));
        assert!(!c.check("a.txt"));

        let q = Constraint::NotMatches("file?.rs".to_string());
        assert!(q.check("file.rs"));
        assert!(q.check("file12.rs"));
        assert!(!q.check("file1.rs"));
        assert!(!q.check("filex.rs"));
    }

    #[test]
    fn empty_not_suffix_and_not_matches_fail_closed() {
        let suffix = Constraint::NotSuffix(String::new());
        let matches = Constraint::NotMatches(String::new());
        assert!(suffix.is_empty_pattern());
        assert!(matches.is_empty_pattern());
        assert!(!suffix.check(""));
        assert!(!suffix.check("anything"));
        assert!(!matches.check(""));
        assert!(!matches.check("anything"));
        assert!(!matches.check("*"));
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
    fn prefix_one_of_subset_tightens_only() {
        let parent = Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()]);
        let shrink = Constraint::PrefixOneOf(vec!["/tmp/".to_string()]);
        let extend =
            Constraint::PrefixOneOf(vec!["/tmp/sub/".to_string(), "/var/log/".to_string()]);
        let same = Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()]);
        let widen = Constraint::PrefixOneOf(vec!["/".to_string()]);
        let outside = Constraint::PrefixOneOf(vec!["/home/".to_string()]);
        let empty = Constraint::PrefixOneOf(vec![]);
        let empty_member = Constraint::PrefixOneOf(vec!["/tmp/".to_string(), String::new()]);

        assert!(shrink.is_subset_of(&parent));
        assert!(extend.is_subset_of(&parent));
        assert!(same.is_subset_of(&parent));
        assert!(!widen.is_subset_of(&parent));
        assert!(!outside.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&shrink));
        assert!(!empty.is_subset_of(&parent));
        assert!(!empty_member.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&empty));

        assert!(Constraint::Prefix("/tmp/sub/".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Prefix("/".to_string()).is_subset_of(&parent));
        assert!(Constraint::PrefixOneOf(vec!["/tmp/sub/".to_string()])
            .is_subset_of(&Constraint::Prefix("/tmp/".to_string())));
        assert!(
            !Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()])
                .is_subset_of(&Constraint::Prefix("/tmp/".to_string()))
        );

        assert!(Constraint::Exact("/tmp/a".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Exact("/home/a".to_string()).is_subset_of(&parent));
        assert!(
            Constraint::OneOf(vec!["/tmp/a".to_string(), "/var/b".to_string()])
                .is_subset_of(&parent)
        );
        assert!(
            !Constraint::OneOf(vec!["/tmp/a".to_string(), "/home/b".to_string()])
                .is_subset_of(&parent)
        );
    }

    #[test]
    fn suffix_one_of_subset_tightens_only() {
        let parent = Constraint::SuffixOneOf(vec![".txt".to_string(), ".md".to_string()]);
        let shrink = Constraint::SuffixOneOf(vec![".txt".to_string()]);
        let extend = Constraint::SuffixOneOf(vec![".bak.txt".to_string(), ".old.md".to_string()]);
        let same = Constraint::SuffixOneOf(vec![".txt".to_string(), ".md".to_string()]);
        let widen = Constraint::SuffixOneOf(vec!["t".to_string()]);
        let outside = Constraint::SuffixOneOf(vec![".rs".to_string()]);
        let empty = Constraint::SuffixOneOf(vec![]);
        let empty_member = Constraint::SuffixOneOf(vec![".txt".to_string(), String::new()]);

        assert!(shrink.is_subset_of(&parent));
        assert!(extend.is_subset_of(&parent));
        assert!(same.is_subset_of(&parent));
        assert!(!widen.is_subset_of(&parent));
        assert!(!outside.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&shrink));
        assert!(!empty.is_subset_of(&parent));
        assert!(!empty_member.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&empty));

        assert!(Constraint::Suffix(".bak.txt".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Suffix(".rs".to_string()).is_subset_of(&parent));
        assert!(Constraint::SuffixOneOf(vec![".bak.txt".to_string()])
            .is_subset_of(&Constraint::Suffix(".txt".to_string())));
        assert!(
            !Constraint::SuffixOneOf(vec![".txt".to_string(), ".md".to_string()])
                .is_subset_of(&Constraint::Suffix(".txt".to_string()))
        );

        assert!(Constraint::Exact("notes.txt".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Exact("notes.rs".to_string()).is_subset_of(&parent));
        assert!(
            Constraint::OneOf(vec!["a.txt".to_string(), "b.md".to_string()]).is_subset_of(&parent)
        );
        assert!(
            !Constraint::OneOf(vec!["a.txt".to_string(), "b.rs".to_string()]).is_subset_of(&parent)
        );
    }

    #[test]
    fn contains_any_subset_tightens_only() {
        let parent = Constraint::ContainsAny(vec!["tmp".to_string(), "var".to_string()]);
        let shrink = Constraint::ContainsAny(vec!["tmp".to_string()]);
        let extend = Constraint::ContainsAny(vec!["tmp/public".to_string(), "var/log".to_string()]);
        let same = Constraint::ContainsAny(vec!["tmp".to_string(), "var".to_string()]);
        let widen = Constraint::ContainsAny(vec!["tm".to_string()]);
        let outside = Constraint::ContainsAny(vec!["home".to_string()]);
        let empty = Constraint::ContainsAny(vec![]);
        let empty_member = Constraint::ContainsAny(vec!["tmp".to_string(), String::new()]);

        assert!(shrink.is_subset_of(&parent));
        assert!(extend.is_subset_of(&parent));
        assert!(same.is_subset_of(&parent));
        assert!(!widen.is_subset_of(&parent));
        assert!(!outside.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&shrink));
        assert!(!empty.is_subset_of(&parent));
        assert!(!empty_member.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&empty));

        assert!(Constraint::Contains("tmp/public".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Contains("tm".to_string()).is_subset_of(&parent));
        assert!(Constraint::ContainsAny(vec!["tmp/public".to_string()])
            .is_subset_of(&Constraint::Contains("tmp".to_string())));
        assert!(
            !Constraint::ContainsAny(vec!["tmp".to_string(), "var".to_string()])
                .is_subset_of(&Constraint::Contains("tmp".to_string()))
        );

        assert!(Constraint::Prefix("/tmp/".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Prefix("/home/".to_string()).is_subset_of(&parent));
        assert!(Constraint::Suffix("/tmp/out".to_string()).is_subset_of(&parent));
        assert!(
            Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()])
                .is_subset_of(&parent)
        );
        assert!(
            !Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/home/".to_string()])
                .is_subset_of(&parent)
        );

        assert!(Constraint::Exact("/tmp/a".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Exact("/home/a".to_string()).is_subset_of(&parent));
        assert!(
            Constraint::OneOf(vec!["/tmp/a".to_string(), "/var/b".to_string()])
                .is_subset_of(&parent)
        );
        assert!(
            !Constraint::OneOf(vec!["/tmp/a".to_string(), "/home/b".to_string()])
                .is_subset_of(&parent)
        );
    }

    #[test]
    fn contains_none_subset_tightens_only() {
        let parent = Constraint::ContainsNone(vec!["secret".to_string(), "password".to_string()]);
        let grow = Constraint::ContainsNone(vec![
            "secret".to_string(),
            "password".to_string(),
            "token".to_string(),
        ]);
        let shorten = Constraint::ContainsNone(vec!["sec".to_string(), "pass".to_string()]);
        let same = Constraint::ContainsNone(vec!["secret".to_string(), "password".to_string()]);
        let drop = Constraint::ContainsNone(vec!["secret".to_string()]);
        let specialize = Constraint::ContainsNone(vec!["secret123".to_string()]);
        let empty = Constraint::ContainsNone(vec![]);
        let empty_member = Constraint::ContainsNone(vec!["secret".to_string(), String::new()]);

        assert!(grow.is_subset_of(&parent));
        assert!(shorten.is_subset_of(&parent));
        assert!(same.is_subset_of(&parent));
        assert!(!drop.is_subset_of(&parent));
        assert!(!specialize.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&grow));
        assert!(parent.is_subset_of(&drop));
        assert!(!empty.is_subset_of(&parent));
        assert!(!empty_member.is_subset_of(&parent));
        assert!(!parent.is_subset_of(&empty));

        assert!(Constraint::NotContains("s".to_string()).is_subset_of(&parent));
        assert!(!Constraint::NotContains("secret".to_string()).is_subset_of(&parent));
        assert!(
            Constraint::ContainsNone(vec!["secret".to_string(), "token".to_string()])
                .is_subset_of(&Constraint::NotContains("secret".to_string()))
        );
        assert!(!Constraint::ContainsNone(vec!["secret123".to_string()])
            .is_subset_of(&Constraint::NotContains("secret".to_string())));

        assert!(Constraint::Exact("ok".to_string()).is_subset_of(&parent));
        assert!(!Constraint::Exact("has-secret".to_string()).is_subset_of(&parent));
        assert!(
            Constraint::OneOf(vec!["ok".to_string(), "fine".to_string()]).is_subset_of(&parent)
        );
        assert!(
            !Constraint::OneOf(vec!["ok".to_string(), "password".to_string()])
                .is_subset_of(&parent)
        );

        assert!(Constraint::ContainsNone(vec!["admin".to_string()])
            .is_subset_of(&Constraint::NotEquals("admin".to_string())));
        assert!(
            Constraint::ContainsNone(vec!["admin".to_string()]).is_subset_of(
                &Constraint::NotOneOf(vec!["admin".to_string(), "administrator".to_string()])
            )
        );
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
    fn not_contains_subset_of_not_contains_is_substring() {
        let short = Constraint::NotContains("tmp".to_string());
        let long = Constraint::NotContains("tmp/public".to_string());
        assert!(short.is_subset_of(&long));
        assert!(!long.is_subset_of(&short));
        assert!(short.is_subset_of(&Constraint::NotContains("tmp".to_string())));
        assert!(!Constraint::NotContains(String::new()).is_subset_of(&long));
        assert!(!short.is_subset_of(&Constraint::NotContains(String::new())));
        assert!(!Constraint::NotContains("var".to_string()).is_subset_of(&long));
    }

    #[test]
    fn not_prefix_subset_of_not_prefix_is_prefix() {
        let short = Constraint::NotPrefix("/tmp/".to_string());
        let long = Constraint::NotPrefix("/tmp/subdir/".to_string());
        assert!(short.is_subset_of(&long));
        assert!(!long.is_subset_of(&short));
        assert!(short.is_subset_of(&Constraint::NotPrefix("/tmp/".to_string())));
        assert!(!Constraint::NotPrefix(String::new()).is_subset_of(&long));
        assert!(!short.is_subset_of(&Constraint::NotPrefix(String::new())));
        assert!(!Constraint::NotPrefix("/var/".to_string()).is_subset_of(&long));
    }

    #[test]
    fn exact_subset_of_not_contains_and_not_prefix() {
        let exact = Constraint::Exact("/var/file".to_string());
        assert!(exact.is_subset_of(&Constraint::NotContains("tmp".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotContains("var".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotContains(String::new())));
        assert!(exact.is_subset_of(&Constraint::NotPrefix("/tmp/".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotPrefix("/var/".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotPrefix(String::new())));
    }

    #[test]
    fn oneof_subset_of_not_contains_and_not_prefix() {
        let oneof = Constraint::OneOf(vec!["/var/a".to_string(), "/var/b".to_string()]);
        assert!(oneof.is_subset_of(&Constraint::NotContains("tmp".to_string())));
        assert!(!oneof.is_subset_of(&Constraint::NotContains("var".to_string())));
        assert!(oneof.is_subset_of(&Constraint::NotPrefix("/tmp/".to_string())));
        assert!(!oneof.is_subset_of(&Constraint::NotPrefix("/var/".to_string())));
    }

    #[test]
    fn not_contains_and_not_prefix_may_replace_denylists() {
        let deny = Constraint::NotEquals("admin".to_string());
        assert!(Constraint::NotContains("adm".to_string()).is_subset_of(&deny));
        assert!(!Constraint::NotContains("root".to_string()).is_subset_of(&deny));
        assert!(Constraint::NotPrefix("ad".to_string()).is_subset_of(&deny));
        assert!(!Constraint::NotPrefix("ro".to_string()).is_subset_of(&deny));

        let list = Constraint::NotOneOf(vec!["admin".to_string(), "adm".to_string()]);
        assert!(Constraint::NotContains("adm".to_string()).is_subset_of(&list));
        assert!(!Constraint::NotContains("root".to_string()).is_subset_of(&list));
        assert!(Constraint::NotPrefix("ad".to_string()).is_subset_of(&list));
        assert!(!Constraint::NotPrefix("ro".to_string()).is_subset_of(&list));
    }

    #[test]
    fn prefix_subset_of_not_prefix_when_incomparable() {
        let prefix = Constraint::Prefix("/tmp/".to_string());
        assert!(prefix.is_subset_of(&Constraint::NotPrefix("/var/".to_string())));
        assert!(!prefix.is_subset_of(&Constraint::NotPrefix("/tmp/".to_string())));
        assert!(!prefix.is_subset_of(&Constraint::NotPrefix("/tmp/sub/".to_string())));
        assert!(!Constraint::Prefix("/tmp/sub/".to_string())
            .is_subset_of(&Constraint::NotPrefix("/tmp/".to_string())));
    }

    #[test]
    fn not_suffix_subset_of_not_suffix_is_suffix() {
        let short = Constraint::NotSuffix(".txt".to_string());
        let long = Constraint::NotSuffix(".bak.txt".to_string());
        assert!(short.is_subset_of(&long));
        assert!(!long.is_subset_of(&short));
        assert!(short.is_subset_of(&Constraint::NotSuffix(".txt".to_string())));
        assert!(!Constraint::NotSuffix(String::new()).is_subset_of(&long));
        assert!(!short.is_subset_of(&Constraint::NotSuffix(String::new())));
        assert!(!Constraint::NotSuffix(".rs".to_string()).is_subset_of(&long));
    }

    #[test]
    fn not_matches_subset_of_not_matches_only_identical() {
        let glob = Constraint::NotMatches("*.txt".to_string());
        assert!(glob.is_subset_of(&Constraint::NotMatches("*.txt".to_string())));
        assert!(!glob.is_subset_of(&Constraint::NotMatches("*.rs".to_string())));
        assert!(!glob.is_subset_of(&Constraint::NotMatches("notes.txt".to_string())));
        assert!(!Constraint::NotMatches("notes.txt".to_string()).is_subset_of(&glob));
        assert!(!Constraint::NotMatches(String::new()).is_subset_of(&glob));
        assert!(!glob.is_subset_of(&Constraint::NotMatches(String::new())));
    }

    #[test]
    fn exact_subset_of_not_suffix_and_not_matches() {
        let exact = Constraint::Exact("notes.rs".to_string());
        assert!(exact.is_subset_of(&Constraint::NotSuffix(".txt".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotSuffix(".rs".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotSuffix(String::new())));
        assert!(exact.is_subset_of(&Constraint::NotMatches("*.txt".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotMatches("*.rs".to_string())));
        assert!(!exact.is_subset_of(&Constraint::NotMatches(String::new())));
    }

    #[test]
    fn oneof_subset_of_not_suffix_and_not_matches() {
        let oneof = Constraint::OneOf(vec!["a.rs".to_string(), "b.rs".to_string()]);
        assert!(oneof.is_subset_of(&Constraint::NotSuffix(".txt".to_string())));
        assert!(!oneof.is_subset_of(&Constraint::NotSuffix(".rs".to_string())));
        assert!(oneof.is_subset_of(&Constraint::NotMatches("*.txt".to_string())));
        assert!(!oneof.is_subset_of(&Constraint::NotMatches("*.rs".to_string())));
    }

    #[test]
    fn not_suffix_and_not_matches_may_replace_denylists() {
        let deny = Constraint::NotEquals("admin.txt".to_string());
        assert!(Constraint::NotSuffix(".txt".to_string()).is_subset_of(&deny));
        assert!(!Constraint::NotSuffix(".rs".to_string()).is_subset_of(&deny));
        assert!(Constraint::NotMatches("*.txt".to_string()).is_subset_of(&deny));
        assert!(!Constraint::NotMatches("*.rs".to_string()).is_subset_of(&deny));

        let list = Constraint::NotOneOf(vec!["admin.txt".to_string(), "root.txt".to_string()]);
        assert!(Constraint::NotSuffix(".txt".to_string()).is_subset_of(&list));
        assert!(!Constraint::NotSuffix(".rs".to_string()).is_subset_of(&list));
        assert!(Constraint::NotMatches("*.txt".to_string()).is_subset_of(&list));
        assert!(!Constraint::NotMatches("*.rs".to_string()).is_subset_of(&list));
    }

    #[test]
    fn suffix_subset_of_not_suffix_when_incomparable() {
        let suffix = Constraint::Suffix(".txt".to_string());
        assert!(suffix.is_subset_of(&Constraint::NotSuffix(".rs".to_string())));
        assert!(!suffix.is_subset_of(&Constraint::NotSuffix(".txt".to_string())));
        assert!(!suffix.is_subset_of(&Constraint::NotSuffix(".bak.txt".to_string())));
        assert!(!Constraint::Suffix(".bak.txt".to_string())
            .is_subset_of(&Constraint::NotSuffix(".txt".to_string())));
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
    fn floatrange_subset_of_floatrange() {
        let inner = Constraint::FloatRange { min: 1.0, max: 5.0 };
        let outer = Constraint::FloatRange {
            min: 0.5,
            max: 10.5,
        };
        assert!(inner.is_subset_of(&outer));
        assert!(!outer.is_subset_of(&inner));
        assert!(!Constraint::FloatRange {
            min: 10.0,
            max: 1.0
        }
        .is_subset_of(&outer));
        assert!(!inner.is_subset_of(&Constraint::FloatRange {
            min: f64::NAN,
            max: 10.0
        }));
    }

    #[test]
    fn exact_subset_of_floatrange() {
        let range = Constraint::FloatRange {
            min: 0.5,
            max: 10.5,
        };
        assert!(Constraint::Exact("1.5".to_string()).is_subset_of(&range));
        assert!(Constraint::Exact("0.5".to_string()).is_subset_of(&range));
        assert!(Constraint::Exact("10".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("0.4".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("abc".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("NaN".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("inf".to_string()).is_subset_of(&range));
    }

    #[test]
    fn oneof_subset_of_floatrange() {
        let range = Constraint::FloatRange {
            min: 0.5,
            max: 10.5,
        };
        assert!(Constraint::OneOf(vec!["1.0".to_string(), "2.5".to_string()]).is_subset_of(&range));
        assert!(!Constraint::OneOf(vec!["1.0".to_string(), "20".to_string()]).is_subset_of(&range));
        assert!(!Constraint::OneOf(vec![]).is_subset_of(&range));
    }

    #[test]
    fn intrange_may_replace_floatrange_when_contained() {
        let range = Constraint::FloatRange {
            min: 0.5,
            max: 10.5,
        };
        assert!(Constraint::IntRange { min: 1, max: 10 }.is_subset_of(&range));
        assert!(!Constraint::IntRange { min: 0, max: 10 }.is_subset_of(&range));
        assert!(!Constraint::IntRange { min: 1, max: 11 }.is_subset_of(&range));
        // FloatRange accepting "5.0" is not a subset of IntRange (fail closed).
        assert!(!range.is_subset_of(&Constraint::IntRange { min: 1, max: 10 }));
    }

    #[test]
    fn lenrange_subset_of_lenrange() {
        let inner = Constraint::LenRange { min: 3, max: 8 };
        let outer = Constraint::LenRange { min: 1, max: 16 };
        assert!(inner.is_subset_of(&outer));
        assert!(!outer.is_subset_of(&inner));
        assert!(!Constraint::LenRange { min: 16, max: 1 }.is_subset_of(&outer));
        assert!(!inner.is_subset_of(&Constraint::LenRange { min: 16, max: 1 }));
    }

    #[test]
    fn exact_subset_of_lenrange() {
        let range = Constraint::LenRange { min: 2, max: 5 };
        assert!(Constraint::Exact("hi".to_string()).is_subset_of(&range));
        assert!(Constraint::Exact("hello".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("h".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("hello!".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("hi".to_string())
            .is_subset_of(&Constraint::LenRange { min: 5, max: 1 }));
    }

    #[test]
    fn oneof_subset_of_lenrange() {
        let range = Constraint::LenRange { min: 2, max: 5 };
        assert!(
            Constraint::OneOf(vec!["hi".to_string(), "hello".to_string()]).is_subset_of(&range)
        );
        assert!(
            !Constraint::OneOf(vec!["hi".to_string(), "hello!".to_string()]).is_subset_of(&range)
        );
        assert!(!Constraint::OneOf(vec![]).is_subset_of(&range));
    }

    #[test]
    fn lenrange_may_replace_minlen_and_maxlen() {
        let min = Constraint::MinLen(3);
        let max = Constraint::MaxLen(16);
        assert!(Constraint::LenRange { min: 3, max: 8 }.is_subset_of(&min));
        assert!(Constraint::LenRange { min: 5, max: 16 }.is_subset_of(&min));
        assert!(!Constraint::LenRange { min: 2, max: 8 }.is_subset_of(&min));
        assert!(Constraint::LenRange { min: 0, max: 8 }.is_subset_of(&max));
        assert!(Constraint::LenRange { min: 3, max: 16 }.is_subset_of(&max));
        assert!(!Constraint::LenRange { min: 0, max: 20 }.is_subset_of(&max));
        assert!(!Constraint::LenRange { min: 8, max: 3 }.is_subset_of(&min));
    }

    #[test]
    fn minlen_and_maxlen_may_replace_lenrange_when_other_bound_holds() {
        let unbounded = Constraint::LenRange {
            min: 3,
            max: usize::MAX,
        };
        assert!(Constraint::MinLen(3).is_subset_of(&unbounded));
        assert!(Constraint::MinLen(8).is_subset_of(&unbounded));
        assert!(!Constraint::MinLen(2).is_subset_of(&unbounded));

        let bounded = Constraint::LenRange { min: 3, max: 16 };
        assert!(!Constraint::MinLen(8).is_subset_of(&bounded));

        let from_zero = Constraint::LenRange { min: 0, max: 16 };
        assert!(Constraint::MaxLen(16).is_subset_of(&from_zero));
        assert!(Constraint::MaxLen(8).is_subset_of(&from_zero));
        assert!(!Constraint::MaxLen(20).is_subset_of(&from_zero));
        assert!(!Constraint::MaxLen(8).is_subset_of(&bounded));
    }

    #[test]
    fn unclear_lenrange_cross_type_pairs_fail_closed() {
        let range = Constraint::LenRange { min: 2, max: 5 };
        assert!(!range.is_subset_of(&Constraint::Prefix("/tmp/".to_string())));
        assert!(!Constraint::Prefix("/tmp/".to_string()).is_subset_of(&range));
        assert!(!range.is_subset_of(&Constraint::IntRange { min: 1, max: 10 }));
        assert!(!Constraint::IntRange { min: 1, max: 10 }.is_subset_of(&range));
        assert!(!range.is_subset_of(&Constraint::FloatRange {
            min: 0.5,
            max: 10.5
        }));
        assert!(!Constraint::FloatRange {
            min: 0.5,
            max: 10.5
        }
        .is_subset_of(&range));
        // LenRange{2,5} tightens MinLen(2) / MaxLen(5); loosening those fails closed.
        assert!(!range.is_subset_of(&Constraint::MinLen(3)));
        assert!(!range.is_subset_of(&Constraint::MaxLen(4)));
        assert!(!Constraint::MinLen(2).is_subset_of(&range));
        assert!(!Constraint::MaxLen(5).is_subset_of(&range));
    }

    #[test]
    fn charlenrange_subset_of_charlenrange() {
        let inner = Constraint::CharLenRange { min: 3, max: 8 };
        let outer = Constraint::CharLenRange { min: 1, max: 16 };
        assert!(inner.is_subset_of(&outer));
        assert!(!outer.is_subset_of(&inner));
        assert!(!Constraint::CharLenRange { min: 16, max: 1 }.is_subset_of(&outer));
        assert!(!inner.is_subset_of(&Constraint::CharLenRange { min: 16, max: 1 }));
    }

    #[test]
    fn exact_subset_of_charlenrange() {
        let range = Constraint::CharLenRange { min: 2, max: 5 };
        assert!(Constraint::Exact("hi".to_string()).is_subset_of(&range));
        assert!(Constraint::Exact("hello".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("h".to_string()).is_subset_of(&range));
        assert!(!Constraint::Exact("hello!".to_string()).is_subset_of(&range));
        // "é" is one scalar; Exact may replace when the scalar count fits.
        assert!(Constraint::Exact("é".to_string())
            .is_subset_of(&Constraint::CharLenRange { min: 1, max: 1 }));
        assert!(!Constraint::Exact("é".to_string())
            .is_subset_of(&Constraint::CharLenRange { min: 2, max: 2 }));
        assert!(!Constraint::Exact("hi".to_string())
            .is_subset_of(&Constraint::CharLenRange { min: 5, max: 1 }));
    }

    #[test]
    fn oneof_subset_of_charlenrange() {
        let range = Constraint::CharLenRange { min: 2, max: 5 };
        assert!(
            Constraint::OneOf(vec!["hi".to_string(), "hello".to_string()]).is_subset_of(&range)
        );
        assert!(
            !Constraint::OneOf(vec!["hi".to_string(), "hello!".to_string()]).is_subset_of(&range)
        );
        assert!(Constraint::OneOf(vec!["é".to_string(), "漢".to_string()])
            .is_subset_of(&Constraint::CharLenRange { min: 1, max: 1 }));
        assert!(
            !Constraint::OneOf(vec!["é".to_string(), "café".to_string()])
                .is_subset_of(&Constraint::CharLenRange { min: 1, max: 1 })
        );
        assert!(!Constraint::OneOf(vec![]).is_subset_of(&range));
    }

    #[test]
    fn unclear_charlenrange_cross_type_pairs_fail_closed() {
        let range = Constraint::CharLenRange { min: 2, max: 5 };
        assert!(!range.is_subset_of(&Constraint::LenRange { min: 2, max: 5 }));
        assert!(!Constraint::LenRange { min: 2, max: 5 }.is_subset_of(&range));
        assert!(!range.is_subset_of(&Constraint::MinLen(2)));
        assert!(!range.is_subset_of(&Constraint::MaxLen(5)));
        assert!(!Constraint::MinLen(2).is_subset_of(&range));
        assert!(!Constraint::MaxLen(5).is_subset_of(&range));
        assert!(!range.is_subset_of(&Constraint::Prefix("/tmp/".to_string())));
        assert!(!Constraint::Prefix("/tmp/".to_string()).is_subset_of(&range));
        assert!(!range.is_subset_of(&Constraint::IntRange { min: 1, max: 10 }));
        assert!(!Constraint::IntRange { min: 1, max: 10 }.is_subset_of(&range));
        assert!(!range.is_subset_of(&Constraint::FloatRange {
            min: 0.5,
            max: 10.5
        }));
        assert!(!Constraint::FloatRange {
            min: 0.5,
            max: 10.5
        }
        .is_subset_of(&range));
    }

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
    fn json_floatrange() {
        let c = Constraint::FloatRange {
            min: -1.5,
            max: 2.25,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"float_range\""));
        assert!(json.contains("\"min\":-1.5"));
        assert!(json.contains("\"max\":2.25"));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"float_range","value":{"min":0.5,"max":10.5}}"#)
                .unwrap();
        assert_eq!(
            from_cli,
            Constraint::FloatRange {
                min: 0.5,
                max: 10.5
            }
        );
    }

    #[test]
    fn json_lenrange() {
        let c = Constraint::LenRange { min: 1, max: 16 };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"len_range\""));
        assert!(json.contains("\"min\":1"));
        assert!(json.contains("\"max\":16"));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"len_range","value":{"min":0,"max":8}}"#).unwrap();
        assert_eq!(from_cli, Constraint::LenRange { min: 0, max: 8 });
    }

    #[test]
    fn json_charlenrange() {
        let c = Constraint::CharLenRange { min: 1, max: 16 };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"char_len_range\""));
        assert!(json.contains("\"min\":1"));
        assert!(json.contains("\"max\":16"));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"char_len_range","value":{"min":0,"max":8}}"#).unwrap();
        assert_eq!(from_cli, Constraint::CharLenRange { min: 0, max: 8 });
    }

    #[test]
    fn json_prefix_one_of() {
        let c = Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"prefix_one_of\""));
        assert!(json.contains("\"/tmp/\""));
        assert!(json.contains("\"/var/\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"prefix_one_of","value":["/tmp/","/var/"]}"#).unwrap();
        assert_eq!(from_cli, c);
    }

    #[test]
    fn json_suffix_one_of() {
        let c = Constraint::SuffixOneOf(vec![".txt".to_string(), ".md".to_string()]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"suffix_one_of\""));
        assert!(json.contains("\".txt\""));
        assert!(json.contains("\".md\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"suffix_one_of","value":[".txt",".md"]}"#).unwrap();
        assert_eq!(from_cli, c);
    }

    #[test]
    fn json_contains_any() {
        let c = Constraint::ContainsAny(vec!["tmp".to_string(), "var".to_string()]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"contains_any\""));
        assert!(json.contains("\"tmp\""));
        assert!(json.contains("\"var\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"contains_any","value":["tmp","var"]}"#).unwrap();
        assert_eq!(from_cli, c);
    }

    #[test]
    fn json_contains_none() {
        let c = Constraint::ContainsNone(vec!["secret".to_string(), "password".to_string()]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"contains_none\""));
        assert!(json.contains("\"secret\""));
        assert!(json.contains("\"password\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"contains_none","value":["secret","password"]}"#)
                .unwrap();
        assert_eq!(from_cli, c);
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
    fn json_not_contains() {
        let c = Constraint::NotContains("secret".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"not_contains\""));
        assert!(json.contains("\"value\":\"secret\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"not_contains","value":"tmp"}"#).unwrap();
        assert_eq!(from_cli, Constraint::NotContains("tmp".to_string()));
    }

    #[test]
    fn json_not_prefix() {
        let c = Constraint::NotPrefix("/tmp/".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"not_prefix\""));
        assert!(json.contains("\"value\":\"/tmp/\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"not_prefix","value":"/var/"}"#).unwrap();
        assert_eq!(from_cli, Constraint::NotPrefix("/var/".to_string()));
    }

    #[test]
    fn json_not_suffix() {
        let c = Constraint::NotSuffix(".txt".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"not_suffix\""));
        assert!(json.contains("\"value\":\".txt\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"not_suffix","value":".log"}"#).unwrap();
        assert_eq!(from_cli, Constraint::NotSuffix(".log".to_string()));
    }

    #[test]
    fn json_not_matches() {
        let c = Constraint::NotMatches("pat*tern".to_string());
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"not_matches\""));
        assert!(json.contains("\"value\":\"pat*tern\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"not_matches","value":"*.txt"}"#).unwrap();
        assert_eq!(from_cli, Constraint::NotMatches("*.txt".to_string()));
    }

    #[test]
    fn all_check() {
        let c = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Suffix(".txt".to_string()),
        ]);
        assert!(c.check("/tmp/notes.txt"));
        assert!(!c.check("/tmp/notes.rs"));
        assert!(!c.check("/var/notes.txt"));
        assert!(!c.check("notes.txt"));
    }

    #[test]
    fn any_check() {
        let c = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ]);
        assert!(c.check("/tmp/a"));
        assert!(c.check("/var/b"));
        assert!(!c.check("/home/c"));
        assert!(!c.check("tmp/a"));
    }

    #[test]
    fn nested_all_any_check() {
        let c = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Any(vec![
                Constraint::Suffix(".txt".to_string()),
                Constraint::Suffix(".md".to_string()),
            ]),
        ]);
        assert!(c.check("/tmp/a.txt"));
        assert!(c.check("/tmp/a.md"));
        assert!(!c.check("/tmp/a.rs"));
        assert!(!c.check("/var/a.txt"));
    }

    #[test]
    fn empty_all_and_any_fail_closed() {
        let all = Constraint::All(vec![]);
        let any = Constraint::Any(vec![]);
        assert!(all.is_empty_pattern());
        assert!(any.is_empty_pattern());
        assert!(!all.check(""));
        assert!(!all.check("anything"));
        assert!(!any.check(""));
        assert!(!any.check("anything"));
    }

    #[test]
    fn all_or_any_with_empty_child_is_empty_pattern() {
        let all = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Suffix(String::new()),
        ]);
        let any = Constraint::Any(vec![Constraint::Matches(String::new())]);
        assert!(all.is_empty_pattern());
        assert!(any.is_empty_pattern());
        let wrapped = Constraint::All(vec![Constraint::PrefixOneOf(vec![])]);
        assert!(wrapped.is_empty_pattern());
        assert!(!wrapped.check("/tmp/foo"));
        let not_empty = Constraint::Not(Box::new(Constraint::SuffixOneOf(vec![String::new()])));
        assert!(not_empty.is_empty_pattern());
        assert!(!not_empty.check("notes.txt"));
        let any_empty = Constraint::All(vec![Constraint::ContainsAny(vec![])]);
        assert!(any_empty.is_empty_pattern());
        assert!(!any_empty.check("tmp"));
        let none_empty = Constraint::Not(Box::new(Constraint::ContainsNone(vec![String::new()])));
        assert!(none_empty.is_empty_pattern());
        assert!(!none_empty.check("ok"));
        assert!(!all.check("/tmp/a.txt"));
        assert!(!any.check("notes.txt"));
    }

    fn nest_all(depth: usize) -> Constraint {
        let mut c = Constraint::Prefix("/tmp/".to_string());
        for _ in 0..depth {
            c = Constraint::All(vec![c]);
        }
        c
    }

    #[test]
    fn nesting_depth_counts_composites() {
        assert_eq!(Constraint::Prefix("/tmp/".to_string()).nesting_depth(), 0);
        assert_eq!(
            Constraint::All(vec![Constraint::Prefix("/tmp/".to_string())]).nesting_depth(),
            1
        );
        assert_eq!(nest_all(8).nesting_depth(), 8);
        assert_eq!(nest_all(9).nesting_depth(), 9);
        assert!(!nest_all(8).exceeds_max_nesting());
        assert!(nest_all(9).exceeds_max_nesting());
        assert_eq!(MAX_CONSTRAINT_NESTING, 8);
    }

    #[test]
    fn all_subset_of_all_may_tighten_and_add_children() {
        let old = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::MaxLen(20),
        ]);
        let tighter = Constraint::All(vec![
            Constraint::Prefix("/tmp/sub/".to_string()),
            Constraint::MaxLen(10),
        ]);
        let extra = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::MaxLen(20),
            Constraint::Suffix(".txt".to_string()),
        ]);
        assert!(tighter.is_subset_of(&old));
        assert!(extra.is_subset_of(&old));
        assert!(!old.is_subset_of(&tighter));
        assert!(!Constraint::All(vec![Constraint::Prefix("/tmp/".to_string())]).is_subset_of(&old));
        assert!(!Constraint::All(vec![]).is_subset_of(&old));
    }

    #[test]
    fn any_subset_of_any_may_drop_or_tighten_alternatives() {
        let old = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ]);
        let fewer = Constraint::Any(vec![Constraint::Prefix("/tmp/".to_string())]);
        let tighter = Constraint::Any(vec![
            Constraint::Prefix("/tmp/sub/".to_string()),
            Constraint::Prefix("/var/log/".to_string()),
        ]);
        let extra = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
            Constraint::Prefix("/home/".to_string()),
        ]);
        assert!(fewer.is_subset_of(&old));
        assert!(tighter.is_subset_of(&old));
        assert!(!extra.is_subset_of(&old));
        assert!(!old.is_subset_of(&fewer));
        assert!(!Constraint::Any(vec![]).is_subset_of(&old));
    }

    #[test]
    fn exact_subset_of_all_and_any() {
        let all = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Suffix(".txt".to_string()),
        ]);
        let any = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ]);
        assert!(Constraint::Exact("/tmp/a.txt".to_string()).is_subset_of(&all));
        assert!(!Constraint::Exact("/tmp/a.rs".to_string()).is_subset_of(&all));
        assert!(Constraint::Exact("/tmp/a".to_string()).is_subset_of(&any));
        assert!(Constraint::Exact("/var/b".to_string()).is_subset_of(&any));
        assert!(!Constraint::Exact("/home/c".to_string()).is_subset_of(&any));
        assert!(!Constraint::Exact("x".to_string()).is_subset_of(&Constraint::All(vec![])));
        assert!(!Constraint::Exact("x".to_string()).is_subset_of(&Constraint::Any(vec![])));
    }

    #[test]
    fn all_may_become_single_child_when_as_strong() {
        let all = Constraint::All(vec![Constraint::Prefix("/tmp/".to_string())]);
        assert!(Constraint::Prefix("/tmp/sub/".to_string()).is_subset_of(&all));
        assert!(Constraint::Prefix("/tmp/".to_string()).is_subset_of(&all));

        let both = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::MaxLen(10),
        ]);
        assert!(!Constraint::Prefix("/tmp/".to_string()).is_subset_of(&both));
    }

    #[test]
    fn any_may_become_single_child_that_tightens_an_alternative() {
        let any = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ]);
        assert!(Constraint::Prefix("/tmp/sub/".to_string()).is_subset_of(&any));
        assert!(Constraint::Prefix("/tmp/".to_string()).is_subset_of(&any));
        assert!(!Constraint::Prefix("/home/".to_string()).is_subset_of(&any));
    }

    #[test]
    fn single_may_become_all_or_any_when_tighter() {
        let prefix = Constraint::Prefix("/tmp/".to_string());
        assert!(Constraint::All(vec![
            Constraint::Prefix("/tmp/sub/".to_string()),
            Constraint::MaxLen(10),
        ])
        .is_subset_of(&prefix));
        assert!(
            Constraint::Any(vec![Constraint::Prefix("/tmp/sub/".to_string())])
                .is_subset_of(&prefix)
        );
        assert!(!Constraint::Any(vec![
            Constraint::Prefix("/tmp/sub/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ])
        .is_subset_of(&prefix));
        assert!(
            !Constraint::All(vec![Constraint::Prefix("/var/".to_string())]).is_subset_of(&prefix)
        );
    }

    #[test]
    fn all_any_swap_does_not_loosen() {
        let all = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::MaxLen(10),
        ]);
        let any = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::MaxLen(10),
        ]);
        assert!(!any.is_subset_of(&all));
        assert!(all.is_subset_of(&any));

        let exact_any = Constraint::Any(vec![Constraint::Exact("/tmp/a".to_string())]);
        assert!(exact_any.is_subset_of(&all));
    }

    #[test]
    fn oneof_subset_of_all_and_any() {
        let all = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Suffix(".txt".to_string()),
        ]);
        let any = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ]);
        assert!(
            Constraint::OneOf(vec!["/tmp/a.txt".to_string(), "/tmp/b.txt".to_string()])
                .is_subset_of(&all)
        );
        assert!(
            !Constraint::OneOf(vec!["/tmp/a.txt".to_string(), "/tmp/b.rs".to_string()])
                .is_subset_of(&all)
        );
        assert!(
            Constraint::OneOf(vec!["/tmp/a".to_string(), "/var/b".to_string()]).is_subset_of(&any)
        );
        assert!(
            !Constraint::OneOf(vec!["/tmp/a".to_string(), "/home/c".to_string()])
                .is_subset_of(&any)
        );
    }

    #[test]
    fn json_all() {
        let c = Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Suffix(".txt".to_string()),
        ]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"all\""));
        assert!(json.contains("\"type\":\"prefix\""));
        assert!(json.contains("\"type\":\"suffix\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint = serde_json::from_str(
            r#"{"type":"all","value":[{"type":"prefix","value":"/tmp/"},{"type":"max_len","value":10}]}"#,
        )
        .unwrap();
        assert_eq!(
            from_cli,
            Constraint::All(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::MaxLen(10)
            ])
        );
    }

    #[test]
    fn not_check() {
        let c = Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string())));
        assert!(c.check("/var/out"));
        assert!(c.check("notes.txt"));
        assert!(!c.check("/tmp/a"));
        assert!(!c.check("/tmp/"));
    }

    #[test]
    fn nested_not_all_check() {
        let c = Constraint::Not(Box::new(Constraint::All(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Suffix(".txt".to_string()),
        ])));
        assert!(c.check("/tmp/a.rs"));
        assert!(c.check("/var/a.txt"));
        assert!(!c.check("/tmp/a.txt"));
    }

    #[test]
    fn not_with_empty_child_fails_closed() {
        let c = Constraint::Not(Box::new(Constraint::Suffix(String::new())));
        assert!(c.is_empty_pattern());
        assert!(!c.check(""));
        assert!(!c.check("anything"));
        assert!(!c.check("/tmp/a"));
    }

    fn nest_not(depth: usize) -> Constraint {
        let mut c = Constraint::Prefix("/tmp/".to_string());
        for _ in 0..depth {
            c = Constraint::Not(Box::new(c));
        }
        c
    }

    #[test]
    fn not_nesting_depth_counts_like_all() {
        assert_eq!(
            Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string()))).nesting_depth(),
            1
        );
        assert_eq!(nest_not(8).nesting_depth(), 8);
        assert_eq!(nest_not(9).nesting_depth(), 9);
        assert!(!nest_not(8).exceeds_max_nesting());
        assert!(nest_not(9).exceeds_max_nesting());
    }

    #[test]
    fn not_subset_of_not_widens_inner() {
        let old = Constraint::Not(Box::new(Constraint::Prefix("/tmp/sub/".to_string())));
        let tighter = Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string())));
        let looser = Constraint::Not(Box::new(Constraint::Prefix("/tmp/sub/pub/".to_string())));
        assert!(tighter.is_subset_of(&old));
        assert!(!old.is_subset_of(&tighter));
        assert!(!looser.is_subset_of(&old));
        assert!(!Constraint::Not(Box::new(Constraint::Suffix(String::new()))).is_subset_of(&old));
    }

    #[test]
    fn exact_subset_of_not() {
        let not_tmp = Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string())));
        assert!(Constraint::Exact("/var/out".to_string()).is_subset_of(&not_tmp));
        assert!(!Constraint::Exact("/tmp/a".to_string()).is_subset_of(&not_tmp));
        assert!(
            !Constraint::Exact("x".to_string()).is_subset_of(&Constraint::Not(Box::new(
                Constraint::Suffix(String::new())
            )))
        );
    }

    #[test]
    fn oneof_subset_of_not() {
        let not_tmp = Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string())));
        assert!(
            Constraint::OneOf(vec!["/var/a".to_string(), "/home/b".to_string()])
                .is_subset_of(&not_tmp)
        );
        assert!(
            !Constraint::OneOf(vec!["/var/a".to_string(), "/tmp/b".to_string()])
                .is_subset_of(&not_tmp)
        );
        assert!(!Constraint::OneOf(vec![]).is_subset_of(&not_tmp));
    }

    #[test]
    fn nested_not_any_check() {
        let c = Constraint::Not(Box::new(Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ])));
        assert!(c.check("/home/c"));
        assert!(!c.check("/tmp/a"));
        assert!(!c.check("/var/b"));
    }

    #[test]
    fn not_is_not_subset_of_not_prefix() {
        let not = Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string())));
        let not_prefix = Constraint::NotPrefix("/tmp/".to_string());
        assert!(!not.is_subset_of(&not_prefix));
        assert!(!not_prefix.is_subset_of(&not));
    }

    #[test]
    fn not_not_does_not_collapse_to_inner() {
        let inner = Constraint::Prefix("/tmp/".to_string());
        let double = Constraint::Not(Box::new(Constraint::Not(Box::new(inner.clone()))));
        assert!(!double.is_subset_of(&inner));
        assert!(!inner.is_subset_of(&double));
    }

    #[test]
    fn json_not() {
        let c = Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string())));
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"not\""));
        assert!(json.contains("\"type\":\"prefix\""));
        assert!(json.contains("\"/tmp/\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint =
            serde_json::from_str(r#"{"type":"not","value":{"type":"suffix","value":".bak"}}"#)
                .unwrap();
        assert_eq!(
            from_cli,
            Constraint::Not(Box::new(Constraint::Suffix(".bak".to_string())))
        );
    }

    #[test]
    fn json_any() {
        let c = Constraint::Any(vec![
            Constraint::Prefix("/tmp/".to_string()),
            Constraint::Prefix("/var/".to_string()),
        ]);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"type\":\"any\""));

        let parsed: Constraint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);

        let from_cli: Constraint = serde_json::from_str(
            r#"{"type":"any","value":[{"type":"suffix","value":".txt"},{"type":"suffix","value":".md"}]}"#,
        )
        .unwrap();
        assert_eq!(
            from_cli,
            Constraint::Any(vec![
                Constraint::Suffix(".txt".to_string()),
                Constraint::Suffix(".md".to_string())
            ])
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
