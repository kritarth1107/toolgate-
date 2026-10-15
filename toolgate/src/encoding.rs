//! Canonical byte encoding for tokens.
//!
//! Format v1 (all integers are big-endian):
//! - tool_name: u16 length + UTF-8 bytes
//! - arg_keys_count: u16
//! - for each arg_key: u16 length + UTF-8 bytes (keys sorted lexicographically)
//! - expiry: u64 (unix seconds)
//! - nonce: u16 length + bytes
//!
//! Format v2 (backward-compatible extension):
//! - All v1 fields
//! - audience: u16 length + UTF-8 bytes (length 0 means unbound/None)
//!
//! Format v3 (backward-compatible extension):
//! - All v2 fields
//! - kid: u16 length + UTF-8 bytes (length 0 means no key id)
//!
//! Format v4 (backward-compatible extension):
//! - All v3 fields
//! - constraints_count: u16
//! - for each constraint (sorted by key):
//!   - key: u16 length + UTF-8 bytes
//!   - constraint_type: u8 (0=Exact, 1=OneOf, 2=Prefix, 3=MaxLen, 4=IntRange, 5=Suffix, 6=Contains, 7=MinLen, 8=Matches, 9=NotEquals, 10=NotOneOf, 11=NotContains, 12=NotPrefix, 13=NotSuffix, 14=NotMatches, 15=All, 16=Any, 17=Not, 18=FloatRange, 19=LenRange, 20=CharLenRange, 21=PrefixOneOf, 22=SuffixOneOf, 23=ContainsAny, 24=ContainsNone, 25=MatchesAny, 26=MatchesNone, 27=PrefixNone, 28=SuffixNone, 29=IntOneOf, 30=IntNone, 31=FloatOneOf, 32=FloatNone, 33=LenOneOf, 34=LenNone, 35=CharLenOneOf, 36=CharLenNone, 37=MinCharLen, 38=MaxCharLen, 39=MinInt, 40=MaxInt, 41=MinFloat, 42=MaxFloat, 43=ExclusiveMinFloat, 44=ExclusiveMaxFloat, 45=ExclusiveMinInt, 46=ExclusiveMaxInt, 47=ExclusiveMinLen, 48=ExclusiveMaxLen)
//!   - constraint_data: type-specific encoding
//!
//! Format v5 (backward-compatible extension):
//! - All v4 fields
//! - jti: u16 length + UTF-8 bytes (length 0 means no token identifier)
//!
//! Format v6 (backward-compatible extension):
//! - All v5 fields
//! - Trailer is omitted when nbf is absent, depth is 0, and max_depth is absent
//!   (tokens without the new fields encode identically to v5)
//! - flags: u8 bitfield (bit 0 = nbf, bit 1 = depth>0, bit 2 = max_depth)
//! - nbf: u64 (only if bit 0 is set)
//! - depth: u32 (only if bit 1 is set)
//! - max_depth: u32 (only if bit 2 is set)
//!
//! Format v7 (backward-compatible extension):
//! - All v6 fields
//! - flags bit 3 = required_keys present
//! - required_keys: u16 count + (for each, sorted unique: u16 length + UTF-8)
//!   only if bit 3 is set
//! - Tokens without required_keys encode identically to v6 (or v5 when the
//!   v6 trailer is also omitted)
//!
//! Constraint data encoding:
//! - Exact: u16 length + UTF-8 bytes
//! - OneOf: u16 count + (for each value, sorted: u16 length + UTF-8 bytes)
//! - Prefix: u16 length + UTF-8 bytes
//! - MaxLen: u64
//! - IntRange: i64 min + i64 max
//! - Suffix: u16 length + UTF-8 bytes
//! - Contains: u16 length + UTF-8 bytes
//! - MinLen: u64
//! - Matches: u16 length + UTF-8 bytes
//! - NotEquals: u16 length + UTF-8 bytes
//! - NotOneOf: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - NotContains: u16 length + UTF-8 bytes
//! - NotPrefix: u16 length + UTF-8 bytes
//! - NotSuffix: u16 length + UTF-8 bytes
//! - NotMatches: u16 length + UTF-8 bytes
//! - All: u16 count + (for each child: constraint type + data)
//! - Any: u16 count + (for each child: constraint type + data)
//! - Not: nested child constraint type + data
//! - FloatRange: IEEE-754 f64 min + f64 max (big-endian bits, same
//!   `to_be_bytes` style as IntRange's i64 pair)
//! - LenRange: u64 min + u64 max (same length encoding as MaxLen/MinLen)
//! - CharLenRange: u64 min + u64 max (same length encoding as LenRange/MaxLen/MinLen)
//! - PrefixOneOf: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - SuffixOneOf: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - ContainsAny: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - ContainsNone: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - MatchesAny: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - MatchesNone: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - PrefixNone: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - SuffixNone: u16 count + (for each value, sorted unique: u16 length + UTF-8 bytes)
//! - IntOneOf: u16 count + (for each value, sorted unique: i64 big-endian)
//! - IntNone: u16 count + (for each value, sorted unique: i64 big-endian)
//! - FloatOneOf: u16 count + (for each value, sorted unique: IEEE-754 f64 big-endian bits)
//! - FloatNone: u16 count + (for each value, sorted unique: IEEE-754 f64 big-endian bits)
//! - LenOneOf: u16 count + (for each value, sorted unique: u64 big-endian length)
//! - LenNone: u16 count + (for each value, sorted unique: u64 big-endian length)
//! - CharLenOneOf: u16 count + (for each value, sorted unique: u64 big-endian scalar count)
//! - CharLenNone: u16 count + (for each value, sorted unique: u64 big-endian scalar count)
//! - MinCharLen: u64 (same length encoding as MinLen, scalar-count unit)
//! - MaxCharLen: u64 (same length encoding as MaxLen, scalar-count unit)
//! - MinInt: i64 (same integer encoding as one IntRange bound)
//! - MaxInt: i64 (same integer encoding as one IntRange bound)
//! - MinFloat: IEEE-754 f64 (same float encoding as one FloatRange bound)
//! - MaxFloat: IEEE-754 f64 (same float encoding as one FloatRange bound)
//! - ExclusiveMinFloat: IEEE-754 f64 (same float encoding as one FloatRange bound)
//! - ExclusiveMaxFloat: IEEE-754 f64 (same float encoding as one FloatRange bound)
//! - ExclusiveMinInt: i64 (same integer encoding as one IntRange bound)
//! - ExclusiveMaxInt: i64 (same integer encoding as one IntRange bound)
//! - ExclusiveMinLen: u64 (same length encoding as MinLen)
//! - ExclusiveMaxLen: u64 (same length encoding as MaxLen)
//!
//! The v5 format appends jti after constraints. Tokens without jti
//! encode identically to v4. Tokens without constraints and without jti
//! encode identically to v3. The v6 format appends nbf/depth/max_depth
//! only when at least one is set, so tokens without those fields encode
//! identically to v5. The v7 format appends required_keys after the v6
//! trailer (flag bit 3); tokens without required keys encode identically
//! to v6.

use crate::constraint::{Constraint, Constraints};

/// Encode a token's fields into canonical bytes for signing/verification (v1 format).
pub fn encode_canonical(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
) -> Vec<u8> {
    encode_canonical_v6(
        tool_name, arg_keys, expiry, nonce, None, None, None, None, None, 0, None,
    )
}

/// Encode a token's fields into canonical bytes for signing/verification (v2 format with audience).
pub fn encode_canonical_v2(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
) -> Vec<u8> {
    encode_canonical_v6(
        tool_name, arg_keys, expiry, nonce, audience, None, None, None, None, 0, None,
    )
}

/// Encode a token's fields into canonical bytes for signing/verification (v3 format with kid).
pub fn encode_canonical_v3(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
    kid: Option<&str>,
) -> Vec<u8> {
    encode_canonical_v6(
        tool_name, arg_keys, expiry, nonce, audience, kid, None, None, None, 0, None,
    )
}

/// Encode a token's fields into canonical bytes for signing/verification (v4 format with constraints).
pub fn encode_canonical_v4(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
    kid: Option<&str>,
    constraints: Option<&Constraints>,
) -> Vec<u8> {
    encode_canonical_v6(
        tool_name,
        arg_keys,
        expiry,
        nonce,
        audience,
        kid,
        constraints,
        None,
        None,
        0,
        None,
    )
}

/// Encode a token's fields into canonical bytes for signing/verification (v5 format with jti).
#[allow(clippy::too_many_arguments)]
pub fn encode_canonical_v5(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
    kid: Option<&str>,
    constraints: Option<&Constraints>,
    jti: Option<&str>,
) -> Vec<u8> {
    encode_canonical_v6(
        tool_name,
        arg_keys,
        expiry,
        nonce,
        audience,
        kid,
        constraints,
        jti,
        None,
        0,
        None,
    )
}

/// Encode a token's fields into canonical bytes (v6 format with nbf and depth).
///
/// When `nbf` is `None`, `depth` is 0, and `max_depth` is `None`, the output
/// is identical to [`encode_canonical_v5`].
#[allow(clippy::too_many_arguments)]
pub fn encode_canonical_v6(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
    kid: Option<&str>,
    constraints: Option<&Constraints>,
    jti: Option<&str>,
    nbf: Option<u64>,
    depth: u32,
    max_depth: Option<u32>,
) -> Vec<u8> {
    encode_canonical_v7(
        tool_name,
        arg_keys,
        expiry,
        nonce,
        audience,
        kid,
        constraints,
        jti,
        nbf,
        depth,
        max_depth,
        &[],
    )
}

/// Encode a token's fields into canonical bytes (v7 format with required keys).
///
/// When `required_keys` is empty the output is identical to
/// [`encode_canonical_v6`] for the same other fields. Tokens without
/// nbf/depth/max_depth/required_keys still encode identically to v5.
#[allow(clippy::too_many_arguments)]
pub fn encode_canonical_v7(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
    kid: Option<&str>,
    constraints: Option<&Constraints>,
    jti: Option<&str>,
    nbf: Option<u64>,
    depth: u32,
    max_depth: Option<u32>,
    required_keys: &[String],
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Tool name: length-prefixed
    let name_bytes = tool_name.as_bytes();
    buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(name_bytes);

    // Arg keys: count + each length-prefixed, sorted
    let mut sorted_keys: Vec<&str> = arg_keys.iter().map(|s| s.as_str()).collect();
    sorted_keys.sort();

    buf.extend_from_slice(&(sorted_keys.len() as u16).to_be_bytes());
    for key in sorted_keys {
        let key_bytes = key.as_bytes();
        buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(key_bytes);
    }

    // Expiry: u64 big-endian
    buf.extend_from_slice(&expiry.to_be_bytes());

    // Nonce: length-prefixed
    buf.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    buf.extend_from_slice(nonce);

    // Audience: length-prefixed (0 means unbound)
    match audience {
        Some(aud) => {
            let aud_bytes = aud.as_bytes();
            buf.extend_from_slice(&(aud_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(aud_bytes);
        }
        None => {
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    // Kid: length-prefixed (0 means no key id)
    match kid {
        Some(k) => {
            let kid_bytes = k.as_bytes();
            buf.extend_from_slice(&(kid_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(kid_bytes);
        }
        None => {
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    // Constraints: only encoded if non-empty (v4 extension)
    // Empty/None constraints produce identical encoding to v3 for backward compatibility
    if let Some(c) = constraints {
        if !c.is_empty() {
            buf.extend_from_slice(&(c.len() as u16).to_be_bytes());
            // BTreeMap iterates in sorted order by key
            for (key, constraint) in c.iter() {
                // Key: length-prefixed
                let key_bytes = key.as_bytes();
                buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(key_bytes);

                // Constraint type + data
                encode_constraint(&mut buf, constraint);
            }
        }
    }

    // Jti: only encoded if present (v5 extension)
    // Tokens without jti produce identical encoding to v4 for backward compatibility
    if let Some(j) = jti {
        let jti_bytes = j.as_bytes();
        buf.extend_from_slice(&(jti_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(jti_bytes);
    }

    // nbf / depth / max_depth / required_keys: only encoded if any is set
    // (v6 + v7 extensions). Tokens without these fields encode identically
    // to v5. Tokens with v6 fields and no required keys encode identically
    // to v6 (flag bit 3 unset, no key list).
    let mut required: Vec<&str> = required_keys
        .iter()
        .filter(|k| !k.is_empty())
        .map(|s| s.as_str())
        .collect();
    required.sort_unstable();
    required.dedup();

    if nbf.is_some() || depth > 0 || max_depth.is_some() || !required.is_empty() {
        let mut flags = 0u8;
        if nbf.is_some() {
            flags |= 0x01;
        }
        if depth > 0 {
            flags |= 0x02;
        }
        if max_depth.is_some() {
            flags |= 0x04;
        }
        if !required.is_empty() {
            flags |= 0x08;
        }
        buf.push(flags);
        if let Some(n) = nbf {
            buf.extend_from_slice(&n.to_be_bytes());
        }
        if depth > 0 {
            buf.extend_from_slice(&depth.to_be_bytes());
        }
        if let Some(m) = max_depth {
            buf.extend_from_slice(&m.to_be_bytes());
        }
        if !required.is_empty() {
            buf.extend_from_slice(&(required.len() as u16).to_be_bytes());
            for key in required {
                let key_bytes = key.as_bytes();
                buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(key_bytes);
            }
        }
    }

    buf
}

/// Encode a single constraint to the buffer.
fn encode_constraint(buf: &mut Vec<u8>, constraint: &Constraint) {
    match constraint {
        Constraint::Exact(value) => {
            buf.push(0); // type = Exact
            let value_bytes = value.as_bytes();
            buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(value_bytes);
        }
        Constraint::OneOf(values) => {
            buf.push(1); // type = OneOf
            buf.extend_from_slice(&(values.len() as u16).to_be_bytes());
            // Sort values for deterministic encoding
            let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            sorted.sort();
            for value in sorted {
                let value_bytes = value.as_bytes();
                buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(value_bytes);
            }
        }
        Constraint::Prefix(prefix) => {
            buf.push(2); // type = Prefix
            encode_len_prefixed(buf, prefix);
        }
        Constraint::MaxLen(max) => {
            buf.push(3); // type = MaxLen
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
        Constraint::IntRange { min, max } => {
            buf.push(4); // type = IntRange
            buf.extend_from_slice(&min.to_be_bytes());
            buf.extend_from_slice(&max.to_be_bytes());
        }
        Constraint::Suffix(suffix) => {
            buf.push(5); // type = Suffix
            encode_len_prefixed(buf, suffix);
        }
        Constraint::Contains(needle) => {
            buf.push(6); // type = Contains
            encode_len_prefixed(buf, needle);
        }
        Constraint::MinLen(min) => {
            buf.push(7); // type = MinLen
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
        }
        Constraint::Matches(pattern) => {
            buf.push(8); // type = Matches
            encode_len_prefixed(buf, pattern);
        }
        Constraint::NotEquals(value) => {
            buf.push(9); // type = NotEquals
            encode_len_prefixed(buf, value);
        }
        Constraint::NotOneOf(values) => {
            buf.push(10); // type = NotOneOf
                          // Sort and unique values for deterministic encoding (same spirit as OneOf)
            let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            sorted.sort();
            sorted.dedup();
            buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
            for value in sorted {
                encode_len_prefixed(buf, value);
            }
        }
        Constraint::NotContains(needle) => {
            buf.push(11); // type = NotContains
            encode_len_prefixed(buf, needle);
        }
        Constraint::NotPrefix(prefix) => {
            buf.push(12); // type = NotPrefix
            encode_len_prefixed(buf, prefix);
        }
        Constraint::NotSuffix(suffix) => {
            buf.push(13); // type = NotSuffix
            encode_len_prefixed(buf, suffix);
        }
        Constraint::NotMatches(pattern) => {
            buf.push(14); // type = NotMatches
            encode_len_prefixed(buf, pattern);
        }
        Constraint::All(children) => {
            buf.push(15); // type = All
            buf.extend_from_slice(&(children.len() as u16).to_be_bytes());
            for child in children {
                encode_constraint(buf, child);
            }
        }
        Constraint::Any(children) => {
            buf.push(16); // type = Any
            buf.extend_from_slice(&(children.len() as u16).to_be_bytes());
            for child in children {
                encode_constraint(buf, child);
            }
        }
        Constraint::Not(child) => {
            buf.push(17); // type = Not
            encode_constraint(buf, child);
        }
        // IEEE-754 f64 big-endian bits — same two-bound layout as IntRange
        // (`to_be_bytes` of each endpoint) but using f64 rather than i64.
        Constraint::FloatRange { min, max } => {
            buf.push(18); // type = FloatRange
            buf.extend_from_slice(&min.to_be_bytes());
            buf.extend_from_slice(&max.to_be_bytes());
        }
        // Two u64 big-endian lengths — same unit/encoding as MaxLen/MinLen.
        Constraint::LenRange { min, max } => {
            buf.push(19); // type = LenRange
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
        // Two u64 big-endian scalar counts — same layout as LenRange.
        Constraint::CharLenRange { min, max } => {
            buf.push(20); // type = CharLenRange
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
        Constraint::PrefixOneOf(values) => {
            buf.push(21); // type = PrefixOneOf
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::SuffixOneOf(values) => {
            buf.push(22); // type = SuffixOneOf
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::ContainsAny(values) => {
            buf.push(23); // type = ContainsAny
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::ContainsNone(values) => {
            buf.push(24); // type = ContainsNone
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::MatchesAny(values) => {
            buf.push(25); // type = MatchesAny
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::MatchesNone(values) => {
            buf.push(26); // type = MatchesNone
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::PrefixNone(values) => {
            buf.push(27); // type = PrefixNone
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::SuffixNone(values) => {
            buf.push(28); // type = SuffixNone
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::IntOneOf(values) => {
            buf.push(29); // type = IntOneOf
            encode_sorted_unique_i64s(buf, values);
        }
        Constraint::IntNone(values) => {
            buf.push(30); // type = IntNone
            encode_sorted_unique_i64s(buf, values);
        }
        Constraint::FloatOneOf(values) => {
            buf.push(31); // type = FloatOneOf
            encode_sorted_unique_f64s(buf, values);
        }
        Constraint::FloatNone(values) => {
            buf.push(32); // type = FloatNone
            encode_sorted_unique_f64s(buf, values);
        }
        Constraint::LenOneOf(values) => {
            buf.push(33); // type = LenOneOf
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::LenNone(values) => {
            buf.push(34); // type = LenNone
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::CharLenOneOf(values) => {
            buf.push(35); // type = CharLenOneOf
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::CharLenNone(values) => {
            buf.push(36); // type = CharLenNone
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::MinCharLen(min) => {
            buf.push(37); // type = MinCharLen
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
        }
        Constraint::MaxCharLen(max) => {
            buf.push(38); // type = MaxCharLen
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
        Constraint::MinInt(min) => {
            buf.push(39); // type = MinInt
            buf.extend_from_slice(&min.to_be_bytes());
        }
        Constraint::MaxInt(max) => {
            buf.push(40); // type = MaxInt
            buf.extend_from_slice(&max.to_be_bytes());
        }
        Constraint::MinFloat(min) => {
            buf.push(41); // type = MinFloat
            buf.extend_from_slice(&min.to_be_bytes());
        }
        Constraint::MaxFloat(max) => {
            buf.push(42); // type = MaxFloat
            buf.extend_from_slice(&max.to_be_bytes());
        }
        Constraint::ExclusiveMinFloat(min) => {
            buf.push(43); // type = ExclusiveMinFloat
            buf.extend_from_slice(&min.to_be_bytes());
        }
        Constraint::ExclusiveMaxFloat(max) => {
            buf.push(44); // type = ExclusiveMaxFloat
            buf.extend_from_slice(&max.to_be_bytes());
        }
        Constraint::ExclusiveMinInt(min) => {
            buf.push(45); // type = ExclusiveMinInt
            buf.extend_from_slice(&min.to_be_bytes());
        }
        Constraint::ExclusiveMaxInt(max) => {
            buf.push(46); // type = ExclusiveMaxInt
            buf.extend_from_slice(&max.to_be_bytes());
        }
        Constraint::ExclusiveMinLen(min) => {
            buf.push(47); // type = ExclusiveMinLen
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
        }
        Constraint::ExclusiveMaxLen(max) => {
            buf.push(48); // type = ExclusiveMaxLen
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
    }
}

/// Encode a UTF-8 string as u16 length + bytes.
fn encode_len_prefixed(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Encode a string list as u16 count + each len-prefixed string,
/// sorted and unique (same layout as OneOf / NotOneOf).
fn encode_sorted_unique_strings(buf: &mut Vec<u8>, values: &[String]) {
    let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
    sorted.sort();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        encode_len_prefixed(buf, value);
    }
}

/// Encode an i64 list as u16 count + each big-endian i64,
/// sorted and unique (same spirit as OneOf / NotOneOf).
fn encode_sorted_unique_i64s(buf: &mut Vec<u8>, values: &[i64]) {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Encode an f64 list as u16 count + each IEEE-754 big-endian bit
/// pattern, sorted and unique by bits (same spirit as IntOneOf).
fn encode_sorted_unique_f64s(buf: &mut Vec<u8>, values: &[f64]) {
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|v| v.to_bits());
    sorted.dedup_by_key(|v| v.to_bits());
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

/// Encode a usize list as u16 count + each big-endian u64,
/// sorted and unique (same length encoding as MaxLen/MinLen).
fn encode_sorted_unique_usizes(buf: &mut Vec<u8>, values: &[usize]) {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        buf.extend_from_slice(&(value as u64).to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_deterministic() {
        let bytes1 = encode_canonical(
            "read_file",
            &["path".into(), "limit".into()],
            1700000000,
            &[1, 2, 3, 4],
        );
        let bytes2 = encode_canonical(
            "read_file",
            &["limit".into(), "path".into()],
            1700000000,
            &[1, 2, 3, 4],
        );
        // Keys are sorted, so order shouldn't matter
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn encoding_is_stable() {
        // Known inputs produce known output - this ensures cross-implementation compatibility
        // v3 format includes audience and kid (length 0 for unbound/none)
        let bytes = encode_canonical("read", &["a".into(), "b".into()], 1000, &[0xAB, 0xCD]);

        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name: len=4, "read"
            0x00, 0x02, // arg_keys count
            0x00, 0x01, b'a', // key "a"
            0x00, 0x01, b'b', // key "b"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // expiry 1000
            0x00, 0x02, 0xAB, 0xCD, // nonce: len=2, bytes
            0x00, 0x00, // audience length 0 (unbound)
            0x00, 0x00, // kid length 0 (none)
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_empty_keys() {
        let bytes = encode_canonical("tool", &[], 0, &[]);

        let expected: Vec<u8> = vec![
            0x00, 0x04, b't', b'o', b'o', b'l', // tool_name
            0x00, 0x00, // zero arg_keys
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // expiry 0
            0x00, 0x00, // empty nonce
            0x00, 0x00, // audience length 0
            0x00, 0x00, // kid length 0
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_with_audience() {
        let bytes = encode_canonical_v2("read", &["a".into()], 1000, &[0xAB], Some("client-123"));

        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name
            0x00, 0x01, // arg_keys count
            0x00, 0x01, b'a', // key "a"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // expiry 1000
            0x00, 0x01, 0xAB, // nonce
            0x00, 0x0A, // audience length 10
            b'c', b'l', b'i', b'e', b'n', b't', b'-', b'1', b'2', b'3', // "client-123"
            0x00, 0x00, // kid length 0 (none)
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_with_kid() {
        let bytes = encode_canonical_v3("read", &["a".into()], 1000, &[0xAB], None, Some("key-1"));

        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name
            0x00, 0x01, // arg_keys count
            0x00, 0x01, b'a', // key "a"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // expiry 1000
            0x00, 0x01, 0xAB, // nonce
            0x00, 0x00, // audience length 0 (unbound)
            0x00, 0x05, // kid length 5
            b'k', b'e', b'y', b'-', b'1', // "key-1"
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_with_audience_and_kid() {
        let bytes = encode_canonical_v3("r", &[], 0, &[], Some("aud"), Some("k1"));

        let expected: Vec<u8> = vec![
            0x00, 0x01, b'r', // tool_name
            0x00, 0x00, // zero arg_keys
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // expiry 0
            0x00, 0x00, // empty nonce
            0x00, 0x03, b'a', b'u', b'd', // audience "aud"
            0x00, 0x02, b'k', b'1', // kid "k1"
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_none_audience_equals_empty() {
        let with_none = encode_canonical_v2("tool", &[], 0, &[], None);
        let without_audience = encode_canonical("tool", &[], 0, &[]);
        assert_eq!(with_none, without_audience);
    }

    #[test]
    fn encoding_v2_equals_v3_without_kid() {
        let v2 = encode_canonical_v2("tool", &["a".into()], 1000, &[1, 2], Some("aud"));
        let v3 = encode_canonical_v3("tool", &["a".into()], 1000, &[1, 2], Some("aud"), None);
        assert_eq!(v2, v3);
    }

    #[test]
    fn encoding_v3_equals_v4_without_constraints() {
        let v3 = encode_canonical_v3(
            "tool",
            &["a".into()],
            1000,
            &[1, 2],
            Some("aud"),
            Some("k1"),
        );
        let v4 = encode_canonical_v4(
            "tool",
            &["a".into()],
            1000,
            &[1, 2],
            Some("aud"),
            Some("k1"),
            None,
        );
        assert_eq!(v3, v4);
    }

    #[test]
    fn encoding_v4_empty_constraints_equals_none() {
        use std::collections::BTreeMap;
        let empty: Constraints = BTreeMap::new();
        let v4_none = encode_canonical_v4("tool", &[], 0, &[], None, None, None);
        let v4_empty = encode_canonical_v4("tool", &[], 0, &[], None, None, Some(&empty));
        assert_eq!(v4_none, v4_empty);
    }

    #[test]
    fn encoding_with_constraints() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let bytes = encode_canonical_v4(
            "read",
            &["path".into()],
            1000,
            &[],
            None,
            None,
            Some(&constraints),
        );

        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name
            0x00, 0x01, // 1 arg key
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // expiry 1000
            0x00, 0x00, // empty nonce
            0x00, 0x00, // no audience
            0x00, 0x00, // no kid
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // constraint key "path"
            0x02, // type = Prefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // prefix "/tmp/"
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_constraint_exact() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("mode".to_string(), Constraint::Exact("read".to_string()));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // Find the constraint section (after kid length 0x00 0x00)
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'm', b'o', b'd', b'e', // key "mode"
            0x00, // type = Exact
            0x00, 0x04, b'r', b'e', b'a', b'd', // value "read"
        ]));
    }

    #[test]
    fn encoding_constraint_oneof() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["write".to_string(), "read".to_string()]), // unsorted
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // Values should be sorted in encoding
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'm', b'o', b'd', b'e', // key "mode"
            0x01, // type = OneOf
            0x00, 0x02, // 2 values
            0x00, 0x04, b'r', b'e', b'a', b'd', // "read" (sorted first)
            0x00, 0x05, b'w', b'r', b'i', b't', b'e', // "write" (sorted second)
        ]));
    }

    #[test]
    fn encoding_constraint_maxlen() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::MaxLen(256));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x03, // type = MaxLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // u64 256
        ]));
    }

    #[test]
    fn encoding_constraint_intrange() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "n".to_string(),
            Constraint::IntRange {
                min: -100,
                max: 100,
            },
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // i64 -100 = 0xFFFFFFFFFFFFFF9C, i64 100 = 0x0000000000000064
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'n', // key "n"
            0x04, // type = IntRange
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x9C, // min = -100
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // max = 100
        ]));
    }

    #[test]
    fn encoding_constraint_floatrange() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "n".to_string(),
            Constraint::FloatRange { min: 1.0, max: 2.0 },
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 1.0 = 0x3FF0000000000000, 2.0 = 0x4000000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'n', // key "n"
            0x12, // type = FloatRange
            0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // min = 1.0
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max = 2.0
        ]));
    }

    #[test]
    fn encoding_constraint_suffix() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::Suffix(".txt".to_string()));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x05, // type = Suffix
            0x00, 0x04, b'.', b't', b'x', b't', // suffix ".txt"
        ]));
    }

    #[test]
    fn encoding_constraint_contains() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Contains("tmp".to_string()));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x06, // type = Contains
            0x00, 0x03, b't', b'm', b'p', // needle "tmp"
        ]));
    }

    #[test]
    fn encoding_constraint_minlen() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::MinLen(8));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x07, // type = MinLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // u64 8
        ]));
    }

    #[test]
    fn encoding_constraint_matches() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::Matches("*.txt".to_string()));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x08, // type = Matches
            0x00, 0x05, b'*', b'.', b't', b'x', b't', // pattern "*.txt"
        ]));
    }

    #[test]
    fn encoding_without_minlen_identical_to_prior() {
        // Tokens that do not use MinLen must keep the 0.16.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::Suffix(".txt".to_string()));
        constraints.insert("path".to_string(), Constraint::Contains("tmp".to_string()));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // Sorted by key: "name" then "path"
        assert!(bytes.ends_with(&[
            0x00, 0x02, // 2 constraints
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x05, // type = Suffix
            0x00, 0x04, b'.', b't', b'x', b't', // suffix ".txt"
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x06, // type = Contains
            0x00, 0x03, b't', b'm', b'p', // needle "tmp"
        ]));
    }

    #[test]
    fn encoding_without_matches_identical_to_prior() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::MinLen(8));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x07, // type = MinLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // u64 8
        ]));
    }

    #[test]
    fn encoding_constraint_not_equals() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "role".to_string(),
            Constraint::NotEquals("admin".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'r', b'o', b'l', b'e', // key "role"
            0x09, // type = NotEquals
            0x00, 0x05, b'a', b'd', b'm', b'i', b'n', // value "admin"
        ]));
    }

    #[test]
    fn encoding_constraint_not_one_of() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "role".to_string(),
            Constraint::NotOneOf(vec![
                "root".to_string(),
                "admin".to_string(),
                "admin".to_string(),
            ]), // unsorted + duplicate
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // Values should be sorted and unique in encoding
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'r', b'o', b'l', b'e', // key "role"
            0x0A, // type = NotOneOf
            0x00, 0x02, // 2 unique values
            0x00, 0x05, b'a', b'd', b'm', b'i', b'n', // "admin" (sorted first)
            0x00, 0x04, b'r', b'o', b'o', b't', // "root" (sorted second)
        ]));
    }

    #[test]
    fn encoding_constraint_not_contains() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::NotContains("tmp".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x0B, // type = NotContains
            0x00, 0x03, b't', b'm', b'p', // needle "tmp"
        ]));
    }

    #[test]
    fn encoding_constraint_not_prefix() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::NotPrefix("/tmp/".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x0C, // type = NotPrefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // prefix "/tmp/"
        ]));
    }

    #[test]
    fn encoding_constraint_not_suffix() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::NotSuffix(".txt".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x0D, // type = NotSuffix
            0x00, 0x04, b'.', b't', b'x', b't', // suffix ".txt"
        ]));
    }

    #[test]
    fn encoding_constraint_not_matches() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::NotMatches("*.txt".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x0E, // type = NotMatches
            0x00, 0x05, b'*', b'.', b't', b'x', b't', // pattern "*.txt"
        ]));
    }

    #[test]
    fn encoding_constraint_all() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::All(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::Suffix(".txt".to_string()),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x0F, // type = All
            0x00, 0x02, // 2 children
            0x02, // type = Prefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
            0x05, // type = Suffix
            0x00, 0x04, b'.', b't', b'x', b't', // ".txt"
        ]));
    }

    #[test]
    fn encoding_constraint_any() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Any(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::Prefix("/var/".to_string()),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x10, // type = Any
            0x00, 0x02, // 2 children
            0x02, // Prefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
            0x02, // Prefix
            0x00, 0x05, b'/', b'v', b'a', b'r', b'/', // "/var/"
        ]));
    }

    #[test]
    fn encoding_constraint_not() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string()))),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x11, // type = Not
            0x02, // type = Prefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
        ]));
    }

    #[test]
    fn encoding_constraint_not_nested_all() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Not(Box::new(Constraint::All(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::Suffix(".txt".to_string()),
            ]))),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x11, // type = Not
            0x0F, // type = All
            0x00, 0x02, // 2 children
            0x02, // Prefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
            0x05, // Suffix
            0x00, 0x04, b'.', b't', b'x', b't', // ".txt"
        ]));
    }

    #[test]
    fn encoding_constraint_lenrange() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::LenRange { min: 3, max: 16 });

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x13, // type = LenRange
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // u64 min 3
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // u64 max 16
        ]));
    }

    #[test]
    fn encoding_constraint_charlenrange() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "q".to_string(),
            Constraint::CharLenRange { min: 3, max: 16 },
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x14, // type = CharLenRange
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // u64 min 3
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // u64 max 16
        ]));
    }

    #[test]
    fn encoding_constraint_prefix_one_of() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::PrefixOneOf(vec!["/var/".to_string(), "/tmp/".to_string()]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x15, // type = PrefixOneOf
            0x00, 0x02, // 2 values, sorted unique
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
            0x00, 0x05, b'/', b'v', b'a', b'r', b'/', // "/var/"
        ]));
    }

    #[test]
    fn encoding_constraint_suffix_one_of() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::SuffixOneOf(vec![
                ".md".to_string(),
                ".txt".to_string(),
                ".md".to_string(),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x16, // type = SuffixOneOf
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x03, b'.', b'm', b'd', // ".md"
            0x00, 0x04, b'.', b't', b'x', b't', // ".txt"
        ]));
    }

    #[test]
    fn encoding_constraint_contains_any() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "note".to_string(),
            Constraint::ContainsAny(vec!["var".to_string(), "tmp".to_string()]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'o', b't', b'e', // key "note"
            0x17, // type = ContainsAny
            0x00, 0x02, // 2 values, sorted unique
            0x00, 0x03, b't', b'm', b'p', // "tmp"
            0x00, 0x03, b'v', b'a', b'r', // "var"
        ]));
    }

    #[test]
    fn encoding_constraint_contains_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "memo".to_string(),
            Constraint::ContainsNone(vec![
                "password".to_string(),
                "secret".to_string(),
                "secret".to_string(),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'm', b'e', b'm', b'o', // key "memo"
            0x18, // type = ContainsNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x08, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', // "password"
            0x00, 0x06, b's', b'e', b'c', b'r', b'e', b't', // "secret"
        ]));
    }

    #[test]
    fn encoding_constraint_matches_any() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "file".to_string(),
            Constraint::MatchesAny(vec!["*.md".to_string(), "*.txt".to_string()]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'f', b'i', b'l', b'e', // key "file"
            0x19, // type = MatchesAny
            0x00, 0x02, // 2 values, sorted unique
            0x00, 0x04, b'*', b'.', b'm', b'd', // "*.md"
            0x00, 0x05, b'*', b'.', b't', b'x', b't', // "*.txt"
        ]));
    }

    #[test]
    fn encoding_constraint_matches_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "skip".to_string(),
            Constraint::MatchesNone(vec![
                "*.bak".to_string(),
                "*.tmp".to_string(),
                "*.tmp".to_string(),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b's', b'k', b'i', b'p', // key "skip"
            0x1A, // type = MatchesNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x05, b'*', b'.', b'b', b'a', b'k', // "*.bak"
            0x00, 0x05, b'*', b'.', b't', b'm', b'p', // "*.tmp"
        ]));
    }

    #[test]
    fn encoding_constraint_prefix_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "dest".to_string(),
            Constraint::PrefixNone(vec![
                "/root/".to_string(),
                "/etc/".to_string(),
                "/etc/".to_string(),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'd', b'e', b's', b't', // key "dest"
            0x1B, // type = PrefixNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x05, b'/', b'e', b't', b'c', b'/', // "/etc/"
            0x00, 0x06, b'/', b'r', b'o', b'o', b't', b'/', // "/root/"
        ]));
    }

    #[test]
    fn encoding_constraint_suffix_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::SuffixNone(vec![
                ".tmp".to_string(),
                ".bak".to_string(),
                ".bak".to_string(),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x1C, // type = SuffixNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x04, b'.', b'b', b'a', b'k', // ".bak"
            0x00, 0x04, b'.', b't', b'm', b'p', // ".tmp"
        ]));
    }

    #[test]
    fn encoding_constraint_int_one_of() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("mode".to_string(), Constraint::IntOneOf(vec![3, 1, 1, 2]));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'm', b'o', b'd', b'e', // key "mode"
            0x1D, // type = IntOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // 2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // 3
        ]));
    }

    #[test]
    fn encoding_constraint_int_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("port".to_string(), Constraint::IntNone(vec![0, -1, 0]));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'o', b'r', b't', // key "port"
            0x1E, // type = IntNone
            0x00, 0x02, // 2 values after sort+unique
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // -1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0
        ]));
    }

    #[test]
    fn encoding_constraint_float_one_of() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "score".to_string(),
            Constraint::FloatOneOf(vec![2.5, 0.5, 0.5, 1.5]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754: 0.5=0x3FE0000000000000, 1.5=0x3FF8000000000000,
        // 2.5=0x4004000000000000 — sorted unique by bits.
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x1F, // type = FloatOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x3F, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0.5
            0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1.5
            0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2.5
        ]));
    }

    #[test]
    fn encoding_constraint_float_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "bias".to_string(),
            Constraint::FloatNone(vec![0.0, -1.0, 0.0]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754: 0.0=0x0000000000000000, -1.0=0xBFF0000000000000
        // sorted unique by bits (0.0 first).
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'b', b'i', b'a', b's', // key "bias"
            0x20, // type = FloatNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0.0
            0xBF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // -1.0
        ]));
    }

    #[test]
    fn encoding_constraint_len_one_of() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("pin".to_string(), Constraint::LenOneOf(vec![8, 4, 4, 16]));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x03, b'p', b'i', b'n', // key "pin"
            0x21, // type = LenOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // 8
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // 16
        ]));
    }

    #[test]
    fn encoding_constraint_len_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::LenNone(vec![0, 1, 0]));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x22, // type = LenNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
        ]));
    }

    #[test]
    fn encoding_constraint_char_len_one_of() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "pin".to_string(),
            Constraint::CharLenOneOf(vec![8, 4, 4, 16]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x03, b'p', b'i', b'n', // key "pin"
            0x23, // type = CharLenOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // 8
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // 16
        ]));
    }

    #[test]
    fn encoding_constraint_char_len_none() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::CharLenNone(vec![0, 1, 0]));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x24, // type = CharLenNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
        ]));
    }

    #[test]
    fn encoding_constraint_min_char_len() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("title".to_string(), Constraint::MinCharLen(3));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b't', b'i', b't', b'l', b'e', // key "title"
            0x25, // type = MinCharLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // u64 3
        ]));
    }

    #[test]
    fn encoding_constraint_max_char_len() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("title".to_string(), Constraint::MaxCharLen(16));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b't', b'i', b't', b'l', b'e', // key "title"
            0x26, // type = MaxCharLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // u64 16
        ]));
    }

    #[test]
    fn encoding_constraint_min_int() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("limit".to_string(), Constraint::MinInt(1));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b'l', b'i', b'm', b'i', b't', // key "limit"
            0x27, // type = MinInt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // i64 1
        ]));
    }

    #[test]
    fn encoding_constraint_max_int() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("limit".to_string(), Constraint::MaxInt(100));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b'l', b'i', b'm', b'i', b't', // key "limit"
            0x28, // type = MaxInt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // i64 100
        ]));
    }

    #[test]
    fn encoding_constraint_min_int_negative() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("offset".to_string(), Constraint::MinInt(-1));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x06, b'o', b'f', b'f', b's', b'e', b't', // key "offset"
            0x27, // type = MinInt
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // i64 -1
        ]));
    }

    #[test]
    fn encoding_constraint_min_float() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("score".to_string(), Constraint::MinFloat(0.5));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 0.5 = 0x3FE0000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x29, // type = MinFloat
            0x3F, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 0.5
        ]));
    }

    #[test]
    fn encoding_constraint_max_float() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("score".to_string(), Constraint::MaxFloat(10.5));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 10.5 = 0x4025000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x2A, // type = MaxFloat
            0x40, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 10.5
        ]));
    }

    #[test]
    fn encoding_constraint_min_float_negative() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("bias".to_string(), Constraint::MinFloat(-1.0));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 -1.0 = 0xBFF0000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'b', b'i', b'a', b's', // key "bias"
            0x29, // type = MinFloat
            0xBF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 -1.0
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_min_int() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("limit".to_string(), Constraint::ExclusiveMinInt(1));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b'l', b'i', b'm', b'i', b't', // key "limit"
            0x2D, // type = ExclusiveMinInt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // i64 1
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_max_int() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("limit".to_string(), Constraint::ExclusiveMaxInt(100));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b'l', b'i', b'm', b'i', b't', // key "limit"
            0x2E, // type = ExclusiveMaxInt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // i64 100
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_min_int_negative() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("offset".to_string(), Constraint::ExclusiveMinInt(-1));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x06, b'o', b'f', b'f', b's', b'e', b't', // key "offset"
            0x2D, // type = ExclusiveMinInt
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // i64 -1
        ]));
    }

    #[test]
    fn encoding_without_exclusive_min_int_identical_to_prior() {
        // Tokens that do not use ExclusiveMinInt/ExclusiveMaxInt must keep the 0.38.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("score".to_string(), Constraint::ExclusiveMinFloat(0.5));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x2B, // type = ExclusiveMinFloat
            0x3F, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 0.5
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_min_len() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::ExclusiveMinLen(0));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x2F, // type = ExclusiveMinLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // u64 0
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_max_len() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::ExclusiveMaxLen(256));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x30, // type = ExclusiveMaxLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // u64 256
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_min_len_nonzero() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::ExclusiveMinLen(8));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x2F, // type = ExclusiveMinLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // u64 8
        ]));
    }

    #[test]
    fn encoding_without_exclusive_min_len_identical_to_prior() {
        // Tokens that do not use ExclusiveMinLen/ExclusiveMaxLen must keep the 0.39.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("limit".to_string(), Constraint::ExclusiveMinInt(1));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b'l', b'i', b'm', b'i', b't', // key "limit"
            0x2D, // type = ExclusiveMinInt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // i64 1
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_min_float() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("score".to_string(), Constraint::ExclusiveMinFloat(0.5));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 0.5 = 0x3FE0000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x2B, // type = ExclusiveMinFloat
            0x3F, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 0.5
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_max_float() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("score".to_string(), Constraint::ExclusiveMaxFloat(10.5));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 10.5 = 0x4025000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x2C, // type = ExclusiveMaxFloat
            0x40, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 10.5
        ]));
    }

    #[test]
    fn encoding_constraint_exclusive_min_float_negative() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("bias".to_string(), Constraint::ExclusiveMinFloat(-1.0));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 -1.0 = 0xBFF0000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'b', b'i', b'a', b's', // key "bias"
            0x2B, // type = ExclusiveMinFloat
            0xBF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 -1.0
        ]));
    }

    #[test]
    fn encoding_without_exclusive_min_float_identical_to_prior() {
        // Tokens that do not use ExclusiveMinFloat/ExclusiveMaxFloat must keep the 0.37.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("score".to_string(), Constraint::MinFloat(0.5));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x29, // type = MinFloat
            0x3F, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // f64 0.5
        ]));
    }

    #[test]
    fn encoding_without_min_float_identical_to_prior() {
        // Tokens that do not use MinFloat/MaxFloat must keep the 0.36.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("limit".to_string(), Constraint::MinInt(1));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b'l', b'i', b'm', b'i', b't', // key "limit"
            0x27, // type = MinInt
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // i64 1
        ]));
    }

    #[test]
    fn encoding_without_min_int_identical_to_prior() {
        // Tokens that do not use MinInt/MaxInt must keep the 0.35.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("title".to_string(), Constraint::MinCharLen(3));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b't', b'i', b't', b'l', b'e', // key "title"
            0x25, // type = MinCharLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // u64 3
        ]));
    }

    #[test]
    fn encoding_without_min_char_len_identical_to_prior() {
        // Tokens that do not use MinCharLen/MaxCharLen must keep the 0.34.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "pin".to_string(),
            Constraint::CharLenOneOf(vec![8, 4, 4, 16]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x03, b'p', b'i', b'n', // key "pin"
            0x23, // type = CharLenOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // 8
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // 16
        ]));
    }

    #[test]
    fn encoding_without_char_len_one_of_identical_to_prior() {
        // Tokens that do not use CharLenOneOf/CharLenNone must keep the 0.33.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("pin".to_string(), Constraint::LenOneOf(vec![8, 4, 4, 16]));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x03, b'p', b'i', b'n', // key "pin"
            0x21, // type = LenOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // 4
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // 8
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // 16
        ]));
    }

    #[test]
    fn encoding_without_len_one_of_identical_to_prior() {
        // Tokens that do not use LenOneOf/LenNone must keep the 0.32.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "score".to_string(),
            Constraint::FloatOneOf(vec![2.5, 0.5, 0.5, 1.5]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x05, b's', b'c', b'o', b'r', b'e', // key "score"
            0x1F, // type = FloatOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x3F, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0.5
            0x3F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1.5
            0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 2.5
        ]));
    }

    #[test]
    fn encoding_without_float_one_of_identical_to_prior() {
        // Tokens that do not use FloatOneOf/FloatNone must keep the 0.31.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("mode".to_string(), Constraint::IntOneOf(vec![3, 1, 1, 2]));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'm', b'o', b'd', b'e', // key "mode"
            0x1D, // type = IntOneOf
            0x00, 0x03, // 3 values after sort+unique
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // 2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // 3
        ]));
    }

    #[test]
    fn encoding_without_int_one_of_identical_to_prior() {
        // Tokens that do not use IntOneOf/IntNone must keep the 0.30.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "dest".to_string(),
            Constraint::PrefixNone(vec!["/etc/".to_string(), "/root/".to_string()]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'd', b'e', b's', b't', // key "dest"
            0x1B, // type = PrefixNone
            0x00, 0x02, // 2 values after sort+unique
            0x00, 0x05, b'/', b'e', b't', b'c', b'/', // "/etc/"
            0x00, 0x06, b'/', b'r', b'o', b'o', b't', b'/', // "/root/"
        ]));
    }

    #[test]
    fn encoding_without_prefix_none_identical_to_prior() {
        // Tokens that do not use PrefixNone/SuffixNone must keep the 0.28.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "file".to_string(),
            Constraint::MatchesAny(vec!["*.md".to_string(), "*.txt".to_string()]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'f', b'i', b'l', b'e', // key "file"
            0x19, // type = MatchesAny
            0x00, 0x02, // 2 values, sorted unique
            0x00, 0x04, b'*', b'.', b'm', b'd', // "*.md"
            0x00, 0x05, b'*', b'.', b't', b'x', b't', // "*.txt"
        ]));
    }

    #[test]
    fn encoding_without_matches_any_identical_to_prior() {
        // Tokens that do not use MatchesAny/MatchesNone must keep the 0.27.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "note".to_string(),
            Constraint::ContainsAny(vec!["var".to_string(), "tmp".to_string()]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'o', b't', b'e', // key "note"
            0x17, // type = ContainsAny
            0x00, 0x02, // 2 values, sorted unique
            0x00, 0x03, b't', b'm', b'p', // "tmp"
            0x00, 0x03, b'v', b'a', b'r', // "var"
        ]));
    }

    #[test]
    fn encoding_without_contains_any_identical_to_prior() {
        // Tokens that do not use ContainsAny/ContainsNone must keep the 0.26.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::PrefixOneOf(vec!["/var/".to_string(), "/tmp/".to_string()]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x15, // type = PrefixOneOf
            0x00, 0x02, // 2 values, sorted unique
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
            0x00, 0x05, b'/', b'v', b'a', b'r', b'/', // "/var/"
        ]));
    }

    #[test]
    fn encoding_without_prefix_one_of_identical_to_prior() {
        // Tokens that do not use PrefixOneOf/SuffixOneOf must keep the 0.25.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "q".to_string(),
            Constraint::CharLenRange { min: 3, max: 16 },
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x14, // type = CharLenRange
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // u64 min 3
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // u64 max 16
        ]));
    }

    #[test]
    fn encoding_without_charlenrange_identical_to_prior() {
        // Tokens that do not use CharLenRange must keep the 0.24.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("q".to_string(), Constraint::LenRange { min: 3, max: 16 });

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'q', // key "q"
            0x13, // type = LenRange
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // u64 min 3
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // u64 max 16
        ]));
    }

    #[test]
    fn encoding_without_lenrange_identical_to_prior() {
        // Tokens that do not use LenRange must keep the 0.23.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "n".to_string(),
            Constraint::FloatRange { min: 1.0, max: 2.0 },
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // IEEE-754 f64 1.0 = 0x3FF0000000000000, 2.0 = 0x4000000000000000
        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x01, b'n', // key "n"
            0x12, // type = FloatRange
            0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // min = 1.0
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max = 2.0
        ]));
    }

    #[test]
    fn encoding_without_floatrange_identical_to_prior() {
        // Tokens that do not use FloatRange must keep the 0.22.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string()))),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x11, // type = Not
            0x02, // type = Prefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
        ]));
    }

    #[test]
    fn encoding_without_not_identical_to_prior() {
        // Tokens that do not use Not must keep the 0.21.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::All(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::Suffix(".txt".to_string()),
            ]),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x0F, // type = All
            0x00, 0x02, // 2 children
            0x02, // type = Prefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // "/tmp/"
            0x05, // type = Suffix
            0x00, 0x04, b'.', b't', b'x', b't', // ".txt"
        ]));
    }

    #[test]
    fn encoding_without_all_any_identical_to_prior() {
        // Tokens that do not use All/Any must keep the 0.20.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::NotSuffix(".txt".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x0D, // type = NotSuffix
            0x00, 0x04, b'.', b't', b'x', b't', // suffix ".txt"
        ]));
    }

    #[test]
    fn encoding_without_not_suffix_identical_to_prior() {
        // Tokens that do not use NotSuffix/NotMatches must keep the 0.19.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::NotPrefix("/tmp/".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'p', b'a', b't', b'h', // key "path"
            0x0C, // type = NotPrefix
            0x00, 0x05, b'/', b't', b'm', b'p', b'/', // prefix "/tmp/"
        ]));
    }

    #[test]
    fn encoding_without_not_contains_identical_to_prior() {
        // Tokens that do not use NotContains/NotPrefix must keep the 0.18.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert(
            "role".to_string(),
            Constraint::NotEquals("admin".to_string()),
        );

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        assert!(bytes.ends_with(&[
            0x00, 0x01, // 1 constraint
            0x00, 0x04, b'r', b'o', b'l', b'e', // key "role"
            0x09, // type = NotEquals
            0x00, 0x05, b'a', b'd', b'm', b'i', b'n', // value "admin"
        ]));
    }

    #[test]
    fn encoding_without_not_equals_identical_to_prior() {
        // Tokens that do not use NotEquals/NotOneOf must keep the 0.17.0 bytes.
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::Matches("*.txt".to_string()));
        constraints.insert("q".to_string(), Constraint::MinLen(8));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // Sorted by key: "name" then "q"
        assert!(bytes.ends_with(&[
            0x00, 0x02, // 2 constraints
            0x00, 0x04, b'n', b'a', b'm', b'e', // key "name"
            0x08, // type = Matches
            0x00, 0x05, b'*', b'.', b't', b'x', b't', // pattern "*.txt"
            0x00, 0x01, b'q', // key "q"
            0x07, // type = MinLen
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // u64 8
        ]));
    }

    #[test]
    fn encoding_multiple_constraints_sorted() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("z".to_string(), Constraint::MaxLen(10));
        constraints.insert("a".to_string(), Constraint::MaxLen(20));

        let bytes = encode_canonical_v4("t", &[], 0, &[], None, None, Some(&constraints));

        // Constraints should be sorted by key: "a" before "z"
        let constraint_section = &bytes[bytes.len() - 26..]; // 2 + (2+1+1+8) + (2+1+1+8)
        assert_eq!(constraint_section[0..2], [0x00, 0x02]); // 2 constraints
        assert_eq!(constraint_section[2..5], [0x00, 0x01, b'a']); // first key is "a"
    }

    #[test]
    fn encoding_with_jti() {
        let bytes = encode_canonical_v5(
            "read",
            &["path".into()],
            1000,
            &[0xAB],
            None,
            None,
            None,
            Some("abc123"),
        );

        // Should end with jti
        assert!(bytes.ends_with(&[
            0x00, 0x06, // jti length 6
            b'a', b'b', b'c', b'1', b'2', b'3', // "abc123"
        ]));
    }

    #[test]
    fn encoding_v5_no_jti_equals_v4() {
        use std::collections::BTreeMap;
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let v4 = encode_canonical_v4(
            "tool",
            &["path".into()],
            1000,
            &[1, 2],
            Some("aud"),
            Some("k1"),
            Some(&constraints),
        );
        let v5 = encode_canonical_v5(
            "tool",
            &["path".into()],
            1000,
            &[1, 2],
            Some("aud"),
            Some("k1"),
            Some(&constraints),
            None,
        );
        assert_eq!(v4, v5);
    }

    // ===== Backward compatibility tests =====

    #[test]
    fn v4_no_constraints_identical_to_v3() {
        // Ensure tokens without constraints produce identical encoding to v3
        let v3 = encode_canonical_v3(
            "read_file",
            &["path".into(), "limit".into()],
            1700000000,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Some("client-123"),
            Some("key-2024"),
        );

        let v4_none = encode_canonical_v4(
            "read_file",
            &["path".into(), "limit".into()],
            1700000000,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Some("client-123"),
            Some("key-2024"),
            None,
        );

        use std::collections::BTreeMap;
        let empty: Constraints = BTreeMap::new();
        let v4_empty = encode_canonical_v4(
            "read_file",
            &["path".into(), "limit".into()],
            1700000000,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Some("client-123"),
            Some("key-2024"),
            Some(&empty),
        );

        assert_eq!(v3, v4_none, "v4 with None should equal v3");
        assert_eq!(v3, v4_empty, "v4 with empty constraints should equal v3");
    }

    #[test]
    fn v3_no_kid_identical_to_v2() {
        let v2 = encode_canonical_v2(
            "tool",
            &["a".into(), "b".into()],
            1000,
            &[0xAB, 0xCD],
            Some("audience"),
        );

        let v3 = encode_canonical_v3(
            "tool",
            &["a".into(), "b".into()],
            1000,
            &[0xAB, 0xCD],
            Some("audience"),
            None,
        );

        assert_eq!(v2, v3, "v3 without kid should equal v2");
    }

    #[test]
    fn v2_no_audience_identical_to_v1() {
        let v1 = encode_canonical("tool", &["x".into()], 500, &[0x01, 0x02]);

        let v2 = encode_canonical_v2("tool", &["x".into()], 500, &[0x01, 0x02], None);

        assert_eq!(v1, v2, "v2 without audience should equal v1");
    }

    #[test]
    fn v5_no_jti_identical_to_v4() {
        use std::collections::BTreeMap;

        // With constraints
        let mut constraints: Constraints = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let v4 = encode_canonical_v4(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
            Some(&constraints),
        );

        let v5_none = encode_canonical_v5(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
            Some(&constraints),
            None,
        );

        assert_eq!(v4, v5_none, "v5 with None jti should equal v4");
    }

    #[test]
    fn v5_no_jti_no_constraints_identical_to_v3() {
        let v3 = encode_canonical_v3(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
        );

        let v5 = encode_canonical_v5(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
            None,
            None,
        );

        assert_eq!(v3, v5, "v5 with no constraints and no jti should equal v3");
    }

    #[test]
    fn known_v5_encoding_with_jti_is_stable() {
        // This test ensures the v5 encoding with jti remains stable
        let bytes = encode_canonical_v5(
            "read",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
            None,
            Some("jti123"),
        );

        // Check that jti is appended at the end
        let jti_section = &bytes[bytes.len() - 8..];
        assert_eq!(
            jti_section,
            &[
                0x00, 0x06, // jti length 6
                b'j', b't', b'i', b'1', b'2', b'3'
            ]
        );
    }

    #[test]
    fn known_v3_encoding_is_stable() {
        // This test ensures the v3 encoding remains stable for cross-implementation compatibility
        // If this test fails after a change, existing v3 tokens will break
        let bytes = encode_canonical_v3(
            "read",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
        );

        // 1700000000 = 0x6553F100 big-endian
        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name
            0x00, 0x01, // 1 arg key
            0x00, 0x04, b'p', b'a', b't', b'h', // "path"
            0x00, 0x00, 0x00, 0x00, 0x65, 0x53, 0xF1, 0x00, // expiry 1700000000
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, // nonce
            0x00, 0x06, b'c', b'l', b'i', b'e', b'n', b't', // audience
            0x00, 0x04, b'k', b'e', b'y', b'1', // kid
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_v6_no_new_fields_equals_v5() {
        let v5 = encode_canonical_v5(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
            None,
            Some("jti123"),
        );
        let v6 = encode_canonical_v6(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD, 0xBE, 0xEF],
            Some("client"),
            Some("key1"),
            None,
            Some("jti123"),
            None,
            0,
            None,
        );
        assert_eq!(v5, v6, "v6 with no nbf/depth/max_depth should equal v5");
    }

    #[test]
    fn encoding_with_nbf() {
        let bytes = encode_canonical_v6(
            "read",
            &["a".into()],
            1000,
            &[0xAB],
            None,
            None,
            None,
            None,
            Some(900),
            0,
            None,
        );

        assert!(bytes.ends_with(&[
            0x01, // flags: nbf only
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x84, // nbf = 900
        ]));
    }

    #[test]
    fn encoding_with_depth_and_max_depth() {
        let bytes = encode_canonical_v6("t", &[], 0, &[], None, None, None, None, None, 2, Some(3));

        assert!(bytes.ends_with(&[
            0x06, // flags: depth + max_depth
            0x00, 0x00, 0x00, 0x02, // depth = 2
            0x00, 0x00, 0x00, 0x03, // max_depth = 3
        ]));
    }

    #[test]
    fn encoding_v6_all_new_fields() {
        let bytes = encode_canonical_v6(
            "t",
            &[],
            0,
            &[],
            None,
            None,
            None,
            None,
            Some(50),
            1,
            Some(4),
        );

        assert!(bytes.ends_with(&[
            0x07, // flags: nbf + depth + max_depth
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, // nbf = 50
            0x00, 0x00, 0x00, 0x01, // depth = 1
            0x00, 0x00, 0x00, 0x04, // max_depth = 4
        ]));
    }

    #[test]
    fn encoding_v7_empty_required_keys_equals_v6() {
        let v6 = encode_canonical_v6(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD],
            None,
            None,
            None,
            None,
            Some(900),
            0,
            None,
        );
        let v7 = encode_canonical_v7(
            "read_file",
            &["path".into()],
            1700000000,
            &[0xDE, 0xAD],
            None,
            None,
            None,
            None,
            Some(900),
            0,
            None,
            &[],
        );
        assert_eq!(v6, v7);
    }

    #[test]
    fn encoding_v7_required_keys_appends_flag_bit_3() {
        let bytes = encode_canonical_v7(
            "t",
            &["a".into(), "b".into()],
            0,
            &[],
            None,
            None,
            None,
            None,
            None,
            0,
            None,
            &["b".into(), "a".into()],
        );
        assert!(bytes.ends_with(&[
            0x08, // flags: required_keys only
            0x00, 0x02, // 2 keys
            0x00, 0x01, b'a', // "a"
            0x00, 0x01, b'b', // "b"
        ]));
    }
}
