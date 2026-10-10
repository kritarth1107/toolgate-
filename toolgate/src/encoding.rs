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
//!   - constraint_type: u8 (0=Exact, 1=OneOf, 2=Prefix, 3=MaxLen, 4=IntRange, 5=Suffix, 6=Contains, 7=MinLen, 8=Matches, 9=NotEquals, 10=NotOneOf, 11=NotContains, 12=NotPrefix)
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
//!
//! The v5 format appends jti after constraints. Tokens without jti
//! encode identically to v4. Tokens without constraints and without jti
//! encode identically to v3. The v6 format appends nbf/depth/max_depth
//! only when at least one is set, so tokens without those fields encode
//! identically to v5.

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

    // nbf / depth / max_depth: only encoded if any is set (v6 extension)
    // Tokens without these fields produce identical encoding to v5
    if nbf.is_some() || depth > 0 || max_depth.is_some() {
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
    }
}

/// Encode a UTF-8 string as u16 length + bytes.
fn encode_len_prefixed(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
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
}
