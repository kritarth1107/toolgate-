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
//!   - constraint_type: u8 (0=Exact, 1=OneOf, 2=Prefix, 3=MaxLen, 4=IntRange)
//!   - constraint_data: type-specific encoding
//!
//! Constraint data encoding:
//! - Exact: u16 length + UTF-8 bytes
//! - OneOf: u16 count + (for each value, sorted: u16 length + UTF-8 bytes)
//! - Prefix: u16 length + UTF-8 bytes
//! - MaxLen: u64
//! - IntRange: i64 min + i64 max
//!
//! The v4 format appends constraints after kid. Tokens without constraints
//! encode with count 0, ensuring backward-compatible MAC verification with v3.

use crate::constraint::{Constraint, Constraints};

/// Encode a token's fields into canonical bytes for signing/verification (v1 format).
pub fn encode_canonical(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
) -> Vec<u8> {
    encode_canonical_v4(tool_name, arg_keys, expiry, nonce, None, None, None)
}

/// Encode a token's fields into canonical bytes for signing/verification (v2 format with audience).
pub fn encode_canonical_v2(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
) -> Vec<u8> {
    encode_canonical_v4(tool_name, arg_keys, expiry, nonce, audience, None, None)
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
    encode_canonical_v4(tool_name, arg_keys, expiry, nonce, audience, kid, None)
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
            let prefix_bytes = prefix.as_bytes();
            buf.extend_from_slice(&(prefix_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(prefix_bytes);
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
}
