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
//! The v2 format appends audience after nonce. Tokens without audience
//! encode with length 0, ensuring backward-compatible MAC verification.

/// Encode a token's fields into canonical bytes for signing/verification (v1 format).
pub fn encode_canonical(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
) -> Vec<u8> {
    encode_canonical_v2(tool_name, arg_keys, expiry, nonce, None)
}

/// Encode a token's fields into canonical bytes for signing/verification (v2 format with audience).
pub fn encode_canonical_v2(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
    audience: Option<&str>,
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

    buf
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
        // v2 format includes audience (length 0 for unbound)
        let bytes = encode_canonical("read", &["a".into(), "b".into()], 1000, &[0xAB, 0xCD]);

        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name
            0x00, 0x02,       // arg_keys count
            0x00, 0x01, b'a', // key "a"
            0x00, 0x01, b'b', // key "b"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // expiry 1000
            0x00, 0x02, 0xAB, 0xCD, // nonce
            0x00, 0x00,       // audience length 0 (unbound)
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
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_with_audience() {
        let bytes =
            encode_canonical_v2("read", &["a".into()], 1000, &[0xAB], Some("client-123"));

        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name
            0x00, 0x01,       // arg_keys count
            0x00, 0x01, b'a', // key "a"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // expiry 1000
            0x00, 0x01, 0xAB, // nonce
            0x00, 0x0A, // audience length 10
            b'c', b'l', b'i', b'e', b'n', b't', b'-', b'1', b'2', b'3', // "client-123"
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn encoding_none_audience_equals_empty() {
        let with_none = encode_canonical_v2("tool", &[], 0, &[], None);
        let without_audience = encode_canonical("tool", &[], 0, &[]);
        assert_eq!(with_none, without_audience);
    }
}
