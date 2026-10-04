//! Canonical byte encoding for tokens.
//!
//! Format (all integers are big-endian):
//! - tool_name: u16 length + UTF-8 bytes
//! - arg_keys_count: u16
//! - for each arg_key: u16 length + UTF-8 bytes (keys sorted lexicographically)
//! - expiry: u64 (unix seconds)
//! - nonce: u16 length + bytes

/// Encode a token's fields into canonical bytes for signing/verification.
pub fn encode_canonical(
    tool_name: &str,
    arg_keys: &[String],
    expiry: u64,
    nonce: &[u8],
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
        let bytes = encode_canonical("read", &["a".into(), "b".into()], 1000, &[0xAB, 0xCD]);

        // Expected encoding:
        // tool_name "read": 00 04 r e a d
        // arg_keys count 2: 00 02
        // key "a": 00 01 a
        // key "b": 00 01 b
        // expiry 1000: 00 00 00 00 00 00 03 e8
        // nonce [0xAB, 0xCD]: 00 02 AB CD
        let expected: Vec<u8> = vec![
            0x00, 0x04, b'r', b'e', b'a', b'd', // tool_name
            0x00, 0x02, // arg_keys count
            0x00, 0x01, b'a', // key "a"
            0x00, 0x01, b'b', // key "b"
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, // expiry 1000
            0x00, 0x02, 0xAB, 0xCD, // nonce
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
        ];

        assert_eq!(bytes, expected);
    }
}
