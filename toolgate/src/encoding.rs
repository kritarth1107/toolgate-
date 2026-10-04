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
}
