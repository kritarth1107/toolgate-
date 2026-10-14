//! Compact binary wire format for Token serialization.
//!
//! This module provides a space-efficient binary encoding for tokens,
//! suitable for transmission over constrained channels.
//!
//! ## Wire Format v6 (all integers big-endian)
//!
//! | Field | Encoding |
//! |-------|----------|
//! | version | u8 (6 when required_keys are set; 5 when nbf/depth/max_depth are set; otherwise 4) |
//! | tool_name | u16 length + UTF-8 bytes |
//! | arg_keys_count | u16 |
//! | arg_keys | for each: u16 length + UTF-8 bytes |
//! | expiry | u64 (unix seconds) |
//! | nonce | u8 length + bytes |
//! | mac | u8 length + bytes |
//! | audience | u16 length + UTF-8 bytes (0 = none) |
//! | kid | u16 length + UTF-8 bytes (0 = none) |
//! | constraints_count | u16 (0 = none) |
//! | constraints | for each: key + type + data (same encoding as canonical; 0=Exact, 1=OneOf, 2=Prefix, 3=MaxLen, 4=IntRange, 5=Suffix, 6=Contains, 7=MinLen, 8=Matches, 9=NotEquals, 10=NotOneOf, 11=NotContains, 12=NotPrefix, 13=NotSuffix, 14=NotMatches, 15=All, 16=Any, 17=Not, 18=FloatRange, 19=LenRange, 20=CharLenRange, 21=PrefixOneOf, 22=SuffixOneOf, 23=ContainsAny, 24=ContainsNone, 25=MatchesAny, 26=MatchesNone, 27=PrefixNone, 28=SuffixNone, 29=IntOneOf, 30=IntNone, 31=FloatOneOf, 32=FloatNone, 33=LenOneOf, 34=LenNone, 35=CharLenOneOf, 36=CharLenNone, 37=MinCharLen, 38=MaxCharLen) |
//! | jti | u16 length + UTF-8 bytes (0 = none) |
//! | nbf_flag | u8 (v5+ only; 0 = none, 1 = present) |
//! | nbf | u64 (v5+ only, if nbf_flag = 1) |
//! | depth | u32 (v5+ only) |
//! | max_depth_flag | u8 (v5+ only; 0 = none, 1 = present) |
//! | max_depth | u32 (v5+ only, if max_depth_flag = 1) |
//! | required_keys_count | u16 (v6 only) |
//! | required_keys | for each, sorted unique: u16 length + UTF-8 (v6 only) |
//!
//! Tokens without required_keys, nbf, with depth 0, and without max_depth
//! encode as v4 so the bytes match v0.5. Tokens with v5 fields and no
//! required keys stay on v5. Wire formats v1–v5 are still supported for
//! decoding.

use crate::constraint::{Constraint, Constraints};
use crate::Token;
use std::collections::BTreeMap;

/// Current wire format version (supports required argument keys)
const WIRE_VERSION: u8 = 6;

/// Wire version used when required_keys are unset but nbf/depth/max_depth are set.
const WIRE_VERSION_V5: u8 = 5;

/// Wire version used when nbf/depth/max_depth/required_keys are unset (identical to v0.5).
const WIRE_VERSION_V4: u8 = 4;

/// Minimum supported wire format version
const WIRE_VERSION_MIN: u8 = 1;

/// Errors that can occur during wire encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    UnsupportedVersion(u8),
    UnexpectedEof,
    InvalidUtf8,
    #[allow(dead_code)]
    BufferTooSmall,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::UnsupportedVersion(v) => write!(f, "unsupported wire version: {}", v),
            WireError::UnexpectedEof => write!(f, "unexpected end of data"),
            WireError::InvalidUtf8 => write!(f, "invalid UTF-8 in token data"),
            WireError::BufferTooSmall => write!(f, "buffer too small for encoding"),
        }
    }
}

impl std::error::Error for WireError {}

/// Encode a single constraint to wire format.
fn encode_constraint_to_wire(buf: &mut Vec<u8>, key: &str, constraint: &Constraint) {
    // Key: length-prefixed
    let key_bytes = key.as_bytes();
    buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(key_bytes);
    encode_constraint_value_to_wire(buf, constraint);
}

/// Encode constraint type + data without a key (used for nested All/Any/Not children).
fn encode_constraint_value_to_wire(buf: &mut Vec<u8>, constraint: &Constraint) {
    match constraint {
        Constraint::Exact(value) => {
            buf.push(0);
            let value_bytes = value.as_bytes();
            buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(value_bytes);
        }
        Constraint::OneOf(values) => {
            buf.push(1);
            buf.extend_from_slice(&(values.len() as u16).to_be_bytes());
            let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            sorted.sort();
            for value in sorted {
                let value_bytes = value.as_bytes();
                buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(value_bytes);
            }
        }
        Constraint::Prefix(prefix) => {
            buf.push(2);
            encode_len_prefixed(buf, prefix);
        }
        Constraint::MaxLen(max) => {
            buf.push(3);
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
        Constraint::IntRange { min, max } => {
            buf.push(4);
            buf.extend_from_slice(&min.to_be_bytes());
            buf.extend_from_slice(&max.to_be_bytes());
        }
        Constraint::Suffix(suffix) => {
            buf.push(5);
            encode_len_prefixed(buf, suffix);
        }
        Constraint::Contains(needle) => {
            buf.push(6);
            encode_len_prefixed(buf, needle);
        }
        Constraint::MinLen(min) => {
            buf.push(7);
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
        }
        Constraint::Matches(pattern) => {
            buf.push(8);
            encode_len_prefixed(buf, pattern);
        }
        Constraint::NotEquals(value) => {
            buf.push(9);
            encode_len_prefixed(buf, value);
        }
        Constraint::NotOneOf(values) => {
            buf.push(10);
            let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
            sorted.sort();
            sorted.dedup();
            buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
            for value in sorted {
                encode_len_prefixed(buf, value);
            }
        }
        Constraint::NotContains(needle) => {
            buf.push(11);
            encode_len_prefixed(buf, needle);
        }
        Constraint::NotPrefix(prefix) => {
            buf.push(12);
            encode_len_prefixed(buf, prefix);
        }
        Constraint::NotSuffix(suffix) => {
            buf.push(13);
            encode_len_prefixed(buf, suffix);
        }
        Constraint::NotMatches(pattern) => {
            buf.push(14);
            encode_len_prefixed(buf, pattern);
        }
        Constraint::All(children) => {
            buf.push(15);
            buf.extend_from_slice(&(children.len() as u16).to_be_bytes());
            for child in children {
                encode_constraint_value_to_wire(buf, child);
            }
        }
        Constraint::Any(children) => {
            buf.push(16);
            buf.extend_from_slice(&(children.len() as u16).to_be_bytes());
            for child in children {
                encode_constraint_value_to_wire(buf, child);
            }
        }
        Constraint::Not(child) => {
            buf.push(17);
            encode_constraint_value_to_wire(buf, child);
        }
        // IEEE-754 f64 big-endian bits — same two-bound layout as IntRange
        // (`to_be_bytes` of each endpoint) but using f64 rather than i64.
        Constraint::FloatRange { min, max } => {
            buf.push(18);
            buf.extend_from_slice(&min.to_be_bytes());
            buf.extend_from_slice(&max.to_be_bytes());
        }
        // Two u64 big-endian lengths — same unit/encoding as MaxLen/MinLen.
        Constraint::LenRange { min, max } => {
            buf.push(19);
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
        // Two u64 big-endian scalar counts — same layout as LenRange.
        Constraint::CharLenRange { min, max } => {
            buf.push(20);
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
        Constraint::PrefixOneOf(values) => {
            buf.push(21);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::SuffixOneOf(values) => {
            buf.push(22);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::ContainsAny(values) => {
            buf.push(23);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::ContainsNone(values) => {
            buf.push(24);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::MatchesAny(values) => {
            buf.push(25);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::MatchesNone(values) => {
            buf.push(26);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::PrefixNone(values) => {
            buf.push(27);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::SuffixNone(values) => {
            buf.push(28);
            encode_sorted_unique_strings(buf, values);
        }
        Constraint::IntOneOf(values) => {
            buf.push(29);
            encode_sorted_unique_i64s(buf, values);
        }
        Constraint::IntNone(values) => {
            buf.push(30);
            encode_sorted_unique_i64s(buf, values);
        }
        Constraint::FloatOneOf(values) => {
            buf.push(31);
            encode_sorted_unique_f64s(buf, values);
        }
        Constraint::FloatNone(values) => {
            buf.push(32);
            encode_sorted_unique_f64s(buf, values);
        }
        Constraint::LenOneOf(values) => {
            buf.push(33);
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::LenNone(values) => {
            buf.push(34);
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::CharLenOneOf(values) => {
            buf.push(35);
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::CharLenNone(values) => {
            buf.push(36);
            encode_sorted_unique_usizes(buf, values);
        }
        Constraint::MinCharLen(min) => {
            buf.push(37);
            buf.extend_from_slice(&(*min as u64).to_be_bytes());
        }
        Constraint::MaxCharLen(max) => {
            buf.push(38);
            buf.extend_from_slice(&(*max as u64).to_be_bytes());
        }
    }
}

fn encode_len_prefixed(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_sorted_unique_strings(buf: &mut Vec<u8>, values: &[String]) {
    let mut sorted: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
    sorted.sort();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        encode_len_prefixed(buf, value);
    }
}

fn encode_sorted_unique_i64s(buf: &mut Vec<u8>, values: &[i64]) {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_sorted_unique_f64s(buf: &mut Vec<u8>, values: &[f64]) {
    let mut sorted = values.to_vec();
    sorted.sort_by_key(|v| v.to_bits());
    sorted.dedup_by_key(|v| v.to_bits());
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

fn encode_sorted_unique_usizes(buf: &mut Vec<u8>, values: &[usize]) {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    buf.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for value in sorted {
        buf.extend_from_slice(&(value as u64).to_be_bytes());
    }
}

fn read_wire_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], WireError> {
    if *pos + len > data.len() {
        return Err(WireError::UnexpectedEof);
    }
    let slice = &data[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn read_wire_u16(data: &[u8], pos: &mut usize) -> Result<usize, WireError> {
    Ok(u16::from_be_bytes(read_wire_bytes(data, pos, 2)?.try_into().unwrap()) as usize)
}

fn read_wire_utf8(data: &[u8], pos: &mut usize) -> Result<String, WireError> {
    let len = read_wire_u16(data, pos)?;
    let bytes = read_wire_bytes(data, pos, len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)
}

fn read_wire_string_list(data: &[u8], pos: &mut usize) -> Result<Vec<String>, WireError> {
    let count = read_wire_u16(data, pos)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read_wire_utf8(data, pos)?);
    }
    Ok(values)
}

fn read_wire_i64_list(data: &[u8], pos: &mut usize) -> Result<Vec<i64>, WireError> {
    let count = read_wire_u16(data, pos)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(i64::from_be_bytes(
            read_wire_bytes(data, pos, 8)?.try_into().unwrap(),
        ));
    }
    Ok(values)
}

fn read_wire_f64_list(data: &[u8], pos: &mut usize) -> Result<Vec<f64>, WireError> {
    let count = read_wire_u16(data, pos)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(f64::from_be_bytes(
            read_wire_bytes(data, pos, 8)?.try_into().unwrap(),
        ));
    }
    Ok(values)
}

fn read_wire_usize_list(data: &[u8], pos: &mut usize) -> Result<Vec<usize>, WireError> {
    let count = read_wire_u16(data, pos)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values
            .push(u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize);
    }
    Ok(values)
}

/// Decode a single constraint from wire format.
fn decode_constraint_from_wire(
    data: &[u8],
    pos: &mut usize,
) -> Result<(String, Constraint), WireError> {
    let key = read_wire_utf8(data, pos)?;
    let constraint = decode_constraint_value_from_wire(data, pos)?;
    Ok((key, constraint))
}

/// Decode constraint type + data (used for nested All/Any/Not children).
fn decode_constraint_value_from_wire(
    data: &[u8],
    pos: &mut usize,
) -> Result<Constraint, WireError> {
    let constraint_type = *read_wire_bytes(data, pos, 1)?.first().unwrap();

    let constraint = match constraint_type {
        0 => Constraint::Exact(read_wire_utf8(data, pos)?),
        1 => {
            let count = read_wire_u16(data, pos)?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(read_wire_utf8(data, pos)?);
            }
            Constraint::OneOf(values)
        }
        2 => Constraint::Prefix(read_wire_utf8(data, pos)?),
        3 => {
            let max =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            Constraint::MaxLen(max)
        }
        4 => {
            let min = i64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap());
            let max = i64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap());
            Constraint::IntRange { min, max }
        }
        5 => Constraint::Suffix(read_wire_utf8(data, pos)?),
        6 => Constraint::Contains(read_wire_utf8(data, pos)?),
        7 => {
            let min =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            Constraint::MinLen(min)
        }
        8 => Constraint::Matches(read_wire_utf8(data, pos)?),
        9 => Constraint::NotEquals(read_wire_utf8(data, pos)?),
        10 => {
            let count = read_wire_u16(data, pos)?;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(read_wire_utf8(data, pos)?);
            }
            Constraint::NotOneOf(values)
        }
        11 => Constraint::NotContains(read_wire_utf8(data, pos)?),
        12 => Constraint::NotPrefix(read_wire_utf8(data, pos)?),
        13 => Constraint::NotSuffix(read_wire_utf8(data, pos)?),
        14 => Constraint::NotMatches(read_wire_utf8(data, pos)?),
        15 => {
            let count = read_wire_u16(data, pos)?;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(decode_constraint_value_from_wire(data, pos)?);
            }
            Constraint::All(children)
        }
        16 => {
            let count = read_wire_u16(data, pos)?;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(decode_constraint_value_from_wire(data, pos)?);
            }
            Constraint::Any(children)
        }
        17 => Constraint::Not(Box::new(decode_constraint_value_from_wire(data, pos)?)),
        18 => {
            let min = f64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap());
            let max = f64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap());
            Constraint::FloatRange { min, max }
        }
        19 => {
            let min =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            let max =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            Constraint::LenRange { min, max }
        }
        20 => {
            let min =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            let max =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            Constraint::CharLenRange { min, max }
        }
        21 => Constraint::PrefixOneOf(read_wire_string_list(data, pos)?),
        22 => Constraint::SuffixOneOf(read_wire_string_list(data, pos)?),
        23 => Constraint::ContainsAny(read_wire_string_list(data, pos)?),
        24 => Constraint::ContainsNone(read_wire_string_list(data, pos)?),
        25 => Constraint::MatchesAny(read_wire_string_list(data, pos)?),
        26 => Constraint::MatchesNone(read_wire_string_list(data, pos)?),
        27 => Constraint::PrefixNone(read_wire_string_list(data, pos)?),
        28 => Constraint::SuffixNone(read_wire_string_list(data, pos)?),
        29 => Constraint::IntOneOf(read_wire_i64_list(data, pos)?),
        30 => Constraint::IntNone(read_wire_i64_list(data, pos)?),
        31 => Constraint::FloatOneOf(read_wire_f64_list(data, pos)?),
        32 => Constraint::FloatNone(read_wire_f64_list(data, pos)?),
        33 => Constraint::LenOneOf(read_wire_usize_list(data, pos)?),
        34 => Constraint::LenNone(read_wire_usize_list(data, pos)?),
        35 => Constraint::CharLenOneOf(read_wire_usize_list(data, pos)?),
        36 => Constraint::CharLenNone(read_wire_usize_list(data, pos)?),
        37 => {
            let min =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            Constraint::MinCharLen(min)
        }
        38 => {
            let max =
                u64::from_be_bytes(read_wire_bytes(data, pos, 8)?.try_into().unwrap()) as usize;
            Constraint::MaxCharLen(max)
        }
        _ => return Err(WireError::UnexpectedEof), // Invalid constraint type
    };

    Ok(constraint)
}

impl Token {
    fn has_v5_fields(&self) -> bool {
        self.nbf.is_some() || self.depth > 0 || self.max_depth.is_some()
    }

    fn has_v6_fields(&self) -> bool {
        !self.required_keys.is_empty()
    }

    /// Encode this token to compact binary wire format.
    ///
    /// Tokens without required_keys and without nbf/depth/max_depth are
    /// written as v4 so the bytes match the v0.5 encoding of the same
    /// fields. Tokens with v5 fields and no required keys stay on v5.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        let version = if self.has_v6_fields() {
            WIRE_VERSION
        } else if self.has_v5_fields() {
            WIRE_VERSION_V5
        } else {
            WIRE_VERSION_V4
        };
        buf.push(version);

        // Tool name
        let name_bytes = self.tool_name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        // Arg keys
        buf.extend_from_slice(&(self.arg_keys.len() as u16).to_be_bytes());
        for key in &self.arg_keys {
            let key_bytes = key.as_bytes();
            buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(key_bytes);
        }

        // Expiry
        buf.extend_from_slice(&self.expiry.to_be_bytes());

        // Nonce (u8 length since nonce is typically 16 bytes)
        buf.push(self.nonce.len() as u8);
        buf.extend_from_slice(&self.nonce);

        // MAC (u8 length since MAC is typically 32 bytes)
        buf.push(self.mac.len() as u8);
        buf.extend_from_slice(&self.mac);

        // Audience (optional)
        match &self.audience {
            Some(aud) => {
                let aud_bytes = aud.as_bytes();
                buf.extend_from_slice(&(aud_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(aud_bytes);
            }
            None => {
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        // Kid (optional, v2+)
        match &self.kid {
            Some(kid) => {
                let kid_bytes = kid.as_bytes();
                buf.extend_from_slice(&(kid_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(kid_bytes);
            }
            None => {
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        // Constraints (optional, v3+)
        match &self.constraints {
            Some(c) if !c.is_empty() => {
                buf.extend_from_slice(&(c.len() as u16).to_be_bytes());
                // BTreeMap iterates in sorted order
                for (key, constraint) in c.iter() {
                    encode_constraint_to_wire(&mut buf, key, constraint);
                }
            }
            _ => {
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        // Jti (optional, v4+)
        match &self.jti {
            Some(jti) => {
                let jti_bytes = jti.as_bytes();
                buf.extend_from_slice(&(jti_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(jti_bytes);
            }
            None => {
                buf.extend_from_slice(&0u16.to_be_bytes());
            }
        }

        // nbf / depth / max_depth (v5+)
        if version >= WIRE_VERSION_V5 {
            match self.nbf {
                Some(nbf) => {
                    buf.push(1);
                    buf.extend_from_slice(&nbf.to_be_bytes());
                }
                None => buf.push(0),
            }
            buf.extend_from_slice(&self.depth.to_be_bytes());
            match self.max_depth {
                Some(max) => {
                    buf.push(1);
                    buf.extend_from_slice(&max.to_be_bytes());
                }
                None => buf.push(0),
            }
        }

        // required_keys (v6 only)
        if version >= WIRE_VERSION {
            buf.extend_from_slice(&(self.required_keys.len() as u16).to_be_bytes());
            for key in &self.required_keys {
                let key_bytes = key.as_bytes();
                buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(key_bytes);
            }
        }

        buf
    }

    /// Decode a token from compact binary wire format.
    ///
    /// Supports both v1 (no kid) and v2 (with kid) formats.
    /// Extra trailing bytes after a complete token are ignored.
    pub fn from_wire(data: &[u8]) -> Result<Token, WireError> {
        Self::from_wire_consumed(data).map(|(token, _)| token)
    }

    /// Decode a token and report how many bytes were consumed.
    ///
    /// Used by the compact string codec to reject trailing garbage after
    /// the wire payload.
    pub(crate) fn from_wire_consumed(data: &[u8]) -> Result<(Token, usize), WireError> {
        let mut pos = 0;

        // Helper to read bytes
        let read_bytes = |pos: &mut usize, len: usize| -> Result<&[u8], WireError> {
            if *pos + len > data.len() {
                return Err(WireError::UnexpectedEof);
            }
            let slice = &data[*pos..*pos + len];
            *pos += len;
            Ok(slice)
        };

        // Version
        let version = *read_bytes(&mut pos, 1)?.first().unwrap();
        if !(WIRE_VERSION_MIN..=WIRE_VERSION).contains(&version) {
            return Err(WireError::UnsupportedVersion(version));
        }

        // Tool name
        let name_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let name_bytes = read_bytes(&mut pos, name_len)?;
        let tool_name =
            String::from_utf8(name_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?;

        // Arg keys
        let keys_count = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let mut arg_keys = Vec::with_capacity(keys_count);
        for _ in 0..keys_count {
            let key_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            let key_bytes = read_bytes(&mut pos, key_len)?;
            let key = String::from_utf8(key_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?;
            arg_keys.push(key);
        }

        // Expiry
        let expiry = u64::from_be_bytes(read_bytes(&mut pos, 8)?.try_into().unwrap());

        // Nonce
        let nonce_len = *read_bytes(&mut pos, 1)?.first().unwrap() as usize;
        let nonce = read_bytes(&mut pos, nonce_len)?.to_vec();

        // MAC
        let mac_len = *read_bytes(&mut pos, 1)?.first().unwrap() as usize;
        let mac = read_bytes(&mut pos, mac_len)?.to_vec();

        // Audience
        let aud_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
        let audience = if aud_len > 0 {
            let aud_bytes = read_bytes(&mut pos, aud_len)?;
            Some(String::from_utf8(aud_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?)
        } else {
            None
        };

        // Kid (v2+ only)
        let kid = if version >= 2 {
            let kid_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            if kid_len > 0 {
                let kid_bytes = read_bytes(&mut pos, kid_len)?;
                Some(String::from_utf8(kid_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?)
            } else {
                None
            }
        } else {
            None
        };

        // Constraints (v3+ only)
        let constraints = if version >= 3 {
            let count = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            if count > 0 {
                let mut constraints: Constraints = BTreeMap::new();
                for _ in 0..count {
                    let (key, constraint) = decode_constraint_from_wire(data, &mut pos)?;
                    constraints.insert(key, constraint);
                }
                Some(constraints)
            } else {
                None
            }
        } else {
            None
        };

        // Jti (v4+ only)
        let jti = if version >= 4 {
            let jti_len = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            if jti_len > 0 {
                let jti_bytes = read_bytes(&mut pos, jti_len)?;
                Some(String::from_utf8(jti_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?)
            } else {
                None
            }
        } else {
            None
        };

        // nbf / depth / max_depth (v5+ only)
        let (nbf, depth, max_depth) = if version >= WIRE_VERSION_V5 {
            let nbf_flag = *read_bytes(&mut pos, 1)?.first().unwrap();
            let nbf = if nbf_flag == 1 {
                Some(u64::from_be_bytes(
                    read_bytes(&mut pos, 8)?.try_into().unwrap(),
                ))
            } else {
                None
            };
            let depth = u32::from_be_bytes(read_bytes(&mut pos, 4)?.try_into().unwrap());
            let max_flag = *read_bytes(&mut pos, 1)?.first().unwrap();
            let max_depth = if max_flag == 1 {
                Some(u32::from_be_bytes(
                    read_bytes(&mut pos, 4)?.try_into().unwrap(),
                ))
            } else {
                None
            };
            (nbf, depth, max_depth)
        } else {
            (None, 0, None)
        };

        // required_keys (v6+ only)
        let required_keys = if version >= WIRE_VERSION {
            let count = u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
            let mut keys = Vec::with_capacity(count);
            for _ in 0..count {
                let key_len =
                    u16::from_be_bytes(read_bytes(&mut pos, 2)?.try_into().unwrap()) as usize;
                let key_bytes = read_bytes(&mut pos, key_len)?;
                let key =
                    String::from_utf8(key_bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)?;
                keys.push(key);
            }
            keys
        } else {
            Vec::new()
        };

        Ok((
            Token {
                tool_name,
                arg_keys,
                expiry,
                nonce,
                mac,
                audience,
                kid,
                constraints,
                jti,
                nbf,
                depth,
                max_depth,
                required_keys,
            },
            pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-key-32-bytes-long!!";

    #[test]
    fn wire_roundtrip_basic() {
        let token = Token::mint(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.tool_name, token.tool_name);
        assert_eq!(decoded.arg_keys, token.arg_keys);
        assert_eq!(decoded.expiry, token.expiry);
        assert_eq!(decoded.nonce, token.nonce);
        assert_eq!(decoded.mac, token.mac);
        assert_eq!(decoded.audience, token.audience);
        assert_eq!(decoded.kid, token.kid);
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_with_audience() {
        let token = Token::mint_with_audience(
            SECRET,
            "write_file",
            vec!["path".into(), "data".into()],
            2000000000,
            Some("client-xyz".to_string()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.audience, Some("client-xyz".to_string()));
        assert!(decoded
            .verify_with_audience(SECRET, 1999999999, Some("client-xyz"))
            .is_ok());
    }

    #[test]
    fn wire_roundtrip_with_kid() {
        let token = Token::mint_with_kid(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            Some("key-2024".to_string()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.kid, Some("key-2024".to_string()));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_with_audience_and_kid() {
        let token = Token::mint_with_kid(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client-abc".to_string()),
            Some("key-2024".to_string()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.audience, Some("client-abc".to_string()));
        assert_eq!(decoded.kid, Some("key-2024".to_string()));
        assert!(decoded
            .verify_with_audience(SECRET, 1999999999, Some("client-abc"))
            .is_ok());
    }

    #[test]
    fn wire_roundtrip_empty_keys() {
        let token = Token::mint(SECRET, "ping", vec![], 2000000000);

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.arg_keys.len(), 0);
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_format_version() {
        let token = Token::mint(SECRET, "test", vec![], 1000);
        let wire = token.to_wire();

        // Tokens without nbf/depth/max_depth stay on v4 (identical to v0.5)
        assert_eq!(wire[0], WIRE_VERSION_V4);
        assert_eq!(wire[0], 4);
    }

    #[test]
    fn wire_unsupported_version() {
        let mut data = vec![99u8]; // Invalid version
        data.extend_from_slice(&[0, 4]); // tool name length
        data.extend_from_slice(b"test");

        let result = Token::from_wire(&data);
        assert_eq!(result, Err(WireError::UnsupportedVersion(99)));
    }

    #[test]
    fn wire_version_0_unsupported() {
        let mut data = vec![0u8]; // Version 0 is below minimum
        data.extend_from_slice(&[0, 4]);
        data.extend_from_slice(b"test");

        let result = Token::from_wire(&data);
        assert_eq!(result, Err(WireError::UnsupportedVersion(0)));
    }

    #[test]
    fn wire_truncated_data() {
        let token = Token::mint(SECRET, "test", vec![], 1000);
        let wire = token.to_wire();

        let truncated = &wire[..wire.len() / 2];
        let result = Token::from_wire(truncated);
        assert_eq!(result, Err(WireError::UnexpectedEof));
    }

    #[test]
    fn wire_is_compact() {
        let token = Token::mint(SECRET, "read", vec!["a".into()], 1000);

        let wire = token.to_wire();
        let json = serde_json::to_string(&token).unwrap();

        assert!(
            wire.len() < json.len(),
            "wire format should be smaller than JSON"
        );
    }

    #[test]
    fn wire_roundtrip_with_constraints() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
        constraints.insert(
            "limit".to_string(),
            Constraint::IntRange { min: 1, max: 100 },
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_exact() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("mode".to_string(), Constraint::Exact("read".to_string()));

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
    }

    #[test]
    fn wire_roundtrip_constraint_oneof() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "mode".to_string(),
            Constraint::OneOf(vec!["read".to_string(), "write".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        // OneOf values are sorted in wire encoding
        let decoded_constraint = decoded.constraints.as_ref().unwrap().get("mode").unwrap();
        match decoded_constraint {
            Constraint::OneOf(values) => {
                assert!(values.contains(&"read".to_string()));
                assert!(values.contains(&"write".to_string()));
            }
            _ => panic!("expected OneOf constraint"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_maxlen() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("query".to_string(), Constraint::MaxLen(256));

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
    }

    #[test]
    fn wire_roundtrip_constraint_suffix() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::Suffix(".txt".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_contains() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Contains("tmp".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_minlen() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("query".to_string(), Constraint::MinLen(8));

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_matches() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::Matches("*.txt".to_string()));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_without_minlen_stays_on_v4() {
        // Tokens that do not use MinLen or v5 fields stay on the v0.5 layout.
        let token = Token::mint(SECRET, "read", vec!["a".into()], 1000);
        let wire = token.to_wire();
        assert_eq!(wire[0], 4);
        let decoded = Token::from_wire(&wire).unwrap();
        assert!(decoded.constraints.is_none());
        assert!(decoded.verify(SECRET, 999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not_equals() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "role".to_string(),
            Constraint::NotEquals("admin".to_string()),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["role".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not_one_of() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "role".to_string(),
            Constraint::NotOneOf(vec!["root".to_string(), "admin".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["role".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        let decoded_constraint = decoded.constraints.as_ref().unwrap().get("role").unwrap();
        match decoded_constraint {
            Constraint::NotOneOf(values) => {
                assert_eq!(values, &vec!["admin".to_string(), "root".to_string()]);
            }
            _ => panic!("expected NotOneOf constraint"),
        }
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not_contains() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::NotContains("tmp".to_string()),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not_prefix() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::NotPrefix("/tmp/".to_string()),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_all() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::All(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::Suffix(".txt".to_string()),
            ]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_any() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Any(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::Prefix("/var/".to_string()),
            ]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_lenrange() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "query".to_string(),
            Constraint::LenRange { min: 1, max: 16 },
        );

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_charlenrange() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "query".to_string(),
            Constraint::CharLenRange { min: 1, max: 16 },
        );

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_prefix_one_of() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'p', b'a', b't', b'h', 21]),
            "wire must include PrefixOneOf type tag 21 after key path"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_suffix_one_of() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::SuffixOneOf(vec![".md".to_string(), ".txt".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "write_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'n', b'a', b'm', b'e', 22]),
            "wire must include SuffixOneOf type tag 22 after key name"
        );
    }

    #[test]
    fn wire_prefix_one_of_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::PrefixOneOf(vec![
                "/var/".to_string(),
                "/tmp/".to_string(),
                "/var/".to_string(),
            ]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("path").unwrap() {
            Constraint::PrefixOneOf(values) => {
                assert_eq!(values, &vec!["/tmp/".to_string(), "/var/".to_string()]);
            }
            other => panic!("expected PrefixOneOf, got {other:?}"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_contains_any() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "note".to_string(),
            Constraint::ContainsAny(vec!["tmp".to_string(), "var".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["note".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'n', b'o', b't', b'e', 23]),
            "wire must include ContainsAny type tag 23 after key note"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_contains_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "memo".to_string(),
            Constraint::ContainsNone(vec!["password".to_string(), "secret".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "write_note",
            vec!["memo".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'm', b'e', b'm', b'o', 24]),
            "wire must include ContainsNone type tag 24 after key memo"
        );
    }

    #[test]
    fn wire_contains_any_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "note".to_string(),
            Constraint::ContainsAny(vec![
                "var".to_string(),
                "tmp".to_string(),
                "var".to_string(),
            ]),
        );

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["note".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("note").unwrap() {
            Constraint::ContainsAny(values) => {
                assert_eq!(values, &vec!["tmp".to_string(), "var".to_string()]);
            }
            other => panic!("expected ContainsAny, got {other:?}"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_matches_any() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "file".to_string(),
            Constraint::MatchesAny(vec!["*.md".to_string(), "*.txt".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["file".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'f', b'i', b'l', b'e', 25]),
            "wire must include MatchesAny type tag 25 after key file"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_matches_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "skip".to_string(),
            Constraint::MatchesNone(vec!["*.bak".to_string(), "*.tmp".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["skip".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b's', b'k', b'i', b'p', 26]),
            "wire must include MatchesNone type tag 26 after key skip"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_prefix_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "dest".to_string(),
            Constraint::PrefixNone(vec!["/etc/".to_string(), "/root/".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["dest".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'd', b'e', b's', b't', 27]),
            "wire must include PrefixNone type tag 27 after key dest"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_suffix_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::SuffixNone(vec![".bak".to_string(), ".tmp".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'n', b'a', b'm', b'e', 28]),
            "wire must include SuffixNone type tag 28 after key name"
        );
    }

    #[test]
    fn wire_prefix_none_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "dest".to_string(),
            Constraint::PrefixNone(vec![
                "/root/".to_string(),
                "/etc/".to_string(),
                "/etc/".to_string(),
            ]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["dest".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("dest").unwrap() {
            Constraint::PrefixNone(values) => {
                assert_eq!(values, &vec!["/etc/".to_string(), "/root/".to_string()]);
            }
            other => panic!("expected PrefixNone, got {other:?}"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_int_one_of() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("mode".to_string(), Constraint::IntOneOf(vec![1, 2, 3]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'm', b'o', b'd', b'e', 29]),
            "wire must include IntOneOf type tag 29 after key mode"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_int_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("port".to_string(), Constraint::IntNone(vec![-1, 0]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["port".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'p', b'o', b'r', b't', 30]),
            "wire must include IntNone type tag 30 after key port"
        );
    }

    #[test]
    fn wire_int_one_of_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("mode".to_string(), Constraint::IntOneOf(vec![3, 1, 1, 2]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("mode").unwrap() {
            Constraint::IntOneOf(values) => {
                assert_eq!(values, &vec![1, 2, 3]);
            }
            other => panic!("expected IntOneOf, got {other:?}"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_float_one_of() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "score".to_string(),
            Constraint::FloatOneOf(vec![0.5, 1.5, 2.5]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["score".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(8)
                .any(|w| w == [0x00, 0x05, b's', b'c', b'o', b'r', b'e', 31]),
            "wire must include FloatOneOf type tag 31 after key score"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_float_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("bias".to_string(), Constraint::FloatNone(vec![0.0, -1.0]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["bias".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'b', b'i', b'a', b's', 32]),
            "wire must include FloatNone type tag 32 after key bias"
        );
    }

    #[test]
    fn wire_float_one_of_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "score".to_string(),
            Constraint::FloatOneOf(vec![2.5, 0.5, 0.5, 1.5]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["score".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("score").unwrap() {
            Constraint::FloatOneOf(values) => {
                assert_eq!(values, &vec![0.5, 1.5, 2.5]);
            }
            other => panic!("expected FloatOneOf, got {other:?}"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_len_one_of() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("pin".to_string(), Constraint::LenOneOf(vec![4, 8, 16]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["pin".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(6)
                .any(|w| w == [0x00, 0x03, b'p', b'i', b'n', 33]),
            "wire must include LenOneOf type tag 33 after key pin"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_len_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::LenNone(vec![0, 1]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'n', b'a', b'm', b'e', 34]),
            "wire must include LenNone type tag 34 after key name"
        );
    }

    #[test]
    fn wire_len_one_of_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("pin".to_string(), Constraint::LenOneOf(vec![16, 4, 4, 8]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["pin".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("pin").unwrap() {
            Constraint::LenOneOf(values) => {
                assert_eq!(values, &vec![4, 8, 16]);
            }
            other => panic!("expected LenOneOf, got {other:?}"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_char_len_one_of() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("pin".to_string(), Constraint::CharLenOneOf(vec![4, 8, 16]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["pin".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(6)
                .any(|w| w == [0x00, 0x03, b'p', b'i', b'n', 35]),
            "wire must include CharLenOneOf type tag 35 after key pin"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_char_len_none() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("name".to_string(), Constraint::CharLenNone(vec![0, 1]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'n', b'a', b'm', b'e', 36]),
            "wire must include CharLenNone type tag 36 after key name"
        );
    }

    #[test]
    fn wire_char_len_one_of_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "pin".to_string(),
            Constraint::CharLenOneOf(vec![16, 4, 4, 8]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["pin".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("pin").unwrap() {
            Constraint::CharLenOneOf(values) => {
                assert_eq!(values, &vec![4, 8, 16]);
            }
            other => panic!("expected CharLenOneOf, got {other:?}"),
        }
    }

    #[test]
    fn wire_roundtrip_constraint_min_char_len() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("title".to_string(), Constraint::MinCharLen(3));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["title".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(8)
                .any(|w| w == [0x00, 0x05, b't', b'i', b't', b'l', b'e', 37]),
            "wire must include MinCharLen type tag 37 after key title"
        );
    }

    #[test]
    fn wire_roundtrip_constraint_max_char_len() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("title".to_string(), Constraint::MaxCharLen(16));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["title".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
        assert!(
            wire.windows(8)
                .any(|w| w == [0x00, 0x05, b't', b'i', b't', b'l', b'e', 38]),
            "wire must include MaxCharLen type tag 38 after key title"
        );
    }

    #[test]
    fn wire_without_min_char_len_keeps_prior_type_tags() {
        // Tokens that do not use MinCharLen/MaxCharLen must keep the 0.34.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("pin".to_string(), Constraint::CharLenOneOf(vec![4, 8, 16]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["pin".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(6)
                .any(|w| w == [0x00, 0x03, b'p', b'i', b'n', 35]),
            "CharLenOneOf must keep type tag 35"
        );
    }

    #[test]
    fn wire_without_char_len_one_of_keeps_prior_type_tags() {
        // Tokens that do not use CharLenOneOf/CharLenNone must keep the 0.33.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("pin".to_string(), Constraint::LenOneOf(vec![4, 8, 16]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["pin".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(6)
                .any(|w| w == [0x00, 0x03, b'p', b'i', b'n', 33]),
            "LenOneOf must keep type tag 33"
        );
    }

    #[test]
    fn wire_without_len_one_of_keeps_prior_type_tags() {
        // Tokens that do not use LenOneOf/LenNone must keep the 0.32.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "score".to_string(),
            Constraint::FloatOneOf(vec![0.5, 1.5, 2.5]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["score".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(8)
                .any(|w| w == [0x00, 0x05, b's', b'c', b'o', b'r', b'e', 31]),
            "wire must keep FloatOneOf type tag 31"
        );
    }

    #[test]
    fn wire_without_float_one_of_keeps_prior_type_tags() {
        // Tokens that do not use FloatOneOf/FloatNone must keep the 0.31.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("mode".to_string(), Constraint::IntOneOf(vec![1, 2, 3]));

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["mode".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'm', b'o', b'd', b'e', 29]),
            "wire must keep IntOneOf type tag 29"
        );
    }

    #[test]
    fn wire_without_int_one_of_keeps_prior_type_tags() {
        // Tokens that do not use IntOneOf/IntNone must keep the 0.30.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "dest".to_string(),
            Constraint::PrefixNone(vec!["/etc/".to_string(), "/root/".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["dest".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'd', b'e', b's', b't', 27]),
            "wire must keep PrefixNone type tag 27"
        );
    }

    #[test]
    fn wire_without_prefix_none_keeps_prior_type_tags() {
        // Tokens that do not use PrefixNone/SuffixNone must keep the 0.28.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "file".to_string(),
            Constraint::MatchesAny(vec!["*.md".to_string(), "*.txt".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["file".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'f', b'i', b'l', b'e', 25]),
            "wire must keep MatchesAny type tag 25"
        );
    }

    #[test]
    fn wire_matches_any_sorts_and_uniques() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "file".to_string(),
            Constraint::MatchesAny(vec![
                "*.md".to_string(),
                "*.txt".to_string(),
                "*.md".to_string(),
            ]),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["file".into()],
            2000000000,
            None,
            None,
            Some(constraints),
        );

        let decoded = Token::from_wire(&token.to_wire()).unwrap();
        match decoded.constraints.as_ref().unwrap().get("file").unwrap() {
            Constraint::MatchesAny(values) => {
                assert_eq!(values, &vec!["*.md".to_string(), "*.txt".to_string()]);
            }
            other => panic!("expected MatchesAny, got {other:?}"),
        }
    }

    #[test]
    fn wire_without_matches_any_keeps_prior_type_tags() {
        // Tokens that do not use MatchesAny/MatchesNone must keep the 0.27.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "note".to_string(),
            Constraint::ContainsAny(vec!["tmp".to_string(), "var".to_string()]),
        );

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["note".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'n', b'o', b't', b'e', 23]),
            "wire must keep ContainsAny type tag 23"
        );
    }

    #[test]
    fn wire_without_contains_any_keeps_prior_type_tags() {
        // Tokens that do not use ContainsAny/ContainsNone must keep the 0.26.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::PrefixOneOf(vec!["/tmp/".to_string(), "/var/".to_string()]),
        );
        constraints.insert("name".to_string(), Constraint::Suffix(".txt".to_string()));

        let token = Token::mint_full(
            SECRET,
            "file_op",
            vec!["path".into(), "name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'p', b'a', b't', b'h', 21]),
            "PrefixOneOf must keep type tag 21"
        );
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'n', b'a', b'm', b'e', 5]),
            "Suffix must keep type tag 5"
        );
        assert!(!wire
            .windows(7)
            .any(|w| w == [0x00, 0x04, b'n', b'o', b't', b'e', 23]));
        assert!(!wire
            .windows(7)
            .any(|w| w == [0x00, 0x04, b'm', b'e', b'm', b'o', 24]));
    }

    #[test]
    fn wire_without_prefix_one_of_keeps_prior_type_tags() {
        // Tokens that do not use PrefixOneOf/SuffixOneOf must keep the 0.25.0 tags.
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "query".to_string(),
            Constraint::CharLenRange { min: 1, max: 16 },
        );
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_full(
            SECRET,
            "search",
            vec!["query".into(), "path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.constraints, Some(constraints));
        assert!(
            wire.windows(8)
                .any(|w| w == [0x00, 0x05, b'q', b'u', b'e', b'r', b'y', 20]),
            "CharLenRange must keep type tag 20"
        );
        assert!(
            wire.windows(7)
                .any(|w| w == [0x00, 0x04, b'p', b'a', b't', b'h', 2]),
            "Prefix must keep type tag 2"
        );
        assert!(!wire
            .windows(7)
            .any(|w| w == [0x00, 0x04, b'p', b'a', b't', b'h', 21]));
    }

    #[test]
    fn wire_roundtrip_constraint_floatrange() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "score".to_string(),
            Constraint::FloatRange {
                min: -1.5,
                max: 2.25,
            },
        );

        let token = Token::mint_full(
            SECRET,
            "score_tool",
            vec!["score".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Not(Box::new(Constraint::Prefix("/tmp/".to_string()))),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not_nested_all() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "path".to_string(),
            Constraint::Not(Box::new(Constraint::All(vec![
                Constraint::Prefix("/tmp/".to_string()),
                Constraint::Suffix(".txt".to_string()),
            ]))),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not_suffix() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::NotSuffix(".txt".to_string()),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_constraint_not_matches() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert(
            "name".to_string(),
            Constraint::NotMatches("*.txt".to_string()),
        );

        let token = Token::mint_full(
            SECRET,
            "read_file",
            vec!["name".into()],
            2000000000,
            None,
            None,
            Some(constraints.clone()),
        );

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.constraints, Some(constraints));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_no_constraints() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert!(decoded.constraints.is_none());
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_v2_token_decodes_without_constraints() {
        // Manually construct a v2 wire format token
        let mut data = vec![2u8]; // Version 2
        data.extend_from_slice(&[0, 4]); // tool name length
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[0, 0]); // 0 arg keys
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x07, 0xD0]); // expiry = 2000
        data.push(16); // nonce length
        data.extend_from_slice(&[0u8; 16]); // nonce
        data.push(32); // mac length
        data.extend_from_slice(&[0u8; 32]); // mac
        data.extend_from_slice(&[0, 0]); // no audience
        data.extend_from_slice(&[0, 0]); // no kid

        let result = Token::from_wire(&data);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(token.constraints.is_none());
    }

    #[test]
    fn wire_v3_token_decodes_without_jti() {
        // Manually construct a v3 wire format token (with constraints, no jti)
        let mut data = vec![3u8]; // Version 3
        data.extend_from_slice(&[0, 4]); // tool name length
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[0, 0]); // 0 arg keys
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x07, 0xD0]); // expiry = 2000
        data.push(16); // nonce length
        data.extend_from_slice(&[0u8; 16]); // nonce
        data.push(32); // mac length
        data.extend_from_slice(&[0u8; 32]); // mac
        data.extend_from_slice(&[0, 0]); // no audience
        data.extend_from_slice(&[0, 0]); // no kid
        data.extend_from_slice(&[0, 0]); // 0 constraints

        let result = Token::from_wire(&data);
        assert!(result.is_ok());
        let token = result.unwrap();
        assert!(token.constraints.is_none());
        assert!(token.jti.is_none());
    }

    #[test]
    fn wire_roundtrip_with_jti() {
        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            true,
        );
        assert!(token.jti.is_some());

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.jti, token.jti);
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_with_jti_and_constraints() {
        use crate::constraint::Constraint;
        use std::collections::BTreeMap;

        let mut constraints: BTreeMap<String, Constraint> = BTreeMap::new();
        constraints.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));

        let token = Token::mint_with_jti(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            Some("client".to_string()),
            Some("key1".to_string()),
            Some(constraints.clone()),
            true,
        );
        assert!(token.jti.is_some());

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert_eq!(decoded.jti, token.jti);
        assert_eq!(decoded.constraints, Some(constraints));
        assert_eq!(decoded.audience, Some("client".to_string()));
        assert_eq!(decoded.kid, Some("key1".to_string()));
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_roundtrip_without_jti() {
        let token = Token::mint(SECRET, "read_file", vec!["path".into()], 2000000000);
        assert!(token.jti.is_none());

        let wire = token.to_wire();
        let decoded = Token::from_wire(&wire).unwrap();

        assert!(decoded.jti.is_none());
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_v4_backward_compatible_decoding() {
        // Create tokens with various combinations and verify roundtrip
        let cases = vec![
            (true, false, false, false),  // only jti
            (false, true, false, false),  // only constraints
            (true, true, false, false),   // jti + constraints
            (true, true, true, true),     // all fields
            (false, false, false, false), // none
        ];

        for (has_jti, has_constraints, has_audience, has_kid) in cases {
            use crate::constraint::Constraint;
            use std::collections::BTreeMap;

            let constraints = if has_constraints {
                let mut c: BTreeMap<String, Constraint> = BTreeMap::new();
                c.insert("path".to_string(), Constraint::Prefix("/tmp/".to_string()));
                Some(c)
            } else {
                None
            };

            let token = Token::mint_with_jti(
                SECRET,
                "test",
                vec!["path".into()],
                2000000000,
                if has_audience {
                    Some("aud".to_string())
                } else {
                    None
                },
                if has_kid {
                    Some("kid".to_string())
                } else {
                    None
                },
                constraints.clone(),
                has_jti,
            );

            let wire = token.to_wire();
            let decoded = Token::from_wire(&wire).unwrap();

            assert_eq!(decoded.jti.is_some(), has_jti);
            assert_eq!(decoded.constraints.is_some(), has_constraints);
            assert_eq!(decoded.audience.is_some(), has_audience);
            assert_eq!(decoded.kid.is_some(), has_kid);
            assert!(decoded.verify(SECRET, 1999999999).is_ok());
        }
    }

    #[test]
    fn wire_roundtrip_with_nbf_and_depth() {
        let token = Token::mint_complete(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            Some(3),
        );
        let attenuated = token.attenuate(SECRET, None, Some(1950000000)).unwrap();
        assert_eq!(attenuated.depth, 1);

        let wire = attenuated.to_wire();
        assert_eq!(wire[0], WIRE_VERSION_V5);
        assert_eq!(wire[0], 5);

        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.nbf, Some(1_900_000_000));
        assert_eq!(decoded.depth, 1);
        assert_eq!(decoded.max_depth, Some(3));
        assert!(decoded.verify(SECRET, 1_940_000_000).is_ok());
    }

    #[test]
    fn wire_v4_v05_token_decodes_without_nbf_or_depth() {
        // Manually construct a v4 (v0.5) wire token: jti present, no nbf/depth
        let mut data = vec![4u8]; // Version 4
        data.extend_from_slice(&[0, 4]); // tool name length
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[0, 0]); // 0 arg keys
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x07, 0xD0]); // expiry = 2000
        data.push(16); // nonce length
        data.extend_from_slice(&[0u8; 16]); // nonce
        data.push(32); // mac length
        data.extend_from_slice(&[0u8; 32]); // mac
        data.extend_from_slice(&[0, 0]); // no audience
        data.extend_from_slice(&[0, 0]); // no kid
        data.extend_from_slice(&[0, 0]); // 0 constraints
        data.extend_from_slice(&[0, 6]); // jti length 6
        data.extend_from_slice(b"jti123");

        let token = Token::from_wire(&data).unwrap();
        assert_eq!(token.jti.as_deref(), Some("jti123"));
        assert!(token.nbf.is_none());
        assert_eq!(token.depth, 0);
        assert!(token.max_depth.is_none());
    }

    #[test]
    fn wire_v05_bytes_match_tokens_without_new_fields() {
        // A freshly minted token without nbf/depth/max_depth must encode as
        // the v0.5 v4 layout: version byte 4 and no trailing v5 fields.
        let token = Token::mint_with_jti(
            SECRET,
            "read",
            vec!["a".into()],
            1000,
            None,
            None,
            None,
            false,
        );
        let wire = token.to_wire();
        assert_eq!(wire[0], 4);

        let decoded = Token::from_wire(&wire).unwrap();
        assert!(decoded.nbf.is_none());
        assert_eq!(decoded.depth, 0);
        assert!(decoded.max_depth.is_none());
        assert!(decoded.verify(SECRET, 999).is_ok());
    }

    #[test]
    fn wire_roundtrip_with_required_keys() {
        let token = Token::mint_with_required_keys(
            SECRET,
            "read_file",
            vec!["path".into(), "limit".into()],
            2000000000,
            None,
            None,
            None,
            false,
            None,
            None,
            vec!["path".into()],
        )
        .unwrap();
        let wire = token.to_wire();
        assert_eq!(wire[0], WIRE_VERSION);
        assert_eq!(wire[0], 6);

        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.required_keys, vec!["path"]);
        assert_eq!(decoded, token);
        assert!(decoded.verify(SECRET, 1999999999).is_ok());
    }

    #[test]
    fn wire_required_keys_with_nbf_uses_v6() {
        let token = Token::mint_with_required_keys(
            SECRET,
            "read_file",
            vec!["path".into()],
            2000000000,
            None,
            None,
            None,
            false,
            Some(1_900_000_000),
            Some(2),
            vec!["path".into()],
        )
        .unwrap();
        let wire = token.to_wire();
        assert_eq!(wire[0], 6);
        let decoded = Token::from_wire(&wire).unwrap();
        assert_eq!(decoded.nbf, Some(1_900_000_000));
        assert_eq!(decoded.max_depth, Some(2));
        assert_eq!(decoded.required_keys, vec!["path"]);
        assert!(decoded.verify(SECRET, 1_950_000_000).is_ok());
    }
}
