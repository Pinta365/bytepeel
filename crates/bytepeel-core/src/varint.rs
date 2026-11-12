//! LEB128 varints as used by protobuf.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// The buffer ended before a byte without the continuation bit.
    Truncated,
    /// More than 64 bits of payload (10th byte > 0x01, or an 11th byte).
    Overflow,
}

/// Decode a varint from the start of `buf`. Returns `(value, encoded_len)`.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), VarintError> {
    let mut value: u64 = 0;
    for i in 0..10 {
        let Some(&b) = buf.get(i) else {
            return Err(VarintError::Truncated);
        };
        if i == 9 && b > 1 {
            return Err(VarintError::Overflow);
        }
        value |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(VarintError::Overflow)
}

/// Encode `value` as a varint.
pub fn encode(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let b = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// ZigZag-decode (protobuf `sint32`/`sint64`).
pub fn zigzag(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}
