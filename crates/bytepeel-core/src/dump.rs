//! Parsing of hex dump text formats: `xxd` and `hexdump -C`.
//!
//! A dump is recognised only by its structural markers — an offset column
//! followed by `:` for `xxd`, or by two spaces and a `|`-delimited ASCII
//! column for `hexdump -C` — never by guessing which column holds the hex.
//! Plain hex, base64 and prose therefore never match.

use crate::Diag;

/// Cap on bytes a single `*` line may expand to (guards against tiny inputs
/// that claim gigabytes of repeated data).
const MAX_REPEAT: usize = 64 << 20;

/// A decoded hex dump.
pub(crate) struct Dump {
    pub bytes: Vec<u8>,
    /// Which dump format this came from: `"xxd"` or `"hexdump"`.
    pub style: &'static str,
}

/// Decode `xxd` / `hexdump -C` text.
///
/// Returns `None` when `s` is not a dump at all (so plain hex, base64 or prose
/// is never claimed). Returns `Some(Err(..))` when `s` clearly is a dump but
/// is malformed.
pub(crate) fn decode_dump(s: &str) -> Option<Result<Dump, Diag>> {
    let lines: Vec<(usize, &str)> = lines_with_offsets(s)
        .into_iter()
        .filter(|(_, line)| !line.trim().is_empty())
        .collect();
    let (_, first) = *lines.first()?;
    let style = detect_style(first)?;
    let result = match style {
        Style::Xxd => parse_xxd(&lines),
        Style::Hexdump => parse_hexdump(&lines),
    };
    Some(result).filter(|r| match r {
        // An offset column with no data byte is not a dump.
        Ok(d) => !d.bytes.is_empty(),
        Err(_) => true,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Xxd,
    Hexdump,
}

/// Recognise the format from the first line. `None` means "not a dump".
fn detect_style(line: &str) -> Option<Style> {
    let (offset, idx) = offset_prefix(line)?;
    // A dump always starts at offset 0.
    if offset != 0 {
        return None;
    }
    let rest = &line.as_bytes()[idx..];
    match rest {
        [b':', ..] => Some(Style::Xxd),
        [b' ', b' ', ..] if line.contains('|') => Some(Style::Hexdump),
        _ => None,
    }
}

/// Parse a leading hex offset. Returns `(value, byte index just past it)`.
fn offset_prefix(line: &str) -> Option<(usize, usize)> {
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_hexdigit() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let value = usize::from_str_radix(&line[..i], 16).ok()?;
    Some((value, i))
}

/// Split `s` into lines, keeping the byte offset of each line start and
/// stripping a trailing `\r`.
fn lines_with_offsets(s: &str) -> Vec<(usize, &str)> {
    let bytes = s.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    loop {
        if i == bytes.len() || bytes[i] == b'\n' {
            let mut end = i;
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            lines.push((start, &s[start..end]));
            start = i + 1;
            if i == bytes.len() {
                break;
            }
        }
        i += 1;
    }
    lines
}

fn bad(offset: usize, message: impl Into<String>) -> Diag {
    Diag::new("BAD_DUMP", message, Some(offset))
}

/// Parse the hex-byte region between an offset and the ASCII column. Tokens
/// are separated by spaces and must have an even number of hex digits.
fn parse_hex_region(region: &str, base: usize, out: &mut Vec<u8>) -> Result<(), Diag> {
    let b = region.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b' ' {
            i += 1;
            continue;
        }
        let tok_start = i;
        let mut digits = Vec::new();
        while i < b.len() && b[i] != b' ' {
            let c = b[i];
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => {
                    return Err(Diag::new(
                        "INVALID_CHAR",
                        format!("byte 0x{c:02x} is not a hex digit"),
                        Some(base + i),
                    ));
                }
            };
            digits.push(v);
            i += 1;
        }
        if digits.len() % 2 != 0 {
            return Err(Diag::new(
                "INVALID_CHAR",
                "hex token has an odd number of digits",
                Some(base + tok_start),
            ));
        }
        for pair in digits.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    }
    Ok(())
}

fn parse_xxd(lines: &[(usize, &str)]) -> Result<Dump, Diag> {
    let mut out = Vec::new();
    let mut expected = 0usize;
    for &(start, line) in lines {
        let (offset, idx) = offset_prefix(line)
            .ok_or_else(|| bad(start, "line does not start with a hex offset"))?;
        if line.as_bytes().get(idx) != Some(&b':') {
            return Err(bad(start, "expected ':' after the offset"));
        }
        if offset != expected {
            return Err(bad(
                start,
                format!("offset 0x{offset:x} does not follow 0x{expected:x}"),
            ));
        }
        // The ASCII column is separated by at least two spaces; everything
        // before them is the hex region. This ignores ASCII that looks hex.
        let rest = &line[idx + 1..];
        let hex_end = rest.find("  ").unwrap_or(rest.len());
        let before = out.len();
        parse_hex_region(&rest[..hex_end], start + idx + 1, &mut out)?;
        expected += out.len() - before;
    }
    Ok(Dump {
        bytes: out,
        style: "xxd",
    })
}

fn parse_hexdump(lines: &[(usize, &str)]) -> Result<Dump, Diag> {
    let mut out = Vec::new();
    let mut expected = 0usize;
    let mut prev: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let (start, line) = lines[i];
        if line.trim() == "*" {
            if prev.is_empty() {
                return Err(bad(start, "'*' with no preceding data line"));
            }
            let Some(&(next_start, next)) = lines.get(i + 1) else {
                return Err(bad(start, "'*' is not followed by an offset"));
            };
            let (next_offset, _) = offset_prefix(next).ok_or_else(|| {
                bad(
                    next_start,
                    "line after '*' does not start with a hex offset",
                )
            })?;
            let Some(span) = next_offset.checked_sub(expected) else {
                return Err(bad(start, "'*' repeats past the following offset"));
            };
            if span > MAX_REPEAT {
                return Err(bad(start, "'*' repeat would expand past 64 MiB"));
            }
            if span == 0 || span % prev.len() != 0 {
                return Err(bad(start, "'*' repeat count does not fit the offset gap"));
            }
            for _ in 0..span / prev.len() {
                out.extend_from_slice(&prev);
            }
            expected = next_offset;
            i += 1;
            continue;
        }
        let (offset, idx) = offset_prefix(line)
            .ok_or_else(|| bad(start, "line does not start with a hex offset"))?;
        if offset != expected {
            return Err(bad(
                start,
                format!("offset 0x{offset:x} does not follow 0x{expected:x}"),
            ));
        }
        if let Some(bar) = line.find('|') {
            // Data line: hex bytes live between the offset and the `|` column.
            let before = out.len();
            parse_hex_region(&line[idx..bar], start + idx, &mut out)?;
            let added = out.len() - before;
            expected += added;
            if added > 0 {
                prev = out[out.len() - added..].to_vec();
            }
        } else {
            // A line with only the end offset terminates the dump.
            if !line[idx..].trim().is_empty() {
                return Err(bad(start, "expected a hex byte or an end offset"));
            }
            break;
        }
        i += 1;
    }
    Ok(Dump {
        bytes: out,
        style: "hexdump",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(s: &str) -> Dump {
        match decode_dump(s) {
            Some(Ok(d)) => d,
            Some(Err(e)) => panic!("unexpected error: {e}"),
            None => panic!("expected a dump, got none for {s:?}"),
        }
    }

    fn err(s: &str) -> Diag {
        match decode_dump(s) {
            Some(Err(e)) => e,
            Some(Ok(_)) => panic!("expected an error for {s:?}"),
            None => panic!("expected a dump, got none for {s:?}"),
        }
    }

    fn none(s: &str) {
        assert!(decode_dump(s).is_none(), "should not be a dump: {s:?}");
    }

    // ------------------------------------------------------------ xxd

    #[test]
    fn xxd_default() {
        // Real xxd output for the 16-byte sample "....foo...bar...".
        let s = "00000000: 2e2e 2e2e 666f 6f2e 2e2e 6261 722e 2e2e  ....foo...bar...\n";
        let d = dump(s);
        assert_eq!(d.style, "xxd");
        assert_eq!(d.bytes, b"....foo...bar...");
    }

    #[test]
    fn xxd_task_example() {
        let s = "00000000: 0a14 0a03 666f 6f12  ....foo.\n";
        let d = dump(s);
        assert_eq!(d.style, "xxd");
        assert_eq!(d.bytes, [0x0a, 0x14, 0x0a, 0x03, 0x66, 0x6f, 0x6f, 0x12]);
    }

    #[test]
    fn xxd_g1() {
        let s = "00000000: 2e 2e 2e 2e 66 6f 6f 2e 2e 2e 62 61 72 2e 2e 2e  ....foo...bar...\n";
        let d = dump(s);
        assert_eq!(d.style, "xxd");
        assert_eq!(d.bytes, b"....foo...bar...");
    }

    #[test]
    fn xxd_short_last_line() {
        let s = "00000000: 2e2e 2e2e 666f 6f2e 2e2e 6261 722e 2e2e  ....foo...bar...\n00000010: 2121 2121                                !!!!\n";
        let d = dump(s);
        assert_eq!(d.style, "xxd");
        assert_eq!(d.bytes, b"....foo...bar...!!!!");
    }

    #[test]
    fn xxd_letter_short_line() {
        // "hello\n" (6 bytes): the last line is padded before the ASCII column.
        let s = "00000000: 6865 6c6c 6f0a                           hello.\n";
        let d = dump(s);
        assert_eq!(d.style, "xxd");
        assert_eq!(d.bytes, b"hello\n");
    }

    #[test]
    fn xxd_ascii_looks_hex() {
        // The trailing `cafe` / `deadbeef` is an ASCII column, not data.
        assert_eq!(dump("00000000: 0a14  cafe\n").bytes, [0x0a, 0x14]);
        assert_eq!(dump("00000000: 0102  deadbeef\n").bytes, [0x01, 0x02]);
    }

    #[test]
    fn xxd_crlf_and_trailing_spaces() {
        let s = "00000000: 0a14 0a03 666f 6f12  ....foo.  \r\n";
        assert_eq!(
            dump(s).bytes,
            [0x0a, 0x14, 0x0a, 0x03, 0x66, 0x6f, 0x6f, 0x12]
        );
    }

    #[test]
    fn xxd_bad_offset_not_contiguous() {
        let s = "00000000: 2e2e 2e2e 666f 6f2e 2e2e 6261 722e 2e2e  ....foo...bar...\n00000020: 2121 2121                                !!!!\n";
        let e = err(s);
        assert_eq!(e.code, "BAD_DUMP");
        assert_eq!(e.offset, Some(s.find("00000020").unwrap()));
    }

    #[test]
    fn xxd_invalid_char() {
        let s = "00000000: 0a1g  cafe\n";
        let e = err(s);
        assert_eq!(e.code, "INVALID_CHAR");
        assert_eq!(e.offset, Some(s.find('g').unwrap()));
    }

    // ------------------------------------------------------------ hexdump

    #[test]
    fn hexdump_c_basic() {
        // Real `hexdump -C` output for the 16-byte sample.
        let s = "00000000  2e 2e 2e 2e 66 6f 6f 2e  2e 2e 62 61 72 2e 2e 2e  |....foo...bar...|\n00000010\n";
        let d = dump(s);
        assert_eq!(d.style, "hexdump");
        assert_eq!(d.bytes, b"....foo...bar...");
    }

    #[test]
    fn hexdump_c_task_example() {
        let s = "00000000  0a 14 0a 03 66 6f 6f 12  0a 03 62 61 72 1a 07 00  |....foo...bar...|\n00000010\n";
        let d = dump(s);
        assert_eq!(d.style, "hexdump");
        assert_eq!(
            d.bytes,
            [
                0x0a, 0x14, 0x0a, 0x03, 0x66, 0x6f, 0x6f, 0x12, 0x0a, 0x03, 0x62, 0x61, 0x72, 0x1a,
                0x07, 0x00
            ]
        );
    }

    #[test]
    fn hexdump_c_short_last_line() {
        // 17 bytes: a full line followed by a one-byte line, then the end offset.
        let s = "00000000  2e 2e 2e 2e 66 6f 6f 2e  2e 2e 62 61 72 2e 2e 2e  |....foo...bar...|\n00000010  21                                                |!|\n00000011\n";
        let d = dump(s);
        assert_eq!(d.style, "hexdump");
        assert_eq!(d.bytes, b"....foo...bar...!");
    }

    #[test]
    fn hexdump_c_repeat_star() {
        // Real `hexdump -C` output: three identical lines collapse to `*`.
        let s = "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n*\n00000030  58 58                                             |XX|\n00000032\n";
        let d = dump(s);
        assert_eq!(d.style, "hexdump");
        assert_eq!(d.bytes.len(), 50);
        assert_eq!(&d.bytes[0..16], b"0123456789abcdef");
        assert_eq!(&d.bytes[16..32], b"0123456789abcdef");
        assert_eq!(&d.bytes[32..48], b"0123456789abcdef");
        assert_eq!(&d.bytes[48..], b"XX");
    }

    #[test]
    fn hexdump_c_repeat_then_data_line() {
        // `*` followed by another data line (not just the end offset).
        let s = "00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|\n*\n00000020  11 22                                             |.\"|\n00000022\n";
        let d = dump(s);
        assert_eq!(d.bytes.len(), 0x22);
        assert!(d.bytes[0..0x20].iter().all(|&b| b == 0));
        assert_eq!(&d.bytes[0x20..], &[0x11, 0x22]);
    }

    #[test]
    fn hexdump_c_ascii_looks_hex() {
        let s =
            "00000000  01 02                                             |deadbeef|\n00000002\n";
        assert_eq!(dump(s).bytes, [0x01, 0x02]);
    }

    #[test]
    fn hexdump_c_bad_offset_not_contiguous() {
        let s = "00000000  68 65 6c 6c 6f 0a                                 |hello.|\n00000020\n";
        let e = err(s);
        assert_eq!(e.code, "BAD_DUMP");
        assert_eq!(e.offset, Some(s.find("00000020").unwrap()));
    }

    #[test]
    fn hexdump_c_star_at_end_is_bad() {
        let s = "00000000  00 00                                             |..|\n*\n";
        let e = err(s);
        assert_eq!(e.code, "BAD_DUMP");
    }

    // ------------------------------------------------------------ not dumps

    #[test]
    fn plain_hex_is_not_a_dump() {
        none("0a 14 0a 03");
        none("0a140a03");
        none("0a:14:0a:03");
        none("00 01 02 03");
    }

    #[test]
    fn base64_is_not_a_dump() {
        none("SGVsbG8gd29ybGQ=");
        none("SGVsbG8gd29ybGQh");
    }

    #[test]
    fn prose_is_not_a_dump() {
        none("The quick brown fox jumps over the lazy dog.");
        none("=== not a dump ===\njust some words\n");
    }

    #[test]
    fn bare_offsets_are_not_dumps() {
        none("00000000"); // offset column but no data byte
        none("00000000:");
        none("00000000\n");
    }
}
