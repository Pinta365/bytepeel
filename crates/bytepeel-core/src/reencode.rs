//! Text-layer encoders that reproduce the style of the original text.
//!
//! The splicing/value/CLI parts live elsewhere; this module only turns bytes
//! back into hex / dump / base64 / PEM text matching a decoded layer's shape,
//! so that re-encoding unchanged bytes is byte-for-byte identical.

use std::fmt::Write as _;

use crate::{Alphabet, Diag};

// ---------------------------------------------------------------- hex

struct HexStyle {
    upper: bool,
    prefix_all: bool,
    prefix_first: bool,
    tok_bytes: usize,
    sep: String,
    wrapped: bool,
    per_line: usize,
    nl: &'static str,
}

fn is_hex_sep(c: u8) -> bool {
    c.is_ascii_whitespace() || c == b':'
}

/// Mirror the original hex text's separator, `0x` style, case, wrapping and
/// surrounding whitespace.
pub(crate) fn hex_like(orig: &str, bytes: &[u8]) -> String {
    let (lead, _core, trail) = split_ws(orig);
    let st = hex_style(orig);
    let mut out = String::new();
    out.push_str(lead);
    if bytes.is_empty() {
        out.push_str(trail);
        return out;
    }
    let per_line = if st.wrapped && st.per_line > 0 {
        st.per_line
    } else {
        bytes.len()
    };
    let mut pos = 0;
    let mut first_line = true;
    let mut first_token = true;
    while pos < bytes.len() {
        if !first_line {
            out.push_str(st.nl);
        }
        first_line = false;
        let line_end = (pos + per_line).min(bytes.len());
        let mut first_in_line = true;
        while pos < line_end {
            if !first_in_line {
                out.push_str(&st.sep);
            }
            first_in_line = false;
            if st.prefix_all || (st.prefix_first && first_token) {
                out.push_str("0x");
            }
            first_token = false;
            let tok_end = (pos + st.tok_bytes).min(line_end);
            for &b in &bytes[pos..tok_end] {
                if st.upper {
                    let _ = write!(out, "{b:02X}");
                } else {
                    let _ = write!(out, "{b:02x}");
                }
            }
            pos = tok_end;
        }
    }
    out.push_str(trail);
    out
}

fn hex_style(orig: &str) -> HexStyle {
    let (_, core, _) = split_ws(orig);
    let wrapped = core.contains('\n');
    let nl = if core.contains("\r\n") { "\r\n" } else { "\n" };
    let b = core.as_bytes();

    // Tokens: (start, end, digits, has_0x, line).
    let mut tokens: Vec<(usize, usize, usize, bool, u32)> = Vec::new();
    let mut line = 0u32;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if is_hex_sep(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && !is_hex_sep(b[i]) {
            i += 1;
        }
        let raw = &b[start..i];
        let has0x = raw.len() >= 2 && raw[0] == b'0' && (raw[1] | 0x20) == b'x';
        let digits = raw.len() - if has0x { 2 } else { 0 };
        tokens.push((start, i, digits, has0x, line));
    }

    let mut up = false;
    let mut low = false;
    for &c in b {
        if (b'A'..=b'F').contains(&c) {
            up = true;
        } else if (b'a'..=b'f').contains(&c) {
            low = true;
        }
    }

    let any0x = tokens.iter().any(|t| t.3);
    let all0x = !tokens.is_empty() && tokens.iter().all(|t| t.3);
    let tok_bytes = tokens.first().map_or(1, |t| (t.2 / 2).max(1));

    let mut sep = String::new();
    for w in tokens.windows(2) {
        let (a, c) = (w[0], w[1]);
        if a.4 == c.4 {
            sep = core[a.1..c.0].to_string();
            break;
        }
    }

    let line0_digits: usize = tokens.iter().filter(|t| t.4 == 0).map(|t| t.2).sum();
    let per_line = if wrapped && line0_digits > 0 {
        line0_digits / 2
    } else {
        0
    };

    HexStyle {
        upper: up && !low,
        prefix_all: all0x,
        prefix_first: any0x && !all0x,
        tok_bytes,
        sep,
        wrapped,
        per_line,
        nl,
    }
}

// ---------------------------------------------------------------- dumps

/// Emit `xxd` (16 bytes/line, group size from the original, ASCII column) or
/// `hexdump -C` (two 8-byte groups, `|ascii|`, `*` repeat compression and the
/// final end-offset line). `origin` is the offset of the first byte (nonzero
/// for `xxd -s` / `hexdump -s`). Blank lines before and line breaks after the
/// dump are kept.
pub(crate) fn dump_like(orig: &str, style: &str, origin: usize, bytes: &[u8]) -> String {
    let nl = if orig.contains("\r\n") { "\r\n" } else { "\n" };
    // Whole blank lines before the first offset, and the line breaks after the
    // last line (a trailing space can belong to the ASCII column).
    let lead_end = orig
        .split_inclusive('\n')
        .take_while(|l| l.trim().is_empty())
        .map(str::len)
        .sum::<usize>();
    let trail_start = orig.trim_end_matches(['\r', '\n']).len().max(lead_end);
    let (lead, body, final_nl) = (
        &orig[..lead_end],
        &orig[lead_end..trail_start],
        &orig[trail_start..],
    );
    let mut out = String::from(lead);

    if style == "hexdump" {
        let chunks: Vec<&[u8]> = bytes.chunks(16).collect();
        let mut prev_full: Option<&[u8]> = None;
        let mut star = false;
        for (i, chunk) in chunks.iter().enumerate() {
            let full = chunk.len() == 16;
            if full && prev_full == Some(*chunk) {
                if !star {
                    out.push('*');
                    out.push_str(nl);
                    star = true;
                }
            } else {
                out.push_str(&hexdump_line(origin + i * 16, chunk));
                out.push_str(nl);
                star = false;
                prev_full = if full { Some(*chunk) } else { None };
            }
        }
        let _ = write!(out, "{:08x}", origin + bytes.len());
        out.push_str(final_nl);
    } else {
        let g = xxd_group_size(body);
        let mut start = 0;
        let mut first = true;
        while start < bytes.len() {
            let end = (start + 16).min(bytes.len());
            if !first {
                out.push_str(nl);
            }
            first = false;
            out.push_str(&xxd_line(origin + start, &bytes[start..end], g));
            start = end;
        }
        out.push_str(final_nl);
    }
    out
}

fn xxd_group_size(orig: &str) -> usize {
    let first = orig.lines().next().unwrap_or("");
    let Some(colon) = first.find(':') else {
        return 2;
    };
    let after = &first[colon + 1..];
    let hex_start = after
        .find(|c: char| c != ' ')
        .map_or(colon + 1, |p| colon + 1 + p);
    let region = &first[hex_start..];
    let hex_end = region.find("  ").unwrap_or(region.len());
    let first_group = region[..hex_end].split(' ').next().unwrap_or("");
    (first_group.len() / 2).clamp(1, 16)
}

fn xxd_line(offset: usize, chunk: &[u8], g: usize) -> String {
    let mut s = String::new();
    let _ = write!(s, "{offset:08x}: ");
    let hex_start = s.len();
    for (i, &b) in chunk.iter().enumerate() {
        if i > 0 && i % g == 0 {
            s.push(' ');
        }
        let _ = write!(s, "{b:02x}");
    }
    let hex_width = 32 + 16usize.div_ceil(g) - 1;
    while s.len() - hex_start < hex_width + 2 {
        s.push(' ');
    }
    for &b in chunk {
        s.push(if (0x20..=0x7e).contains(&b) {
            b as char
        } else {
            '.'
        });
    }
    s
}

fn hexdump_line(offset: usize, chunk: &[u8]) -> String {
    let mut s = String::new();
    let _ = write!(s, "{offset:08x}  ");
    for i in 0..16 {
        if i > 0 {
            s.push(' ');
        }
        if i == 8 {
            s.push(' ');
        }
        match chunk.get(i) {
            Some(&b) => {
                let _ = write!(s, "{b:02x}");
            }
            None => s.push_str("  "),
        }
    }
    s.push_str("  |");
    for &b in chunk {
        s.push(if (0x20..=0x7e).contains(&b) {
            b as char
        } else {
            '.'
        });
    }
    s.push('|');
    s
}

// ---------------------------------------------------------------- base64

/// Encode `bytes` with the given alphabet and padding, wrapping at the
/// original's first-line width when it was wrapped, and preserving the
/// original's leading/trailing whitespace (including CRLF).
pub(crate) fn base64_like(orig: &str, alphabet: Alphabet, padded: bool, bytes: &[u8]) -> String {
    let (lead, core, trail) = split_ws(orig);
    let encoded = b64_encode(bytes, alphabet, padded);
    let mut out = String::new();
    out.push_str(lead);
    if core.contains('\n') {
        let nl = if core.contains("\r\n") { "\r\n" } else { "\n" };
        let first = core.split('\n').next().unwrap_or("");
        let first = first.strip_suffix('\r').unwrap_or(first);
        let width = first.trim_end().chars().count().max(1);
        for (i, chunk) in encoded.as_bytes().chunks(width).enumerate() {
            if i > 0 {
                out.push_str(nl);
            }
            let _ = out.write_str(std::str::from_utf8(chunk).unwrap_or(""));
        }
    } else {
        out.push_str(&encoded);
    }
    out.push_str(trail);
    out
}

fn b64_encode(bytes: &[u8], alphabet: Alphabet, padded: bool) -> String {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let a = match alphabet {
        Alphabet::Std => STD,
        Alphabet::Url => URL,
    };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(a[((n >> 18) & 63) as usize] as char);
        out.push(a[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(a[((n >> 6) & 63) as usize] as char);
        } else if padded {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(a[(n & 63) as usize] as char);
        } else if padded {
            out.push('=');
        }
    }
    out
}

// ---------------------------------------------------------------- PEM

/// Replace only the block at `block_range` with a re-encoded one, keeping the
/// rest of `orig` byte-exact. Fails for a block with RFC 1421 header lines.
pub(crate) fn pem_like(
    orig: &str,
    block_range: [usize; 2],
    label: &str,
    bytes: &[u8],
) -> Result<String, Diag> {
    let [start, end] = block_range;
    let block = &orig[start..end];
    let nl = if block.contains("\r\n") { "\r\n" } else { "\n" };
    let lines: Vec<&str> = block
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    if lines.len() >= 2 {
        for l in &lines[1..lines.len() - 1] {
            if l.contains(':') {
                return Err(Diag::new(
                    "REENCODE_UNSUPPORTED",
                    "PEM block has RFC 1421 headers; re-encoding is not supported",
                    Some(start),
                ));
            }
        }
    }
    let width = lines
        .get(1)
        .map(|l| l.trim_end().chars().count())
        .filter(|&w| w > 0)
        .unwrap_or(64);

    let b64 = b64_encode(bytes, Alphabet::Std, true);
    let mut out = String::new();
    let _ = write!(out, "-----BEGIN {label}-----");
    out.push_str(nl);
    for chunk in b64.as_bytes().chunks(width) {
        let _ = out.write_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push_str(nl);
    }
    let _ = write!(out, "-----END {label}-----");

    let mut result = String::with_capacity(orig.len());
    result.push_str(&orig[..start]);
    result.push_str(&out);
    result.push_str(&orig[end..]);
    Ok(result)
}

// ---------------------------------------------------------------- shared

/// Split `s` into leading whitespace, core and trailing whitespace.
fn split_ws(s: &str) -> (&str, &str, &str) {
    let lead_len = s.len() - s.trim_start().len();
    let rest = &s[lead_len..];
    let core_len = rest.trim_end().len();
    (&s[..lead_len], &rest[..core_len], &rest[core_len..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dump::{Dump, decode_dump};
    use crate::text::decode_pem;
    use crate::{decode_b64, decode_hex};

    fn dump(s: &str) -> Dump {
        decode_dump(s).expect("a dump").expect("decodable")
    }

    fn wrap(s: &str, width: usize, nl: &str, final_nl: bool) -> String {
        let mut out = String::new();
        for (i, chunk) in s.as_bytes().chunks(width).enumerate() {
            if i > 0 {
                out.push_str(nl);
            }
            out.push_str(std::str::from_utf8(chunk).unwrap());
        }
        if final_nl {
            out.push_str(nl);
        }
        out
    }

    #[test]
    fn hex_exact() {
        for o in [
            "089601",
            "08 96 01",
            "08:96:01",
            "0x089601",
            "0x08 0x96 0x01",
            "0896 0102",
            "08 96 A0",
            "08 96 a0",
            "0a14 0a03 666f 6f12",
            "08 96 01 02 03 04\n05 06",
            "08 96 01 02 03 04\n05 06\n",
            "\n08 96 01\n",
        ] {
            let bytes = decode_hex(o).unwrap();
            assert_eq!(hex_like(o, &bytes), o, "hex {o:?}");
        }
    }

    #[test]
    fn hex_changed_roundtrip() {
        let b = [0x0au8, 0x14, 0x0a, 0x03, 0x66];
        assert_eq!(hex_like("08 96 01", &b), "0a 14 0a 03 66");
        assert_eq!(hex_like("0x08 0x96 0x01", &b), "0x0a 0x14 0x0a 0x03 0x66");
        assert_eq!(hex_like("08 96 A0", &[1, 2]), "01 02");
        // A length change alters the line count at the original width.
        let out = hex_like("08 96 01\n02 03", &[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(out, "01 02 03\n04 05 06\n07");
        assert_eq!(decode_hex(&out).unwrap(), [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn xxd_exact() {
        for o in [
            "00000000: 2e2e 2e2e 666f 6f2e 2e2e 6261 722e 2e2e  ....foo...bar...\n",
            "00000000: 2e 2e 2e 2e 66 6f 6f 2e 2e 2e 62 61 72 2e 2e 2e  ....foo...bar...\n",
            "00000000: 2e2e2e2e 666f6f2e 2e2e6261 722e2e2e  ....foo...bar...\n",
            "00000000: 2e2e2e2e666f6f2e 2e2e6261722e2e2e  ....foo...bar...\n",
            "00000000: 2e2e 2e2e 666f 6f2e 2e2e 6261 722e 2e2e  ....foo...bar...\n00000010: 2121 2121                                !!!!\n",
            "00000000: 6865 6c6c 6f0a                           hello.\n",
        ] {
            let d = dump(o);
            assert_eq!(d.style, "xxd");
            assert_eq!(dump_like(o, "xxd", d.start, &d.bytes), o, "xxd {o:?}");
        }
    }

    #[test]
    fn hexdump_exact() {
        for o in [
            "00000000  2e 2e 2e 2e 66 6f 6f 2e  2e 2e 62 61 72 2e 2e 2e  |....foo...bar...|\n00000010\n",
            "00000000  2e 2e 2e 2e 66 6f 6f 2e  2e 2e 62 61 72 2e 2e 2e  |....foo...bar...|\n00000010  21                                                |!|\n00000011\n",
            "00000000  30 31 32 33 34 35 36 37  38 39 61 62 63 64 65 66  |0123456789abcdef|\n*\n00000030  58 58                                             |XX|\n00000032\n",
            "00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|\n*\n00000020  11 22                                             |.\"|\n00000022\n",
        ] {
            let d = dump(o);
            assert_eq!(d.style, "hexdump");
            assert_eq!(
                dump_like(o, "hexdump", d.start, &d.bytes),
                o,
                "hexdump {o:?}"
            );
        }
    }

    #[test]
    fn dump_changed_roundtrip() {
        let b: Vec<u8> = (0u8..40).collect();
        let xxd = "00000000: 6865 6c6c 6f0a                           hello.\n";
        let out = dump_like(xxd, "xxd", dump(xxd).start, &b);
        assert_eq!(dump(&out).bytes, b);
        let hd = "00000000  68 65 6c 6c 6f 0a                                 |hello.|\n00000006\n";
        let out = dump_like(hd, "hexdump", dump(hd).start, &b);
        assert_eq!(dump(&out).bytes, b);
    }

    #[test]
    fn dump_keeps_blank_edges_and_start() {
        let xxd = "\n\n00000040: 0896 01                                  ...\n\n";
        let d = dump(xxd);
        assert_eq!(dump_like(xxd, "xxd", d.start, &d.bytes), xxd);
        let out = dump_like(xxd, "xxd", d.start, &[0x08, 0x05]);
        assert_eq!(
            out,
            "\n\n00000040: 0805                                     ..\n\n"
        );
        let hd =
            "\r\n00000040  08 96 01                                          |...|\r\n00000043\r\n";
        let d = dump(hd);
        assert_eq!(dump_like(hd, "hexdump", d.start, &d.bytes), hd);
    }

    #[test]
    fn dump_nonzero_start_exact() {
        let xxd = "00000040: 2e2e 2e2e 666f 6f2e 2e2e 6261 722e 2e2e  ....foo...bar...\n";
        let d = dump(xxd);
        assert_eq!(d.start, 0x40);
        assert_eq!(dump_like(xxd, "xxd", d.start, &d.bytes), xxd);
        let hd = "00000040  2e 2e 2e 2e 66 6f 6f 2e  2e 2e 62 61 72 2e 2e 2e  |....foo...bar...|\n00000050\n";
        let d = dump(hd);
        assert_eq!(d.start, 0x40);
        assert_eq!(dump_like(hd, "hexdump", d.start, &d.bytes), hd);
    }

    #[test]
    fn dump_nonzero_start_changed_keeps_offsets() {
        let b: Vec<u8> = (0u8..40).collect();
        let xxd = "00000040: 6865 6c6c 6f0a                           hello.\n";
        let out = dump_like(xxd, "xxd", dump(xxd).start, &b);
        assert!(out.starts_with("00000040: "), "{out}");
        let d = dump(&out);
        assert_eq!(d.start, 0x40);
        assert_eq!(d.bytes, b);
        let hd = "00000040  68 65 6c 6c 6f 0a                                 |hello.|\n00000046\n";
        let out = dump_like(hd, "hexdump", dump(hd).start, &b);
        assert!(out.starts_with("00000040  "), "{out}");
        // The final end-offset line is start + len, not len.
        let last = out.trim_end().lines().last().unwrap();
        assert_eq!(last, format!("{:08x}", 0x40 + b.len()));
        let d = dump(&out);
        assert_eq!(d.start, 0x40);
        assert_eq!(d.bytes, b);
    }

    #[test]
    fn base64_exact() {
        for (o, alph, pad) in [
            ("SGVsbG8gd29ybGQ=", Alphabet::Std, true),
            ("SGVsbG8gd29ybGQ", Alphabet::Std, false),
            ("-_8", Alphabet::Url, false),
            ("SGVsbG8gd29ybGQh", Alphabet::Std, false),
        ] {
            let b = decode_b64(o).unwrap();
            assert_eq!(base64_like(o, alph, pad, &b.bytes), o, "b64 {o:?}");
        }

        let data: Vec<u8> = (0u8..=200).collect();
        let enc = b64_encode(&data, Alphabet::Std, true);
        // 64 columns, LF, trailing newline.
        let w64 = wrap(&enc, 64, "\n", true);
        assert_eq!(base64_like(&w64, Alphabet::Std, true, &data), w64);
        // 76 columns, CRLF, no trailing newline.
        let w76 = wrap(&enc, 76, "\r\n", false);
        assert_eq!(base64_like(&w76, Alphabet::Std, true, &data), w76);
    }

    #[test]
    fn base64_changed_roundtrip() {
        let o = wrap(&b64_encode(&[0u8; 96], Alphabet::Std, true), 64, "\n", true);
        let new: Vec<u8> = (0u8..150).collect();
        let out = base64_like(&o, Alphabet::Std, true, &new);
        assert_eq!(decode_b64(&out).unwrap().bytes, new);
        // The wrapping is still at 64 columns.
        for line in out.trim_end().split('\n') {
            assert!(line.len() <= 64, "{line:?}");
        }
    }

    #[test]
    fn pem_exact() {
        let isrg = include_str!("../tests/fixtures/isrg-root-x2.pem");
        let bundle = decode_pem(isrg).unwrap().unwrap();
        let b = &bundle.blocks[0];
        assert_eq!(
            pem_like(isrg, b.range, &b.label, &b.b64.bytes).unwrap(),
            isrg
        );
    }

    #[test]
    fn pem_bundle_second_block_exact() {
        let isrg = include_str!("../tests/fixtures/isrg-root-x2.pem");
        let double = format!("{isrg}{isrg}");
        let bundle = decode_pem(&double).unwrap().unwrap();
        assert_eq!(bundle.blocks.len(), 2);
        let b = &bundle.blocks[1];
        assert_eq!(
            pem_like(&double, b.range, &b.label, &b.b64.bytes).unwrap(),
            double
        );
    }

    #[test]
    fn pem_changed_roundtrip() {
        let isrg = include_str!("../tests/fixtures/isrg-root-x2.pem");
        let bundle = decode_pem(isrg).unwrap().unwrap();
        let b = &bundle.blocks[0];
        let new: Vec<u8> = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let out = pem_like(isrg, b.range, &b.label, &new).unwrap();
        // Text before the block is byte-exact.
        assert!(out.starts_with(&isrg[..b.range[0]]));
        let parsed = decode_pem(&out).unwrap().unwrap();
        assert_eq!(parsed.blocks[0].b64.bytes, new);
    }

    #[test]
    fn pem_rfc1421_headers_unsupported() {
        let pem = "-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\nSGVsbG8=\n-----END X-----\n";
        let bundle = decode_pem(pem).unwrap().unwrap();
        let b = &bundle.blocks[0];
        let e = pem_like(pem, b.range, &b.label, &b.b64.bytes).unwrap_err();
        assert_eq!(e.code, "REENCODE_UNSUPPORTED");
        assert_eq!(e.offset, Some(b.range[0]));
    }
}
