//! Compressed layers: gzip and zlib (feature `deflate`), zstd (feature `zstd`).
//!
//! Without the feature, a recognized stream is reported as a bytes leaf with an
//! `UNSUPPORTED_FORMAT` warning, exactly as before the decoder existed.

use crate::Diag;

#[cfg(any(feature = "deflate", feature = "zstd"))]
/// Decompressed output cap per stream: guards against decompression bombs.
pub(crate) const MAX_OUTPUT: usize = 64 << 20;

/// Total decompressed output allowed per [`crate::peel`] call, across every
/// compressed layer it finds (many small bombs nested in one input).
#[cfg(any(feature = "deflate", feature = "zstd"))]
pub(crate) const TOTAL_BUDGET: usize = 256 << 20;

#[cfg(any(feature = "deflate", feature = "zstd"))]
thread_local! {
    /// Bytes the current peel may still decompress; `usize::MAX` outside one.
    static REMAINING: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Gives the current thread a fresh [`TOTAL_BUDGET`] until dropped, then
/// restores the previous one (so a peel nested in another is safe).
pub(crate) struct BudgetScope {
    #[cfg(any(feature = "deflate", feature = "zstd"))]
    prev: usize,
}

impl BudgetScope {
    pub(crate) fn new() -> Self {
        #[cfg(any(feature = "deflate", feature = "zstd"))]
        return Self::with(TOTAL_BUDGET);
        #[cfg(not(any(feature = "deflate", feature = "zstd")))]
        BudgetScope {}
    }

    #[cfg(any(feature = "deflate", feature = "zstd"))]
    fn with(budget: usize) -> Self {
        BudgetScope {
            prev: REMAINING.replace(budget),
        }
    }
}

impl Drop for BudgetScope {
    fn drop(&mut self) {
        #[cfg(any(feature = "deflate", feature = "zstd"))]
        REMAINING.set(self.prev);
    }
}

/// The output cap for the next stream: the per-stream cap or what is left of
/// the budget, whichever is smaller.
#[cfg(any(feature = "deflate", feature = "zstd"))]
fn cap() -> usize {
    MAX_OUTPUT.min(REMAINING.get())
}

pub(crate) struct Inflated {
    /// `gzip`, `zlib` or `zstd`.
    pub kind: &'static str,
    pub bytes: Vec<u8>,
    /// gzip FNAME, when present.
    pub name: Option<String>,
    pub warnings: Vec<Diag>,
}

pub(crate) enum Outcome {
    Decoded(Inflated),
    /// Recognized but not decodable (corrupt, too large, or feature disabled).
    Failed(Diag),
}

/// `None` when `buf` is not a recognized compressed stream.
pub(crate) fn decompress(buf: &[u8]) -> Option<Outcome> {
    let kind = sniff(buf)?;
    let res = match kind {
        Magic::Gzip => gzip(buf),
        Magic::Zstd => zstd(buf),
        Magic::Zlib { common } => match zlib(buf) {
            Ok(z) => Ok(z),
            // Two header bytes are a weak signal: only a common header (78 01,
            // 78 5e, 78 9c, 78 da) is reported as broken zlib.
            Err(e) if common => Err(e),
            Err(_) => return None,
        },
    };
    Some(match res {
        Ok(i) => {
            #[cfg(any(feature = "deflate", feature = "zstd"))]
            REMAINING.with(|r| {
                // `usize::MAX` means no peel is running: nothing to charge.
                if r.get() != usize::MAX {
                    r.set(r.get().saturating_sub(i.bytes.len()));
                }
            });
            Outcome::Decoded(i)
        }
        Err(d) => Outcome::Failed(d),
    })
}

#[derive(Clone, Copy)]
enum Magic {
    Gzip,
    Zstd,
    Zlib { common: bool },
}

fn sniff(buf: &[u8]) -> Option<Magic> {
    match buf {
        [0x1f, 0x8b, 0x08, ..] => Some(Magic::Gzip),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Some(Magic::Zstd),
        [cmf, flg, _, ..]
            if cmf & 0x0f == 8
                && cmf >> 4 <= 7
                && flg & 0x20 == 0
                && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0 =>
        {
            Some(Magic::Zlib {
                common: *cmf == 0x78 && matches!(flg, 0x01 | 0x5e | 0x9c | 0xda),
            })
        }
        _ => None,
    }
}

#[cfg(any(feature = "deflate", feature = "zstd"))]
fn corrupt(kind: &str, msg: impl std::fmt::Display, off: Option<usize>) -> Diag {
    Diag::new("CORRUPT_DATA", format!("{kind}: {msg}"), off)
}

#[cfg(any(feature = "deflate", feature = "zstd"))]
fn too_large(kind: &str) -> Diag {
    let message = if REMAINING.get() < MAX_OUTPUT {
        format!(
            "{kind}: the {} MiB total decompression budget for this input is exhausted",
            TOTAL_BUDGET >> 20
        )
    } else {
        format!("{kind}: decompressed size exceeds {} MiB", MAX_OUTPUT >> 20)
    };
    Diag::new("OUTPUT_TOO_LARGE", message, Some(0))
}

#[cfg(any(feature = "deflate", feature = "zstd"))]
fn trailing(kind: &str, n: usize, at: usize) -> Diag {
    Diag::new(
        "TRAILING_DATA",
        format!("{n} bytes after the {kind} stream were ignored"),
        Some(at),
    )
}

// ---------------------------------------------------------------- gzip

#[cfg(feature = "deflate")]
fn gzip(buf: &[u8]) -> Result<Inflated, Diag> {
    let mut out = Vec::new();
    let mut name = None;
    let mut warnings = Vec::new();
    let mut pos = 0;
    loop {
        let (body, fname) = gzip_header(buf, pos)?;
        if name.is_none() {
            name = fname;
        }
        let start = out.len();
        let used = inflate(&buf[body..], false, &mut out, "gzip", body)?;
        let t = body + used;
        if buf.len() - t < 8 {
            return Err(corrupt("gzip", "missing CRC32/ISIZE trailer", Some(t)));
        }
        let crc = u32::from_le_bytes(buf[t..t + 4].try_into().expect("4 bytes"));
        let isize = u32::from_le_bytes(buf[t + 4..t + 8].try_into().expect("4 bytes"));
        if crc32(&out[start..]) != crc {
            return Err(Diag::new(
                "CHECKSUM_MISMATCH",
                "gzip: CRC32 of the decompressed data does not match the trailer",
                Some(t),
            ));
        }
        if (out.len() - start) as u32 != isize {
            return Err(corrupt(
                "gzip",
                "ISIZE does not match the data length",
                Some(t + 4),
            ));
        }
        pos = t + 8;
        match &buf[pos..] {
            [] => break,
            // Concatenated members decode as one stream (RFC 1952 §2.2).
            [0x1f, 0x8b, 0x08, ..] => continue,
            rest => {
                warnings.push(trailing("gzip", rest.len(), pos));
                break;
            }
        }
    }
    Ok(Inflated {
        kind: "gzip",
        bytes: out,
        name,
        warnings,
    })
}

/// Parse a gzip member header at `pos`; returns (body offset, FNAME).
#[cfg(feature = "deflate")]
fn gzip_header(buf: &[u8], pos: usize) -> Result<(usize, Option<String>), Diag> {
    let short = |at| corrupt("gzip", "header is truncated", Some(at));
    let h = buf.get(pos..pos + 10).ok_or_else(|| short(pos))?;
    let flg = h[3];
    if flg & 0xe0 != 0 {
        return Err(corrupt(
            "gzip",
            "reserved header flags are set",
            Some(pos + 3),
        ));
    }
    let mut i = pos + 10;
    if flg & 0x04 != 0 {
        let x = buf.get(i..i + 2).ok_or_else(|| short(i))?;
        i += 2 + usize::from(u16::from_le_bytes([x[0], x[1]]));
    }
    let zstr = |i: &mut usize| -> Result<String, Diag> {
        let rest = buf.get(*i..).ok_or_else(|| short(*i))?;
        let n = rest.iter().position(|&b| b == 0).ok_or_else(|| short(*i))?;
        // RFC 1952: ISO 8859-1.
        let s = rest[..n].iter().map(|&b| char::from(b)).collect();
        *i += n + 1;
        Ok(s)
    };
    let name = if flg & 0x08 != 0 {
        Some(zstr(&mut i)?)
    } else {
        None
    };
    if flg & 0x10 != 0 {
        zstr(&mut i)?;
    }
    if flg & 0x02 != 0 {
        i += 2;
    }
    if i > buf.len() {
        return Err(short(buf.len()));
    }
    Ok((i, name))
}

#[cfg(feature = "deflate")]
fn zlib(buf: &[u8]) -> Result<Inflated, Diag> {
    let mut out = Vec::new();
    let used = inflate(buf, true, &mut out, "zlib", 0)?;
    let mut warnings = Vec::new();
    if used < buf.len() {
        warnings.push(trailing("zlib", buf.len() - used, used));
    }
    Ok(Inflated {
        kind: "zlib",
        bytes: out,
        name: None,
        warnings,
    })
}

/// Inflate one DEFLATE (or zlib, with adler32 check) stream, appending to
/// `out`. Returns the number of input bytes consumed.
#[cfg(feature = "deflate")]
fn inflate(
    input: &[u8],
    zlib: bool,
    out: &mut Vec<u8>,
    kind: &str,
    base: usize,
) -> Result<usize, Diag> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags as f};

    let mut flags = f::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    if zlib {
        flags |= f::TINFL_FLAG_PARSE_ZLIB_HEADER | f::TINFL_FLAG_COMPUTE_ADLER32;
    }
    let mut d = Box::<DecompressorOxide>::default();
    // `cap` bounds the whole output, so concatenated gzip members share it.
    let cap = cap().max(out.len());
    let start = out.len();
    let mut out_pos = start;
    out.resize((start + input.len().saturating_mul(3).max(64)).min(cap), 0);
    let mut consumed = 0;
    loop {
        let (status, used, wrote) = decompress(&mut d, &input[consumed..], out, out_pos, flags);
        consumed += used;
        out_pos += wrote;
        match status {
            TINFLStatus::Done => {
                out.truncate(out_pos);
                return Ok(consumed);
            }
            TINFLStatus::HasMoreOutput => {
                if out.len() >= cap {
                    return Err(too_large(kind));
                }
                let grow = (out.len() - start).max(64).min(cap - out.len());
                out.resize(out.len() + grow, 0);
            }
            TINFLStatus::Adler32Mismatch => {
                return Err(Diag::new(
                    "CHECKSUM_MISMATCH",
                    "zlib: Adler-32 of the decompressed data does not match",
                    Some(base + consumed),
                ));
            }
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::NeedsMoreInput => {
                return Err(corrupt(kind, "stream is truncated", Some(base + consumed)));
            }
            s => {
                return Err(corrupt(
                    kind,
                    format!("invalid DEFLATE data ({s:?})"),
                    Some(base + consumed),
                ));
            }
        }
    }
}

#[cfg(not(feature = "deflate"))]
fn gzip(_: &[u8]) -> Result<Inflated, Diag> {
    Err(disabled("gzip", "deflate"))
}

#[cfg(not(feature = "deflate"))]
fn zlib(_: &[u8]) -> Result<Inflated, Diag> {
    Err(disabled("zlib", "deflate"))
}

// ---------------------------------------------------------------- zstd

#[cfg(feature = "zstd")]
fn zstd(buf: &[u8]) -> Result<Inflated, Diag> {
    use ruzstd::decoding::StreamingDecoder;
    use std::io::Read;

    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let mut src: &[u8] = buf;
    loop {
        let at = buf.len() - src.len();
        let mut dec = StreamingDecoder::new(&mut src).map_err(|e| corrupt("zstd", e, Some(at)))?;
        let room = cap().saturating_sub(out.len()) as u64;
        let n = (&mut dec)
            .take(room + 1)
            .read_to_end(&mut out)
            .map_err(|e| corrupt("zstd", e, Some(at)))?;
        if n as u64 > room {
            return Err(too_large("zstd"));
        }
        let fd = dec.into_frame_decoder();
        if let (Some(want), Some(got)) = (fd.get_checksum_from_data(), fd.get_calculated_checksum())
        {
            if want != got {
                return Err(Diag::new(
                    "CHECKSUM_MISMATCH",
                    "zstd: content checksum does not match",
                    Some(buf.len() - src.len()),
                ));
            }
        }
        match src {
            [] => break,
            [0x28, 0xb5, 0x2f, 0xfd, ..] => continue,
            rest => {
                warnings.push(trailing("zstd", rest.len(), buf.len() - rest.len()));
                break;
            }
        }
    }
    Ok(Inflated {
        kind: "zstd",
        bytes: out,
        name: None,
        warnings,
    })
}

#[cfg(not(feature = "zstd"))]
fn zstd(_: &[u8]) -> Result<Inflated, Diag> {
    Err(disabled("zstd", "zstd"))
}

#[cfg(not(all(feature = "deflate", feature = "zstd")))]
fn disabled(kind: &str, feature: &str) -> Diag {
    Diag::new(
        "UNSUPPORTED_FORMAT",
        format!("looks like {kind}; built without the `{feature}` feature"),
        Some(0),
    )
}

// ---------------------------------------------------------------- re-encoding

/// Re-compress `new` in the format of `orig` (`kind` is `gzip`, `zlib` or
/// `zstd`), for `bytepeel set`. gzip keeps the original member header
/// verbatim (name, mtime, flags) and writes a fresh CRC32/ISIZE; zlib keeps
/// its 2-byte header and writes a fresh Adler-32. Bytes after the stream are
/// kept. The compressed bytes themselves differ from the original encoder's.
pub(crate) fn recompress(kind: &str, orig: &[u8], new: &[u8]) -> Result<Vec<u8>, Diag> {
    match kind {
        "gzip" => regzip(orig, new),
        "zlib" => rezlib(orig, new),
        _ => rezstd(orig, new),
    }
}

#[cfg(any(feature = "deflate", feature = "zstd"))]
fn multi(kind: &str) -> Diag {
    Diag::new(
        "REENCODE_UNSUPPORTED",
        format!("re-encoding a multi-member/multi-frame {kind} stream is not supported"),
        None,
    )
}

#[cfg(feature = "deflate")]
fn regzip(orig: &[u8], new: &[u8]) -> Result<Vec<u8>, Diag> {
    let (body, _) = gzip_header(orig, 0)?;
    let mut scratch = Vec::new();
    let used = inflate(&orig[body..], false, &mut scratch, "gzip", body)?;
    let end = body + used + 8;
    let rest = orig.get(end..).unwrap_or_default();
    if rest.starts_with(&[0x1f, 0x8b, 0x08]) {
        return Err(multi("gzip"));
    }
    let mut out = orig[..body].to_vec();
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(new, 9));
    out.extend_from_slice(&crc32(new).to_le_bytes());
    out.extend_from_slice(&(new.len() as u32).to_le_bytes());
    out.extend_from_slice(rest);
    Ok(out)
}

#[cfg(feature = "deflate")]
fn rezlib(orig: &[u8], new: &[u8]) -> Result<Vec<u8>, Diag> {
    let mut scratch = Vec::new();
    let used = inflate(orig, true, &mut scratch, "zlib", 0)?;
    let mut out = orig[..2].to_vec();
    out.extend_from_slice(&miniz_oxide::deflate::compress_to_vec(new, 9));
    out.extend_from_slice(&adler32(new).to_be_bytes());
    out.extend_from_slice(&orig[used..]);
    Ok(out)
}

#[cfg(feature = "deflate")]
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= 65_521;
        b %= 65_521;
    }
    (b << 16) | a
}

#[cfg(not(feature = "deflate"))]
fn regzip(_: &[u8], _: &[u8]) -> Result<Vec<u8>, Diag> {
    Err(disabled("gzip", "deflate"))
}

#[cfg(not(feature = "deflate"))]
fn rezlib(_: &[u8], _: &[u8]) -> Result<Vec<u8>, Diag> {
    Err(disabled("zlib", "deflate"))
}

#[cfg(feature = "zstd")]
fn rezstd(orig: &[u8], new: &[u8]) -> Result<Vec<u8>, Diag> {
    use ruzstd::decoding::StreamingDecoder;
    use std::io::Read;

    let mut src: &[u8] = orig;
    let mut dec = StreamingDecoder::new(&mut src).map_err(|e| corrupt("zstd", e, Some(0)))?;
    let mut sink = Vec::new();
    (&mut dec)
        .take(MAX_OUTPUT as u64)
        .read_to_end(&mut sink)
        .map_err(|e| corrupt("zstd", e, Some(0)))?;
    drop(dec);
    if src.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Err(multi("zstd"));
    }
    let mut out =
        ruzstd::encoding::compress_to_vec(new, ruzstd::encoding::CompressionLevel::Fastest);
    out.extend_from_slice(src);
    Ok(out)
}

#[cfg(not(feature = "zstd"))]
fn rezstd(_: &[u8], _: &[u8]) -> Result<Vec<u8>, Diag> {
    Err(disabled("zstd", "zstd"))
}

// ---------------------------------------------------------------- crc32

#[cfg(feature = "deflate")]
const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32 (IEEE 802.3), as used by gzip.
#[cfg(feature = "deflate")]
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |c, &b| {
        CRC_TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8)
    })
}

#[cfg(all(test, feature = "deflate"))]
mod tests {
    use super::*;

    #[test]
    fn total_budget_spans_streams_and_is_restored() {
        let gz = include_bytes!("../tests/fixtures/msg.bin.gz");
        let len = match decompress(gz) {
            Some(Outcome::Decoded(i)) => i.bytes.len(),
            _ => panic!("fixture did not decode"),
        };
        {
            let _outer = BudgetScope::with(2 * len + len / 2);
            for _ in 0..2 {
                assert!(matches!(decompress(gz), Some(Outcome::Decoded(_))));
            }
            {
                // A nested scope gets its own budget and restores the outer one.
                let _inner = BudgetScope::with(len);
                assert!(matches!(decompress(gz), Some(Outcome::Decoded(_))));
            }
            match decompress(gz) {
                Some(Outcome::Failed(d)) => {
                    assert_eq!(d.code, "OUTPUT_TOO_LARGE");
                    assert!(d.message.contains("budget"), "{}", d.message);
                }
                _ => panic!("third stream should exceed the budget"),
            }
        }
        // Outside any scope there is no total budget.
        assert_eq!(REMAINING.get(), usize::MAX);
    }

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn zlib_sniff_needs_valid_fcheck() {
        assert!(matches!(
            sniff(&[0x78, 0x9c, 0]),
            Some(Magic::Zlib { common: true })
        ));
        assert!(matches!(
            sniff(&[0x48, 0x89, 0]),
            Some(Magic::Zlib { common: false })
        ));
        assert!(sniff(&[0x78, 0x9d, 0]).is_none());
        // FDICT set: needs a preset dictionary we can't have.
        assert!(sniff(&[0x78, 0xbb, 0]).is_none());
    }
}
