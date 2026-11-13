//! Schemaless protobuf wire-format decoding with ranked interpretations.

use crate::detect;
use crate::node::{Alt, AltKind, Field, FieldValue};
use crate::text::printable_ratio;
use crate::varint::{self, VarintError};
use crate::{Diag, Options};

const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;
/// Hard recursion cap for groups, independent of `Options::depth`.
const MAX_NESTING: usize = 100;

/// Facts about one message level, used to score how protobuf-like it is.
#[derive(Debug, Default)]
pub(crate) struct Stats {
    fields: usize,
    overlong: usize,
    max_field: u32,
    groups: usize,
    conflicts: usize,
    seen: Vec<(u32, u8)>,
}

impl Stats {
    fn record(&mut self, number: u32, wire: u8) {
        self.fields += 1;
        self.max_field = self.max_field.max(number);
        let mut exact = false;
        for &(n, w) in &self.seen {
            if n != number {
                continue;
            }
            if w == wire {
                exact = true;
            } else if w != 2 && wire != 2 {
                // LEN vs scalar is legal (packed vs unpacked); scalar vs scalar is not.
                self.conflicts += 1;
            }
        }
        if !exact {
            self.seen.push((number, wire));
        }
    }
}

/// How plausible a successfully parsed message is as real protobuf (0..=0.9).
pub(crate) fn plausibility(st: &Stats, len: usize) -> f64 {
    if st.fields == 0 {
        return 0.0;
    }
    let mut s = 0.9;
    s *= 0.85f64.powi(st.overlong.min(20) as i32);
    if st.max_field > 100_000 {
        s *= 0.3;
    } else if st.max_field > 1_000 {
        s *= 0.5;
    }
    s *= 0.7f64.powi(st.groups.min(20) as i32);
    s *= 0.6f64.powi(st.conflicts.min(20) as i32);
    if st.fields == 1 && len <= 3 {
        s *= 0.6;
    }
    s
}

/// Parse `buf[start..end]` as a complete message.
pub(crate) fn parse_message(
    buf: &[u8],
    start: usize,
    end: usize,
    depth: usize,
    opts: &Options,
) -> Result<(Vec<Field>, Stats), Diag> {
    let mut pos = start;
    parse_fields(buf, &mut pos, end, depth, opts, None)
}

/// Returns `(value, len, overlong)`.
fn read_varint(buf: &[u8], pos: usize, end: usize) -> Result<(u64, usize, bool), Diag> {
    match varint::decode(&buf[pos..end]) {
        Ok((v, n)) => Ok((v, n, n > 1 && buf[pos + n - 1] == 0)),
        Err(VarintError::Truncated) => Err(Diag::new(
            "TRUNCATED_VARINT",
            "varint runs past the end of the buffer",
            Some(pos),
        )),
        Err(VarintError::Overflow) => Err(Diag::new(
            "VARINT_OVERFLOW",
            "varint does not fit in 64 bits",
            Some(pos),
        )),
    }
}

fn take<'a>(
    buf: &'a [u8],
    pos: &mut usize,
    end: usize,
    n: usize,
    tag_start: usize,
) -> Result<&'a [u8], Diag> {
    if end - *pos < n {
        return Err(Diag::new(
            "TRUNCATED_FIELD",
            format!(
                "fixed-width field needs {n} bytes but only {} remain",
                end - *pos
            ),
            Some(tag_start),
        ));
    }
    let s = &buf[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

fn parse_fields(
    buf: &[u8],
    pos: &mut usize,
    end: usize,
    depth: usize,
    opts: &Options,
    group: Option<u32>,
) -> Result<(Vec<Field>, Stats), Diag> {
    if depth > MAX_NESTING {
        return Err(Diag::new(
            "NESTING_TOO_DEEP",
            format!("more than {MAX_NESTING} nested groups"),
            Some(*pos),
        ));
    }
    let mut fields = Vec::new();
    let mut st = Stats::default();
    while *pos < end {
        let tag_start = *pos;
        let (tag, n, overlong) = read_varint(buf, *pos, end)?;
        st.overlong += usize::from(overlong);
        *pos += n;
        let wire = (tag & 7) as u8;
        let number = tag >> 3;
        if number == 0 {
            return Err(Diag::new(
                "FIELD_NUMBER_ZERO",
                "field number 0 is not valid protobuf",
                Some(tag_start),
            ));
        }
        if number > MAX_FIELD_NUMBER {
            return Err(Diag::new(
                "FIELD_NUMBER_TOO_LARGE",
                format!("field number {number} exceeds 2^29-1"),
                Some(tag_start),
            ));
        }
        let number = number as u32;
        let value = match wire {
            0 => {
                let (v, n, overlong) = read_varint(buf, *pos, end)?;
                st.overlong += usize::from(overlong);
                let raw = buf[*pos..*pos + n].to_vec();
                *pos += n;
                FieldValue::Varint { raw, value: v }
            }
            1 => {
                let b = take(buf, pos, end, 8, tag_start)?;
                FieldValue::I64 {
                    value: u64::from_le_bytes(b.try_into().expect("8 bytes")),
                }
            }
            5 => {
                let b = take(buf, pos, end, 4, tag_start)?;
                FieldValue::I32 {
                    value: u32::from_le_bytes(b.try_into().expect("4 bytes")),
                }
            }
            2 => {
                let (len, n, overlong) = read_varint(buf, *pos, end)?;
                st.overlong += usize::from(overlong);
                *pos += n;
                let remaining = end - *pos;
                if len > remaining as u64 {
                    return Err(Diag::new(
                        "TRUNCATED_FIELD",
                        format!("field {number} declares {len} bytes but only {remaining} remain"),
                        Some(tag_start),
                    ));
                }
                let (s, e) = (*pos, *pos + len as usize);
                *pos = e;
                FieldValue::Len {
                    data_range: [s, e],
                    data: buf[s..e].to_vec(),
                    alts: classify_len(buf, s, e, depth, opts),
                }
            }
            3 => {
                st.groups += 1;
                let (inner, gst) = parse_fields(buf, pos, end, depth + 1, opts, Some(number))?;
                st.overlong += gst.overlong;
                FieldValue::Group { fields: inner }
            }
            4 => {
                return if group == Some(number) {
                    Ok((fields, st))
                } else {
                    Err(Diag::new(
                        "UNEXPECTED_END_GROUP",
                        format!("end-group tag for field {number} without a matching start"),
                        Some(tag_start),
                    ))
                };
            }
            w => {
                return Err(Diag::new(
                    "INVALID_WIRE_TYPE",
                    format!("wire type {w} is not valid protobuf"),
                    Some(tag_start),
                ));
            }
        };
        st.record(number, wire);
        fields.push(Field {
            number,
            range: [tag_start, *pos],
            value,
        });
    }
    if let Some(g) = group {
        return Err(Diag::new(
            "UNTERMINATED_GROUP",
            format!("group for field {g} has no end-group tag"),
            Some(*pos),
        ));
    }
    Ok((fields, st))
}

/// Rank the possible meanings of a LEN field's payload `buf[s..e]`.
/// Run nested detection on string alts (`decoded`), once, over a message that
/// was parsed structurally and chosen. `depth` is the message's own depth, as
/// passed to `parse_message`.
///
/// Candidate parsing must stay structural: if a losing candidate also ran
/// nested detection, bytes reachable from two candidates would be detected
/// twice per level, and the cost would double with depth.
pub(crate) fn enrich(fields: &mut [Field], depth: usize, opts: &Options) {
    for f in fields {
        match &mut f.value {
            FieldValue::Len { alts, .. } => {
                for a in alts {
                    match &mut a.kind {
                        AltKind::Message(sub) => enrich(sub, depth + 1, opts),
                        AltKind::String { text, decoded } => {
                            *decoded =
                                detect::nested_text_layer(text, depth + 1, opts).map(Box::new);
                        }
                        _ => {}
                    }
                }
            }
            FieldValue::Group { fields } => enrich(fields, depth + 1, opts),
            _ => {}
        }
    }
}

fn classify_len(buf: &[u8], s: usize, e: usize, depth: usize, opts: &Options) -> Vec<Alt> {
    let data = &buf[s..e];
    if data.is_empty() {
        return vec![Alt {
            kind: AltKind::Empty,
            score: 1.0,
        }];
    }
    let text = std::str::from_utf8(data).ok();
    let pr = text.map_or(0.0, printable_ratio);
    let mut alts = Vec::new();

    if depth + 1 < opts.depth {
        if let Ok((fields, st)) = parse_message(buf, s, e, depth + 1, opts) {
            let mut score = plausibility(&st, data.len());
            if pr >= 1.0 {
                // Fully printable text that happens to parse is usually just text.
                score *= 0.3;
            }
            if score > 0.0 {
                alts.push(Alt {
                    kind: AltKind::Message(fields),
                    score,
                });
            }
        }
    }
    if let Some(t) = text {
        let score = 0.9 * pr.powi(4);
        if score > 0.01 {
            // `decoded` is filled by `enrich` once this message has won.
            alts.push(Alt {
                kind: AltKind::String {
                    text: t.to_string(),
                    decoded: None,
                },
                score,
            });
        }
    }
    if let Some(values) = packed_varints(data) {
        alts.push(Alt {
            kind: AltKind::PackedVarint(values),
            score: if pr < 0.5 { 0.25 } else { 0.03 },
        });
    }
    alts.push(Alt {
        kind: AltKind::Bytes,
        score: 0.02,
    });

    let total: f64 = alts.iter().map(|a| a.score).sum();
    for a in &mut alts {
        a.score /= total;
    }
    alts.sort_by(|a, b| b.score.total_cmp(&a.score));
    alts.truncate(opts.alts.max(1));
    alts
}

fn packed_varints(data: &[u8]) -> Option<Vec<u64>> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < data.len() {
        let (v, n) = varint::decode(&data[p..]).ok()?;
        if n > 1 && data[p + n - 1] == 0 {
            return None; // overlong encodings never come from a real encoder
        }
        out.push(v);
        p += n;
    }
    Some(out)
}

#[cfg(test)]
mod structural_tests {
    use super::*;

    /// Candidate parsing must not run nested detection (see `enrich`): if it
    /// did, bytes reachable from a losing candidate and the winner would be
    /// detected twice per level, doubling the cost with depth.
    #[test]
    fn parse_is_structural_and_enrich_decodes_once() {
        // Field 1 LEN "SGVsbG8gd29ybGQh" (base64 of "Hello world!").
        let mut buf = vec![0x0a, 16];
        buf.extend_from_slice(b"SGVsbG8gd29ybGQh");
        let opts = Options::default();
        let (mut fields, _) = parse_message(&buf, 0, buf.len(), 0, &opts).unwrap();
        let decoded = |fields: &[Field]| match &fields[0].value {
            FieldValue::Len { alts, .. } => alts.iter().any(|a| {
                matches!(
                    &a.kind,
                    AltKind::String {
                        decoded: Some(_),
                        ..
                    }
                )
            }),
            _ => panic!(),
        };
        assert!(!decoded(&fields), "parse_message ran nested detection");
        enrich(&mut fields, 0, &opts);
        assert!(decoded(&fields), "enrich did not decode the base64 string");
    }
}
