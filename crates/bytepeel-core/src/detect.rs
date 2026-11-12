//! Layer detection: decides what each buffer is and recurses.

use crate::node::{Codec, Detail, Node};
use crate::protobuf;
use crate::text::{self, is_printable};
use crate::{Diag, Force, InputForm, Options};

/// Minimum confidence for a text layer at the top level (beats "plain text").
const TOP_THRESHOLD: f64 = 0.5;
/// Minimum confidence for a text layer found inside already-decoded data.
const NESTED_THRESHOLD: f64 = 0.75;
/// Minimum protobuf plausibility to report a binary buffer as a message.
const MESSAGE_THRESHOLD: f64 = 0.3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Inside decoded data: look for further text layers (strict thresholds).
    Nested,
    /// Do not look for text layers in this buffer.
    NoLayers,
}

struct Cand {
    codec: Codec,
    decoded: Vec<u8>,
    conf: f64,
    warnings: Vec<Diag>,
}

pub(crate) fn peel(input: &[u8], opts: &Options) -> Result<Node, Diag> {
    match opts.input {
        InputForm::Auto => {
            if opts.depth > 0 {
                if let Ok(t) = std::str::from_utf8(input) {
                    if is_printable(t) {
                        if let Some(c) = best_layer(t, false) {
                            let child = finish(&c.decoded, 1, opts)?;
                            return Ok(layer_node(c, input.len(), child));
                        }
                    }
                }
            }
            finish(input, 0, opts)
        }
        InputForm::Raw => finish(input, 0, opts),
        InputForm::Hex => {
            let bytes = text::decode_hex(as_text(input)?)?;
            let child = finish(&bytes, 1, opts)?;
            let c = Cand {
                codec: Codec::Hex,
                decoded: bytes,
                conf: 1.0,
                warnings: vec![],
            };
            Ok(layer_node(c, input.len(), child))
        }
        InputForm::Base64 => {
            let b = text::decode_b64(as_text(input)?)?;
            let child = finish(&b.bytes, 1, opts)?;
            let mut warnings = vec![];
            if b.noncanonical {
                warnings.push(text::noncanonical_diag());
            }
            let c = Cand {
                codec: Codec::Base64 {
                    alphabet: b.alphabet,
                    padded: b.padded,
                },
                decoded: b.bytes,
                conf: 1.0,
                warnings,
            };
            Ok(layer_node(c, input.len(), child))
        }
    }
}

fn as_text(input: &[u8]) -> Result<&str, Diag> {
    std::str::from_utf8(input).map_err(|e| {
        Diag::new(
            "INVALID_UTF8",
            "input is not text; use --in raw for binary input",
            Some(e.valid_up_to()),
        )
    })
}

/// Interpret the first byte layer, honoring `Options::force`.
fn finish(buf: &[u8], depth: usize, opts: &Options) -> Result<Node, Diag> {
    match opts.force {
        Some(f) => forced(buf, depth, opts, f),
        None => Ok(detect(
            buf,
            depth,
            opts,
            if depth == 0 {
                Mode::NoLayers
            } else {
                Mode::Nested
            },
        )),
    }
}

fn forced(buf: &[u8], depth: usize, opts: &Options, f: Force) -> Result<Node, Diag> {
    match f {
        Force::Protobuf => {
            let (fields, st) = protobuf::parse_message(buf, 0, buf.len(), depth, opts)?;
            Ok(Node {
                codec: Codec::Protobuf,
                range: [0, buf.len()],
                confidence: protobuf::plausibility(&st, buf.len()),
                detail: Detail::Message { fields },
                warnings: vec![],
            })
        }
        Force::Text => {
            let t = std::str::from_utf8(buf).map_err(|e| {
                Diag::new(
                    "INVALID_UTF8",
                    "bytes are not valid UTF-8",
                    Some(e.valid_up_to()),
                )
            })?;
            Ok(text_leaf(t, text::printable_ratio(t)))
        }
        Force::Bytes => Ok(bytes_leaf(buf, 1.0, vec![])),
    }
}

fn detect(buf: &[u8], depth: usize, opts: &Options, mode: Mode) -> Node {
    if let Ok(t) = std::str::from_utf8(buf) {
        if !t.is_empty() && is_printable(t) {
            if mode == Mode::Nested {
                if let Some(n) = nested_text_layer(t, depth, opts) {
                    return n;
                }
            }
            return text_leaf(t, 1.0);
        }
    }
    binary_node(buf, depth, opts)
}

/// A text layer (hex/base64/PEM) inside already-decoded data, if one is
/// confidently present. Used for decoded buffers and protobuf string fields.
pub(crate) fn nested_text_layer(t: &str, depth: usize, opts: &Options) -> Option<Node> {
    if depth >= opts.depth {
        return None;
    }
    let c = best_layer(t, true)?;
    let child = detect(&c.decoded, depth + 1, opts, Mode::Nested);
    Some(layer_node(c, t.len(), child))
}

fn keep(best: &mut Option<Cand>, c: Cand) {
    if best.as_ref().is_none_or(|b| c.conf > b.conf) {
        *best = Some(c);
    }
}

fn best_layer(t: &str, nested: bool) -> Option<Cand> {
    let mut best = None;
    if let Some(Ok(p)) = text::decode_pem(t) {
        let mut warnings = Vec::new();
        if p.trailing {
            warnings.push(Diag::new(
                "TRAILING_DATA",
                "text outside the first PEM block was ignored",
                None,
            ));
        }
        if p.b64.noncanonical {
            warnings.push(text::noncanonical_diag());
        }
        keep(
            &mut best,
            Cand {
                codec: Codec::Pem { label: p.label },
                decoded: p.b64.bytes,
                conf: 0.99,
                warnings,
            },
        );
    }
    let core_len = t.trim().len();
    if !nested || core_len >= 8 {
        if let Some((bytes, conf)) = text::hex_candidate(t) {
            keep(
                &mut best,
                Cand {
                    codec: Codec::Hex,
                    decoded: bytes,
                    conf,
                    warnings: vec![],
                },
            );
        }
    }
    if !nested || core_len >= 16 {
        if let Some((b, conf)) = text::b64_candidate(t) {
            let mut warnings = vec![];
            if b.noncanonical {
                warnings.push(text::noncanonical_diag());
            }
            keep(
                &mut best,
                Cand {
                    codec: Codec::Base64 {
                        alphabet: b.alphabet,
                        padded: b.padded,
                    },
                    decoded: b.bytes,
                    conf,
                    warnings,
                },
            );
        }
    }
    let threshold = if nested {
        NESTED_THRESHOLD
    } else {
        TOP_THRESHOLD
    };
    best.filter(|c| c.conf > threshold)
}

fn binary_node(buf: &[u8], depth: usize, opts: &Options) -> Node {
    if buf.is_empty() {
        return bytes_leaf(buf, 1.0, vec![]);
    }
    if let Some(format) = sniff(buf) {
        let w = Diag::new(
            "UNSUPPORTED_FORMAT",
            format!("looks like {format}; this decoder is not implemented yet"),
            Some(0),
        );
        return bytes_leaf(buf, 0.9, vec![w]);
    }
    if depth < opts.depth {
        if let Ok((fields, st)) = protobuf::parse_message(buf, 0, buf.len(), depth, opts) {
            let p = protobuf::plausibility(&st, buf.len());
            if p >= MESSAGE_THRESHOLD {
                return Node {
                    codec: Codec::Protobuf,
                    range: [0, buf.len()],
                    confidence: p,
                    detail: Detail::Message { fields },
                    warnings: vec![],
                };
            }
        }
    }
    bytes_leaf(buf, 0.5, vec![])
}

/// Recognize formats by magic bytes so they are not misread as protobuf.
fn sniff(buf: &[u8]) -> Option<&'static str> {
    match buf {
        [0x1f, 0x8b, 0x08, ..] => Some("gzip"),
        [0x28, 0xb5, 0x2f, 0xfd, ..] => Some("zstd"),
        [0x78, 0x01 | 0x5e | 0x9c | 0xda, ..] => Some("zlib"),
        [0x89, b'P', b'N', b'G', ..] => Some("png"),
        [b'P', b'K', 0x03, 0x04, ..] => Some("zip"),
        [0x30, ..] if buf.len() >= 4 && der_len_matches(buf) => Some("DER/ASN.1"),
        _ => None,
    }
}

fn der_len_matches(buf: &[u8]) -> bool {
    let b1 = buf[1] as usize;
    if b1 < 0x80 {
        return 2 + b1 == buf.len();
    }
    let n = b1 & 0x7f;
    if n == 0 || n > 4 || buf.len() < 2 + n {
        return false;
    }
    let len = buf[2..2 + n]
        .iter()
        .fold(0usize, |a, &b| (a << 8) | b as usize);
    2 + n + len == buf.len()
}

fn layer_node(c: Cand, input_len: usize, child: Node) -> Node {
    Node {
        codec: c.codec,
        range: [0, input_len],
        confidence: c.conf,
        detail: Detail::Layer {
            decoded: c.decoded,
            child: Box::new(child),
        },
        warnings: c.warnings,
    }
}

fn text_leaf(t: &str, conf: f64) -> Node {
    Node {
        codec: Codec::Utf8,
        range: [0, t.len()],
        confidence: conf,
        detail: Detail::Text {
            text: t.to_string(),
        },
        warnings: vec![],
    }
}

fn bytes_leaf(buf: &[u8], conf: f64, warnings: Vec<Diag>) -> Node {
    Node {
        codec: Codec::Bytes,
        range: [0, buf.len()],
        confidence: conf,
        detail: Detail::Bytes {
            bytes: buf.to_vec(),
        },
        warnings,
    }
}
