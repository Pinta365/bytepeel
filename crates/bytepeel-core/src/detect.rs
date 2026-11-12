//! Layer detection: decides what each buffer is and recurses.

use crate::compress::{self, Outcome};
use crate::jwt;
use crate::node::{Alphabet, Codec, Detail, Node};
use crate::text::{self, is_printable};
use crate::{Diag, Force, InputForm, Options};
use crate::{der, dump, protobuf};

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
                        if let Some(p) = best_layer(t, false, 0, opts) {
                            return Ok(match p {
                                Picked::Layer(c) => {
                                    let child = finish(&c.decoded, 1, opts)?;
                                    layer_node(c, input.len(), child)
                                }
                                Picked::Jwt(node) => node,
                            });
                        }
                    }
                }
            }
            finish(input, 0, opts)
        }
        InputForm::Raw => finish(input, 0, opts),
        InputForm::Hex => {
            let t = as_text(input)?;
            let (codec, bytes) = match dump::decode_dump(t) {
                Some(d) => {
                    let d = d?;
                    (Codec::Dump { style: d.style }, d.bytes)
                }
                None => (Codec::Hex, text::decode_hex(t)?),
            };
            let child = finish(&bytes, 1, opts)?;
            let c = Cand {
                codec,
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
    // Compression is transparent: --as applies to the decompressed bytes.
    if depth < opts.depth && f != Force::Bytes {
        if let Some(Outcome::Decoded(i)) = compress::decompress(buf) {
            let child = forced(&i.bytes, depth + 1, opts, f)?;
            return Ok(compressed_node(i, buf.len(), child));
        }
    }
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
        Force::Der => {
            let mut st = der::Stats::default();
            let items = der::parse(buf, &mut st)?;
            Ok(der_node(buf.len(), items, &st))
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
    match best_layer(t, true, depth, opts)? {
        Picked::Layer(c) => {
            let child = detect(&c.decoded, depth + 1, opts, Mode::Nested);
            Some(layer_node(c, t.len(), child))
        }
        Picked::Jwt(node) => Some(node),
    }
}

/// A candidate text layer: bytes that still need a child, or a finished node.
enum Picked {
    Layer(Cand),
    Jwt(Node),
}

fn keep(best: &mut Option<(f64, Picked)>, conf: f64, p: Picked) {
    if best.as_ref().is_none_or(|(b, _)| conf > *b) {
        *best = Some((conf, p));
    }
}

fn best_layer(t: &str, nested: bool, depth: usize, opts: &Options) -> Option<Picked> {
    let mut best: Option<(f64, Picked)> = None;
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
            0.99,
            Picked::Layer(Cand {
                codec: Codec::Pem { label: p.label },
                decoded: p.b64.bytes,
                conf: 0.99,
                warnings,
            }),
        );
    }
    if let Some(Ok(d)) = dump::decode_dump(t) {
        keep(
            &mut best,
            0.98,
            Picked::Layer(Cand {
                codec: Codec::Dump { style: d.style },
                decoded: d.bytes,
                conf: 0.98,
                warnings: vec![],
            }),
        );
    }
    if let Some(node) = jwt_node(t, depth, opts) {
        keep(&mut best, 0.97, Picked::Jwt(node));
    }
    let core_len = t.trim().len();
    if !nested || core_len >= 8 {
        if let Some((bytes, conf)) = text::hex_candidate(t) {
            keep(
                &mut best,
                conf,
                Picked::Layer(Cand {
                    codec: Codec::Hex,
                    decoded: bytes,
                    conf,
                    warnings: vec![],
                }),
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
                conf,
                Picked::Layer(Cand {
                    codec: Codec::Base64 {
                        alphabet: b.alphabet,
                        padded: b.padded,
                    },
                    decoded: b.bytes,
                    conf,
                    warnings,
                }),
            );
        }
    }
    let threshold = if nested {
        NESTED_THRESHOLD
    } else {
        TOP_THRESHOLD
    };
    best.filter(|(c, _)| *c > threshold).map(|(_, p)| p)
}

/// Build the full JWT node: a base64 layer node per part, with the header and
/// payload detected as text and time claims converted on the jwt node.
fn jwt_node(t: &str, depth: usize, opts: &Options) -> Option<Node> {
    let j = jwt::decode_jwt(t)?;
    let parts = j
        .parts
        .into_iter()
        .map(|p| {
            let child = detect(&p.decoded, depth + 1, opts, Mode::Nested);
            Node {
                codec: Codec::Base64 {
                    alphabet: Alphabet::Url,
                    padded: false,
                },
                range: p.range,
                confidence: 1.0,
                detail: Detail::Layer {
                    decoded: p.decoded,
                    child: Box::new(child),
                },
                warnings: vec![],
            }
        })
        .collect();
    Some(Node {
        codec: Codec::Jwt { kind: j.kind },
        range: [0, t.len()],
        confidence: 0.97,
        detail: Detail::Parts {
            parts,
            times: j.times,
        },
        warnings: vec![],
    })
}

fn binary_node(buf: &[u8], depth: usize, opts: &Options) -> Node {
    if buf.is_empty() {
        return bytes_leaf(buf, 1.0, vec![]);
    }
    if depth < opts.depth {
        match compress::decompress(buf) {
            Some(Outcome::Decoded(i)) => {
                let child = detect(&i.bytes, depth + 1, opts, Mode::Nested);
                return compressed_node(i, buf.len(), child);
            }
            Some(Outcome::Failed(d)) => return bytes_leaf(buf, 0.9, vec![d]),
            None => {}
        }
    }
    if let Some((items, st)) = der::detect(buf) {
        return der_node(buf.len(), items, &st);
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
        [0x89, b'P', b'N', b'G', ..] => Some("png"),
        [b'P', b'K', 0x03, 0x04, ..] => Some("zip"),
        _ => None,
    }
}

fn compressed_node(i: compress::Inflated, len: usize, child: Node) -> Node {
    let codec = match i.kind {
        "gzip" => Codec::Gzip { name: i.name },
        "zlib" => Codec::Zlib,
        _ => Codec::Zstd,
    };
    Node {
        codec,
        range: [0, len],
        confidence: 1.0,
        detail: Detail::Layer {
            decoded: i.bytes,
            child: Box::new(child),
        },
        warnings: i.warnings,
    }
}

fn der_node(len: usize, items: Vec<crate::Asn1>, st: &der::Stats) -> Node {
    let mut warnings = vec![];
    if st.noncanonical > 0 {
        warnings.push(Diag::new(
            "NONCANONICAL_DER",
            "valid BER but not DER: non-minimal length or integer encoding",
            None,
        ));
    }
    Node {
        codec: Codec::Der,
        range: [0, len],
        confidence: der::confidence(st),
        detail: Detail::Der { items },
        warnings,
    }
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
