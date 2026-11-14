//! Layer detection: decides what each buffer is and recurses.

use crate::cbor;
use crate::compress::{self, Outcome};
use crate::jwt;
use crate::msgpack;
use crate::node::{Alphabet, Codec, Detail, Node};
use crate::text::{self, is_printable};
use crate::value::{Value, ValueKind};
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
    let _budget = compress::BudgetScope::new();
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
                                Picked::Ready(node) => node,
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
                    (
                        Codec::Dump {
                            style: d.style,
                            start: d.start,
                        },
                        d.bytes,
                    )
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
            let (mut fields, st) = protobuf::parse_message(buf, 0, buf.len(), depth, opts)?;
            protobuf::enrich(&mut fields, depth, opts);
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
        Force::Cbor => {
            let mut items = cbor::parse_sequence(buf)?;
            enrich_values(&mut items, depth, opts);
            Ok(cbor::node(items, 1.0, buf.len()))
        }
        Force::Msgpack => {
            let mut items = msgpack::parse_sequence(buf)?;
            enrich_values(&mut items, depth, opts);
            Ok(msgpack::node(items, 1.0, buf.len()))
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
        Picked::Ready(node) => Some(node),
    }
}

/// Detect further structure inside a byte string (a CBOR `bytes` value):
/// another CBOR/DER/protobuf/compressed buffer, or a text encoding. Returns
/// `None` for a plain text or opaque result, so callers do not echo bytes.
/// `depth` is the child's depth.
pub(crate) fn nested_bytes(buf: &[u8], depth: usize, opts: &Options) -> Option<Node> {
    if depth >= opts.depth {
        return None;
    }
    let n = detect(buf, depth, opts, Mode::Nested);
    match n.codec {
        // A bytes leaf with a warning (a corrupt or over-budget compressed
        // stream, an unsupported format) is kept so the warning is reported.
        Codec::Bytes if !n.warnings.is_empty() => Some(n),
        Codec::Utf8 | Codec::Bytes => None,
        _ => Some(n),
    }
}

/// Fill the `decoded` node of every byte string in a structurally parsed CBOR
/// or MessagePack tree, in one pass.
///
/// `depth` is the depth of the buffer these values were parsed from, so their
/// byte-string contents are one level deeper. Running this only on the winning
/// candidate is what keeps candidate parsing structural and linear.
pub(crate) fn enrich_values(items: &mut [Value], depth: usize, opts: &Options) {
    for v in items {
        enrich_value(v, depth, opts);
    }
}

fn enrich_value(v: &mut Value, depth: usize, opts: &Options) {
    match &mut v.kind {
        ValueKind::Bytes { data, decoded } => {
            *decoded = nested_bytes(data, depth + 1, opts).map(Box::new);
        }
        ValueKind::Array(items) => enrich_values(items, depth, opts),
        ValueKind::Map(entries) => {
            for (k, val) in entries.iter_mut() {
                enrich_value(k, depth, opts);
                enrich_value(val, depth, opts);
            }
        }
        // Tag 24 is embedded CBOR: decode it as CBOR only, never with the
        // general (multi-codec) nested detection.
        ValueKind::Tag(24, inner) => {
            if let ValueKind::Bytes { data, decoded } = &mut inner.kind {
                *decoded = cbor::embedded(data, depth + 1, opts).map(Box::new);
            } else {
                enrich_value(inner, depth, opts);
            }
        }
        ValueKind::Tag(_, inner) => enrich_value(inner, depth, opts),
        _ => {}
    }
}

/// A candidate text layer: bytes that still need a child, or a finished node
/// (JWT, PEM bundle) that already built its own part nodes.
enum Picked {
    Layer(Cand),
    Ready(Node),
}

fn keep(best: &mut Option<(f64, Picked)>, conf: f64, p: Picked) {
    if best.as_ref().is_none_or(|(b, _)| conf > *b) {
        *best = Some((conf, p));
    }
}

fn best_layer(t: &str, nested: bool, depth: usize, opts: &Options) -> Option<Picked> {
    let mut best: Option<(f64, Picked)> = None;
    if let Some(Ok(b)) = text::decode_pem(t) {
        if b.blocks.len() == 1 {
            let blk = b.blocks.into_iter().next().expect("checked one block");
            let mut warnings = Vec::new();
            if b.ignored > 0 {
                warnings.push(trailing_diag(b.ignored));
            }
            if blk.b64.noncanonical {
                warnings.push(text::noncanonical_diag());
            }
            // A later broken block is reported on the (otherwise good) node.
            if let Some(e) = b.error {
                warnings.push(e);
            }
            keep(
                &mut best,
                0.99,
                Picked::Layer(Cand {
                    codec: Codec::Pem { label: blk.label },
                    decoded: blk.b64.bytes,
                    conf: 0.99,
                    warnings,
                }),
            );
        } else {
            keep(
                &mut best,
                0.99,
                Picked::Ready(bundle_node(t, b, depth, opts)),
            );
        }
    }
    if let Some(Ok(d)) = dump::decode_dump(t) {
        keep(
            &mut best,
            0.98,
            Picked::Layer(Cand {
                codec: Codec::Dump {
                    style: d.style,
                    start: d.start,
                },
                decoded: d.bytes,
                conf: 0.98,
                warnings: vec![],
            }),
        );
    }
    if let Some(node) = jwt_node(t, depth, opts) {
        keep(&mut best, 0.97, Picked::Ready(node));
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

fn trailing_diag(bytes: usize) -> Diag {
    Diag::new(
        "TRAILING_DATA",
        format!("{bytes} bytes outside the PEM blocks were ignored"),
        None,
    )
}

/// Build the full bundle node: one pem layer node per block, each with its
/// child detected normally (certificates become DER).
fn bundle_node(t: &str, b: text::PemBundle, depth: usize, opts: &Options) -> Node {
    let parts = b
        .blocks
        .into_iter()
        .map(|blk| {
            let mut warnings = Vec::new();
            if blk.b64.noncanonical {
                warnings.push(text::noncanonical_diag());
            }
            let child = detect(&blk.b64.bytes, depth + 1, opts, Mode::Nested);
            Node {
                codec: Codec::Pem { label: blk.label },
                range: blk.range,
                confidence: 0.99,
                detail: Detail::Layer {
                    decoded: blk.b64.bytes,
                    child: Box::new(child),
                },
                warnings,
            }
        })
        .collect();
    let mut warnings = Vec::new();
    if b.ignored > 0 {
        warnings.push(trailing_diag(b.ignored));
    }
    // A later broken block is reported once, on the bundle.
    if let Some(e) = b.error {
        warnings.push(e);
    }
    Node {
        codec: Codec::Bundle,
        range: [0, t.len()],
        confidence: 0.99,
        detail: Detail::Parts {
            parts,
            times: vec![],
        },
        warnings,
    }
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
    // CBOR, MessagePack and protobuf compete. Candidates are parsed
    // structurally (no nested detection); only the winner is enriched.
    if depth >= opts.depth {
        return bytes_leaf(buf, 0.5, vec![]);
    }
    let mut cands: Vec<Candidate> = Vec::new();
    if let Some((items, conf, text_keys)) = cbor::detect(buf) {
        cands.push(Candidate {
            codec: Codec::Cbor,
            conf,
            text_keys,
            payload: Payload::Values(items),
        });
    }
    if let Some((items, conf, text_keys)) = msgpack::detect(buf) {
        cands.push(Candidate {
            codec: Codec::Msgpack,
            conf,
            text_keys,
            payload: Payload::Values(items),
        });
    }
    if let Ok((fields, st)) = protobuf::parse_message(buf, 0, buf.len(), depth, opts) {
        let conf = protobuf::plausibility(&st, buf.len());
        if conf >= MESSAGE_THRESHOLD {
            cands.push(Candidate {
                codec: Codec::Protobuf,
                conf,
                text_keys: false,
                payload: Payload::Fields(fields),
            });
        }
    }
    // Highest confidence wins; on a tie prefer all-text map keys, then the
    // order above (CBOR, MessagePack, protobuf). A stable sort keeps that order.
    cands.sort_by(|a, b| {
        b.conf
            .total_cmp(&a.conf)
            .then(b.text_keys.cmp(&a.text_keys))
    });
    let mut cands = cands.into_iter();
    let Some(best) = cands.next() else {
        return bytes_leaf(buf, 0.5, vec![]);
    };
    let others: Vec<String> = cands
        .map(|c| format!("{} ({:.2})", c.codec.name(), c.conf))
        .collect();
    let mut warnings = vec![];
    if !others.is_empty() {
        warnings.push(Diag::new(
            "AMBIGUOUS_FORMAT",
            format!("also parses as {}", others.join(", ")),
            None,
        ));
    }
    // Nested detection runs once, on the winner only.
    let detail = match best.payload {
        Payload::Values(mut items) => {
            enrich_values(&mut items, depth, opts);
            Detail::Values { items }
        }
        Payload::Fields(mut fields) => {
            protobuf::enrich(&mut fields, depth, opts);
            Detail::Message { fields }
        }
    };
    Node {
        codec: best.codec,
        range: [0, buf.len()],
        confidence: best.conf,
        detail,
        warnings,
    }
}

/// A binary-format candidate, parsed structurally.
struct Candidate {
    codec: Codec,
    conf: f64,
    /// Every map key is a text string (tie-break signal).
    text_keys: bool,
    payload: Payload,
}

enum Payload {
    Values(Vec<crate::Value>),
    Fields(Vec<crate::Field>),
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
            len: buf.len(),
            head: buf[..buf.len().min(crate::node::BYTES_HEAD)].to_vec(),
        },
        warnings,
    }
}
