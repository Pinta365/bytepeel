//! WebAssembly build of `bytepeel-core`, for the npm package in `npm/`.
//!
//! The ABI is three functions, so the module loads with plain
//! `WebAssembly.instantiate` and needs no generated glue:
//!
//! - `bp_alloc(len) -> ptr` / `bp_free(ptr, len)` manage buffers in linear
//!   memory.
//! - `bp_call(op, input, input_len, arg, arg_len, opts, opts_len) -> ptr`
//!   runs one operation and returns a result buffer:
//!   `[status: u8][len: u32 LE][len bytes]`, where status 0 is success and 1
//!   is an error whose bytes are `{"error":{...}}` JSON. The caller frees it
//!   with `bp_free(ptr, 5 + len)`.
//!
//! All logic lives in the safe [`call`] function, which is unit-tested
//! natively; the exports only move bytes in and out of linear memory.

use bytepeel_core::{self as core, Diag, Force, InputForm, Op, Options};

/// `bp_call` operations.
pub const OP_PEEL: u32 = 0;
pub const OP_TREE: u32 = 1;
pub const OP_GET: u32 = 2;
pub const OP_GET_RAW: u32 = 3;
pub const OP_EDIT: u32 = 4;

fn bad(msg: impl Into<String>) -> Diag {
    Diag::new("USAGE", msg, None)
}

/// Options as `key=value` pairs separated by `\n`: `in` (auto|hex|base64|raw),
/// `as` (protobuf|der|cbor|msgpack|text|bytes), `depth`, `alts`, `max_items`.
pub fn parse_opts(s: &str) -> Result<Options, Diag> {
    let mut o = Options::default();
    for line in s.split('\n').filter(|l| !l.is_empty()) {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| bad(format!("bad option '{line}'")))?;
        match k {
            "in" => {
                o.input = match v {
                    "auto" => InputForm::Auto,
                    "hex" => InputForm::Hex,
                    "base64" | "b64" => InputForm::Base64,
                    "raw" => InputForm::Raw,
                    _ => return Err(bad(format!("unknown in '{v}' (auto|hex|base64|raw)"))),
                }
            }
            "as" => {
                o.force = Some(match v {
                    "protobuf" | "pb" => Force::Protobuf,
                    "der" | "asn1" => Force::Der,
                    "cbor" => Force::Cbor,
                    "msgpack" | "mp" => Force::Msgpack,
                    "text" => Force::Text,
                    "bytes" => Force::Bytes,
                    _ => {
                        return Err(bad(format!(
                            "unknown as '{v}' (protobuf|der|cbor|msgpack|text|bytes)"
                        )));
                    }
                })
            }
            "depth" => o.depth = v.parse().map_err(|_| bad(format!("bad depth '{v}'")))?,
            "alts" => o.alts = v.parse().map_err(|_| bad(format!("bad alts '{v}'")))?,
            "max_items" => {
                o.max_items = v.parse().map_err(|_| bad(format!("bad max_items '{v}'")))?
            }
            _ => return Err(bad(format!("unknown option '{k}'"))),
        }
    }
    Ok(o)
}

/// Edits as records separated by `\0`, each `kind`, `path`, `value`
/// (`set`/`add` take a value in the CLI syntax; `del` takes an empty one).
pub fn parse_ops(arg: &str) -> Result<Vec<Op>, Diag> {
    let parts: Vec<&str> = arg.split('\0').collect();
    if !parts.len().is_multiple_of(3) || parts.is_empty() || arg.is_empty() {
        return Err(bad("edits must be (kind, path, value) triples"));
    }
    parts
        .chunks(3)
        .map(|c| {
            Ok(match c[0] {
                "set" => Op::Set(c[1].to_string(), core::parse_value(c[2])?),
                "add" => Op::Add(c[1].to_string(), core::parse_value(c[2])?),
                "del" => Op::Del(c[1].to_string()),
                k => return Err(bad(format!("unknown edit '{k}' (set|add|del)"))),
            })
        })
        .collect()
}

fn text(b: &[u8], what: &str) -> Result<String, Diag> {
    String::from_utf8(b.to_vec()).map_err(|_| bad(format!("{what} is not UTF-8")))
}

/// Run one operation. Returns the output bytes (JSON, tree text, raw
/// payload, or edited data) or a diagnostic.
pub fn call(op: u32, input: &[u8], arg: &[u8], opts: &[u8]) -> Result<Vec<u8>, Diag> {
    let opts = parse_opts(&text(opts, "options")?)?;
    match op {
        OP_PEEL => Ok(core::to_json(&core::peel(input, &opts)?).into_bytes()),
        OP_TREE => Ok(core::to_tree(&core::peel(input, &opts)?).into_bytes()),
        OP_GET | OP_GET_RAW => {
            let node = core::peel(input, &opts)?;
            let path = text(arg, "path")?;
            let raw = op == OP_GET_RAW;
            let p = core::get(&node, &path)?;
            if raw {
                p.payload()
            } else {
                Ok(p.to_json().into_bytes())
            }
        }
        OP_EDIT => {
            let mut data = input.to_vec();
            for o in parse_ops(&text(arg, "edits")?)? {
                data = core::edit(&data, &opts, &o)?;
            }
            Ok(data)
        }
        _ => Err(bad(format!("unknown operation {op}"))),
    }
}

/// `[status][len u32 LE][bytes]`.
pub fn frame(result: Result<Vec<u8>, Diag>) -> Vec<u8> {
    let (status, body) = match result {
        Ok(b) => (0u8, b),
        Err(d) => (1u8, core::diag_to_json(&d).into_bytes()),
    };
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(status);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

// ---------------------------------------------------------------- exports

/// Allocate `len` bytes in linear memory for the caller to fill.
#[unsafe(no_mangle)]
pub extern "C" fn bp_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// Free a buffer from `bp_alloc` or `bp_call`.
///
/// # Safety
/// `ptr` must come from `bp_alloc(len)` (or be a `bp_call` result of total
/// length `len`) and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bp_free(ptr: *mut u8, len: usize) {
    // SAFETY: the caller passes back a pointer and capacity we handed out.
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
}

/// Run one operation; see the module docs for the result layout.
///
/// # Safety
/// Each `(ptr, len)` pair must describe initialized memory owned by the
/// caller (a null pointer is allowed with length 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bp_call(
    op: u32,
    input: *const u8,
    input_len: usize,
    arg: *const u8,
    arg_len: usize,
    opts: *const u8,
    opts_len: usize,
) -> *mut u8 {
    // SAFETY: guaranteed by the caller; empty slices for zero lengths.
    let slice = |p: *const u8, n: usize| -> &[u8] {
        if n == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(p, n) }
        }
    };
    let out = frame(call(
        op,
        slice(input, input_len),
        slice(arg, arg_len),
        slice(opts, opts_len),
    ));
    // Hand out a buffer whose capacity equals its length, so the caller can
    // free it with `bp_free(ptr, 5 + len)`.
    let mut out = out.into_boxed_slice();
    let p = out.as_mut_ptr();
    std::mem::forget(out);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(op: u32, input: &[u8], arg: &str, opts: &str) -> Vec<u8> {
        call(op, input, arg.as_bytes(), opts.as_bytes()).unwrap()
    }

    #[test]
    fn peel_tree_get() {
        let j = String::from_utf8(ok(OP_PEEL, b"1a03089601", "", "")).unwrap();
        assert!(j.starts_with(r#"{"codec":"hex""#), "{j}");
        let t = String::from_utf8(ok(OP_TREE, b"1a03089601", "", "")).unwrap();
        assert!(t.contains("#3 LEN"), "{t}");
        let g = String::from_utf8(ok(OP_GET, b"1a03089601", "3.1", "")).unwrap();
        assert!(g.contains(r#""uint":"150""#), "{g}");
        assert_eq!(ok(OP_GET_RAW, b"1a03089601", "3.1", ""), vec![0x96, 0x01]);
        // DER and CBOR paths dispatch like the CLI.
        let d = String::from_utf8(ok(OP_GET, b"30 03 02 01 05", "0.0", "")).unwrap();
        assert!(d.contains(r#""int":"5""#), "{d}");
        assert_eq!(ok(OP_GET_RAW, b"a1 61 61 63 78 79 7a", "a", ""), b"xyz");
        // A path that crosses from CBOR into protobuf.
        assert_eq!(
            ok(OP_GET_RAW, b"a1 61 70 45 0a 03 66 6f 6f", "p.1", ""),
            b"foo"
        );
        // JWT parts and JSON claims.
        let jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhXG5iIiwiZXhwIjoxfQ._wA";
        assert_eq!(ok(OP_GET_RAW, jwt, "payload.sub", ""), b"a\nb");
        let j = String::from_utf8(ok(OP_GET, jwt, "header.alg", "")).unwrap();
        assert!(j.contains(r#""value":"HS256""#), "{j}");
    }

    #[test]
    fn options_and_edits() {
        let o = parse_opts("in=raw\nas=der\ndepth=4\nalts=2").unwrap();
        assert_eq!(
            (o.input, o.force, o.depth, o.alts),
            (InputForm::Raw, Some(Force::Der), 4, 2)
        );
        assert_eq!(parse_opts("in=nope").unwrap_err().code, "USAGE");
        let out = ok(
            OP_EDIT,
            b"08 96 01 12 03 66 6f 6f",
            "add\x003\x0042\x00del\x002\x00",
            "",
        );
        assert_eq!(out, b"08 96 01 18 2a");
        assert_eq!(
            call(OP_EDIT, b"0801", b"set\x001", b"").unwrap_err().code,
            "USAGE"
        );
    }

    #[test]
    fn errors_are_framed_json() {
        let f = frame(call(OP_GET, b"089601", b"9", b""));
        assert_eq!(f[0], 1);
        let len = u32::from_le_bytes([f[1], f[2], f[3], f[4]]) as usize;
        let body = std::str::from_utf8(&f[5..5 + len]).unwrap();
        assert!(body.contains(r#""code":"PATH_NOT_FOUND""#), "{body}");
    }
}
