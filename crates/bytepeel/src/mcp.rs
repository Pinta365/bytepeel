//! `bytepeel mcp`: a Model Context Protocol server on stdio.
//!
//! Messages are newline-delimited JSON-RPC 2.0. The server offers two tools,
//! `peel` (decode, optionally select one item by path) and `set` (edit and
//! re-encode). Tool failures are results with `isError: true` whose text is
//! the same `{"error":{..}}` JSON the CLI prints; protocol problems are
//! JSON-RPC errors. No dependencies: the request JSON is read by the small
//! parser below.

use std::io::{self, BufRead, Write};

use bytepeel_core::{self as core, Diag, Options};

use crate::{parse_as, parse_in, usage};

/// Protocol versions this server speaks (it uses only tools, which every
/// version has). A client asking for another gets the first.
const VERSIONS: &[&str] = &["2025-06-18", "2025-11-25", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "bytepeel decodes encoded and binary data byte-exactly: hex, base64, \
PEM, JWTs, xxd/hexdump dumps, gzip/zlib/zstd, DER/ASN.1 (X.509), CBOR, MessagePack and \
schemaless protobuf, nested in any order. Use `peel` instead of decoding bytes by reading them \
or writing a one-off script, and `set` to change a value and get the data back in its original \
encoding. Ambiguous data is reported as ranked alternatives, never silently resolved.";

/// Serve until stdin closes.
pub(crate) fn serve() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(resp) = handle(&line) {
            writeln!(out, "{resp}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// Answer one message; `None` for notifications and client responses.
pub(crate) fn handle(line: &str) -> Option<String> {
    let msg = match parse(line) {
        Ok(m @ J::Obj(_)) => m,
        Ok(_) => return Some(rpc_error("null", -32600, "expected a JSON-RPC object")),
        Err(e) => return Some(rpc_error("null", -32700, &format!("parse error: {e}"))),
    };
    let id = write_json(msg.get("id")?);
    let Some(method) = msg.get("method").and_then(J::as_str) else {
        // A response to a request we never sent: nothing to answer.
        if msg.get("result").is_some() || msg.get("error").is_some() {
            return None;
        }
        return Some(rpc_error(&id, -32600, "missing method"));
    };
    let params = msg.get("params");
    let result = match method {
        "initialize" => Ok(initialize(params)),
        "ping" => Ok("{}".to_string()),
        "tools/list" => Ok(tools_list()),
        "tools/call" => tools_call(params),
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    Some(match result {
        Ok(r) => format!(r#"{{"jsonrpc":"2.0","id":{id},"result":{r}}}"#),
        Err((code, m)) => rpc_error(&id, code, &m),
    })
}

fn rpc_error(id: &str, code: i32, message: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{code},"message":{}}}}}"#,
        esc(message)
    )
}

fn initialize(params: Option<&J>) -> String {
    let asked = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(J::as_str);
    let version = VERSIONS
        .iter()
        .find(|v| Some(**v) == asked)
        .unwrap_or(&VERSIONS[0]);
    format!(
        r#"{{"protocolVersion":"{version}","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"bytepeel","version":"{}"}},"instructions":{}}}"#,
        env!("CARGO_PKG_VERSION"),
        esc(INSTRUCTIONS)
    )
}

// ---------------------------------------------------------------- tools

const COMMON_PROPS: &str = r#""input":{"type":"string","description":"The data as text: hex, base64, PEM, a JWT, an xxd or hexdump -C dump, or any nesting of these. Give either input or file."},
"file":{"type":"string","description":"Path of a local file to read instead of input (binary files are fine)."},
"in":{"type":"string","enum":["auto","hex","base64","raw"],"description":"How to read the input (default auto). raw = the bytes as they are."},
"as":{"type":"string","enum":["protobuf","der","cbor","msgpack","text","bytes"],"description":"Force how the innermost decoded bytes are interpreted, when auto-detection picks wrongly."},
"depth":{"type":"integer","minimum":0,"description":"Max nesting of layers and messages (default 16)."},
"alts":{"type":"integer","minimum":0,"description":"Max interpretations kept per protobuf LEN field (default 3)."},
"max_items":{"type":"integer","minimum":0,"description":"Max protobuf fields, CBOR/MessagePack values and DER elements decoded in total (default 1000000)."},
"output_file":{"type":"string","description":"Write the result to this file instead of returning it. Fails if the file exists, unless overwrite is true."},
"overwrite":{"type":"boolean","description":"Allow output_file to replace an existing file."}"#;

const PATHS: &str = "Paths: protobuf field numbers (1.3[2].4: the third field 3 of message 1), \
DER child indices (0.0.5), a PEM bundle's block index first, CBOR/MessagePack map keys and array \
indices (users.0.name), a JWT part then JSON keys (payload.sub). Paths cross formats: 2.0.0.5 is \
the subject of a certificate (base64, PEM or raw DER) held in protobuf field 2.";

fn tools_list() -> String {
    let peel_desc = format!(
        "Decode data byte-exactly through every layer (hex, base64, PEM, JWT, dumps, gzip/zlib/zstd, \
         DER/ASN.1, CBOR, MessagePack, schemaless protobuf) and return a JSON tree with byte ranges. \
         Ambiguous protobuf LEN fields list ranked alternatives (message, string, bytes, packed); \
         64-bit integers are JSON strings. Long text and bytes are previewed (\"truncated\":true); \
         use get with format raw for a full payload. {PATHS}"
    );
    let set_desc = format!(
        "Change, add or remove values and get the data back in its original encoding (hex spacing, \
         base64 alphabet and wrapping, PEM label, gzip header), with every other byte preserved. \
         Edits apply in order; the result is decoded again and checked (REENCODE_VERIFY_FAILED \
         otherwise). Editing signed data (a certificate) invalidates its signature; JWTs are not \
         editable. {PATHS}"
    );
    format!(
        r#"{{"tools":[{{"name":"peel","title":"Decode data","description":{},"inputSchema":{{"type":"object","properties":{{{COMMON_PROPS},
"get":{{"type":"string","description":"Select one item by path and return only it."}},
"format":{{"type":"string","enum":["json","tree","raw"],"description":"json (default); tree: a compact indented outline; raw: the selected item's payload bytes as lowercase hex (needs get)."}}}},"additionalProperties":false}},"annotations":{{"readOnlyHint":true,"openWorldHint":false}}}},
{{"name":"set","title":"Edit and re-encode data","description":{},"inputSchema":{{"type":"object","properties":{{{COMMON_PROPS},
"edits":{{"type":"array","minItems":1,"description":"Edits, applied in order.","items":{{"type":"object","properties":{{"op":{{"type":"string","enum":["set","add","del"],"description":"set (default) changes the item at path; add inserts: protobuf PARENT.N appends field N, a new map key, an array index (inserted before it), a DER index (value = one whole element as hex:/b64:); del removes it."}},"path":{{"type":"string"}},"value":{{"type":"string","description":"The new value (not for del), in bytepeel's value syntax: \"42\" or \"-2\" for integers, \"1.5\" or \"float:NaN\" for floats, \"true\"/\"false\", \"null\", \"\\\"text\\\"\" or \"str:text\" for text, \"hex:0a0b\" or \"b64:CgM=\" for bytes, \"sint:-2\" for zigzag. Protobuf fields keep their wire type; DER elements their tag."}}}},"required":["path"],"additionalProperties":false}}}}}},"required":["edits"],"additionalProperties":false}},"annotations":{{"readOnlyHint":false,"openWorldHint":false}}}}]}}"#,
        esc(&peel_desc),
        esc(&set_desc)
    )
    .replace('\n', "")
}

fn tools_call(params: Option<&J>) -> Result<String, (i32, String)> {
    let params = params.ok_or((-32602, "tools/call needs params".to_string()))?;
    let name = params
        .get("name")
        .and_then(J::as_str)
        .ok_or((-32602, "tools/call needs a tool name".to_string()))?;
    let empty = J::Obj(Vec::new());
    let args = params.get("arguments").unwrap_or(&empty);
    if !matches!(args, J::Obj(_)) {
        return Err((-32602, "arguments must be an object".to_string()));
    }
    let res = match name {
        "peel" => tool_peel(args),
        "set" => tool_set(args),
        _ => return Err((-32602, format!("unknown tool: {name}"))),
    };
    let (text, is_error) = match res {
        Ok(t) => (t, false),
        Err(e) => (core::diag_to_json(&e), true),
    };
    Ok(format!(
        r#"{{"content":[{{"type":"text","text":{}}}],"isError":{is_error}}}"#,
        esc(&text)
    ))
}

const COMMON_KEYS: &[&str] = &[
    "input",
    "file",
    "in",
    "as",
    "depth",
    "alts",
    "max_items",
    "output_file",
    "overwrite",
];

fn check_keys(args: &J, extra: &[&str]) -> Result<(), Diag> {
    if let J::Obj(m) = args {
        for (k, _) in m {
            if !COMMON_KEYS.contains(&k.as_str()) && !extra.contains(&k.as_str()) {
                return Err(usage(format!("unknown argument '{k}'")));
            }
        }
    }
    Ok(())
}

fn str_arg<'a>(args: &'a J, key: &str) -> Result<Option<&'a str>, Diag> {
    match args.get(key) {
        None | Some(J::Null) => Ok(None),
        Some(J::Str(s)) => Ok(Some(s)),
        Some(_) => Err(usage(format!("'{key}' must be a string"))),
    }
}

fn num_arg(args: &J, key: &str) -> Result<Option<usize>, Diag> {
    match args.get(key) {
        None | Some(J::Null) => Ok(None),
        Some(J::Num(n)) => n
            .parse()
            .map(Some)
            .map_err(|_| usage(format!("'{key}' must be a non-negative integer, got {n}"))),
        Some(_) => Err(usage(format!("'{key}' must be a non-negative integer"))),
    }
}

fn options(args: &J) -> Result<Options, Diag> {
    let mut o = Options::default();
    if let Some(v) = str_arg(args, "in")? {
        o.input = parse_in(v, "'in'")?;
    }
    if let Some(v) = str_arg(args, "as")? {
        o.force = Some(parse_as(v, "'as'")?);
    }
    if let Some(n) = num_arg(args, "depth")? {
        o.depth = n;
    }
    if let Some(n) = num_arg(args, "alts")? {
        o.alts = n;
    }
    if let Some(n) = num_arg(args, "max_items")? {
        o.max_items = n;
    }
    Ok(o)
}

fn input(args: &J) -> Result<Vec<u8>, Diag> {
    match (str_arg(args, "input")?, str_arg(args, "file")?) {
        (Some(s), None) => Ok(s.as_bytes().to_vec()),
        (None, Some(p)) => std::fs::read(p).map_err(|e| Diag::new("IO", format!("{p}: {e}"), None)),
        (Some(_), Some(_)) => Err(usage("give either 'input' or 'file', not both")),
        (None, None) => Err(usage("give the data as 'input' (text) or 'file' (a path)")),
    }
}

/// Write `data` to `output_file` when given (returning a short report), or
/// return `inline()`.
fn deliver(args: &J, data: &[u8], inline: impl FnOnce() -> String) -> Result<String, Diag> {
    let Some(path) = str_arg(args, "output_file")? else {
        return Ok(inline());
    };
    let overwrite = match args.get("overwrite") {
        None | Some(J::Null) => false,
        Some(J::Bool(b)) => *b,
        Some(_) => return Err(usage("'overwrite' must be true or false")),
    };
    let io_err = |e: io::Error| Diag::new("IO", format!("{path}: {e}"), None);
    let mut f = if overwrite {
        std::fs::File::create(path)
    } else {
        std::fs::File::create_new(path)
    }
    .map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => Diag::new(
            "IO",
            format!("{path} already exists; pass overwrite: true to replace it"),
            None,
        ),
        _ => io_err(e),
    })?;
    f.write_all(data).map_err(io_err)?;
    Ok(format!(
        r#"{{"written":{},"bytes":{}}}"#,
        esc(path),
        data.len()
    ))
}

fn tool_peel(args: &J) -> Result<String, Diag> {
    check_keys(args, &["get", "format"])?;
    let opts = options(args)?;
    let data = input(args)?;
    let get = str_arg(args, "get")?;
    let format = str_arg(args, "format")?.unwrap_or("json");
    if !["json", "tree", "raw"].contains(&format) {
        return Err(usage(format!(
            "unknown format '{format}' (expected json|tree|raw)"
        )));
    }
    let node = core::peel(&data, &opts)?;
    let out = match get {
        Some(path) => {
            let p = core::get(&node, path)?;
            match format {
                "json" => p.to_json(),
                "tree" => p.to_tree(),
                _ => {
                    let b = p.payload()?;
                    // Raw bytes go to a file as they are; inline they are hex.
                    return deliver(args, &b, || hex(&b));
                }
            }
        }
        None => match format {
            "json" => core::to_json(&node),
            "tree" => core::to_tree(&node),
            _ => return Err(usage("format raw needs get (a path)")),
        },
    };
    deliver(args, out.as_bytes(), || out.clone())
}

fn tool_set(args: &J) -> Result<String, Diag> {
    check_keys(args, &["edits"])?;
    let opts = options(args)?;
    let edits = match args.get("edits") {
        Some(J::Arr(a)) if !a.is_empty() => a,
        _ => {
            return Err(usage(
                "'edits' must be a non-empty array of {op, path, value}",
            ));
        }
    };
    let ops = edits.iter().map(edit_op).collect::<Result<Vec<_>, _>>()?;
    let mut data = input(args)?;
    for op in &ops {
        data = core::edit(&data, &opts, op)?;
    }
    deliver(args, &data, || match std::str::from_utf8(&data) {
        Ok(t) => format!(r#"{{"encoding":"text","data":{}}}"#, esc(t)),
        Err(_) => format!(r#"{{"encoding":"hex","data":"{}"}}"#, hex(&data)),
    })
}

fn edit_op(e: &J) -> Result<core::Op, Diag> {
    let J::Obj(m) = e else {
        return Err(usage("each edit must be an object {op, path, value}"));
    };
    if let Some((k, _)) = m
        .iter()
        .find(|(k, _)| !["op", "path", "value"].contains(&k.as_str()))
    {
        return Err(usage(format!("unknown edit key '{k}'")));
    }
    let path = str_arg(e, "path")?
        .ok_or_else(|| usage("each edit needs a 'path'"))?
        .to_string();
    let op = str_arg(e, "op")?.unwrap_or("set");
    let value = || -> Result<core::NewValue, Diag> {
        let text = match e.get("value") {
            None => return Err(usage(format!("the {op} edit at '{path}' needs a 'value'"))),
            Some(J::Str(s)) => s.clone(),
            Some(J::Num(n)) => n.clone(),
            Some(J::Bool(b)) => b.to_string(),
            Some(J::Null) => "null".to_string(),
            Some(_) => {
                return Err(usage(
                    "'value' must be a number, true/false/null or a string in the value syntax",
                ));
            }
        };
        core::parse_value(&text)
    };
    Ok(match op {
        "set" => core::Op::Set(path.clone(), value()?),
        "add" => core::Op::Add(path.clone(), value()?),
        "del" => {
            if e.get("value").is_some() {
                return Err(usage("a del edit takes no 'value'"));
            }
            core::Op::Del(path)
        }
        _ => {
            return Err(usage(format!(
                "unknown edit op '{op}' (expected set|add|del)"
            )));
        }
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------- JSON

/// A parsed JSON value. Numbers keep their source text (ids are echoed back
/// exactly; integer arguments are parsed from it).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 64;

/// Parse strict RFC 8259 JSON.
pub(crate) fn parse(s: &str) -> Result<J, String> {
    let mut p = Parser {
        b: s.as_bytes(),
        i: 0,
        depth: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err());
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn err(&self) -> String {
        format!("invalid JSON at byte {}", self.i)
    }

    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        let hit = self.b.get(self.i) == Some(&c);
        if hit {
            self.i += 1;
        }
        hit
    }

    fn lit(&mut self, word: &str, v: J) -> Result<J, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err())
        }
    }

    fn value(&mut self) -> Result<J, String> {
        match self.b.get(self.i) {
            Some(b'n') => self.lit("null", J::Null),
            Some(b't') => self.lit("true", J::Bool(true)),
            Some(b'f') => self.lit("false", J::Bool(false)),
            Some(b'"') => self.string().map(J::Str),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'[') => {
                self.enter()?;
                let mut items = Vec::new();
                self.ws();
                if !self.eat(b']') {
                    loop {
                        self.ws();
                        items.push(self.value()?);
                        self.ws();
                        if self.eat(b']') {
                            break;
                        }
                        if !self.eat(b',') {
                            return Err(self.err());
                        }
                    }
                }
                self.depth -= 1;
                Ok(J::Arr(items))
            }
            Some(b'{') => {
                self.enter()?;
                let mut members = Vec::new();
                self.ws();
                if !self.eat(b'}') {
                    loop {
                        self.ws();
                        if self.b.get(self.i) != Some(&b'"') {
                            return Err(self.err());
                        }
                        let k = self.string()?;
                        self.ws();
                        if !self.eat(b':') {
                            return Err(self.err());
                        }
                        self.ws();
                        members.push((k, self.value()?));
                        self.ws();
                        if self.eat(b'}') {
                            break;
                        }
                        if !self.eat(b',') {
                            return Err(self.err());
                        }
                    }
                }
                self.depth -= 1;
                Ok(J::Obj(members))
            }
            _ => Err(self.err()),
        }
    }

    fn enter(&mut self) -> Result<(), String> {
        self.i += 1;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("JSON nested too deeply".to_string());
        }
        Ok(())
    }

    fn digits(&mut self) -> usize {
        let s = self.i;
        while matches!(self.b.get(self.i), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        self.i - s
    }

    fn number(&mut self) -> Result<J, String> {
        let s = self.i;
        self.eat(b'-');
        match self.b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(self.err()),
        }
        if self.eat(b'.') && self.digits() == 0 {
            return Err(self.err());
        }
        if self.eat(b'e') || self.eat(b'E') {
            if !self.eat(b'+') {
                self.eat(b'-');
            }
            if self.digits() == 0 {
                return Err(self.err());
            }
        }
        let text = std::str::from_utf8(&self.b[s..self.i]).expect("ASCII");
        Ok(J::Num(text.to_string()))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.b.get(self.i..self.i + 4).ok_or_else(|| self.err())?;
        let v = std::str::from_utf8(h)
            .ok()
            .filter(|t| t.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|t| u32::from_str_radix(t, 16).ok())
            .ok_or_else(|| self.err())?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // the opening quote
        let mut out = String::new();
        loop {
            let s = self.i;
            while let Some(&c) = self.b.get(self.i) {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // The input is a &str and the run stops at ASCII, so it is UTF-8.
            out.push_str(std::str::from_utf8(&self.b[s..self.i]).expect("UTF-8 run"));
            match self.b.get(self.i) {
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let c = *self.b.get(self.i).ok_or_else(|| self.err())?;
                    self.i += 1;
                    out.push(match c {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xd800..0xdc00).contains(&hi) {
                                if !(self.eat(b'\\') && self.eat(b'u')) {
                                    return Err(self.err());
                                }
                                let lo = self.hex4()?;
                                if !(0xdc00..0xe000).contains(&lo) {
                                    return Err(self.err());
                                }
                                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or_else(|| self.err())?
                        }
                        _ => return Err(self.err()),
                    });
                }
                _ => return Err(self.err()),
            }
        }
    }
}

/// `s` as a quoted JSON string.
pub(crate) fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn write_json(j: &J) -> String {
    match j {
        J::Null => "null".to_string(),
        J::Bool(b) => b.to_string(),
        J::Num(n) => n.clone(),
        J::Str(s) => esc(s),
        J::Arr(a) => format!(
            "[{}]",
            a.iter().map(write_json).collect::<Vec<_>>().join(",")
        ),
        J::Obj(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| format!("{}:{}", esc(k), write_json(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_parser_is_strict() {
        let v = parse(r#" {"a":[1,-2.5e3,true,null],"b":"x\"\u00e9\ud83d\ude00\n"} "#).unwrap();
        assert_eq!(v.get("b").and_then(J::as_str), Some("x\"é😀\n"));
        assert_eq!(write_json(v.get("a").unwrap()), "[1,-2.5e3,true,null]");
        for bad in [
            "",
            "{",
            "[1,]",
            "01",
            "1.",
            "-",
            "\"\\x\"",
            "\"\u{1}\"",
            "{\"a\" 1}",
            "nul",
            "\"\\ud800\"",
            "[1] 2",
            "{'a':1}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse(&"[".repeat(65)).is_err());
        assert!(parse(&format!("{}{}", "[".repeat(64), "]".repeat(64))).is_ok());
    }

    #[test]
    fn tool_list_is_valid_json() {
        let v = parse(&tools_list()).unwrap();
        let J::Arr(tools) = v.get("tools").unwrap() else {
            panic!()
        };
        assert_eq!(tools.len(), 2);
        assert!(parse(&initialize(None)).is_ok());
    }
}
