use std::io::{self, IsTerminal, Read, Write};
use std::process::ExitCode;

use bytepeel_core::{self as core, Diag, Force, InputForm, Options};

mod mcp;

const HELP: &str = "\
bytepeel - peel layers of encoding off binary data

USAGE:
    bytepeel [OPTIONS] [FILE]      (reads stdin when FILE is omitted or '-')
    bytepeel mcp                   Run as an MCP server on stdio (tools: peel, set)
    bytepeel [OPTIONS] set EDIT... [FILE]
                                   Edit protobuf fields, CBOR/MessagePack values or DER
                                   elements and re-encode every layer (hex, base64, PEM,
                                   gzip, ...) in its original style. Writes the new data
                                   to stdout. Edits apply in order:
                                     PATH=VALUE   change
                                     PATH+=VALUE  add: protobuf field PARENT.N, map key,
                                                  array index (insert), DER index (insert;
                                                  VALUE = one element as hex:/b64:)
                                     --del PATH   remove
                                   Paths are --get paths and cross formats the same way.

OPTIONS:
    --in <auto|hex|base64|raw>     How to read the input (default: auto)
    --as <protobuf|der|cbor|msgpack|text|bytes>  Force how the decoded bytes are interpreted
    --depth <N>                    Max nesting of layers and messages (default: 16)
    --alts <N>                     Max interpretations kept per LEN field (default: 3)
    --max-items <N>                Max fields/values/elements decoded in total (default: 1000000)
    --get <PATH>                   Select one protobuf field (field numbers, e.g. 1.3[2].4),
                                   DER element (child indices, e.g. 0.0.6), or CBOR/MessagePack
                                   value (map keys / array indices, e.g. users.0.name), or JWT
                                   part and JSON claim (e.g. payload, payload.sub, header.alg),
                                   or a value in decoded JSON text (e.g. users.37.id).
                                   Paths cross formats: 2.0.0.5 is the subject of a certificate
                                   in protobuf field 2
    --format <json|tree|raw>       Output format (default: json; raw needs --get)
    -h, --help                     Print help
    -V, --version                  Print version

SET VALUES:
    42, -2                         integer (negative: 10-byte two's complement varint)
    sint:-2                        zigzag (sint32/sint64)
    1.5, float:NaN                 float (I32 fields: float32, I64 fields: double)
    true, false, null              bool / null (null: CBOR, MessagePack, DER NULL)
    \"text\", str:text               string (the quoted form takes JSON escapes)
    hex:0a0b, b64:CgM=             bytes
    Protobuf fields keep their wire type; DER elements keep their tag; CBOR and
    MessagePack values may change type. New protobuf fields: integers -> VARINT,
    floats -> double, text/bytes -> LEN. The output is decoded again and checked.

EXIT CODES:
    0 success, 1 decode error, 2 usage or I/O error.
    Errors go to stderr as {\"error\":{\"code\":..,\"message\":..,\"offset\":..}}.
";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Tree,
    Raw,
}

struct Args {
    file: Option<String>,
    /// `set` mode: (path, value) assignments, applied in order.
    set: Option<Vec<core::Op>>,
    /// `--del` paths seen before `set` (checked after parsing).
    pending_del: Vec<String>,
    opts: Options,
    get: Option<String>,
    format: Format,
}

enum Cmd {
    Run(Args),
    Mcp,
    Help,
    Version,
}

fn usage(msg: impl Into<String>) -> Diag {
    Diag::new("USAGE", msg, None)
}

fn parse_num(v: &str, flag: &str) -> Result<usize, Diag> {
    v.parse()
        .map_err(|_| usage(format!("{flag} expects a non-negative integer, got '{v}'")))
}

fn parse_in(v: &str, flag: &str) -> Result<InputForm, Diag> {
    Ok(match v {
        "auto" => InputForm::Auto,
        "hex" => InputForm::Hex,
        "base64" | "b64" => InputForm::Base64,
        "raw" => InputForm::Raw,
        v => {
            return Err(usage(format!(
                "unknown {flag} value '{v}' (expected auto|hex|base64|raw)"
            )));
        }
    })
}

fn parse_as(v: &str, flag: &str) -> Result<Force, Diag> {
    Ok(match v {
        "protobuf" | "pb" => Force::Protobuf,
        "der" | "asn1" => Force::Der,
        "cbor" | "cb" => Force::Cbor,
        "msgpack" | "mp" => Force::Msgpack,
        "text" => Force::Text,
        "bytes" => Force::Bytes,
        v => {
            return Err(usage(format!(
                "unknown {flag} value '{v}' (expected protobuf|der|cbor|msgpack|text|bytes)"
            )));
        }
    })
}

fn parse_args(argv: Vec<String>) -> Result<Cmd, Diag> {
    // `bytepeel mcp`: the MCP server (a file named `mcp` is `./mcp`).
    if argv.first().map(String::as_str) == Some("mcp") {
        return if argv.len() == 1 {
            Ok(Cmd::Mcp)
        } else {
            Err(usage("mcp takes no arguments (bytepeel mcp)"))
        };
    }
    let mut args = Args {
        file: None,
        set: None,
        pending_del: Vec::new(),
        opts: Options::default(),
        get: None,
        format: Format::Json,
    };
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].clone();
        i += 1;
        let (flag, inline) = match a.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (a.clone(), None),
        };
        let mut value = || -> Result<String, Diag> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            let v = argv
                .get(i)
                .cloned()
                .ok_or_else(|| usage(format!("{flag} needs a value")))?;
            i += 1;
            Ok(v)
        };
        match flag.as_str() {
            "-h" | "--help" => return Ok(Cmd::Help),
            "-V" | "--version" => return Ok(Cmd::Version),
            "--in" => args.opts.input = parse_in(&value()?, "--in")?,
            "--as" => args.opts.force = Some(parse_as(&value()?, "--as")?),
            "--depth" => args.opts.depth = parse_num(&value()?, "--depth")?,
            "--alts" => args.opts.alts = parse_num(&value()?, "--alts")?,
            "--max-items" => args.opts.max_items = parse_num(&value()?, "--max-items")?,
            "--get" => args.get = Some(value()?),
            "--del" => {
                let p = value()?;
                match args.set.as_mut() {
                    Some(ops) => ops.push(core::Op::Del(p)),
                    None => args.pending_del.push(p),
                }
            }
            "--format" => {
                args.format = match value()?.as_str() {
                    "json" => Format::Json,
                    "tree" => Format::Tree,
                    "raw" => Format::Raw,
                    v => {
                        return Err(usage(format!(
                            "unknown --format value '{v}' (expected json|tree|raw)"
                        )));
                    }
                }
            }
            s if s.starts_with('-') && s != "-" => {
                return Err(usage(format!("unknown option '{s}' (see --help)")));
            }
            // `set` is the subcommand when it is the first positional argument
            // (options may come before it); a file named `set` is `./set`.
            "set" if args.set.is_none() && args.file.is_none() => args.set = Some(Vec::new()),
            _ if args.set.is_some() && a.contains('=') => {
                let (path, v) = a.split_once('=').expect("contains '='");
                let value = core::parse_value(v)?;
                let op = match path.strip_suffix('+') {
                    Some(p) => core::Op::Add(p.to_string(), value),
                    None => core::Op::Set(path.to_string(), value),
                };
                args.set.as_mut().expect("set mode").push(op);
            }
            _ => {
                if args.file.is_some() {
                    return Err(usage("only one input file is accepted"));
                }
                args.file = Some(a);
            }
        }
    }
    if !args.pending_del.is_empty() {
        match args.set.as_mut() {
            Some(ops) => {
                let dels = std::mem::take(&mut args.pending_del);
                for (i, p) in dels.into_iter().enumerate() {
                    ops.insert(i, core::Op::Del(p));
                }
            }
            None => {
                return Err(usage(
                    "--del is only valid with set (bytepeel set --del PATH FILE)",
                ));
            }
        }
    }
    if let Some(set) = &args.set {
        if set.is_empty() {
            return Err(usage(
                "set needs at least one edit: PATH=VALUE, PATH+=VALUE or --del PATH \
                 (e.g. bytepeel set 1.3=42 FILE)",
            ));
        }
        if args.get.is_some() || args.format != Format::Json {
            return Err(usage(
                "set writes the re-encoded data; --get and --format do not apply",
            ));
        }
    }
    if args.format == Format::Raw && args.get.is_none() {
        return Err(usage("--format raw requires --get <PATH>"));
    }
    Ok(Cmd::Run(args))
}

fn read_input(file: Option<&str>) -> Result<Vec<u8>, Diag> {
    match file {
        Some(p) if p != "-" => {
            std::fs::read(p).map_err(|e| Diag::new("IO", format!("{p}: {e}"), None))
        }
        _ => {
            let stdin = io::stdin();
            if stdin.is_terminal() {
                return Err(usage(
                    "no input: pass a FILE or pipe data on stdin (see --help)",
                ));
            }
            let mut buf = Vec::new();
            stdin
                .lock()
                .read_to_end(&mut buf)
                .map_err(|e| Diag::new("IO", format!("stdin: {e}"), None))?;
            Ok(buf)
        }
    }
}

fn fail(e: &Diag, code: u8) -> ExitCode {
    eprintln!("{}", core::diag_to_json(e));
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1).collect()) {
        Ok(Cmd::Run(a)) => a,
        Ok(Cmd::Help) => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Ok(Cmd::Mcp) => {
            return match mcp::serve() {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&Diag::new("IO", e.to_string(), None), 2),
            };
        }
        Ok(Cmd::Version) => {
            println!("bytepeel {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => return fail(&e, 2),
    };
    let input = match read_input(args.file.as_deref()) {
        Ok(b) => b,
        Err(e) => return fail(&e, 2),
    };
    if let Some(set) = &args.set {
        let mut data = input;
        for op in set {
            data = match core::edit(&data, &args.opts, op) {
                Ok(d) => d,
                Err(e) => return fail(&e, 1),
            };
        }
        let mut out = io::stdout().lock();
        return match out.write_all(&data).and_then(|()| out.flush()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
            Err(e) => fail(&Diag::new("IO", e.to_string(), None), 2),
        };
    }
    let node = match core::peel(&input, &args.opts) {
        Ok(n) => n,
        Err(e) => return fail(&e, 1),
    };

    let mut out = io::stdout().lock();
    let res = match &args.get {
        Some(path) => {
            let p = match core::get(&node, path) {
                Ok(p) => p,
                Err(e) => return fail(&e, 1),
            };
            match args.format {
                Format::Json => writeln!(out, "{}", p.to_json()),
                Format::Tree => write!(out, "{}", p.to_tree()),
                Format::Raw => match p.payload() {
                    Ok(b) => out.write_all(&b),
                    Err(e) => return fail(&e, 1),
                },
            }
        }
        None => match args.format {
            Format::Json => writeln!(out, "{}", core::to_json(&node)),
            Format::Tree => write!(out, "{}", core::to_tree(&node)),
            Format::Raw => unreachable!("rejected in parse_args"),
        },
    };
    match res.and_then(|()| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => fail(&Diag::new("IO", e.to_string(), None), 2),
    }
}
