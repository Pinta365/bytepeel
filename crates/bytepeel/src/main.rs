use std::io::{self, IsTerminal, Read, Write};
use std::process::ExitCode;

use bytepeel_core::{self as core, Diag, Force, InputForm, Options};

const HELP: &str = "\
bytepeel - peel layers of encoding off binary data

USAGE:
    bytepeel [OPTIONS] [FILE]      (reads stdin when FILE is omitted or '-')

OPTIONS:
    --in <auto|hex|base64|raw>     How to read the input (default: auto)
    --as <protobuf|text|bytes>     Force how the decoded bytes are interpreted
    --depth <N>                    Max nesting of layers and messages (default: 16)
    --alts <N>                     Max interpretations kept per LEN field (default: 3)
    --get <PATH>                   Select one protobuf field, e.g. 1.3[2].4
    --format <json|tree|raw>       Output format (default: json; raw needs --get)
    -h, --help                     Print help
    -V, --version                  Print version

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
    opts: Options,
    get: Option<String>,
    format: Format,
}

enum Cmd {
    Run(Args),
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

fn parse_args(argv: Vec<String>) -> Result<Cmd, Diag> {
    let mut args = Args {
        file: None,
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
            "--in" => {
                args.opts.input = match value()?.as_str() {
                    "auto" => InputForm::Auto,
                    "hex" => InputForm::Hex,
                    "base64" | "b64" => InputForm::Base64,
                    "raw" => InputForm::Raw,
                    v => {
                        return Err(usage(format!(
                            "unknown --in value '{v}' (expected auto|hex|base64|raw)"
                        )));
                    }
                }
            }
            "--as" => {
                args.opts.force = Some(match value()?.as_str() {
                    "protobuf" | "pb" => Force::Protobuf,
                    "text" => Force::Text,
                    "bytes" => Force::Bytes,
                    v => {
                        return Err(usage(format!(
                            "unknown --as value '{v}' (expected protobuf|text|bytes)"
                        )));
                    }
                })
            }
            "--depth" => args.opts.depth = parse_num(&value()?, "--depth")?,
            "--alts" => args.opts.alts = parse_num(&value()?, "--alts")?,
            "--get" => args.get = Some(value()?),
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
            _ => {
                if args.file.is_some() {
                    return Err(usage("only one input file is accepted"));
                }
                args.file = Some(a);
            }
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
    let node = match core::peel(&input, &args.opts) {
        Ok(n) => n,
        Err(e) => return fail(&e, 1),
    };

    let mut out = io::stdout().lock();
    let res = match &args.get {
        Some(path) => {
            let f = match core::select(&node, path) {
                Ok(f) => f,
                Err(e) => return fail(&e, 1),
            };
            match args.format {
                Format::Json => writeln!(out, "{}", core::field_to_json(f)),
                Format::Tree => write!(out, "{}", core::field_to_tree(f)),
                Format::Raw => match f.payload() {
                    Some(b) => out.write_all(&b),
                    None => {
                        let e = Diag::new(
                            "NO_PAYLOAD",
                            "a group has no single payload; use --format json",
                            None,
                        );
                        return fail(&e, 1);
                    }
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
