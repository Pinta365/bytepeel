//! `bytepeel set`: `path\0value\0input`. The first byte of the path picks the
//! operation: `+` add, `-` delete, otherwise change. Must never panic; a
//! successful change or add must decode back to a tree where the path exists
//! (the library verifies this itself; this re-checks it independently).
#![no_main]

use bytepeel_core::{Op, Options, edit, get, parse_value, peel};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |&b| b == 0);
    let (Some(path), Some(value), Some(input)) = (parts.next(), parts.next(), parts.next()) else {
        return;
    };
    let (Ok(path), Ok(value)) = (std::str::from_utf8(path), std::str::from_utf8(value)) else {
        return;
    };
    let (op, path) = match path.as_bytes().first() {
        Some(b'+') => ("add", &path[1..]),
        Some(b'-') => ("del", &path[1..]),
        _ => ("set", path),
    };
    let op = match op {
        "del" => Op::Del(path.to_string()),
        kind => {
            let Ok(v) = parse_value(value) else { return };
            if kind == "add" {
                Op::Add(path.to_string(), v)
            } else {
                Op::Set(path.to_string(), v)
            }
        }
    };
    let opts = Options::default();
    let result = edit(input, &opts, &op);
    if matches!(op, Op::Del(_)) {
        if let Ok(out) = result {
            let _ = peel(&out, &opts).expect("auto-detection never fails");
        }
        return;
    }
    if let Ok(out) = result {
        let n = peel(&out, &opts).expect("auto-detection never fails");
        // The same lookup as the CLI's --get, which crosses formats.
        assert!(get(&n, path).is_ok(), "edited output lost the path");
    }
});
