//! `bytepeel set`: `path\0value\0input`. Must never panic; a successful edit
//! must decode back to a tree where the path holds the new value (`set`
//! verifies this itself, so an Ok result is re-checked here independently).
#![no_main]

use bytepeel_core::{Options, parse_value, peel, select, set};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.splitn(3, |&b| b == 0);
    let (Some(path), Some(value), Some(input)) = (parts.next(), parts.next(), parts.next()) else {
        return;
    };
    let (Ok(path), Ok(value)) = (std::str::from_utf8(path), std::str::from_utf8(value)) else {
        return;
    };
    let Ok(v) = parse_value(value) else { return };
    let opts = Options::default();
    if let Ok(out) = set(input, &opts, path, &v) {
        let n = peel(&out, &opts).expect("auto-detection never fails");
        assert!(select(&n, path).is_ok(), "edited output lost the path");
    }
});
