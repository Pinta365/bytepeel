//! Auto-detection on arbitrary bytes: must never panic, and output must be
//! deterministic.
#![no_main]

use bytepeel_core::{Options, peel, to_json, to_tree};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let opts = Options::default();
    // Auto-detection never fails.
    let node = peel(data, &opts).expect("auto-detection returned an error");
    let json = to_json(&node);
    assert_eq!(
        json,
        to_json(&peel(data, &opts).unwrap()),
        "non-deterministic"
    );
    let _ = to_tree(&node);
});
