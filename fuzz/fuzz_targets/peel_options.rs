//! Every option combination: the first two bytes pick the options, the rest
//! is the input. Errors are fine; panics are not.
#![no_main]

use bytepeel_core::{Force, InputForm, MAX_ITEMS, Options, diag_to_json, peel, to_json, to_tree};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let [a, b, input @ ..] = data else { return };
    let opts = Options {
        input: [
            InputForm::Auto,
            InputForm::Hex,
            InputForm::Base64,
            InputForm::Raw,
        ][usize::from(a & 3)],
        force: [
            None,
            Some(Force::Protobuf),
            Some(Force::Der),
            Some(Force::Cbor),
            Some(Force::Msgpack),
            Some(Force::Text),
            Some(Force::Bytes),
        ][usize::from((a >> 2) % 7)],
        depth: usize::from(b & 0x1f),
        alts: usize::from(b >> 5) + 1,
        // Small limits exercise the TOO_MANY_ITEMS paths.
        max_items: [MAX_ITEMS, 1, 7][input.len() % 3],
    };
    match peel(input, &opts) {
        Ok(node) => {
            let _ = to_json(&node);
            let _ = to_tree(&node);
        }
        Err(e) => {
            // Offsets index the buffer being decoded at the failing layer
            // (possibly decompressed data), so they are not bounded by input.
            assert!(!e.code.is_empty());
            let _ = diag_to_json(&e);
        }
    }
});
