//! `--get` paths: input and path are split at the first NUL byte.
#![no_main]

use bytepeel_core::{
    Options, asn1_to_json, asn1_to_tree, field_to_json, field_to_tree, is_der, peel, select,
    select_der,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(nul) = data.iter().position(|&b| b == 0) else {
        return;
    };
    let Ok(path) = std::str::from_utf8(&data[..nul]) else {
        return;
    };
    let node = peel(&data[nul + 1..], &Options::default()).unwrap();
    if is_der(&node) {
        if let Ok(e) = select_der(&node, path) {
            let _ = (asn1_to_json(e), asn1_to_tree(e), e.payload());
        }
    } else if let Ok(f) = select(&node, path) {
        let _ = (field_to_json(f), field_to_tree(f), f.payload());
    }
});
