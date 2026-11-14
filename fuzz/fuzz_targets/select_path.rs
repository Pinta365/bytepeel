//! `--get` paths: input and path are split at the first NUL byte. Uses the
//! cross-format `get` (what the CLI and WASM call), then each single-format
//! selector the input supports.
#![no_main]

use bytepeel_core::{
    Options, get, is_der, is_jwt, is_values, peel, select, select_der, select_jwt, select_value,
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
    if let Ok(p) = get(&node, path) {
        let _ = (p.to_json(), p.to_tree(), p.payload());
    }
    if is_der(&node) {
        let _ = select_der(&node, path);
    }
    if is_values(&node) {
        let _ = select_value(&node, path);
    }
    if is_jwt(&node) {
        let _ = select_jwt(&node, path);
    }
    let _ = select(&node, path);
});
