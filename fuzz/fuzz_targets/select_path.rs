//! `--get` paths: input and path are split at the first NUL byte. Selection
//! dispatches like the CLI: DER, then CBOR/MessagePack, then JWT, then protobuf.
#![no_main]

use bytepeel_core::{
    Options, asn1_to_json, asn1_to_tree, field_to_json, field_to_tree, is_der, is_jwt, is_values,
    peel, select, select_der, select_jwt, select_value, value_to_json, value_to_tree,
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
    } else if is_values(&node) {
        if let Ok(v) = select_value(&node, path) {
            let _ = (value_to_json(v), value_to_tree(v), v.payload());
        }
    } else if is_jwt(&node) {
        if let Ok(p) = select_jwt(&node, path) {
            let _ = (p.to_json(), p.to_tree(), p.payload());
        }
    } else if let Ok(f) = select(&node, path) {
        let _ = (field_to_json(f), field_to_tree(f), f.payload());
    }
});
