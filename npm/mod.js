// The JSR entry point: the same API as index.js, with the WebAssembly module
// embedded, so it loads without file or network access (no Deno permissions).
// @ts-self-types="./mod.d.ts"
import { load as loadFrom } from "./index.js";
import wasm from "./bytepeel_wasm.js";

export { BytepeelError, raw } from "./index.js";

let bytes;

/**
 * Load bytepeel. `source` is optional (see index.js); by default the
 * embedded module is used.
 */
export function load(source) {
  if (source !== undefined) return loadFrom(source);
  if (!bytes) {
    const s = atob(wasm);
    bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  }
  return loadFrom(bytes);
}
