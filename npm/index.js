// bytepeel for JavaScript: a thin wrapper over bytepeel.wasm (Node, Deno,
// Bun, browsers). See README.md. The JSON schema is docs/DESIGN.md.

const OP_PEEL = 0;
const OP_TREE = 1;
const OP_GET = 2;
const OP_GET_RAW = 3;
const OP_EDIT = 4;

const enc = new TextEncoder();
const dec = new TextDecoder();

/** An error from bytepeel, with the same stable `code` the CLI prints. */
export class BytepeelError extends Error {
  constructor({ code, message, offset }) {
    super(`${code}: ${message}`);
    this.name = "BytepeelError";
    /** Stable SCREAMING_SNAKE identifier, e.g. "PATH_NOT_FOUND". */
    this.code = code;
    /** Byte offset into the buffer being decoded, or null. */
    this.offset = offset;
    this.detail = message;
  }
}

/** Pass a value in the CLI value syntax verbatim, e.g. raw("sint:-2"). */
export function raw(syntax) {
  return { syntax: String(syntax) };
}

function toBytes(input) {
  if (typeof input === "string") return enc.encode(input);
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  throw new TypeError("input must be a string, Uint8Array, ArrayBuffer or typed array");
}

function optsString(opts = {}) {
  const lines = [];
  for (const [k, v] of Object.entries(opts)) {
    if (v === undefined) continue;
    if (!["in", "as", "depth", "alts"].includes(k)) {
      throw new TypeError(`unknown option '${k}' (in, as, depth, alts)`);
    }
    lines.push(`${k}=${v}`);
  }
  return lines.join("\n");
}

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

/** A JS value to the CLI value syntax. Strings are text, never parsed. */
function valueSyntax(v) {
  if (v !== null && typeof v === "object" && "syntax" in v) return v.syntax;
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "number") {
    if (Number.isInteger(v)) {
      if (!Number.isSafeInteger(v)) {
        throw new RangeError(`${v} is not a safe integer; pass a BigInt`);
      }
      return String(v);
    }
    if (Number.isNaN(v)) return "float:NaN";
    if (v === Infinity) return "float:Infinity";
    if (v === -Infinity) return "float:-Infinity";
    return `float:${v}`;
  }
  if (typeof v === "string") return `str:${v}`;
  if (v instanceof Uint8Array || ArrayBuffer.isView(v) || v instanceof ArrayBuffer) {
    const b = toBytes(v);
    let s = "hex:";
    for (const x of b) s += HEX[x];
    return s;
  }
  throw new TypeError(`unsupported value type: ${typeof v}`);
}

function editsString(edits) {
  if (!Array.isArray(edits) || edits.length === 0) {
    throw new TypeError("edits must be a non-empty array");
  }
  const parts = [];
  for (const e of edits) {
    if ("set" in e) parts.push("set", e.set, valueSyntax(e.value));
    else if ("add" in e) parts.push("add", e.add, valueSyntax(e.value));
    else if ("del" in e) parts.push("del", e.del, "");
    else throw new TypeError("each edit is {set, value}, {add, value} or {del}");
  }
  for (const p of parts) {
    if (p.includes("\0")) throw new TypeError("paths and values cannot contain NUL");
  }
  return parts.join("\0");
}

function wrap(instance) {
  const { memory, bp_alloc, bp_free, bp_call } = instance.exports;

  function put(bytes) {
    const ptr = bp_alloc(bytes.length);
    new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  }

  function call(op, input, arg, opts) {
    const bufs = [put(toBytes(input)), put(enc.encode(arg)), put(enc.encode(opts))];
    try {
      const res = bp_call(op, ...bufs[0], ...bufs[1], ...bufs[2]);
      // Re-read the buffer: memory may have grown during the call.
      const view = new DataView(memory.buffer);
      const status = view.getUint8(res);
      const len = view.getUint32(res + 1, true);
      const body = new Uint8Array(memory.buffer, res + 5, len).slice();
      bp_free(res, 5 + len);
      if (status !== 0) throw new BytepeelError(JSON.parse(dec.decode(body)).error);
      return body;
    } finally {
      for (const [p, n] of bufs) bp_free(p, n);
    }
  }

  return {
    /** Decode `input` into the node tree (DESIGN.md schema). */
    peel(input, opts) {
      return JSON.parse(dec.decode(call(OP_PEEL, input, "", optsString(opts))));
    },
    /** The human-readable outline (`--format tree`). */
    tree(input, opts) {
      return dec.decode(call(OP_TREE, input, "", optsString(opts)));
    },
    /** One protobuf field, DER element or CBOR/MessagePack value by path. */
    get(input, path, opts) {
      return JSON.parse(dec.decode(call(OP_GET, input, String(path), optsString(opts))));
    },
    /** The payload bytes at `path` (`--get PATH --format raw`). */
    getRaw(input, path, opts) {
      return call(OP_GET_RAW, input, String(path), optsString(opts));
    },
    /**
     * Apply edits in order and return the re-encoded data, in the input's
     * original outer format. Each edit is verified.
     */
    edit(input, edits, opts) {
      return call(OP_EDIT, input, editsString(edits), optsString(opts));
    },
  };
}

async function readDefault() {
  const url = new URL("./bytepeel.wasm", import.meta.url);
  if (url.protocol === "file:") {
    const { readFile } = await import("node:fs/promises");
    return readFile(url);
  }
  const res = await fetch(url);
  if (!res.ok) throw new Error(`failed to fetch ${url}: ${res.status}`);
  return res.arrayBuffer();
}

/**
 * Load bytepeel. `source` is optional: the wasm bytes, a URL, a Response,
 * or a compiled WebAssembly.Module. By default bytepeel.wasm next to this
 * file is used.
 */
export async function load(source) {
  let module;
  if (source instanceof WebAssembly.Module) {
    module = source;
  } else {
    let bytes = source;
    if (source === undefined) bytes = await readDefault();
    else if (source instanceof URL || typeof source === "string") {
      bytes = await (await fetch(source)).arrayBuffer();
    } else if (typeof Response !== "undefined" && source instanceof Response) {
      bytes = await source.arrayBuffer();
    }
    module = await WebAssembly.compile(bytes);
  }
  const instance = await WebAssembly.instantiate(module, {});
  return wrap(instance);
}
