export interface Options {
  /** How to read the top-level input (default "auto"). */
  in?: "auto" | "hex" | "base64" | "raw";
  /** Force the interpretation of the first decoded byte layer. */
  as?: "protobuf" | "der" | "cbor" | "msgpack" | "text" | "bytes";
  /** Max nesting of layers and messages (default 16). */
  depth?: number;
  /** Max interpretations kept per protobuf LEN field (default 3). */
  alts?: number;
  /** Max protobuf fields, CBOR/MessagePack values and DER elements in total (default 1000000). */
  max_items?: number;
}

/**
 * A value for an edit. Strings are text (never parsed); numbers that are
 * integers are integers, other numbers are floats; Uint8Array is bytes.
 * Use raw("sint:-2"), raw("float:1") etc. for the CLI value syntax.
 */
export type Value = string | number | bigint | boolean | null | Uint8Array | { syntax: string };

export type Edit =
  | { set: string; value: Value }
  | { add: string; value: Value }
  | { del: string };

/** The decoded tree. See docs/DESIGN.md for the full schema. */
export type Node = { codec: string; range: [number, number]; confidence: number; [key: string]: unknown };

export interface Bytepeel {
  peel(input: string | Uint8Array | ArrayBuffer | ArrayBufferView, opts?: Options): Node;
  tree(input: string | Uint8Array | ArrayBuffer | ArrayBufferView, opts?: Options): string;
  get(input: string | Uint8Array | ArrayBuffer | ArrayBufferView, path: string, opts?: Options): Record<string, unknown>;
  getRaw(input: string | Uint8Array | ArrayBuffer | ArrayBufferView, path: string, opts?: Options): Uint8Array;
  edit(input: string | Uint8Array | ArrayBuffer | ArrayBufferView, edits: Edit[], opts?: Options): Uint8Array;
}

export class BytepeelError extends Error {
  /** Stable SCREAMING_SNAKE identifier, e.g. "PATH_NOT_FOUND". */
  readonly code: string;
  /** Byte offset into the buffer being decoded, or null. */
  readonly offset: number | null;
  readonly detail: string;
}

/** Pass a value in the CLI value syntax verbatim. */
export function raw(syntax: string): { syntax: string };

export function load(source?: BufferSource | URL | string | Response | WebAssembly.Module): Promise<Bytepeel>;
