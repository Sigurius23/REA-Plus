import {
  brotliDecompressSync,
  gunzipSync,
  inflateRawSync,
  inflateSync,
  zstdDecompressSync,
} from "node:zlib";

import { BlobFormatError } from "./BlobTree.js";
import { decodeLz4Frames, isLz4Frame } from "./Lz4Frame.js";

/**
 * Encoding and compression layers around a payload. Layers with a
 * signature (gzip, zlib, zstd, LZ4 frames) and text encodings (base64, hex)
 * are peeled automatically; raw deflate and Brotli have no signature and are
 * only applied when named.
 */

export const LAYER_KINDS = [
  "base64",
  "hex",
  "gzip",
  "zlib",
  "deflate",
  "zstd",
  "lz4",
  "brotli",
] as const;
export type LayerKind = (typeof LAYER_KINDS)[number];

export interface Layer {
  readonly kind: LayerKind;
  readonly input_bytes: number;
  readonly output_bytes: number;
}

const MAX_LAYERS = 8;

/** Printable ASCII and common whitespace only. */
export const isText = (bytes: Buffer): boolean => {
  if (bytes.length === 0) return false;
  for (const byte of bytes)
    if (
      (byte < 0x20 && byte !== 9 && byte !== 10 && byte !== 13) ||
      byte > 0x7e
    )
      return false;
  return true;
};

const isJson = (text: string): boolean => {
  const trimmed = text.trim();
  if (!/^[[{"]/u.test(trimmed)) return false;
  try {
    JSON.parse(trimmed);
    return true;
  } catch {
    return false;
  }
};

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/u;
const BASE64_URL = /^[A-Za-z0-9_-]+={0,2}$/u;
const HEX = /^(?:0x)?(?:[0-9a-fA-F]{2})+$/u;

/** Which text encoding, if any, the bytes are in. */
const textLayer = (bytes: Buffer): LayerKind | null => {
  const text = bytes.toString("latin1");
  if (isJson(text)) return null;
  const compact = text.replace(/\s+/gu, "");
  if (compact.length < 8) return null;
  if (HEX.test(compact)) return "hex";
  if (
    (BASE64.test(compact) && compact.length % 4 === 0) ||
    (BASE64_URL.test(compact) && compact.length % 4 !== 1)
  )
    return "base64";
  return null;
};

/** A layer the bytes visibly carry, or null. */
export const detectLayer = (bytes: Buffer): LayerKind | null => {
  if (
    bytes.length >= 3 &&
    bytes[0] === 0x1f &&
    bytes[1] === 0x8b &&
    bytes[2] === 0x08
  )
    return "gzip";
  if (bytes.length >= 4 && bytes.readUInt32LE(0) === 0xfd2fb528) return "zstd";
  if (isLz4Frame(bytes)) return "lz4";
  // zlib: deflate with a window of at most 32 KiB and a header checksum that divides by 31.
  if (
    bytes.length >= 2 &&
    ((bytes[0] ?? 0) & 0x0f) === 8 &&
    (bytes[0] ?? 0) >> 4 <= 7 &&
    ((bytes[0] ?? 0) * 256 + (bytes[1] ?? 0)) % 31 === 0
  )
    return "zlib";
  return isText(bytes) ? textLayer(bytes) : null;
};

/** Apply one named layer. */
export const applyLayer = (
  kind: LayerKind,
  bytes: Buffer,
  maxOutput: number,
): Buffer => {
  const options = { maxOutputLength: maxOutput };
  try {
    switch (kind) {
      case "gzip":
        return gunzipSync(bytes, options);
      case "zlib":
        return inflateSync(bytes, options);
      case "deflate":
        return inflateRawSync(bytes, options);
      case "zstd":
        return zstdDecompressSync(bytes, options);
      case "brotli":
        return brotliDecompressSync(bytes, options);
      case "lz4":
        return decodeLz4Frames(bytes, maxOutput);
      case "hex": {
        const compact = bytes
          .toString("latin1")
          .replace(/\s+/gu, "")
          .replace(/^0x/u, "");
        if (!/^(?:[0-9a-fA-F]{2})*$/u.test(compact))
          throw new BlobFormatError("Not hex text.");
        return Buffer.from(compact, "hex");
      }
      default: {
        const compact = bytes.toString("latin1").replace(/\s+/gu, "");
        if (!BASE64.test(compact) && !BASE64_URL.test(compact))
          throw new BlobFormatError("Not base64 text.");
        return Buffer.from(compact, "base64");
      }
    }
  } catch (cause) {
    if (cause instanceof BlobFormatError) throw cause;
    throw new BlobFormatError(
      `The ${kind} layer does not decode: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
};

/** Peel the named layers in order, or every recognizable one when none are named. */
export const peelLayers = (
  bytes: Buffer,
  named: readonly LayerKind[] | undefined,
  maxOutput: number,
): { readonly bytes: Buffer; readonly layers: Layer[] } => {
  const layers: Layer[] = [];
  let current = bytes;
  const step = (kind: LayerKind) => {
    const next = applyLayer(kind, current, maxOutput);
    layers.push({
      kind,
      input_bytes: current.length,
      output_bytes: next.length,
    });
    current = next;
  };
  if (named !== undefined) {
    for (const kind of named) step(kind);
    return { bytes: current, layers };
  }
  for (let index = 0; index < MAX_LAYERS; index += 1) {
    const kind = detectLayer(current);
    if (kind === null) break;
    try {
      step(kind);
    } catch (cause) {
      // A text guess that does not decode leaves the bytes as they are; a signature that fails does not.
      if (kind === "base64" || kind === "hex" || kind === "zlib") break;
      throw cause;
    }
  }
  return { bytes: current, layers };
};
