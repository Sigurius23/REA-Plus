/**
 * RPG Maker MV/MZ asset encryption, as rpg_core.js Decrypter and rmmz_core.js
 * Utils.decryptArrayBuffer implement it: a fixed 16-byte "RPGMV" header, then
 * the original file with only its first 16 bytes XORed with the System.json key.
 */

export const RPGMV_HEADER = Buffer.from("5250474d560000000003010000000000", "hex");

/** The first 16 bytes of every PNG: signature, IHDR length and type. */
const PNG_HEAD = Buffer.from("89504e470d0a1a0a0000000d49484452", "hex");

const ENCRYPTED_EXTENSIONS: Readonly<Record<string, string>> = {
  ".rpgmvp": ".png",
  ".rpgmvo": ".ogg",
  ".rpgmvm": ".m4a",
  ".png_": ".png",
  ".ogg_": ".ogg",
  ".m4a_": ".m4a",
};

export type AssetSignature = "png" | "ogg" | "m4a" | "webm" | "mp4" | "unknown";

/** The decrypted name the engine requests, or null for a plain file. */
export const decryptedName = (path: string): string | null => {
  const lower = path.toLowerCase();
  for (const [suffix, plain] of Object.entries(ENCRYPTED_EXTENSIONS))
    if (lower.endsWith(suffix)) return path.slice(0, -suffix.length) + plain;
  return null;
};

/** System.json encryptionKey as 16 bytes, or null when it is not 32 hex digits. */
export const keyBytes = (key: string | null): Buffer | null =>
  key !== null && /^[0-9a-f]{32}$/iu.test(key) ? Buffer.from(key, "hex") : null;

export const hasEncryptionHeader = (bytes: Buffer): boolean =>
  bytes.length >= 16 && bytes.subarray(0, 16).equals(RPGMV_HEADER);

/** Strip the header and restore the first 16 bytes, as the engine does. */
export const decryptAsset = (bytes: Buffer, key: Buffer): Buffer => {
  const body = Buffer.from(bytes.subarray(16));
  for (let index = 0; index < 16 && index < body.length; index += 1)
    body[index] = (body[index] ?? 0) ^ (key[index] ?? 0);
  return body;
};

export const signatureOf = (bytes: Buffer): AssetSignature => {
  if (bytes.subarray(0, 8).equals(PNG_HEAD.subarray(0, 8))) return "png";
  if (bytes.subarray(0, 4).toString("latin1") === "OggS") return "ogg";
  if (bytes.subarray(0, 4).equals(Buffer.from("1a45dfa3", "hex")))
    return "webm";
  if (bytes.subarray(4, 8).toString("latin1") === "ftyp") {
    const brand = bytes.subarray(8, 12).toString("latin1");
    return brand.startsWith("M4A") ? "m4a" : "mp4";
  }
  return "unknown";
};

/** An encrypted PNG gives the whole key: its first 16 bytes never vary. */
export const recoverKeyFromPng = (bytes: Buffer): string | null => {
  if (!hasEncryptionHeader(bytes) || bytes.length < 32) return null;
  const key = Buffer.alloc(16);
  for (let index = 0; index < 16; index += 1)
    key[index] = (bytes[16 + index] ?? 0) ^ (PNG_HEAD[index] ?? 0);
  return key.toString("hex");
};

/** Width and height from a PNG's IHDR chunk. */
export const pngSize = (
  bytes: Buffer,
): { width: number; height: number } | null =>
  signatureOf(bytes) === "png" && bytes.length >= 24
    ? { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) }
    : null;
