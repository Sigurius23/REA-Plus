import { GodotFormatError } from "./GodotBytes.js";

/**
 * FastLZ decompression (levels 1 and 2), Godot's compression mode 0. The
 * level is in the top three bits of the first byte.
 */

const copyMatch = (
  out: Uint8Array,
  at: number,
  distance: number,
  length: number,
): void => {
  if (distance > at)
    throw new GodotFormatError("A FastLZ match reaches before the output.");
  if (at + length > out.length)
    throw new GodotFormatError("FastLZ output overflows the block.");
  for (let index = 0; index < length; index += 1)
    out[at + index] = out[at - distance + index] ?? 0;
};

/** One match: its length and how far back it reaches. */
const match = (
  input: Uint8Array,
  start: number,
  control: number,
  level: number,
): { length: number; distance: number; next: number } => {
  let at = start;
  const byte = () => {
    if (at >= input.length)
      throw new GodotFormatError("A FastLZ match runs past the input.");
    return input[at++] ?? 0;
  };
  let length = (control >> 5) - 1;
  let offset = (control & 31) << 8;
  if (length === 6) {
    if (level === 1) length += byte();
    else {
      let code: number;
      do {
        code = byte();
        length += code;
      } while (code === 255);
    }
  }
  const low = byte();
  offset += low;
  if (level === 2 && low === 255 && offset === (31 << 8) + 255)
    // A far match: a 16-bit distance past the 8191 bytes the short form reaches.
    offset = (byte() << 8) + byte() + 8190;
  return { length: length + 3, distance: offset + 1, next: at };
};

export const fastLzDecompress = (
  input: Uint8Array,
  outputLength: number,
): Buffer => {
  const out = Buffer.alloc(outputLength);
  if (input.length === 0) return out;
  const level = ((input[0] ?? 0) >> 5) + 1;
  if (level !== 1 && level !== 2)
    throw new GodotFormatError(`FastLZ level ${String(level)} is unknown.`);
  let at = 1;
  let written = 0;
  let control = (input[0] ?? 0) & 31;
  for (;;) {
    if (control >= 32) {
      const step = match(input, at, control, level);
      copyMatch(out, written, step.distance, step.length);
      written += step.length;
      at = step.next;
    } else {
      const length = control + 1;
      if (at + length > input.length || written + length > outputLength)
        throw new GodotFormatError("A FastLZ literal run overflows.");
      out.set(input.subarray(at, at + length), written);
      written += length;
      at += length;
    }
    if (at >= input.length) break;
    control = input[at++] ?? 0;
  }
  if (written !== outputLength)
    throw new GodotFormatError(
      `FastLZ produced ${String(written)} of ${String(outputLength)} bytes.`,
    );
  return out;
};
