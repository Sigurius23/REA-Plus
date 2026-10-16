/** Compressed data that does not decode to the size its header promised. */
export class UnityCompressionError extends Error {}

const fail = (message: string): never => {
  throw new UnityCompressionError(message);
};

/** A run length continued by 255-valued bytes, as LZ4 encodes long runs. */
const runLength = (
  input: Buffer,
  start: number,
  base: number,
): { length: number; next: number } => {
  let length = base;
  let at = start;
  if (base === 15)
    for (;;) {
      if (at >= input.length) fail("LZ4 run length ends early.");
      const byte = input[at] ?? 0;
      at += 1;
      length += byte;
      if (byte !== 255) break;
    }
  return { length, next: at };
};

/**
 * Decode one raw LZ4 block (no frame header), as Unity stores chunk-based
 * bundle blocks. The output must be exactly `size` bytes, or at most `size`
 * when `exact` is false (LZ4 legacy frames do not record block sizes).
 */
export const decodeLz4Block = (
  input: Buffer,
  size: number,
  exact = true,
): Buffer => {
  const output = Buffer.alloc(size);
  let read = 0;
  let written = 0;
  while (read < input.length) {
    const token = input[read] ?? 0;
    const literals = runLength(input, read + 1, token >> 4);
    read = literals.next;
    if (read + literals.length > input.length)
      fail("LZ4 literals run past the block.");
    if (written + literals.length > size)
      fail("LZ4 literals overflow the declared size.");
    input.copy(output, written, read, read + literals.length);
    read += literals.length;
    written += literals.length;
    if (read === input.length) break;
    if (read + 2 > input.length) fail("LZ4 match offset is truncated.");
    const offset = input.readUInt16LE(read);
    read += 2;
    if (offset === 0 || offset > written)
      fail("LZ4 match points before the block start.");
    const match = runLength(input, read, token & 0x0f);
    read = match.next;
    const length = match.length + 4;
    if (written + length > size) fail("LZ4 match overflows the declared size.");
    // Matches may overlap their own output, so copy byte by byte.
    for (let index = 0; index < length; index += 1)
      output[written + index] = output[written - offset + index] ?? 0;
    written += length;
  }
  if (!exact) return output.subarray(0, written);
  if (written !== size)
    fail(
      `LZ4 block decoded to ${String(written)} bytes, expected ${String(size)}.`,
    );
  return output;
};
