import { BlobFormatError } from "./BlobTree.js";

/**
 * The LZ4 frame format (lz4_Frame_format.md): a header with flags and block
 * size, blocks that may reference up to 64 KiB of earlier output when the
 * frame links them, an end mark, and optional checksums (not verified).
 */

const MAGIC = 0x184d2204;
const BLOCK_SIZES: Readonly<Record<number, number>> = {
  4: 64 * 1024,
  5: 256 * 1024,
  6: 1024 * 1024,
  7: 4 * 1024 * 1024,
};

/** Decode one LZ4 block onto the end of `output`, which may hold earlier blocks it refers to. */
const decodeBlock = (
  input: Buffer,
  output: Buffer,
  start: number,
  limit: number,
): number => {
  let read = 0;
  let written = start;
  const run = (base: number): number => {
    let length = base;
    if (base === 15)
      for (;;) {
        if (read >= input.length)
          throw new BlobFormatError("LZ4 run length ends early.");
        const byte = input[read] ?? 0;
        read += 1;
        length += byte;
        if (byte !== 255) break;
      }
    return length;
  };
  while (read < input.length) {
    const token = input[read] ?? 0;
    read += 1;
    const literals = run(token >> 4);
    if (read + literals > input.length || written + literals > limit)
      throw new BlobFormatError("LZ4 literals run past the block.");
    input.copy(output, written, read, read + literals);
    read += literals;
    written += literals;
    if (read === input.length) break;
    if (read + 2 > input.length)
      throw new BlobFormatError("LZ4 match offset is truncated.");
    const offset = input.readUInt16LE(read);
    read += 2;
    if (offset === 0 || offset > written)
      throw new BlobFormatError("LZ4 match points before the data.");
    const length = run(token & 0x0f) + 4;
    if (written + length > limit)
      throw new BlobFormatError("LZ4 match runs past the block size.");
    for (let index = 0; index < length; index += 1)
      output[written + index] = output[written - offset + index] ?? 0;
    written += length;
  }
  return written;
};

export const isLz4Frame = (bytes: Buffer): boolean =>
  bytes.length >= 7 && bytes.readUInt32LE(0) === MAGIC;

/** Decode every concatenated LZ4 frame in `bytes`, refusing output past `maxOutput`. */
export const decodeLz4Frames = (bytes: Buffer, maxOutput: number): Buffer => {
  const frames: Buffer[] = [];
  let at = 0;
  let total = 0;
  while (at < bytes.length) {
    if (at + 7 > bytes.length || bytes.readUInt32LE(at) !== MAGIC)
      throw new BlobFormatError(`No LZ4 frame magic at ${String(at)}.`);
    const flags = bytes[at + 4] ?? 0;
    const blockDescriptor = bytes[at + 5] ?? 0;
    if (flags >> 6 !== 1)
      throw new BlobFormatError("Unsupported LZ4 frame version.");
    const independent = (flags & 0x20) !== 0;
    const blockChecksum = (flags & 0x10) !== 0;
    const contentSize = (flags & 0x08) !== 0;
    const contentChecksum = (flags & 0x04) !== 0;
    const dictionary = (flags & 0x01) !== 0;
    if (dictionary)
      throw new BlobFormatError(
        "LZ4 frames that need an external dictionary are not supported.",
      );
    const blockMax = BLOCK_SIZES[(blockDescriptor >> 4) & 7];
    if (blockMax === undefined)
      throw new BlobFormatError("Unknown LZ4 block size.");
    at += 6 + (contentSize ? 8 : 0) + 1;
    // Linked blocks may reach 64 KiB back, so keep a window before each block.
    const window = independent ? 0 : 64 * 1024;
    let output = Buffer.alloc(window + blockMax);
    let history = 0;
    const parts: Buffer[] = [];
    for (;;) {
      if (at + 4 > bytes.length)
        throw new BlobFormatError("LZ4 frame ends without an end mark.");
      const word = bytes.readUInt32LE(at);
      at += 4;
      if (word === 0) break;
      const size = word & 0x7fffffff;
      if (at + size > bytes.length)
        throw new BlobFormatError("An LZ4 block runs past the input.");
      const block = bytes.subarray(at, at + size);
      at += size + (blockChecksum ? 4 : 0);
      let produced: Buffer;
      if ((word & 0x80000000) !== 0) produced = Buffer.from(block);
      else {
        const end = decodeBlock(block, output, history, history + blockMax);
        produced = Buffer.from(output.subarray(history, end));
      }
      total += produced.length;
      if (total > maxOutput)
        throw new BlobFormatError(
          `LZ4 output passes ${String(maxOutput)} bytes.`,
        );
      parts.push(produced);
      if (!independent) {
        // Slide the last 64 KiB of output in front of the next block.
        const recent = Buffer.concat([
          output.subarray(0, history),
          produced,
        ]).subarray(-window);
        output = Buffer.alloc(window + blockMax);
        recent.copy(output, 0);
        history = recent.length;
      }
    }
    at += contentChecksum ? 4 : 0;
    frames.push(...parts);
  }
  return Buffer.concat(frames);
};
