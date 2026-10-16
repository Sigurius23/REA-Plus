/**
 * Minimal encoders for building compressed Unity fixtures in source: a greedy
 * LZ4 block encoder and a literal-only LZMA encoder (range coder plus literal
 * coder, no matches). Both produce streams standard decoders accept.
 */

const writeLength = (out: number[], length: number): void => {
  let rest = length;
  while (rest >= 255) {
    out.push(255);
    rest -= 255;
  }
  out.push(rest);
};

/** Raw LZ4 block (no frame), with matches found through a 4-byte hash. */
export const encodeLz4Block = (input: Buffer): Buffer => {
  const out: number[] = [];
  const seen = new Map<number, number>();
  let anchor = 0;
  let at = 0;
  const emit = (
    literalEnd: number,
    match?: { offset: number; length: number },
  ) => {
    const literals = literalEnd - anchor;
    const matchCode = match === undefined ? 0 : match.length - 4;
    out.push((Math.min(literals, 15) << 4) | Math.min(matchCode, 15));
    if (literals >= 15) writeLength(out, literals - 15);
    for (let index = anchor; index < literalEnd; index += 1)
      out.push(input[index] ?? 0);
    if (match === undefined) return;
    out.push(match.offset & 0xff, match.offset >> 8);
    if (matchCode >= 15) writeLength(out, matchCode - 15);
  };
  // The format keeps the last five bytes literal and starts no match in the last twelve.
  while (at + 12 <= input.length) {
    const key = input.readUInt32LE(at);
    const previous = seen.get(key);
    seen.set(key, at);
    if (previous === undefined || at - previous > 0xffff) {
      at += 1;
      continue;
    }
    let length = 4;
    while (
      at + length < input.length - 5 &&
      input[previous + length] === input[at + length]
    )
      length += 1;
    emit(at, { offset: at - previous, length });
    at += length;
    anchor = at;
  }
  emit(input.length);
  return Buffer.from(out);
};

/** LZMA range encoder (LZMA SDK), enough to code literals. */
class RangeEncoder {
  private low = 0;
  private range = 0xffff_ffff;
  private cache = 0;
  private cacheSize = 1;
  readonly out: number[] = [];

  private shiftLow(): void {
    if (this.low < 0xff00_0000 || this.low >= 0x1_0000_0000) {
      const carry = this.low >= 0x1_0000_0000 ? 1 : 0;
      let temp = this.cache;
      do {
        this.out.push((temp + carry) & 0xff);
        temp = 0xff;
        this.cacheSize -= 1;
      } while (this.cacheSize !== 0);
      this.cache = Math.floor(this.low / 0x100_0000) & 0xff;
    }
    this.cacheSize += 1;
    this.low = (this.low % 0x100_0000) * 256;
  }

  bit(probabilities: Uint16Array, index: number, bit: number): void {
    const probability = probabilities[index] ?? 1024;
    const bound = (this.range >>> 11) * probability;
    if (bit === 0) {
      this.range = bound;
      probabilities[index] = probability + ((2048 - probability) >>> 5);
    } else {
      this.low += bound;
      this.range -= bound;
      probabilities[index] = probability - (probability >>> 5);
    }
    while (this.range < 0x100_0000) {
      this.range *= 256;
      this.shiftLow();
    }
  }

  flush(): void {
    for (let index = 0; index < 5; index += 1) this.shiftLow();
  }
}

/**
 * Unity-style LZMA block (5 property bytes, then the stream, no end marker)
 * coding every byte as a literal with lc=3, lp=0, pb=2.
 */
export const encodeLzmaLiterals = (input: Buffer): Buffer => {
  const encoder = new RangeEncoder();
  const isMatch = new Uint16Array(12 << 4).fill(1024);
  const literals = new Uint16Array(0x300 << 3).fill(1024);
  input.forEach((byte, position) => {
    encoder.bit(isMatch, position & 3, 0);
    const previous = position === 0 ? 0 : (input[position - 1] ?? 0);
    const base = 0x300 * (previous >> 5);
    let context = 1;
    for (let shift = 7; shift >= 0; shift -= 1) {
      const bit = (byte >> shift) & 1;
      encoder.bit(literals, base + context, bit);
      context = (context << 1) | bit;
    }
  });
  encoder.flush();
  const header = Buffer.alloc(5);
  header[0] = (2 * 5 + 0) * 9 + 3;
  header.writeUInt32LE(1 << 16, 1);
  return Buffer.concat([header, Buffer.from(encoder.out)]);
};
