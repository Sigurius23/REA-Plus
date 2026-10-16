import { UnityCompressionError } from "./Lz4Block.js";

const fail = (message: string): never => {
  throw new UnityCompressionError(message);
};

const PROBABILITY_BITS = 11;
const PROBABILITY_INITIAL = 1 << (PROBABILITY_BITS - 1);
const MOVE_BITS = 5;
const TOP = 1 << 24;
const STATES = 12;
const POS_STATES_MAX = 1 << 4;
const END_POS_MODEL_INDEX = 14;
const FULL_DISTANCES = 1 << (END_POS_MODEL_INDEX >> 1);
const ALIGN_BITS = 4;
const MATCH_MIN_LENGTH = 2;
const END_MARKER = 0xffff_ffff;

/** Range decoder over one LZMA stream (LZMA SDK specification). */
class RangeDecoder {
  private range = 0xffff_ffff;
  private code = 0;
  private at: number;

  constructor(
    private readonly input: Buffer,
    start: number,
  ) {
    if (input[start] !== 0) fail("LZMA stream does not start with zero.");
    this.at = start + 1;
    for (let index = 0; index < 4; index += 1)
      this.code = this.code * 256 + this.next();
    if (this.code === this.range) fail("LZMA range coder is corrupted.");
  }

  private next(): number {
    if (this.at >= this.input.length) fail("LZMA stream ends early.");
    const byte = this.input[this.at] ?? 0;
    this.at += 1;
    return byte;
  }

  private normalize(): void {
    if (this.range < TOP) {
      this.range *= 256;
      this.code = this.code * 256 + this.next();
    }
  }

  bit(probabilities: Uint16Array, index: number): number {
    const probability = probabilities[index] ?? PROBABILITY_INITIAL;
    const bound = (this.range >>> PROBABILITY_BITS) * probability;
    let bit: number;
    if (this.code < bound) {
      this.range = bound;
      probabilities[index] =
        probability + (((1 << PROBABILITY_BITS) - probability) >>> MOVE_BITS);
      bit = 0;
    } else {
      this.range -= bound;
      this.code -= bound;
      probabilities[index] = probability - (probability >>> MOVE_BITS);
      bit = 1;
    }
    this.normalize();
    return bit;
  }

  direct(count: number): number {
    let result = 0;
    for (let index = 0; index < count; index += 1) {
      this.range = this.range >>> 1;
      let bit = 0;
      if (this.code >= this.range) {
        this.code -= this.range;
        bit = 1;
      }
      if (this.code === this.range) fail("LZMA range coder is corrupted.");
      this.normalize();
      result = result * 2 + bit;
    }
    return result;
  }

  tree(probabilities: Uint16Array, offset: number, bits: number): number {
    let symbol = 1;
    for (let index = 0; index < bits; index += 1)
      symbol = symbol * 2 + this.bit(probabilities, offset + symbol);
    return symbol - (1 << bits);
  }

  reverseTree(probabilities: Uint16Array, offset: number, bits: number) {
    let node = 1;
    let symbol = 0;
    for (let index = 0; index < bits; index += 1) {
      const bit = this.bit(probabilities, offset + node);
      node = node * 2 + bit;
      symbol |= bit << index;
    }
    return symbol;
  }
}

const probabilities = (size: number) =>
  new Uint16Array(size).fill(PROBABILITY_INITIAL);

/** Match lengths: 2-9 low, 10-17 mid, 18-273 high, per position state. */
class LengthDecoder {
  private readonly choice = probabilities(2);
  private readonly low = probabilities(POS_STATES_MAX << 3);
  private readonly mid = probabilities(POS_STATES_MAX << 3);
  private readonly high = probabilities(256);

  decode(range: RangeDecoder, posState: number): number {
    if (range.bit(this.choice, 0) === 0)
      return range.tree(this.low, posState << 3, 3);
    if (range.bit(this.choice, 1) === 0)
      return 8 + range.tree(this.mid, posState << 3, 3);
    return 16 + range.tree(this.high, 0, 8);
  }
}

interface LzmaProperties {
  readonly lc: number;
  readonly lp: number;
  readonly pb: number;
}

const properties = (byte: number): LzmaProperties => {
  if (byte >= 9 * 5 * 5) fail("LZMA properties byte is out of range.");
  return {
    lc: byte % 9,
    lp: Math.floor(byte / 9) % 5,
    pb: Math.floor(byte / 45),
  };
};

/** Decoder state for one stream decoded completely into `output`. */
class LzmaStream {
  private readonly literals: Uint16Array;
  private readonly isMatch = probabilities(STATES << 4);
  private readonly isRep = probabilities(STATES);
  private readonly isRepG0 = probabilities(STATES);
  private readonly isRepG1 = probabilities(STATES);
  private readonly isRepG2 = probabilities(STATES);
  private readonly isRep0Long = probabilities(STATES << 4);
  private readonly posSlot = probabilities(4 << 6);
  private readonly posDecoders = probabilities(
    1 + FULL_DISTANCES - END_POS_MODEL_INDEX,
  );
  private readonly align = probabilities(1 << ALIGN_BITS);
  private readonly lengths = new LengthDecoder();
  private readonly repLengths = new LengthDecoder();
  private readonly reps = [0, 0, 0, 0];
  private state = 0;
  private written = 0;

  constructor(
    private readonly range: RangeDecoder,
    private readonly props: LzmaProperties,
    private readonly output: Buffer,
  ) {
    this.literals = probabilities(0x300 << (props.lc + props.lp));
  }

  private literal(): void {
    const { lc, lp } = this.props;
    const previous =
      this.written > 0 ? (this.output[this.written - 1] ?? 0) : 0;
    const base =
      0x300 *
      (((this.written & ((1 << lp) - 1)) << lc) + (previous >>> (8 - lc)));
    let symbol = 1;
    if (this.state >= 7) {
      let match = this.output[this.written - (this.reps[0] ?? 0) - 1] ?? 0;
      while (symbol < 0x100) {
        const matchBit = (match >>> 7) & 1;
        match <<= 1;
        const bit = this.range.bit(
          this.literals,
          base + ((1 + matchBit) << 8) + symbol,
        );
        symbol = (symbol << 1) | bit;
        if (matchBit !== bit) break;
      }
    }
    while (symbol < 0x100)
      symbol = (symbol << 1) | this.range.bit(this.literals, base + symbol);
    this.output[this.written] = symbol - 0x100;
    this.written += 1;
    this.state =
      this.state < 4 ? 0 : this.state < 10 ? this.state - 3 : this.state - 6;
  }

  private distance(length: number): number {
    const slot = this.range.tree(this.posSlot, Math.min(length, 3) << 6, 6);
    if (slot < 4) return slot;
    const directBits = (slot >>> 1) - 1;
    let distance = (2 | (slot & 1)) * 2 ** directBits;
    if (slot < END_POS_MODEL_INDEX)
      return (
        distance +
        this.range.reverseTree(this.posDecoders, distance - slot, directBits)
      );
    distance += this.range.direct(directBits - ALIGN_BITS) * 2 ** ALIGN_BITS;
    return distance + this.range.reverseTree(this.align, 0, ALIGN_BITS);
  }

  private copy(length: number): void {
    const distance = (this.reps[0] ?? 0) + 1;
    if (distance > this.written) fail("LZMA match points before the output.");
    if (this.written + length > this.output.length)
      fail("LZMA match overflows the declared size.");
    for (let index = 0; index < length; index += 1)
      this.output[this.written + index] =
        this.output[this.written - distance + index] ?? 0;
    this.written += length;
  }

  /** Rep matches reuse one of the last four distances. */
  private repeat(posState: number): number | null {
    const [rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0] = this.reps;
    if (this.written === 0) fail("LZMA repeat match before any output.");
    if (this.range.bit(this.isRepG0, this.state) === 0) {
      if (this.range.bit(this.isRep0Long, (this.state << 4) + posState) === 0) {
        this.state = this.state < 7 ? 9 : 11;
        this.copy(1);
        return null;
      }
    } else {
      let distance: number;
      if (this.range.bit(this.isRepG1, this.state) === 0) distance = rep1;
      else if (this.range.bit(this.isRepG2, this.state) === 0) {
        distance = rep2;
        this.reps[2] = rep1;
      } else {
        distance = rep3;
        this.reps[3] = rep2;
        this.reps[2] = rep1;
      }
      this.reps[1] = rep0;
      this.reps[0] = distance;
    }
    const length = this.repLengths.decode(this.range, posState);
    this.state = this.state < 7 ? 8 : 11;
    return length;
  }

  /** Decode until the output is full or the stream's end marker. */
  run(): number {
    const posMask = (1 << this.props.pb) - 1;
    while (this.written < this.output.length) {
      const posState = this.written & posMask;
      if (this.range.bit(this.isMatch, (this.state << 4) + posState) === 0) {
        this.literal();
        continue;
      }
      let length: number | null;
      if (this.range.bit(this.isRep, this.state) === 1)
        length = this.repeat(posState);
      else {
        this.reps.unshift(0);
        this.reps.length = 4;
        length = this.lengths.decode(this.range, posState);
        this.state = this.state < 7 ? 7 : 10;
        this.reps[0] = this.distance(length);
        if (this.reps[0] === END_MARKER) return this.written;
      }
      if (length !== null) this.copy(length + MATCH_MIN_LENGTH);
    }
    return this.written;
  }
}

/**
 * Decode Unity's LZMA blocks: five property bytes (lc/lp/pb and dictionary
 * size) followed by the raw stream, with the decoded size known in advance.
 */
export const decodeLzma = (input: Buffer, size: number): Buffer => {
  if (input.length < 5 + 5) fail("LZMA block is shorter than its header.");
  const output = Buffer.alloc(size);
  const props = properties(input[0] ?? 0);
  const written = new LzmaStream(
    new RangeDecoder(input, 5),
    props,
    output,
  ).run();
  if (written !== size)
    fail(
      `LZMA block decoded to ${String(written)} bytes, expected ${String(size)}.`,
    );
  return output;
};
