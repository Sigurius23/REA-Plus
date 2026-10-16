/**
 * GameMaker data files (data.win, game.unx, game.droid, game.ios): an IFF
 * FORM of named chunks. Most chunks hold a pointer list (count, then one
 * absolute offset per entry); strings are referenced by the offset of their
 * text, just past a 32-bit length. Offsets are relative to the FORM, so a
 * FORM appended to a runner executable reads the same way.
 */

export class GameMakerFormatError extends Error {
  override readonly name = "GameMakerFormatError";
}

export interface Chunk {
  readonly name: string;
  /** File offset of the chunk header. */
  readonly offset: number;
  readonly size: number;
  /** FORM-relative offset of the chunk's data. */
  readonly data: number;
}

const MAX_STRING_BYTES = 16 * 1024 * 1024;

const isChunkName = (bytes: Buffer, at: number): boolean => {
  for (let index = 0; index < 4; index += 1) {
    const code = bytes[at + index] ?? 0;
    if (code < 0x30 || code > 0x5a) return false;
  }
  return true;
};

/** The FORM start: 0 for a data file, else a FORM whose first chunk is GEN8. */
export const locateForm = (bytes: Buffer): number => {
  if (bytes.subarray(0, 4).toString("latin1") === "FORM") return 0;
  let at = bytes.indexOf("GEN8", 8, "latin1");
  while (at >= 8) {
    const start = at - 8;
    if (
      bytes.subarray(start, start + 4).toString("latin1") === "FORM" &&
      start + 8 + bytes.readUInt32LE(start + 4) <= bytes.length
    )
      return start;
    at = bytes.indexOf("GEN8", at + 4, "latin1");
  }
  throw new GameMakerFormatError(
    "No FORM chunk starting with GEN8: not a GameMaker data file.",
  );
};

/** Bounds-checked, FORM-relative reads over the data file's bytes. */
export class Form {
  readonly chunks: readonly Chunk[];
  readonly size: number;
  readonly #strings = new Map<number, string | null>();
  /** Text offsets of STRG entries; every string reference must name one. */
  readonly #texts: ReadonlySet<number>;

  constructor(
    readonly bytes: Buffer,
    readonly start: number,
  ) {
    if (bytes.length < start + 8)
      throw new GameMakerFormatError("Truncated FORM header.");
    this.size = bytes.readUInt32LE(start + 4);
    if (start + 8 + this.size > bytes.length)
      throw new GameMakerFormatError(
        `FORM declares ${String(this.size)} bytes but the file ends first.`,
      );
    const chunks: Chunk[] = [];
    let at = 8;
    while (at + 8 <= 8 + this.size) {
      if (!isChunkName(bytes, start + at))
        throw new GameMakerFormatError(
          `Invalid chunk name at ${String(start + at)}.`,
        );
      const name = bytes
        .subarray(start + at, start + at + 4)
        .toString("latin1");
      const size = bytes.readUInt32LE(start + at + 4);
      if (at + 8 + size > 8 + this.size)
        throw new GameMakerFormatError(`Chunk ${name} runs past the FORM.`);
      chunks.push({ name, offset: start + at, size, data: at + 8 });
      at += 8 + size;
    }
    if (
      chunks[0]?.name !== "GEN8" &&
      !chunks.some(({ name }) => name === "AUDO")
    )
      throw new GameMakerFormatError(
        "The first chunk is not GEN8, and there is no AUDO chunk of an audio group file.",
      );
    this.chunks = chunks;
    const strings = this.chunk("STRG");
    this.#texts = new Set(
      strings === undefined
        ? []
        : this.pointerList(strings).map((at) => at + 4),
    );
  }

  /** Whether this is a data file (GEN8 first) rather than an audiogroupN.dat. */
  get hasGeneral(): boolean {
    return this.chunks[0]?.name === "GEN8";
  }

  chunk(name: string): Chunk | undefined {
    return this.chunks.find((chunk) => chunk.name === name);
  }

  private check(at: number, length: number): number {
    if (at < 0 || at + length > this.size + 8)
      throw new GameMakerFormatError(
        `Read of ${String(length)} bytes at ${String(at)} is outside the FORM.`,
      );
    return this.start + at;
  }

  u8(at: number): number {
    return this.bytes.readUInt8(this.check(at, 1));
  }

  u16(at: number): number {
    return this.bytes.readUInt16LE(this.check(at, 2));
  }

  u32(at: number): number {
    return this.bytes.readUInt32LE(this.check(at, 4));
  }

  i32(at: number): number {
    return this.bytes.readInt32LE(this.check(at, 4));
  }

  f32(at: number): number {
    return this.bytes.readFloatLE(this.check(at, 4));
  }

  u64(at: number): bigint {
    return this.bytes.readBigUInt64LE(this.check(at, 8));
  }

  slice(at: number, length: number): Buffer {
    const from = this.check(at, length);
    return this.bytes.subarray(from, from + length);
  }

  /** Entry offsets of a pointer list at a chunk's data (after `skip` header bytes). */
  pointerList(chunk: Chunk, skip = 0): number[] {
    if (chunk.size < skip + 4) return [];
    const count = this.u32(chunk.data + skip);
    if (count > (chunk.size - skip - 4) / 4)
      throw new GameMakerFormatError(
        `${chunk.name} lists ${String(count)} entries, more than fit in the chunk.`,
      );
    const pointers: number[] = [];
    for (let index = 0; index < count; index += 1) {
      const pointer = this.u32(chunk.data + skip + 4 + index * 4);
      if (
        pointer !== 0 &&
        (pointer < chunk.data || pointer >= chunk.data + chunk.size)
      )
        throw new GameMakerFormatError(
          `${chunk.name} entry ${String(index)} points outside the chunk.`,
        );
      pointers.push(pointer);
    }
    return pointers;
  }

  /** A string referenced by the offset of its text; null for a zero reference. */
  string(pointer: number): string | null {
    if (pointer === 0) return null;
    const cached = this.#strings.get(pointer);
    if (cached !== undefined) return cached;
    if (!this.#texts.has(pointer))
      throw new GameMakerFormatError(
        `Reference ${String(pointer)} does not point at a STRG string.`,
      );
    const length = this.u32(pointer - 4);
    if (length > MAX_STRING_BYTES)
      throw new GameMakerFormatError(
        `String at ${String(pointer)} is too long.`,
      );
    const text = this.slice(pointer, length).toString("utf8");
    this.#strings.set(pointer, text);
    return text;
  }
}
