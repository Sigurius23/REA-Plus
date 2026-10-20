/** Lua bytecode that cannot be decoded; reported as an input error. */
export class LuaFormatError extends Error {
  override readonly name = "LuaFormatError";
}

/** A function or chunk offset the file does not contain; reported against that input. */
export class LuaSelectionError extends Error {
  override readonly name = "LuaSelectionError";

  constructor(
    message: string,
    readonly field: "function" | "chunk_offset",
  ) {
    super(message);
  }
}

/** Sizes a PUC Lua header declares for the types it serializes. */
export interface LuaSizes {
  readonly littleEndian: boolean;
  readonly int: number;
  readonly sizeT: number;
  readonly instruction: number;
  /** Bytes of lua_Integer (5.3+); 0 before. */
  readonly integer: number;
  readonly number: number;
  /** lua_Number is an integer type (5.1/5.2 builds with LUA_NUMBER integral). */
  readonly integralNumber: boolean;
}

/** A bounded cursor with the integer readers the Lua dump formats use. */
export class LuaReader {
  constructor(
    readonly bytes: Buffer,
    public at: number,
    readonly end: number = bytes.length,
    public littleEndian = true,
  ) {}

  get done(): boolean {
    return this.at >= this.end;
  }

  need(length: number): void {
    if (length < 0 || this.at + length > this.end)
      throw new LuaFormatError(
        `Unexpected end of bytecode at ${String(this.at)}.`,
      );
  }

  u8(): number {
    this.need(1);
    const value = this.bytes[this.at] ?? 0;
    this.at += 1;
    return value;
  }

  slice(length: number): Buffer {
    this.need(length);
    const value = this.bytes.subarray(this.at, this.at + length);
    this.at += length;
    return value;
  }

  /** An unsigned integer of 1, 2, 4 or 8 bytes in the chunk's byte order. */
  unsigned(size: number): number {
    this.need(size);
    const at = this.at;
    this.at += size;
    switch (size) {
      case 1:
        return this.bytes[at] ?? 0;
      case 2:
        return this.littleEndian
          ? this.bytes.readUInt16LE(at)
          : this.bytes.readUInt16BE(at);
      case 4:
        return this.littleEndian
          ? this.bytes.readUInt32LE(at)
          : this.bytes.readUInt32BE(at);
      case 8: {
        const value = this.littleEndian
          ? this.bytes.readBigUInt64LE(at)
          : this.bytes.readBigUInt64BE(at);
        if (value > BigInt(Number.MAX_SAFE_INTEGER))
          throw new LuaFormatError(
            `Size ${value.toString()} at ${String(at)} is too large.`,
          );
        return Number(value);
      }
      default:
        throw new LuaFormatError(`Unsupported integer size ${String(size)}.`);
    }
  }

  /** A signed integer of 4 or 8 bytes, kept exact as a bigint. */
  signed(size: number): bigint {
    this.need(size);
    const at = this.at;
    this.at += size;
    if (size === 4)
      return BigInt(
        this.littleEndian
          ? this.bytes.readInt32LE(at)
          : this.bytes.readInt32BE(at),
      );
    if (size === 8)
      return this.littleEndian
        ? this.bytes.readBigInt64LE(at)
        : this.bytes.readBigInt64BE(at);
    throw new LuaFormatError(`Unsupported integer size ${String(size)}.`);
  }

  /** A float of 4 or 8 bytes. */
  float(size: number): number {
    this.need(size);
    const at = this.at;
    this.at += size;
    if (size === 8)
      return this.littleEndian
        ? this.bytes.readDoubleLE(at)
        : this.bytes.readDoubleBE(at);
    if (size === 4)
      return this.littleEndian
        ? this.bytes.readFloatLE(at)
        : this.bytes.readFloatBE(at);
    throw new LuaFormatError(`Unsupported float size ${String(size)}.`);
  }

  /** Lua 5.4's size encoding: 7-bit groups, most significant first, the last with bit 7 set. */
  varint(): number {
    let value = 0;
    for (let index = 0; index < 10; index += 1) {
      const byte = this.u8();
      value = value * 128 + (byte & 0x7f);
      if (value > Number.MAX_SAFE_INTEGER)
        throw new LuaFormatError(`Integer overflow at ${String(this.at)}.`);
      if ((byte & 0x80) !== 0) return value;
    }
    throw new LuaFormatError(`Integer too long at ${String(this.at)}.`);
  }

  /** LuaJIT's ULEB128, up to 32 bits. */
  uleb128(): number {
    let value = 0;
    let shift = 0;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.u8();
      value += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) return value;
      shift += 7;
    }
    throw new LuaFormatError(`ULEB128 too long at ${String(this.at)}.`);
  }

  /** A count that must fit in what is left, so a corrupt length fails fast. */
  count(value: number, unit = 1): number {
    if (value * unit > this.end - this.at)
      throw new LuaFormatError(
        `A count of ${String(value)} at ${String(this.at)} runs past the chunk.`,
      );
    return value;
  }
}

/** The signature every PUC Lua and LuaJIT chunk starts with: ESC, then "Lua" or "LJ". */
export const isChunkStart = (bytes: Buffer, at: number): boolean =>
  bytes[at] === 0x1b &&
  ((bytes[at + 1] === 0x4c &&
    bytes[at + 2] === 0x75 &&
    bytes[at + 3] === 0x61) ||
    (bytes[at + 1] === 0x4c && bytes[at + 2] === 0x4a));

/** Offsets of chunk signatures inside a larger file, for chunks embedded in game data. */
export const findChunkStarts = (bytes: Buffer, limit: number): number[] => {
  const found: number[] = [];
  for (
    let at = bytes.indexOf(0x1b);
    at >= 0 && found.length < limit;
    at = bytes.indexOf(0x1b, at + 1)
  )
    if (isChunkStart(bytes, at)) found.push(at);
  return found;
};
