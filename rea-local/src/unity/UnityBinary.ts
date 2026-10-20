/** A file whose Unity structures are truncated, inconsistent or unsupported. */
export class UnityFormatError extends Error {}

export const formatFail = (message: string): never => {
  throw new UnityFormatError(message);
};

/** Strings longer than this are treated as corruption. */
export const MAX_STRING_BYTES = 1024 * 1024;

/**
 * Bounds-checked reads over one buffer. Alignment is relative to the buffer
 * start, which callers place at the structure the format aligns against (a
 * serialized file or one object).
 */
export class ByteCursor {
  position: number;
  readonly end: number;

  constructor(
    readonly bytes: Buffer,
    start = 0,
    public littleEndian = false,
  ) {
    this.position = start;
    this.end = bytes.length;
  }

  get remaining(): number {
    return this.end - this.position;
  }

  private take(length: number, what: string): number {
    if (length < 0 || this.position + length > this.end)
      formatFail(`${what} runs past the end of its data.`);
    const at = this.position;
    this.position += length;
    return at;
  }

  u8(what = "byte"): number {
    return this.bytes[this.take(1, what)] ?? 0;
  }

  bool(what = "boolean"): boolean {
    return this.u8(what) !== 0;
  }

  u16(what = "u16"): number {
    const at = this.take(2, what);
    return this.littleEndian
      ? this.bytes.readUInt16LE(at)
      : this.bytes.readUInt16BE(at);
  }

  i16(what = "i16"): number {
    const at = this.take(2, what);
    return this.littleEndian
      ? this.bytes.readInt16LE(at)
      : this.bytes.readInt16BE(at);
  }

  u32(what = "u32"): number {
    const at = this.take(4, what);
    return this.littleEndian
      ? this.bytes.readUInt32LE(at)
      : this.bytes.readUInt32BE(at);
  }

  i32(what = "i32"): number {
    const at = this.take(4, what);
    return this.littleEndian
      ? this.bytes.readInt32LE(at)
      : this.bytes.readInt32BE(at);
  }

  i64(what = "i64"): bigint {
    const at = this.take(8, what);
    return this.littleEndian
      ? this.bytes.readBigInt64LE(at)
      : this.bytes.readBigInt64BE(at);
  }

  u64(what = "u64"): bigint {
    const at = this.take(8, what);
    return this.littleEndian
      ? this.bytes.readBigUInt64LE(at)
      : this.bytes.readBigUInt64BE(at);
  }

  /** A u64 that must fit a JavaScript integer, such as an offset or size. */
  offset(what = "offset"): number {
    const value = this.u64(what);
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      formatFail(`${what} is too large.`);
    return Number(value);
  }

  /** A non-negative i32 count no larger than `limit`. */
  count(limit: number, what: string): number {
    const value = this.i32(what);
    if (value < 0 || value > limit)
      formatFail(`${what} ${String(value)} is out of range.`);
    return value;
  }

  slice(length: number, what = "bytes"): Buffer {
    const at = this.take(length, what);
    return this.bytes.subarray(at, at + length);
  }

  skip(length: number, what = "field"): void {
    this.take(length, what);
  }

  /** NUL-terminated UTF-8 text. */
  cString(what = "string", limit = MAX_STRING_BYTES): string {
    const stop = Math.min(this.end, this.position + limit + 1);
    const end = this.bytes.indexOf(0, this.position);
    if (end < 0 || end >= stop) formatFail(`${what} is not NUL-terminated.`);
    const text = this.bytes.toString("utf8", this.position, end);
    this.position = end + 1;
    return text;
  }

  /** Length-prefixed (i32) UTF-8 text, as Unity serializes `string`. */
  sizedString(what = "string", limit = MAX_STRING_BYTES): string {
    const length = this.i32(`${what} length`);
    if (length < 0 || length > limit || length > this.remaining)
      formatFail(`${what} length ${String(length)} is out of range.`);
    return this.slice(length, what).toString("utf8");
  }

  align(boundary = 4): void {
    const misaligned = this.position % boundary;
    if (misaligned !== 0) this.skip(boundary - misaligned, "alignment padding");
  }
}

/** Unity GUIDs print each byte's low nibble first, as in `.meta` files. */
export const unityGuid = (bytes: Buffer): string =>
  Array.from(
    bytes,
    (byte) => `${(byte & 0x0f).toString(16)}${(byte >> 4).toString(16)}`,
  ).join("");

/** `2019.4.15f1` as comparable numbers; unparsable versions are zero. */
export const unityVersionParts = (
  version: string,
): readonly [number, number, number] => {
  const match = /^(\d+)\.(\d+)\.(\d+)/u.exec(version);
  return match === null
    ? [0, 0, 0]
    : [Number(match[1]), Number(match[2]), Number(match[3])];
};

export const versionAtLeast = (
  version: readonly [number, number, number],
  minimum: readonly [number, number, number],
): boolean => {
  for (let index = 0; index < 3; index += 1) {
    const left = version[index] ?? 0;
    const right = minimum[index] ?? 0;
    if (left !== right) return left > right;
  }
  return true;
};
