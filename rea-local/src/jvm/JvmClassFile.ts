/** A class file's declared name and format version (JVMS 4.1). */
export interface JvmClassHeader {
  readonly name: string;
  readonly major: number;
  readonly minor: number;
}

/** Malformed class-file bytes; the reason names the violated structure. */
export class JvmClassFormatError extends Error {
  override readonly name = "JvmClassFormatError";
}

/** Constant-pool entry payload sizes after the tag byte (JVMS 4.4). */
const FIXED_ENTRY_BYTES: Readonly<Record<number, number>> = {
  3: 4,
  4: 4,
  5: 8,
  6: 8,
  7: 2,
  8: 2,
  9: 4,
  10: 4,
  11: 4,
  12: 4,
  15: 3,
  16: 2,
  17: 4,
  18: 4,
  19: 2,
  20: 2,
};
const UTF8 = 1;
const CLASS = 7;

/** Whether bytes begin with the 0xCAFEBABE class-file magic. */
export const isJvmClassFile = (bytes: Uint8Array): boolean =>
  bytes.length >= 4 &&
  bytes[0] === 0xca &&
  bytes[1] === 0xfe &&
  bytes[2] === 0xba &&
  bytes[3] === 0xbe;

/** Read the version and `this_class` binary name without loading the class. */
export const readJvmClassHeader = (bytes: Buffer): JvmClassHeader => {
  if (!isJvmClassFile(bytes))
    throw new JvmClassFormatError("missing 0xCAFEBABE class-file magic");
  const need = (offset: number, length: number): void => {
    if (offset + length > bytes.length)
      throw new JvmClassFormatError("class file ends inside its constant pool");
  };
  need(4, 6);
  const minor = bytes.readUInt16BE(4);
  const major = bytes.readUInt16BE(6);
  const count = bytes.readUInt16BE(8);
  const utf8 = new Map<number, string>();
  const classNames = new Map<number, number>();
  let offset = 10;
  for (let index = 1; index < count; index++) {
    need(offset, 1);
    const tag = bytes[offset] ?? 0;
    offset += 1;
    if (tag === UTF8) {
      need(offset, 2);
      const length = bytes.readUInt16BE(offset);
      need(offset + 2, length);
      utf8.set(
        index,
        decodeModifiedUtf8(bytes.subarray(offset + 2, offset + 2 + length)),
      );
      offset += 2 + length;
      continue;
    }
    const size = FIXED_ENTRY_BYTES[tag];
    if (size === undefined)
      throw new JvmClassFormatError(
        `unknown constant-pool tag ${String(tag)} at entry ${String(index)}`,
      );
    need(offset, size);
    if (tag === CLASS) classNames.set(index, bytes.readUInt16BE(offset));
    offset += size;
    // Long and double constants occupy two pool slots.
    if (tag === 5 || tag === 6) index += 1;
  }
  need(offset, 4);
  const thisClass = bytes.readUInt16BE(offset + 2);
  const internal = utf8.get(classNames.get(thisClass) ?? 0);
  if (internal === undefined || internal.length === 0)
    throw new JvmClassFormatError("this_class does not name a class constant");
  return { name: internal.replaceAll("/", "."), major, minor };
};

/** Java SE release for major versions 45+ (45 is 1.1, so 46 reports 2 for 1.2). */
export const javaRelease = (major: number): number | null =>
  major >= 45 ? major - 44 : null;

/** Decode JVMS 4.4.7 modified UTF-8, including encoded NUL and surrogates. */
const decodeModifiedUtf8 = (bytes: Buffer): string => {
  const units: number[] = [];
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index] ?? 0;
    if (first < 0x80 && first !== 0) {
      units.push(first);
      index += 1;
    } else if ((first & 0xe0) === 0xc0) {
      const second = continuation(bytes, index + 1);
      units.push(((first & 0x1f) << 6) | second);
      index += 2;
    } else if ((first & 0xf0) === 0xe0) {
      const second = continuation(bytes, index + 1);
      const third = continuation(bytes, index + 2);
      units.push(((first & 0x0f) << 12) | (second << 6) | third);
      index += 3;
    } else
      throw new JvmClassFormatError("invalid modified UTF-8 in a constant");
  }
  return String.fromCharCode(...units);
};

const continuation = (bytes: Buffer, index: number): number => {
  const byte = bytes[index];
  if (byte === undefined || (byte & 0xc0) !== 0x80)
    throw new JvmClassFormatError("invalid modified UTF-8 in a constant");
  return byte & 0x3f;
};
