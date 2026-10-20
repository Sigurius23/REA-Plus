import { err, ok, type Result } from "./result.js";

/** Bytes in a DEX header; every supported version uses this size. */
export const DEX_HEADER_SIZE = 0x70;

const ENDIAN_CONSTANT = 0x12345678;

/** Header facts of an Android DEX file, read without I/O. */
export interface DexHeader {
  /** The three-digit format version from the magic, such as `"039"`. */
  readonly version: string;
  /** Total size the header declares, which may be smaller than the file. */
  readonly declaredSize: number;
  readonly classCount: number;
  readonly methodCount: number;
  readonly stringCount: number;
}

/** Whether the bytes start with a DEX magic (`dex\n` + three digits + NUL). */
export const isDexMagic = (bytes: Buffer): boolean =>
  bytes.length >= 8 &&
  bytes.toString("latin1", 0, 4) === "dex\n" &&
  /^[0-9]{3}$/u.test(bytes.toString("latin1", 4, 7)) &&
  bytes[7] === 0;

/**
 * Parse the fixed DEX header. Only little-endian files with the standard
 * 0x70-byte header are accepted, which covers every DEX that Android loads.
 */
export const parseDexHeader = (
  bytes: Buffer,
  fileSize = bytes.length,
): Result<DexHeader, string> => {
  if (!isDexMagic(bytes)) return err("not a DEX file");
  if (bytes.length < DEX_HEADER_SIZE)
    return err(
      `truncated DEX header: it needs ${String(DEX_HEADER_SIZE)} bytes; the file has ${String(fileSize)}`,
    );
  const endian = bytes.readUInt32LE(0x28);
  if (endian !== ENDIAN_CONSTANT)
    return err(
      endian === 0x78563412
        ? "unsupported big-endian DEX file"
        : "invalid DEX endian tag",
    );
  const headerSize = bytes.readUInt32LE(0x24);
  if (headerSize !== DEX_HEADER_SIZE)
    return err(`unsupported DEX header size ${String(headerSize)}`);
  const declaredSize = bytes.readUInt32LE(0x20);
  if (declaredSize < DEX_HEADER_SIZE || declaredSize > fileSize)
    return err(
      `truncated DEX file: the header declares ${String(declaredSize)} bytes; the file has ${String(fileSize)}`,
    );
  return ok({
    version: bytes.toString("latin1", 4, 7),
    declaredSize,
    stringCount: bytes.readUInt32LE(0x38),
    methodCount: bytes.readUInt32LE(0x58),
    classCount: bytes.readUInt32LE(0x60),
  });
};
