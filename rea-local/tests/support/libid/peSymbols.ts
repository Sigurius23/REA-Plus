import { readFile } from "node:fs/promises";

/** Function symbols of an unstripped PE image's COFF symbol table, by `0x` address. */
export const peFunctionSymbols = async (
  path: string,
): Promise<Map<string, string>> => {
  const data = await readFile(path);
  const pe = data.readUInt32LE(0x3c);
  const optional = pe + 24;
  const optionalSize = data.readUInt16LE(pe + 20);
  const base =
    data.readUInt16LE(optional) === 0x20b
      ? data.readBigUInt64LE(optional + 24)
      : BigInt(data.readUInt32LE(optional + 28));
  const sections = Array.from(
    { length: data.readUInt16LE(pe + 6) },
    (_, index) => data.readUInt32LE(optional + optionalSize + index * 40 + 12),
  );
  const pointer = data.readUInt32LE(pe + 12);
  const count = data.readUInt32LE(pe + 16);
  const strings = pointer + count * 18;
  const symbols = new Map<string, string>();
  for (let index = 0; index < count; index += 1) {
    const at = pointer + index * 18;
    const section = data.readInt16LE(at + 12);
    const type = data.readUInt16LE(at + 14);
    if ((type & 0x30) === 0x20 && section > 0) {
      const start = strings + data.readUInt32LE(at + 4);
      const name =
        data.readUInt32LE(at) === 0
          ? data.toString("latin1", start, data.indexOf(0, start))
          : data.toString("latin1", at, at + 8).replace(/\0.*$/su, "");
      const address =
        base +
        BigInt(sections[section - 1] ?? 0) +
        BigInt(data.readUInt32LE(at + 8));
      symbols.set(`0x${address.toString(16)}`, name);
    }
    index += data.readUInt8(at + 17);
  }
  return symbols;
};
