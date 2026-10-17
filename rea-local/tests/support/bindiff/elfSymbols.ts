import { readFile } from "node:fs/promises";

/** Function symbols of an unstripped little-endian ELF64, by `0x` address. */
export const elfFunctionSymbols = async (
  path: string,
): Promise<Map<string, string>> => {
  const data = await readFile(path);
  const sectionAt = (index: number) => {
    const at =
      Number(data.readBigUInt64LE(0x28)) + index * data.readUInt16LE(0x3a);
    return {
      type: data.readUInt32LE(at + 4),
      offset: Number(data.readBigUInt64LE(at + 0x18)),
      size: Number(data.readBigUInt64LE(at + 0x20)),
      link: data.readUInt32LE(at + 0x28),
    };
  };
  const symbols = new Map<string, string>();
  for (let index = 0; index < data.readUInt16LE(0x3c); index += 1) {
    const table = sectionAt(index);
    if (table.type !== 2) continue;
    const strings = sectionAt(table.link);
    for (let at = table.offset; at < table.offset + table.size; at += 24) {
      const value = data.readBigUInt64LE(at + 8);
      if ((data.readUInt8(at + 4) & 0xf) !== 2 || value === 0n) continue;
      const start = strings.offset + data.readUInt32LE(at);
      const name = data.toString("latin1", start, data.indexOf(0, start));
      symbols.set(`0x${value.toString(16)}`, name);
    }
  }
  return symbols;
};

/** A source-level name: GCC's clone suffixes (.constprop.0, .isra.0, .part.0, .cold) removed. */
export const sourceName = (name: string): string =>
  name.replace(/\.(?:constprop|isra|part|cold|lto_priv)(?:\.\d+)?/gu, "");
