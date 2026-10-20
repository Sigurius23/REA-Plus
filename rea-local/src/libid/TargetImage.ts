/**
 * The loaded image of an ELF or PE executable or shared library: regions of
 * file bytes at their virtual addresses, so code can be scanned and the
 * targets of PC-relative references read.
 */

export interface ImageRegion {
  readonly address: bigint;
  readonly bytes: Buffer;
  readonly executable: boolean;
}

export interface TargetImage {
  readonly format: "elf" | "pe";
  readonly machine: string;
  readonly regions: readonly ImageRegion[];
}

const ELF_MACHINES: Readonly<Record<number, string>> = {
  3: "x86",
  62: "x86-64",
  40: "arm",
  183: "aarch64",
};
const PE_MACHINES: Readonly<Record<number, string>> = {
  0x14c: "x86",
  0x8664: "x86-64",
  0xaa64: "aarch64",
  0x1c4: "arm",
};

const elfImage = (data: Buffer): TargetImage | null => {
  if (data.length < 0x34 || data.readUInt32BE(0) !== 0x7f454c46) return null;
  if (data.readUInt8(5) !== 1) return null;
  const type = data.readUInt16LE(0x10);
  if (type !== 2 && type !== 3) return null;
  const wide = data.readUInt8(4) === 2;
  const phoff = wide
    ? Number(data.readBigUInt64LE(0x20))
    : data.readUInt32LE(0x1c);
  const entsize = data.readUInt16LE(wide ? 0x36 : 0x2a);
  const count = data.readUInt16LE(wide ? 0x38 : 0x2c);
  const regions: ImageRegion[] = [];
  for (let index = 0; index < count; index += 1) {
    const at = phoff + index * entsize;
    if (data.readUInt32LE(at) !== 1) continue;
    const offset = wide
      ? Number(data.readBigUInt64LE(at + 8))
      : data.readUInt32LE(at + 4);
    const address = wide
      ? data.readBigUInt64LE(at + 0x10)
      : BigInt(data.readUInt32LE(at + 8));
    const size = wide
      ? Number(data.readBigUInt64LE(at + 0x20))
      : data.readUInt32LE(at + 0x10);
    const flags = data.readUInt32LE(at + (wide ? 4 : 0x18));
    if (size === 0) continue;
    regions.push({
      address,
      bytes: data.subarray(offset, offset + size),
      executable: (flags & 1) !== 0,
    });
  }
  return {
    format: "elf",
    machine: ELF_MACHINES[data.readUInt16LE(0x12)] ?? "unknown",
    regions,
  };
};

const peImage = (data: Buffer): TargetImage | null => {
  if (data.length < 0x40 || data.readUInt16LE(0) !== 0x5a4d) return null;
  const pe = data.readUInt32LE(0x3c);
  if (pe + 24 > data.length || data.readUInt32LE(pe) !== 0x4550) return null;
  const machine = data.readUInt16LE(pe + 4);
  const sections = data.readUInt16LE(pe + 6);
  const optional = pe + 24;
  const optionalSize = data.readUInt16LE(pe + 20);
  const magic = data.readUInt16LE(optional);
  const base =
    magic === 0x20b
      ? data.readBigUInt64LE(optional + 24)
      : BigInt(data.readUInt32LE(optional + 28));
  const regions: ImageRegion[] = [];
  for (let index = 0; index < sections; index += 1) {
    const at = optional + optionalSize + index * 40;
    const virtualAddress = data.readUInt32LE(at + 12);
    const rawSize = data.readUInt32LE(at + 16);
    const rawOffset = data.readUInt32LE(at + 20);
    const characteristics = data.readUInt32LE(at + 36);
    if (rawSize === 0 || rawOffset === 0) continue;
    regions.push({
      address: base + BigInt(virtualAddress),
      bytes: data.subarray(rawOffset, rawOffset + rawSize),
      executable: (characteristics & 0x20000020) !== 0,
    });
  }
  return {
    format: "pe",
    machine: PE_MACHINES[machine] ?? "unknown",
    regions,
  };
};

/** Read an ELF or PE image; null for other formats or malformed headers. */
export const readTargetImage = (data: Buffer): TargetImage | null => {
  try {
    return elfImage(data) ?? peImage(data);
  } catch {
    return null;
  }
};

/** Up to `length` file bytes at a virtual address, or null when unmapped. */
export const bytesAt = (
  image: TargetImage,
  address: bigint,
  length: number,
): Buffer | null => {
  for (const region of image.regions) {
    const offset = address - region.address;
    if (offset >= 0n && offset < BigInt(region.bytes.length))
      return region.bytes.subarray(Number(offset), Number(offset) + length);
  }
  return null;
};
