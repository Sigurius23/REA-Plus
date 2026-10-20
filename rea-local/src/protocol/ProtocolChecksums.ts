import { crc32 } from "node:zlib";

/**
 * Checksums protocols commonly carry, with the width of the field each
 * fills. CRC parameters follow the catalogue of parametrised CRC algorithms
 * (reveng): CRC-16/CCITT-FALSE, XMODEM, MODBUS and ARC.
 */

export interface Checksum {
  readonly name: string;
  readonly width: 1 | 2 | 4;
  readonly compute: (data: Buffer) => number;
}

const table = (poly: number, reflected: boolean, width: 16 | 32): Uint32Array =>
  Uint32Array.from({ length: 256 }, (_, index) => {
    let value = reflected ? index : index << (width - 8);
    for (let bit = 0; bit < 8; bit += 1)
      if (reflected) value = value & 1 ? (value >>> 1) ^ poly : value >>> 1;
      else
        value =
          value & (1 << (width - 1))
            ? ((value << 1) ^ poly) & (width === 32 ? 0xffffffff : 0xffff)
            : (value << 1) & 0xffff;
    return value >>> 0;
  });

const CRC32C = table(0x82f63b78, true, 32);
const CRC16_1021 = table(0x1021, false, 16);
const CRC16_A001 = table(0xa001, true, 16);

const crc16 = (data: Buffer, init: number): number => {
  let crc = init;
  for (const byte of data)
    crc =
      ((crc << 8) ^ (CRC16_1021[((crc >>> 8) ^ byte) & 0xff] ?? 0)) & 0xffff;
  return crc;
};

const crc16Reflected = (data: Buffer, init: number): number => {
  let crc = init;
  for (const byte of data)
    crc = (crc >>> 8) ^ (CRC16_A001[(crc ^ byte) & 0xff] ?? 0);
  return crc & 0xffff;
};

const sum = (data: Buffer): number =>
  data.reduce((total, byte) => total + byte, 0);

export const CHECKSUMS: readonly Checksum[] = [
  { name: "crc32", width: 4, compute: (data) => crc32(data) >>> 0 },
  {
    name: "crc32c",
    width: 4,
    compute: (data) => {
      let crc = 0xffffffff;
      for (const byte of data)
        crc = (crc >>> 8) ^ (CRC32C[(crc ^ byte) & 0xff] ?? 0);
      return (crc ^ 0xffffffff) >>> 0;
    },
  },
  {
    name: "adler32",
    width: 4,
    compute: (data) => {
      let a = 1;
      let b = 0;
      for (const byte of data) {
        a = (a + byte) % 65521;
        b = (b + a) % 65521;
      }
      return ((b << 16) | a) >>> 0;
    },
  },
  {
    name: "crc16-ccitt-false",
    width: 2,
    compute: (data) => crc16(data, 0xffff),
  },
  { name: "crc16-xmodem", width: 2, compute: (data) => crc16(data, 0) },
  {
    name: "crc16-modbus",
    width: 2,
    compute: (data) => crc16Reflected(data, 0xffff),
  },
  { name: "crc16-arc", width: 2, compute: (data) => crc16Reflected(data, 0) },
  {
    name: "fletcher16",
    width: 2,
    compute: (data) => {
      let a = 0;
      let b = 0;
      for (const byte of data) {
        a = (a + byte) % 255;
        b = (b + a) % 255;
      }
      return (b << 8) | a;
    },
  },
  {
    name: "internet",
    width: 2,
    compute: (data) => {
      let total = 0;
      for (let at = 0; at < data.length; at += 2)
        total += ((data[at] ?? 0) << 8) | (data[at + 1] ?? 0);
      while (total > 0xffff) total = (total & 0xffff) + (total >>> 16);
      return ~total & 0xffff;
    },
  },
  { name: "sum16", width: 2, compute: (data) => sum(data) & 0xffff },
  { name: "sum8", width: 1, compute: (data) => sum(data) & 0xff },
  { name: "negated-sum8", width: 1, compute: (data) => -sum(data) & 0xff },
  {
    name: "xor8",
    width: 1,
    compute: (data) => data.reduce((total, byte) => total ^ byte, 0),
  },
];
