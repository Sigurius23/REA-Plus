import { describe, expect, it } from "vitest";

import { DEX_HEADER_SIZE, isDexMagic, parseDexHeader } from "./dexHeader.js";

const header = (
  options: {
    readonly version?: string;
    readonly size?: number;
    readonly headerSize?: number;
    readonly endian?: number;
  } = {},
): Buffer => {
  const bytes = Buffer.alloc(options.size ?? 0x200);
  bytes.write(`dex\n${options.version ?? "039"}\0`, 0, "latin1");
  bytes.writeUInt32LE(options.size ?? bytes.length, 0x20);
  bytes.writeUInt32LE(options.headerSize ?? DEX_HEADER_SIZE, 0x24);
  bytes.writeUInt32LE(options.endian ?? 0x12345678, 0x28);
  bytes.writeUInt32LE(27, 0x38);
  bytes.writeUInt32LE(9, 0x58);
  bytes.writeUInt32LE(1, 0x60);
  return bytes;
};

describe("DEX header", () => {
  it("reads the version and table counts", () => {
    expect(parseDexHeader(header())).toEqual({
      ok: true,
      value: {
        version: "039",
        declaredSize: 0x200,
        stringCount: 27,
        methodCount: 9,
        classCount: 1,
      },
    });
  });

  it("recognizes only the DEX magic", () => {
    expect(isDexMagic(header({ version: "035" }))).toBe(true);
    expect(isDexMagic(Buffer.from("dex\n03a\0"))).toBe(false);
    expect(isDexMagic(Buffer.from("cdex001\0"))).toBe(false);
  });

  it("rejects truncated, big-endian and nonstandard headers", () => {
    expect(parseDexHeader(header().subarray(0, 0x40))).toMatchObject({
      ok: false,
      error: expect.stringContaining("truncated DEX header"),
    });
    expect(parseDexHeader(header(), 0x100)).toMatchObject({
      ok: false,
      error: expect.stringContaining("truncated DEX file"),
    });
    expect(parseDexHeader(header({ endian: 0x78563412 }))).toMatchObject({
      ok: false,
      error: "unsupported big-endian DEX file",
    });
    expect(parseDexHeader(header({ headerSize: 0x78 }))).toMatchObject({
      ok: false,
      error: "unsupported DEX header size 120",
    });
  });
});
