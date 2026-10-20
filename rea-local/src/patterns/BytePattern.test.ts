import { describe, expect, it } from "vitest";

import {
  BytePatternError,
  parseBytePattern,
  scanBytes,
} from "./BytePattern.js";
import { moduleAddress, scriptDirectives } from "./CheatTable.js";
import { readImageLayout, sectionAtAddress } from "./ImageLayout.js";

describe("byte patterns", () => {
  it("parses spaced, unspaced, single-? and nibble forms", () => {
    expect(parseBytePattern("48 8b ? 4?").text).toBe("48 8B ?? 4?");
    expect(parseBytePattern("488B05????????").text).toBe(
      "48 8B 05 ?? ?? ?? ??",
    );
    const pattern = parseBytePattern(
      "?? 48 8B ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? C3",
    );
    expect(pattern.anchor).toEqual({
      offset: 1,
      bytes: Buffer.from("488b", "hex"),
    });
    // A run of five wildcards is not a rel32; runs of exactly four are.
    expect(pattern.displacements).toEqual([3]);
    for (const bad of ["", "48 G0", "?? ??", "488", "48 8B8"])
      expect(() => parseBytePattern(bad)).toThrow(BytePatternError);
    expect(() => parseBytePattern(Array(257).fill("90").join(" "))).toThrow(
      /1-256/u,
    );
  });

  it("finds overlapping matches inside the range only", () => {
    const bytes = Buffer.from("0000004100", "hex");
    const pattern = parseBytePattern("00 00");
    expect(scanBytes(bytes, pattern, { start: 0, end: 5 }, 10)).toEqual({
      offsets: [0, 1],
      complete: true,
    });
    expect(scanBytes(bytes, pattern, { start: 1, end: 3 }, 10).offsets).toEqual(
      [1],
    );
    expect(scanBytes(bytes, pattern, { start: 0, end: 5 }, 1)).toEqual({
      offsets: [0],
      complete: false,
    });
    expect(
      scanBytes(
        Buffer.from("4f41", "hex"),
        parseBytePattern("4? 41"),
        { start: 0, end: 2 },
        5,
      ).offsets,
    ).toEqual([0]);
  });
});

describe("image layouts", () => {
  it("maps thin Mach-O 64 sections and skips zero-fill", () => {
    const file = Buffer.alloc(0x400);
    file.writeUInt32LE(0xfeedfacf, 0);
    file.writeUInt32LE(0x0100000c, 4);
    file.writeUInt32LE(1, 16);
    const command = 32;
    file.writeUInt32LE(0x19, command);
    file.writeUInt32LE(72 + 2 * 80, command + 4);
    file.write("__TEXT", command + 8, "latin1");
    file.writeBigUInt64LE(0x1_0000_0000n, command + 24);
    file.writeUInt32LE(2, command + 64);
    const section = (
      index: number,
      name: string,
      offset: number,
      flags: number,
    ) => {
      const at = command + 72 + index * 80;
      file.write(name, at, "latin1");
      file.write("__TEXT", at + 16, "latin1");
      file.writeBigUInt64LE(0x1_0000_0000n + BigInt(offset), at + 32);
      file.writeBigUInt64LE(0x40n, at + 40);
      file.writeUInt32LE(offset, at + 48);
      file.writeUInt32LE(flags, at + 64);
    };
    section(0, "__text", 0x300, 0x80000400);
    section(1, "__bss", 0, 0x1);
    const layout = readImageLayout(file);
    expect(layout).toMatchObject({
      format: "macho",
      architecture: "arm64",
      imageBase: 0x1_0000_0000n,
      sections: [
        {
          name: "__TEXT,__text",
          fileOffset: 0x300,
          size: 0x40,
          executable: true,
        },
      ],
    });
    expect(sectionAtAddress(layout, 0x1_0000_0310n)?.name).toBe(
      "__TEXT,__text",
    );
    expect(readImageLayout(Buffer.from("plain")).format).toBe("raw");
  });
});

describe("cheat table scripts", () => {
  it("reads module addresses and Auto Assembler directives", () => {
    expect(moduleAddress('"Game.exe"+0x1A2B')).toEqual({
      module: "Game.exe",
      offset: 0x1a2bn,
    });
    expect(moduleAddress("[player]+10")).toBeNull();
    expect(moduleAddress("1400ABCD")).toBeNull();
    expect(
      scriptDirectives(
        [
          "AOBScan(a, 90 90)",
          "aobscanregion(b, 1000, 2000, CC CC)",
          "assert(player+8, 00)",
          "globalalloc(mem, 100)",
          "registersymbol(a, b)",
        ].join("\n"),
      ),
    ).toEqual({
      aobScans: [
        { kind: "aobscan", symbol: "a", module: null, pattern: "90 90" },
        { kind: "aobscanregion", symbol: "b", module: null, pattern: "CC CC" },
      ],
      asserts: [
        { address: "player+8", module: null, offset: null, bytes: "00" },
      ],
      registeredSymbols: ["a", "b"],
      allocations: 1,
      lines: 5,
    });
  });
});
