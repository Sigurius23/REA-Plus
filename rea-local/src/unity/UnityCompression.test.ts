import { describe, expect, it } from "vitest";

import {
  encodeLz4Block,
  encodeLzmaLiterals,
} from "../../tests/fixtures/unityCompression.js";
import { decodeLz4Block, UnityCompressionError } from "./Lz4Block.js";
import { decodeLzma } from "./LzmaDecoder.js";

/** Deterministic mixed data: repeats at several distances plus noise. */
const sample = (length: number): Buffer => {
  const bytes = Buffer.alloc(length);
  let seed = 7;
  for (let index = 0; index < length; index += 1) {
    seed = (seed * 1103515245 + 12345) >>> 0;
    bytes[index] =
      index % 97 < 40 && index >= 300
        ? (bytes[index - 300] ?? 0)
        : (seed >>> 24) & (index % 5 === 0 ? 0xff : 0x0f);
  }
  return bytes;
};

describe("decodeLz4Block", () => {
  it("decodes literals and overlapping matches", () => {
    // "ab" then a match of offset 2, length 8 (copying its own output).
    const block = Buffer.from([0x24, 0x61, 0x62, 0x02, 0x00, 0x10, 0x21]);
    expect(decodeLz4Block(block, 11).toString("latin1")).toBe("ababababab!");
  });

  it.each([0, 1, 16, 4096, 70_000])(
    "round-trips %i bytes through a standard block encoder",
    (length) => {
      const data = sample(length);
      expect(decodeLz4Block(encodeLz4Block(data), length).equals(data)).toBe(
        true,
      );
    },
  );

  it.each([
    ["a zero match offset", [0x14, 0x61, 0x00, 0x00, 0x00], 6],
    ["an offset before the block", [0x14, 0x61, 0x05, 0x00, 0x00], 6],
    ["literals past the input", [0x50, 0x61], 5],
    ["output past the declared size", [0x30, 0x61, 0x62, 0x63], 2],
    ["output short of the declared size", [0x30, 0x61, 0x62, 0x63], 4],
  ])("rejects %s", (_name, bytes, size) => {
    expect(() => decodeLz4Block(Buffer.from(bytes), size)).toThrow(
      UnityCompressionError,
    );
  });
});

/** Python 3.13 lzma.compress(FORMAT_RAW, LZMA1 lc=3 lp=0 pb=2) of TEXT. */
const XZ_VECTOR = Buffer.from(
  "5d00000100003697c5c644bcd23d2d5cc0b0ccce6b850b01fe084d80827876cbeb540e928557b388ddfe378d2686ddcbf440a2001cafa38f4c56d318f2d747b85168a28199bf789baa12ebeb4e5739fa05b4828722b6e37267385299be9ffac174a0ffff9eb3e000",
  "hex",
);
const TEXT = Buffer.concat([
  Buffer.from("m_Name m_Script m_GameObject ".repeat(3)),
  Buffer.from("abcXabcYabcXabcY".repeat(4)),
  Buffer.alloc(40),
  Buffer.from("Assets/Textures/hero.png Assets/Textures/hera.png"),
  Buffer.from([
    ...Array.from({ length: 16 }, (_, i) => i),
    ...Array.from({ length: 16 }, (_, i) => i),
  ]),
]);

describe("decodeLzma", () => {
  it("decodes an xz-produced stream with matches and repeats", () => {
    expect(decodeLzma(XZ_VECTOR, TEXT.length).equals(TEXT)).toBe(true);
  });

  it("stops at the end marker when the declared size is too large", () => {
    expect(() => decodeLzma(XZ_VECTOR, TEXT.length + 1)).toThrow(
      /decoded to 272 bytes/u,
    );
  });

  it.each([0, 1, 4096, 70_000])(
    "round-trips %i literal-coded bytes",
    (length) => {
      const data = sample(length);
      expect(decodeLzma(encodeLzmaLiterals(data), length).equals(data)).toBe(
        true,
      );
    },
  );

  it.each([
    ["a truncated stream", XZ_VECTOR.subarray(0, 40)],
    [
      "an invalid properties byte",
      Buffer.concat([Buffer.from([0xe1]), XZ_VECTOR.subarray(1)]),
    ],
    [
      "a non-zero first range byte",
      Buffer.concat([
        XZ_VECTOR.subarray(0, 5),
        Buffer.from([1]),
        XZ_VECTOR.subarray(6),
      ]),
    ],
  ])("rejects %s", (_name, bytes) => {
    expect(() => decodeLzma(bytes, TEXT.length)).toThrow(UnityCompressionError);
  });
});
