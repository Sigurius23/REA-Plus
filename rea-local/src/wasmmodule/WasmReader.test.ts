import { describe, expect, it } from "vitest";

import {
  skipExpression,
  skipImmediates,
  WasmFormatError,
  WasmReader,
} from "./WasmReader.js";

const reader = (...bytes: number[]) =>
  new WasmReader(Buffer.from(bytes), 0, bytes.length);

describe("LEB128", () => {
  it("reads unsigned and signed integers at their limits", () => {
    expect(reader(0xe5, 0x8e, 0x26).u32()).toBe(624_485);
    expect(reader(0xff, 0xff, 0xff, 0xff, 0x0f).u32()).toBe(0xffff_ffff);
    expect(reader(0x7f).signed(32)).toBe(-1n);
    expect(reader(0xc0, 0xbb, 0x78).signed(32)).toBe(-123_456n);
    expect(reader(0x80, 0x80, 0x80, 0x80, 0x78).signed(32)).toBe(-(2n ** 31n));
    expect(
      reader(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01).u64(),
    ).toBe(2 ** 63);
  });

  it("refuses integers longer than their width and reads past the end", () => {
    expect(() => reader(0x80, 0x80, 0x80, 0x80, 0x80, 0x01).u32()).toThrow(
      WasmFormatError,
    );
    expect(() => reader(0x80).u32()).toThrow(WasmFormatError);
    expect(() => reader(0x05, 0x61).name()).toThrow(WasmFormatError);
  });
});

describe("types and instructions", () => {
  it("names value and reference types", () => {
    expect(reader(0x7b).valueType()).toBe("v128");
    expect(reader(0x63, 0x70).valueType()).toBe("(ref null func)");
    expect(reader(0x64, 0x05).valueType()).toBe("(ref $5)");
    expect(() => reader(0x42).valueType()).toThrow(WasmFormatError);
  });

  it.each([
    ["i32.load with a memarg", 0x28, [0x02, 0x10]],
    ["multi-memory i32.store", 0x36, [0x42, 0x01, 0x08]],
    ["br_table", 0x0e, [0x02, 0x00, 0x01, 0x00]],
    ["v128.const", 0xfd, [0x0c, ...Array.from({ length: 16 }, () => 0)]],
    ["i8x16.shuffle", 0xfd, [0x0d, ...Array.from({ length: 16 }, () => 1)]],
    ["v128.load8_lane", 0xfd, [0x54, 0x00, 0x00, 0x03]],
    ["memory.init", 0xfc, [0x08, 0x01, 0x00]],
    ["i32.atomic.rmw.add", 0xfe, [0x1e, 0x02, 0x00]],
    ["atomic.fence", 0xfe, [0x03, 0x00]],
    ["struct.get", 0xfb, [0x02, 0x00, 0x01]],
    ["br_on_cast", 0xfb, [0x18, 0x03, 0x00, 0x6e, 0x6c]],
    ["try_table", 0x1f, [0x40, 0x01, 0x00, 0x00, 0x00]],
  ])("skips the immediates of %s", (_name, opcode, immediates) => {
    const cursor = reader(...immediates, 0x0b);
    skipImmediates(cursor, opcode);
    expect(cursor.at).toBe(immediates.length);
  });

  it("refuses unknown opcodes and walks nested expressions", () => {
    expect(() => skipImmediates(reader(), 0xff)).toThrow(WasmFormatError);
    expect(() => skipImmediates(reader(0x7f), 0xfc)).toThrow(WasmFormatError);
    const nested = reader(0x02, 0x40, 0x41, 0x01, 0x1a, 0x0b, 0x0b, 0x99);
    skipExpression(nested);
    expect(nested.at).toBe(7);
  });
});
