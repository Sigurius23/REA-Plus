import { describe, expect, it } from "vitest";

import {
  isJvmClassFile,
  javaRelease,
  readJvmClassHeader,
} from "./JvmClassFile.js";
import { topLevelClass } from "./JvmJarInventory.js";

const u2 = (value: number) => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
};
const utf8 = (bytes: Buffer) =>
  Buffer.concat([Buffer.from([1]), u2(bytes.length), bytes]);

/** Minimal class: a long constant (two slots) before the Class entry. */
const classFile = (internalName: Buffer, major = 61) =>
  Buffer.concat([
    Buffer.from("cafebabe", "hex"),
    u2(0),
    u2(major),
    u2(5),
    Buffer.from([5, 0, 0, 0, 0, 0, 0, 0, 42]),
    utf8(internalName),
    Buffer.concat([Buffer.from([7]), u2(3)]),
    u2(0x0021),
    u2(4),
  ]);

describe("JVM class-file header", () => {
  it("reads this_class past two-slot constants", () => {
    const bytes = classFile(Buffer.from("com/example/mod/Main"));
    expect(isJvmClassFile(bytes)).toBe(true);
    expect(readJvmClassHeader(bytes)).toEqual({
      name: "com.example.mod.Main",
      major: 61,
      minor: 0,
    });
    expect(javaRelease(61)).toBe(17);
    expect(javaRelease(46)).toBe(2);
    expect(javaRelease(44)).toBeNull();
  });

  it("decodes modified UTF-8 names", () => {
    // U+00E9 is two bytes; U+20AC three; class names cannot contain NUL.
    const name = Buffer.from([
      0x63, 0x61, 0x66, 0xc3, 0xa9, 0x2f, 0xe2, 0x82, 0xac,
    ]);
    expect(readJvmClassHeader(classFile(name)).name).toBe("café.€");
  });

  it("rejects non-class bytes, truncation, unknown tags and bad encodings", () => {
    expect(() => readJvmClassHeader(Buffer.from("PK\x03\x04"))).toThrow(
      /CAFEBABE/u,
    );
    const complete = classFile(Buffer.from("A"));
    expect(() => readJvmClassHeader(complete.subarray(0, 20))).toThrow(
      /ends inside its constant pool/u,
    );
    const unknownTag = Buffer.from(complete);
    unknownTag[10] = 2;
    expect(() => readJvmClassHeader(unknownTag)).toThrow(
      /unknown constant-pool tag 2/u,
    );
    expect(() =>
      readJvmClassHeader(classFile(Buffer.from([0x41, 0xc3]))),
    ).toThrow(/modified UTF-8/u);
  });
});

describe("JVM nested class sources", () => {
  it("maps nested binary names to the outermost class CFR writes", () => {
    const inventory = new Set([
      "a.Outer",
      "a.Outer$Inner",
      "a.Outer$Inner$Deep",
      "a.$Proxy1",
    ]);
    expect(topLevelClass("a.Outer$Inner$Deep", inventory)).toBe("a.Outer");
    expect(topLevelClass("a.Outer", inventory)).toBe("a.Outer");
    // A `$` in a top-level name is kept when no shorter class exists.
    expect(topLevelClass("a.$Proxy1", inventory)).toBe("a.$Proxy1");
  });
});
