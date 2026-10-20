import { describe, expect, it } from "vitest";

import { accessDetails, ModuleIndex } from "./MinidumpAnalysis.js";
import { readContext } from "./MinidumpContext.js";
import { MinidumpFile, MinidumpFormatError } from "./MinidumpFile.js";
import { exceptionName } from "./MinidumpNames.js";
import { readModules } from "./MinidumpStreams.js";

/** A dump holding one stream and arbitrary trailing blobs at known RVAs. */
const dump = (type: number, stream: Buffer, blobs: readonly Buffer[] = []) => {
  const header = Buffer.alloc(32 + 12);
  header.write("MDMP", 0, "latin1");
  header.writeUInt32LE(0xa793, 4);
  header.writeUInt32LE(1, 8);
  header.writeUInt32LE(32, 12);
  header.writeUInt32LE(type, 32);
  header.writeUInt32LE(stream.length, 36);
  header.writeUInt32LE(44, 40);
  return new MinidumpFile(Buffer.concat([header, stream, ...blobs]));
};

describe("minidump decoding", () => {
  it("reads NB10 CodeView records and module names", () => {
    const name = Buffer.from("\u0000\u0000\u0000\u0000legacy.dll", "latin1");
    const utf16 = Buffer.from("legacy.dll", "utf16le");
    name.writeUInt32LE(utf16.length, 0);
    const nameRecord = Buffer.concat([name.subarray(0, 4), utf16]);
    const codeView = Buffer.concat([
      Buffer.from("NB10", "latin1"),
      Buffer.from([0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 3, 0, 0, 0]),
      Buffer.from("legacy.pdb\0"),
    ]);
    const stream = Buffer.alloc(4 + 108);
    stream.writeUInt32LE(1, 0);
    stream.writeBigUInt64LE(0x10000000n, 4);
    stream.writeUInt32LE(0x2000, 12);
    const nameRva = 44 + stream.length;
    const codeViewRva = nameRva + nameRecord.length;
    stream.writeUInt32LE(nameRva, 4 + 20);
    stream.writeUInt32LE(codeView.length, 4 + 76);
    stream.writeUInt32LE(codeViewRva, 4 + 80);
    const [module] = readModules(dump(4, stream, [nameRecord, codeView])) ?? [];
    expect(module).toMatchObject({
      name: "legacy.dll",
      fileVersion: null,
      codeView: {
        format: "NB10",
        pdb: "legacy.pdb",
        signature: 0x12345678,
        age: 3,
        debugId: "123456783",
      },
    });
  });

  it("decodes ARM64 and ARM contexts by their recorded size", () => {
    const arm64 = Buffer.alloc(912);
    arm64.writeUInt32LE(0x60000000, 4);
    arm64.writeBigUInt64LE(0x1111n, 8);
    arm64.writeBigUInt64LE(0x7ff0n, 240);
    arm64.writeBigUInt64LE(0x7fe0n, 256);
    arm64.writeBigUInt64LE(0x4000n, 264);
    const file = dump(0x9999, Buffer.alloc(0), [arm64]);
    expect(readContext(file, { size: 912, rva: 44 })).toMatchObject({
      architecture: "arm64",
      instructionPointer: 0x4000n,
      stackPointer: 0x7fe0n,
      framePointer: 0x7ff0n,
    });
    expect(
      readContext(file, { size: 912, rva: 44 })?.registers.get("cpsr"),
    ).toBe(0x60000000n);
    const arm = Buffer.alloc(368);
    arm.writeUInt32LE(0x8000, 4 + 11 * 4);
    arm.writeUInt32LE(0x9000, 56);
    arm.writeUInt32LE(0xa000, 64);
    expect(
      readContext(dump(0x9999, Buffer.alloc(0), [arm]), {
        size: 368,
        rva: 44,
      }),
    ).toMatchObject({
      architecture: "arm",
      instructionPointer: 0xa000n,
      stackPointer: 0x9000n,
      framePointer: 0x8000n,
    });
    expect(readContext(file, { size: 100, rva: 44 })).toBeNull();
  });

  it("names exceptions for the platform that wrote the dump", () => {
    expect(exceptionName(0xc00000fd, 0, 2)).toBe("EXCEPTION_STACK_OVERFLOW");
    expect(exceptionName(11, 2, 0x8201)).toBe("SIGSEGV / SEGV_ACCERR");
    expect(exceptionName(6, 0, 0x8203)).toBe("SIGABRT");
    expect(exceptionName(1, 2, 0x8101)).toBe(
      "EXC_BAD_ACCESS / KERN_PROTECTION_FAILURE",
    );
    expect(exceptionName(0x12345678, 0, 2)).toBeNull();
    expect(accessDetails(0xc0000005, [8n, 0x4000n])).toEqual({
      kind: "execute",
      address: "0x4000",
    });
    expect(accessDetails(0xc0000094, [1n, 2n])).toBeNull();
  });

  it("maps addresses to modules and rejects bad headers", () => {
    const index = new ModuleIndex([
      {
        base: 0x2000n,
        size: 0x100,
        checksum: 0,
        timestamp: 0,
        name: "b",
        fileVersion: null,
        productVersion: null,
        codeView: null,
      },
      {
        base: 0x1000n,
        size: 0x100,
        checksum: 0,
        timestamp: 0,
        name: "a",
        fileVersion: null,
        productVersion: null,
        codeView: null,
      },
    ]);
    expect(index.locate(0x1080n)).toEqual({ module: "a", offset: "0x80" });
    expect(index.locate(0x2100n)).toBeNull();
    expect(() => new MinidumpFile(Buffer.from("PAGEDUMP"))).toThrow(
      MinidumpFormatError,
    );
    const header = Buffer.alloc(32);
    header.write("MDMP", 0, "latin1");
    header.writeUInt32LE(0x1234, 4);
    expect(() => new MinidumpFile(header)).toThrow(/version 0x1234/u);
    header.writeUInt32LE(0xa793, 4);
    header.writeUInt32LE(5, 8);
    header.writeUInt32LE(32, 12);
    expect(() => new MinidumpFile(header)).toThrow(/stream directory/u);
  });
});
