import type { MinidumpFile } from "./MinidumpFile.js";
import type { LocationDescriptor } from "./MinidumpStreams.js";

/** General-purpose registers of one recorded thread context. */
export interface ThreadRegisters {
  readonly architecture: "x86" | "amd64" | "arm64" | "arm";
  readonly instructionPointer: bigint;
  readonly stackPointer: bigint;
  readonly framePointer: bigint;
  readonly registers: ReadonlyMap<string, bigint>;
}

/** Register name, byte offset and width when it differs from the pointer width. */
type Field = readonly [name: string, offset: number, width?: 4];

const X86: readonly Field[] = [
  ["eax", 176],
  ["ebx", 164],
  ["ecx", 172],
  ["edx", 168],
  ["esi", 160],
  ["edi", 156],
  ["ebp", 180],
  ["esp", 196],
  ["eip", 184],
  ["eflags", 192],
];

const AMD64: readonly Field[] = [
  ["rax", 120],
  ["rbx", 144],
  ["rcx", 128],
  ["rdx", 136],
  ["rsi", 168],
  ["rdi", 176],
  ["rbp", 160],
  ["rsp", 152],
  ...Array.from({ length: 8 }, (_, index): Field => [
    `r${String(index + 8)}`,
    184 + index * 8,
  ]),
  ["rip", 248],
  ["eflags", 68, 4],
];

const ARM64: readonly Field[] = [
  ...Array.from({ length: 29 }, (_, index): Field => [
    `x${String(index)}`,
    8 + index * 8,
  ]),
  ["fp", 240],
  ["lr", 248],
  ["sp", 256],
  ["pc", 264],
  ["cpsr", 4, 4],
];

const ARM: readonly Field[] = [
  ...Array.from({ length: 13 }, (_, index): Field => [
    `r${String(index)}`,
    4 + index * 4,
  ]),
  ["sp", 56],
  ["lr", 60],
  ["pc", 64],
  ["cpsr", 68],
];

/** Context layouts by recorded size: Windows CONTEXT and Breakpad equivalents. */
const LAYOUTS = [
  {
    size: 716,
    architecture: "x86",
    width: 4,
    fields: X86,
    pointers: ["eip", "esp", "ebp"],
  },
  {
    size: 1232,
    architecture: "amd64",
    width: 8,
    fields: AMD64,
    pointers: ["rip", "rsp", "rbp"],
  },
  {
    size: 912,
    architecture: "arm64",
    width: 8,
    fields: ARM64,
    pointers: ["pc", "sp", "fp"],
  },
  {
    size: 368,
    architecture: "arm",
    width: 4,
    fields: ARM,
    pointers: ["pc", "sp", "r11"],
  },
] as const;

/** Decode a thread context; unknown sizes or architectures return null. */
export const readContext = (
  file: MinidumpFile,
  context: LocationDescriptor,
): ThreadRegisters | null => {
  const layout = LAYOUTS.find(({ size }) => size === context.size);
  if (layout === undefined || context.rva === 0) return null;
  const bytes = file.slice(context.rva, context.size, "thread context");
  const registers = new Map<string, bigint>(
    layout.fields.map(([name, offset, width]) => [
      name,
      (width ?? layout.width) === 8
        ? bytes.readBigUInt64LE(offset)
        : BigInt(bytes.readUInt32LE(offset)),
    ]),
  );
  const [ip, sp, fp] = layout.pointers;
  return {
    architecture: layout.architecture,
    instructionPointer: registers.get(ip) ?? 0n,
    stackPointer: registers.get(sp) ?? 0n,
    framePointer: registers.get(fp) ?? 0n,
    registers,
  };
};

export const pointerWidth = (architecture: ThreadRegisters["architecture"]) =>
  architecture === "x86" || architecture === "arm" ? 4 : 8;
