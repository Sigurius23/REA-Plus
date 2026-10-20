import type { Minidump } from "../domain/minidump/minidump.js";
import { pointerWidth, type ThreadRegisters } from "./MinidumpContext.js";
import type { MinidumpFile } from "./MinidumpFile.js";
import type { MemoryRange, RawModule, RawThread } from "./MinidumpStreams.js";

export const hex = (value: bigint | number): string =>
  `0x${value.toString(16)}`;

export const hex32 = (value: number): string =>
  `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

/** time_t seconds as UTC ISO-8601; zero means unrecorded. */
export const isoTime = (seconds: number | null): string | null =>
  seconds === null || seconds === 0
    ? null
    : new Date(seconds * 1000).toISOString();

/** Resolve addresses to the module image containing them. */
export class ModuleIndex {
  readonly #modules: readonly RawModule[];

  constructor(modules: readonly RawModule[]) {
    this.#modules = [...modules].sort((left, right) =>
      left.base < right.base ? -1 : left.base > right.base ? 1 : 0,
    );
  }

  find(address: bigint): RawModule | null {
    let low = 0;
    let high = this.#modules.length - 1;
    while (low <= high) {
      const middle = (low + high) >> 1;
      const module = this.#modules[middle];
      if (module === undefined) return null;
      if (address < module.base) high = middle - 1;
      else if (address >= module.base + BigInt(module.size)) low = middle + 1;
      else return module;
    }
    return null;
  }

  locate(address: bigint | null): { module: string; offset: string } | null {
    if (address === null) return null;
    const module = this.find(address);
    return module === null
      ? null
      : { module: module.name, offset: hex(address - module.base) };
  }
}

export const registerRecord = (
  context: ThreadRegisters | null,
): Record<string, string> | null =>
  context === null
    ? null
    : Object.fromEntries(
        [...context.registers].map(([name, value]) => [name, hex(value)]),
      );

/** Windows access violations record the access kind and data address. */
export const accessDetails = (
  code: number,
  parameters: readonly bigint[],
): { kind: "read" | "write" | "execute"; address: string } | null => {
  if ((code !== 0xc0000005 && code !== 0xc0000006) || parameters.length < 2)
    return null;
  const kinds = { 0: "read", 1: "write", 8: "execute" } as const;
  const kind = kinds[Number(parameters[0]) as keyof typeof kinds];
  return kind === undefined
    ? null
    : { kind, address: hex(parameters[1] ?? 0n) };
};

/**
 * Scan a thread's captured stack from its stack pointer for values inside
 * module images. This is the classic return-address heuristic, not unwinding.
 */
export const scanStack = (
  file: MinidumpFile,
  thread: RawThread,
  {
    context,
    modules,
    limit,
  }: {
    readonly context: ThreadRegisters | null;
    readonly modules: ModuleIndex;
    readonly limit: number;
  },
): NonNullable<Minidump["selected_thread"]>["stack_scan"] => {
  if (limit === 0 || thread.stack.size === 0 || thread.stack.rva === 0)
    return [];
  const width = context === null ? 8 : pointerWidth(context.architecture);
  const bytes = file.slice(thread.stack.rva, thread.stack.size, "thread stack");
  const end = thread.stackStart + BigInt(bytes.length);
  const sp = context?.stackPointer ?? thread.stackStart;
  const from =
    sp >= thread.stackStart && sp < end ? Number(sp - thread.stackStart) : 0;
  const frames: NonNullable<Minidump["selected_thread"]>["stack_scan"] = [];
  for (
    let offset = from - (from % width);
    offset + width <= bytes.length && frames.length < limit;
    offset += width
  ) {
    const value =
      width === 8
        ? bytes.readBigUInt64LE(offset)
        : BigInt(bytes.readUInt32LE(offset));
    const module = modules.find(value);
    if (module !== null)
      frames.push({
        slot: hex(thread.stackStart + BigInt(offset)),
        value: hex(value),
        module: module.name,
        offset: hex(value - module.base),
      });
  }
  return frames;
};

export const memorySummary = (
  ranges: readonly MemoryRange[],
  full: boolean,
): Minidump["memory"] => ({
  ranges: ranges.length,
  bytes: Number(ranges.reduce((total, { size }) => total + size, 0n)),
  full_memory: full,
});
