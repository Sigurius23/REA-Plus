/**
 * Deterministic Windows x64 minidump for minidump reader tests: a game whose
 * render thread wrote to address 0x10 inside game.exe. Built stream by
 * stream with the documented MINIDUMP_* layouts.
 */
export const MINIDUMP_FIXTURE = Object.freeze({
  processId: 4242,
  mainThread: 100,
  renderThread: 200,
  gameBase: 0x1_4000_0000n,
  gameSize: 0x10000,
  gameTimestamp: 0x65000000,
  faultOffset: 0x1000,
  returnOffset: 0x1234,
  ntdllBase: 0x7ffb_6000_0000n,
  mainStack: 0x1000_0000n,
  renderStack: 0x2000_0000n,
  guid: "1F2E3D4C-5B6A-7988-A1B2-C3D4E5F60718",
  age: 2,
});

const F = MINIDUMP_FIXTURE;

/** Appends blobs and returns their RVAs, keeping 8-byte alignment. */
class Layout {
  readonly #parts: Buffer[] = [];
  #size = 0;

  constructor(reserved: number) {
    this.#parts.push(Buffer.alloc(reserved));
    this.#size = reserved;
  }

  add(bytes: Buffer): number {
    const padding = (8 - (this.#size % 8)) % 8;
    if (padding > 0) this.#parts.push(Buffer.alloc(padding));
    const rva = this.#size + padding;
    this.#parts.push(bytes);
    this.#size = rva + bytes.length;
    return rva;
  }

  string(value: string): number {
    const text = Buffer.from(value, "utf16le");
    const bytes = Buffer.alloc(4 + text.length + 2);
    bytes.writeUInt32LE(text.length, 0);
    text.copy(bytes, 4);
    return this.add(bytes);
  }

  bytes(): Buffer {
    return Buffer.concat(this.#parts);
  }
}

const amd64Context = (registers: Readonly<Record<string, bigint>>) => {
  const offsets: Readonly<Record<string, number>> = {
    rax: 120,
    rcx: 128,
    rbx: 144,
    rsp: 152,
    rbp: 160,
    rip: 248,
  };
  const context = Buffer.alloc(1232);
  context.writeUInt32LE(0x10001f, 48);
  context.writeUInt32LE(0x10246, 68);
  for (const [name, value] of Object.entries(registers))
    context.writeBigUInt64LE(value, offsets[name] ?? 0);
  return context;
};

const guidBytes = (guid: string) => {
  const hex = guid.replaceAll("-", "");
  const bytes = Buffer.alloc(16);
  bytes.writeUInt32LE(Number.parseInt(hex.slice(0, 8), 16), 0);
  bytes.writeUInt16LE(Number.parseInt(hex.slice(8, 12), 16), 4);
  bytes.writeUInt16LE(Number.parseInt(hex.slice(12, 16), 16), 6);
  Buffer.from(hex.slice(16), "hex").copy(bytes, 8);
  return bytes;
};

const stacks = (layout: Layout) => {
  const main = Buffer.alloc(0x100);
  const render = Buffer.alloc(0x100);
  // A return address into game.exe just above the render thread's rsp.
  render.writeBigUInt64LE(F.gameBase + BigInt(F.returnOffset), 0x10);
  render.writeBigUInt64LE(0xdeadbeefn, 0x18);
  return { main: layout.add(main), render: layout.add(render), size: 0x100 };
};

const threadEntry = (
  id: number,
  stack: { start: bigint; rva: number; size: number },
  context: number,
) => {
  const entry = Buffer.alloc(48);
  entry.writeUInt32LE(id, 0);
  entry.writeUInt32LE(8, 12);
  entry.writeBigUInt64LE(0x7ff0_0000_0000n + BigInt(id), 16);
  entry.writeBigUInt64LE(stack.start, 24);
  entry.writeUInt32LE(stack.size, 32);
  entry.writeUInt32LE(stack.rva, 36);
  entry.writeUInt32LE(1232, 40);
  entry.writeUInt32LE(context, 44);
  return entry;
};

const moduleEntry = (
  layout: Layout,
  module: {
    name: string;
    base: bigint;
    size: number;
    timestamp: number;
    codeView: Buffer | null;
  },
) => {
  const entry = Buffer.alloc(108);
  entry.writeBigUInt64LE(module.base, 0);
  entry.writeUInt32LE(module.size, 8);
  entry.writeUInt32LE(module.timestamp, 16);
  entry.writeUInt32LE(layout.string(module.name), 20);
  entry.writeUInt32LE(0xfeef04bd, 24);
  entry.writeUInt32LE(0x00010002, 32);
  entry.writeUInt32LE(0x00030004, 36);
  if (module.codeView !== null) {
    entry.writeUInt32LE(module.codeView.length, 76);
    entry.writeUInt32LE(layout.add(module.codeView), 80);
  }
  return entry;
};

const counted = (count: number, entries: readonly Buffer[]) => {
  const header = Buffer.alloc(4);
  header.writeUInt32LE(count, 0);
  return Buffer.concat([header, ...entries]);
};

/** Stream type and body, in directory order. */
const buildStreams = (layout: Layout): (readonly [number, Buffer])[] => {
  const system = Buffer.alloc(56);
  system.writeUInt16LE(9, 0);
  system.writeUInt16LE(6, 2);
  system.writeUInt8(8, 6);
  system.writeUInt8(1, 7);
  system.writeUInt32LE(10, 8);
  system.writeUInt32LE(22631, 16);
  system.writeUInt32LE(2, 20);
  system.write("GenuineIntel", 32, "latin1");
  const misc = Buffer.alloc(24);
  misc.writeUInt32LE(24, 0);
  misc.writeUInt32LE(3, 4);
  misc.writeUInt32LE(F.processId, 8);
  misc.writeUInt32LE(1_700_000_000, 12);
  const stack = stacks(layout);
  const mainContext = layout.add(
    amd64Context({
      rip: F.ntdllBase + 0x9d4n,
      rsp: F.mainStack + 0x80n,
      rbp: F.mainStack + 0xc0n,
    }),
  );
  const faultContext = layout.add(
    amd64Context({
      rip: F.gameBase + BigInt(F.faultOffset),
      rsp: F.renderStack + 0x8n,
      rax: 0x10n,
    }),
  );
  const codeView = Buffer.concat([
    Buffer.from("RSDS", "latin1"),
    guidBytes(F.guid),
    Buffer.from([F.age, 0, 0, 0]),
    Buffer.from("C:\\build\\game.pdb\0", "utf8"),
  ]);
  const modules = counted(2, [
    moduleEntry(layout, {
      name: "C:\\Games\\Example\\game.exe",
      base: F.gameBase,
      size: F.gameSize,
      timestamp: F.gameTimestamp,
      codeView,
    }),
    moduleEntry(layout, {
      name: "C:\\Windows\\System32\\ntdll.dll",
      base: F.ntdllBase,
      size: 0x200000,
      timestamp: 0,
      codeView: null,
    }),
  ]);
  const threads = counted(2, [
    threadEntry(
      F.mainThread,
      { start: F.mainStack, rva: stack.main, size: stack.size },
      mainContext,
    ),
    threadEntry(
      F.renderThread,
      { start: F.renderStack, rva: stack.render, size: stack.size },
      faultContext,
    ),
  ]);
  const exception = Buffer.alloc(168);
  exception.writeUInt32LE(F.renderThread, 0);
  exception.writeUInt32LE(0xc0000005, 8);
  exception.writeBigUInt64LE(F.gameBase + BigInt(F.faultOffset), 24);
  exception.writeUInt32LE(2, 32);
  exception.writeBigUInt64LE(1n, 40);
  exception.writeBigUInt64LE(0x10n, 48);
  exception.writeUInt32LE(1232, 160);
  exception.writeUInt32LE(faultContext, 164);
  const memory = counted(
    2,
    (
      [
        [F.mainStack, stack.main],
        [F.renderStack, stack.render],
      ] as const
    ).map(([start, rva]) => {
      const entry = Buffer.alloc(16);
      entry.writeBigUInt64LE(start, 0);
      entry.writeUInt32LE(stack.size, 8);
      entry.writeUInt32LE(rva, 12);
      return entry;
    }),
  );
  const names = counted(
    2,
    [
      [F.mainThread, "MainThread"],
      [F.renderThread, "RenderThread"],
    ].map(([id, name]) => {
      const entry = Buffer.alloc(12);
      entry.writeUInt32LE(Number(id), 0);
      entry.writeBigUInt64LE(BigInt(layout.string(String(name))), 4);
      return entry;
    }),
  );
  const unloaded = Buffer.alloc(12 + 24);
  unloaded.writeUInt32LE(12, 0);
  unloaded.writeUInt32LE(24, 4);
  unloaded.writeUInt32LE(1, 8);
  unloaded.writeBigUInt64LE(0x1_8000_0000n, 12);
  unloaded.writeUInt32LE(0x4000, 20);
  unloaded.writeUInt32LE(
    layout.string("C:\\Games\\Example\\old_plugin.dll"),
    32,
  );
  return [
    [7, system],
    [15, misc],
    [3, threads],
    [4, modules],
    [6, exception],
    [5, memory],
    [24, names],
    [14, unloaded],
    [0x47670009, Buffer.from("unknown stream")],
  ];
};

/** Build the dump; every call returns an identical buffer. */
export const createMinidump = (): Buffer => {
  const layout = new Layout(32);
  const streams = buildStreams(layout).map(
    ([type, body]) => [type, layout.add(body), body.length] as const,
  );
  const directory = Buffer.alloc(streams.length * 12);
  streams.forEach(([type, rva, size], index) => {
    directory.writeUInt32LE(type, index * 12);
    directory.writeUInt32LE(size, index * 12 + 4);
    directory.writeUInt32LE(rva, index * 12 + 8);
  });
  const directoryRva = layout.add(directory);
  const dump = layout.bytes();
  dump.write("MDMP", 0, "latin1");
  dump.writeUInt32LE(0xa793, 4);
  dump.writeUInt32LE(streams.length, 8);
  dump.writeUInt32LE(directoryRva, 12);
  dump.writeUInt32LE(1_700_000_100, 20);
  dump.writeBigUInt64LE(0x1826n, 24);
  return dump;
};

/** RVA of the ModuleList stream's entry count, for corruption tests. */
export const moduleCountRva = (dump: Buffer): number => {
  const count = dump.readUInt32LE(8);
  const directory = dump.readUInt32LE(12);
  for (let index = 0; index < count; index += 1)
    if (dump.readUInt32LE(directory + index * 12) === 4)
      return dump.readUInt32LE(directory + index * 12 + 8);
  throw new Error("fixture has no ModuleList");
};
