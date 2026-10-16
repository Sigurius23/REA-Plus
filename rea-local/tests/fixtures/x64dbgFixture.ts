import { encodeLz4Block } from "./unityCompression.js";

/**
 * An x64dbg program database as DbSave writes it for game.exe (the
 * peImage.ts fixture): json_hex "0x%llX" strings, addresses relative to the
 * module base, one-space indentation, and a legacy "auto" list.
 */
export const X64DBG_DATABASE = {
  comments: [
    {
      module: "game.exe",
      address: "0x1007",
      manual: true,
      text: "null check on the health pointer",
    },
  ],
  labels: [
    { module: "game.exe", address: "0x1000", manual: true, text: "LoadHealth" },
    { module: "game.exe", address: "0x1100", manual: false, text: "helper" },
  ],
  autolabels: [
    { module: "game.exe", address: "0x1011", text: "legacy_return" },
  ],
  bookmarks: [{ module: "game.exe", address: "0x100C", manual: true }],
  functions: [
    {
      module: "game.exe",
      start: "0x1000",
      end: "0x1011",
      manual: true,
      icount: "0x5",
      parent: "0x1000",
    },
    {
      module: "kernel32.dll",
      start: "0x2A10",
      end: "0x2A40",
      manual: false,
      icount: "0xC",
      parent: "0x2A10",
    },
  ],
  arguments: [
    {
      module: "game.exe",
      start: "0x1000",
      end: "0x1007",
      manual: true,
      icount: "0x1",
    },
  ],
  loops: [
    {
      module: "game.exe",
      start: "0x1000",
      end: "0x100A",
      manual: true,
      depth: 0,
      parent: "0x0",
      icount: "0x3",
    },
  ],
  xrefs: [
    {
      module: "game.exe",
      address: "0x1100",
      references: [{ addr: "0x100C", type: "0x2" }],
    },
  ],
  breakpoints: [
    {
      address: "0x1000",
      enabled: true,
      oldbytes: "0x8B48",
      type: 0,
      titantype: "0x0",
      name: "health read",
      module: "game.exe",
      breakCondition: "rax==0",
      logText: "hp={rax}",
      logCondition: "",
      commandText: "",
      commandCondition: "",
      logFile: "",
      fastResume: false,
      silent: false,
    },
    {
      address: "0x1007",
      enabled: false,
      oldbytes: "0x9090",
      type: 0,
      titantype: "0x0",
      name: "",
      module: "game.exe",
      breakCondition: "",
      logText: "",
      logCondition: "",
      commandText: "",
      commandCondition: "",
      logFile: "",
      fastResume: false,
      silent: false,
    },
    {
      address: "0x2000",
      enabled: true,
      memsize: "0x8",
      type: 2,
      titantype: "0x2000",
      name: "health write",
      module: "game.exe",
      breakCondition: "",
      logText: "",
      logCondition: "",
      commandText: "dump rax",
      commandCondition: "1",
      logFile: "",
      fastResume: true,
      silent: true,
    },
    {
      address: "0x0",
      enabled: true,
      type: 3,
      titantype: "0x0",
      name: "",
      module: "steam_api64.dll",
      breakCondition: "",
      logText: "",
      logCondition: "",
      commandText: "",
      commandCondition: "",
      logFile: "",
      fastResume: false,
      silent: false,
    },
  ],
  watch: [
    {
      Expression: "[rax+0x10]",
      Name: "hp",
      DataType: "int",
      WatchdogMode: "Changed",
      watchdog: 0,
    },
  ],
  modules: [{ hash: "0x1C2B3A4D5E6F7081", party: 0 }],
  notes: "Health lives at [rip+0xff9]; the check at 0x1007 skips the helper.",
  initscript: "C:\\scripts\\init.txt",
  plugins: { xAnalyzer: { version: 1 } },
  hashAlgorithm: "murmurhash",
  hash: "0xDEADBEEF12345678",
};

export const createX64dbgDatabase = (
  database: object = X64DBG_DATABASE,
): Buffer => Buffer.from(JSON.stringify(database, null, 1), "utf8");

/** x64dbg's lz4file: magic 0x184C2102, then [compressed size][LZ4 block] per chunk. */
export const compressX64dbgDatabase = (
  json: Buffer,
  blockSize = 8 << 20,
): Buffer => {
  const parts: Buffer[] = [Buffer.from([0x02, 0x21, 0x4c, 0x18])];
  for (let at = 0; at < json.length; at += blockSize) {
    const block = encodeLz4Block(json.subarray(at, at + blockSize));
    const size = Buffer.alloc(4);
    size.writeUInt32LE(block.length);
    parts.push(size, block);
  }
  return Buffer.concat(parts);
};
