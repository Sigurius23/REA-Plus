import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createLuaBytecodeService } from "../../../../src/composition/lua.js";
import type { LuaBytecodeReport } from "../../../../src/domain/lua/luaBytecode.js";
import {
  abc53,
  abc54,
  abcJit,
  abx53,
  abx54,
  ad,
  asbx53,
  dump51,
  dump53,
  dump54,
  dumpJit,
  OP51,
  OP53,
  OP54,
  OPJIT,
  sj54,
  type FixtureProto,
  type JitProto,
} from "../../../fixtures/luaFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const K = 256;
const proto = (
  values: Partial<FixtureProto> & Pick<FixtureProto, "code">,
): FixtureProto => ({
  source: null,
  line: 0,
  lastLine: 0,
  params: 0,
  vararg: false,
  maxStack: 2,
  lines: [],
  constants: [],
  upvalues: [],
  locals: [],
  children: [],
  ...values,
});

/** print("hi"); function greet(n) return n + 1 end; greet(2) */
const LUA51 = proto({
  source: "@game.lua",
  vararg: true,
  code: [
    abx53(OP51.GETGLOBAL, 0, 0),
    abx53(OP51.LOADK, 1, 1),
    abc53(OP51.CALL, 0, 2, 1),
    abx53(OP51.CLOSURE, 0, 0),
    abx53(OP51.SETGLOBAL, 0, 2),
    abx53(OP51.GETGLOBAL, 0, 2),
    abx53(OP51.LOADK, 1, 3),
    abc53(OP51.CALL, 0, 2, 1),
    asbx53(OP51.JMP, 0, 0),
    abc53(OP51.RETURN, 0, 1, 0),
  ],
  lines: [1, 1, 1, 2, 2, 3, 3, 3, 3, 3],
  constants: [
    ["str", "print"],
    ["str", "hi"],
    ["str", "greet"],
    ["num", 2],
    ["nil"],
    ["bool", true],
  ],
  children: [
    proto({
      line: 2,
      lastLine: 2,
      params: 1,
      code: [
        abc53(OP51.ADD, 1, 0, K | 0),
        abc53(OP51.RETURN, 1, 2, 0),
        abc53(OP51.RETURN, 0, 1, 0),
      ],
      lines: [2, 2, 2],
      constants: [["num", 1]],
      locals: [{ name: "n", start: 0, end: 3 }],
    }),
  ],
});

/** print(42); function onTick() return count end */
const LUA53 = proto({
  source: "@tick.lua",
  vararg: true,
  code: [
    abc53(OP53.GETTABUP, 0, 0, K | 0),
    abx53(OP53.LOADK, 1, 1),
    abc53(OP53.CALL, 0, 2, 1),
    abx53(OP53.CLOSURE, 0, 0),
    abc53(OP53.SETTABUP, 0, K | 2, 0),
    abc53(OP53.RETURN, 0, 1, 0),
  ],
  lines: [1, 1, 1, 2, 2, 2],
  constants: [
    ["str", "print"],
    ["int", 42n],
    ["str", "onTick"],
    ["num", 1.5],
  ],
  upvalues: [{ name: "_ENV", inStack: true, slot: 0 }],
  children: [
    proto({
      line: 2,
      lastLine: 2,
      code: [abc53(OP53.GETUPVAL, 0, 0, 0), abc53(OP53.RETURN, 0, 2, 0)],
      lines: [2, 2],
      upvalues: [{ name: "count", inStack: true, slot: 1 }],
    }),
  ],
});

/** local M = {}; function M.update(a, b) end; ... */
const LUA54 = proto({
  source: "@mod.lua",
  vararg: true,
  maxStack: 4,
  code: [
    abc54(OP54.VARARGPREP, 0, 0, 0),
    abc54(OP54.NEWTABLE, 0, 0, 0),
    abx54(OP54.EXTRAARG, 0, 0),
    abx54(OP54.CLOSURE, 1, 0),
    abc54(OP54.SETFIELD, 0, 0, 1),
    abx54(OP54.LOADI, 2, -5 + 65535),
    sj54(OP54.JMP, 1),
    abc54(OP54.GETTABUP, 3, 0, 1),
    abc54(OP54.RETURN0, 0, 0, 0),
  ],
  lines: [1, 1, 1, 2, 2, 3, 3, 4, 4],
  constants: [
    ["str", "update"],
    ["str", "print"],
    ["int", 7n],
    ["num", 0.25],
    ["bool", true],
    ["bool", false],
    ["nil"],
  ],
  upvalues: [{ name: "_ENV", inStack: true, slot: 0 }],
  locals: [{ name: "M", start: 3, end: 9 }],
  children: [
    proto({
      line: 2,
      lastLine: 2,
      params: 2,
      code: [abc54(OP54.RETURN0, 0, 0, 0)],
      lines: [2],
    }),
  ],
});

const JIT_CHILD: JitProto = {
  flags: 0,
  params: 1,
  frameSize: 2,
  code: [ad(OPJIT.KSHORT, 1, 0xffff), ad(OPJIT.RET0, 0, 1)],
  gc: [],
  numbers: [],
  upvalues: [],
  firstLine: 2,
  lines: [2, 2],
  locals: [{ name: "x", start: 0, length: 3 }],
};
const JIT_MAIN: JitProto = {
  flags: 0x02,
  params: 0,
  frameSize: 3,
  code: [
    ad(OPJIT.FNEW, 0, 0),
    ad(OPJIT.GSET, 0, 1),
    ad(OPJIT.GGET, 0, 2),
    ad(OPJIT.KSTR, 1, 3),
    ad(OPJIT.KNUM, 2, 0),
    abcJit(OPJIT.CALL, 0, 1, 3),
    ad(OPJIT.JMP, 0, 0x7fff + 1),
    ad(OPJIT.RET0, 0, 1),
  ],
  gc: [["child"], ["str", "onLoad"], ["str", "print"], ["str", "hello"]],
  numbers: [
    ["num", 2.5],
    ["int", 7],
  ],
  upvalues: [],
  firstLine: 0,
  lines: [2, 2, 4, 4, 4, 4, 5, 5],
  locals: [],
};

const service = createLuaBytecodeService();
let root = "";
const paths = {
  lua51: "",
  lua51be: "",
  lua53: "",
  lua54: "",
  jit: "",
  jitStripped: "",
  jitBe: "",
  embedded: "",
};
const offsets = { lua53: 0, jit: 0 };

beforeAll(async () => {
  root = (await createTestWorkspace("rea-lua-")).root;
  const files: Record<keyof typeof paths, Buffer> = {
    lua51: dump51(LUA51),
    lua51be: dump51(LUA51, { littleEndian: false, sizeT: 4 }),
    lua53: dump53(LUA53),
    lua54: dump54(LUA54, [0]),
    jit: dumpJit([JIT_CHILD, JIT_MAIN]),
    jitStripped: dumpJit([JIT_CHILD, JIT_MAIN], { strip: true }),
    jitBe: dumpJit([JIT_CHILD, JIT_MAIN], { littleEndian: false }),
    embedded: Buffer.alloc(0),
  };
  const prefix = Buffer.from("PAK\0assets/scripts/tick.luac\0");
  offsets.lua53 = prefix.length;
  offsets.jit = prefix.length + files.lua53.length + 7;
  files.embedded = Buffer.concat([
    prefix,
    files.lua53,
    Buffer.from("\x1bLua\x99xx", "latin1"),
    files.jit,
  ]);
  for (const [name, bytes] of Object.entries(files)) {
    paths[name as keyof typeof paths] = join(root, `${name}.bin`);
    await writeFile(paths[name as keyof typeof paths], bytes);
  }
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as LuaBytecodeReport;
};
const listing = (report: LuaBytecodeReport) =>
  report.instructions.map(({ pc, op, operands }) => [pc, op, operands]);

describe("PUC Lua 5.1 chunks", () => {
  it("reads the header, function tree and name hints", async () => {
    const report = await inspect({ path: paths.lua51 });
    expect(report.chunk).toMatchObject({
      dialect: "lua5.1",
      version: "0x51",
      byte_order: "little",
      sizes: { int: 4, size_t: 8, instruction: 4, lua_Number: 8 },
      chunk_name: "@game.lua",
      stripped: false,
    });
    expect(
      report.functions.map(
        ({
          id,
          parent,
          name_hint,
          params,
          vararg,
          instructions,
          constants,
          locals,
        }) => [
          id,
          parent,
          name_hint,
          params,
          vararg,
          instructions,
          constants,
          locals,
        ],
      ),
    ).toEqual([
      ["0", null, "main", 0, true, 10, 6, 0],
      ["0/0", "0", "greet", 1, false, 3, 1, 1],
    ]);
    expect(report.summary).toMatchObject({
      functions: 2,
      instructions: 13,
      strings: 3,
      named_functions: 1,
      unknown_opcodes: 0,
    });
  });

  it("lists instructions as luac -l prints them", async () => {
    const report = await inspect({
      path: paths.lua51,
      view: "instructions",
      function: "0",
    });
    expect(listing(report)).toEqual([
      [1, "GETGLOBAL", "0 -1"],
      [2, "LOADK", "1 -2"],
      [3, "CALL", "0 2 1"],
      [4, "CLOSURE", "0 0"],
      [5, "SETGLOBAL", "0 -3"],
      [6, "GETGLOBAL", "0 -3"],
      [7, "LOADK", "1 -4"],
      [8, "CALL", "0 2 1"],
      [9, "JMP", "0"],
      [10, "RETURN", "0 1"],
    ]);
    expect(
      report.instructions.map(({ comment }) => comment).slice(0, 5),
    ).toEqual(["print", '"hi"', null, "function 0/0", "greet"]);
    expect(report.instructions[8]).toMatchObject({
      target: 10,
      line: 3,
      fields: { a: 0, sbx: 0 },
    });
    const child = await inspect({
      path: paths.lua51,
      view: "instructions",
      function: "0/0",
    });
    expect(child.instructions[0]).toMatchObject({
      op: "ADD",
      operands: "1 0 -1",
      comment: "1",
    });
  });

  it("lists constants and locals, and reads big-endian 32-bit chunks alike", async () => {
    const constants = await inspect({
      path: paths.lua51,
      view: "constants",
      function: "0",
    });
    expect(constants.constants.map(({ type, value }) => [type, value])).toEqual(
      [
        ["string", "print"],
        ["string", "hi"],
        ["string", "greet"],
        ["number", "2"],
        ["nil", "nil"],
        ["boolean", "true"],
      ],
    );
    const locals = await inspect({ path: paths.lua51, view: "locals" });
    expect(locals.locals).toEqual([
      { function: "0/0", name: "n", start_pc: 1, end_pc: 4 },
    ]);
    const big = await inspect({
      path: paths.lua51be,
      view: "instructions",
      function: "0",
    });
    expect(big.chunk).toMatchObject({
      byte_order: "big",
      sizes: { size_t: 4 },
    });
    const little = await inspect({
      path: paths.lua51,
      view: "instructions",
      function: "0",
    });
    expect(big.instructions).toEqual(little.instructions);
  });
});

describe("PUC Lua 5.3 and 5.4 chunks", () => {
  it("reads 5.3 integers, upvalues and _ENV globals", async () => {
    const report = await inspect({ path: paths.lua53, view: "instructions" });
    expect(listing(report)).toEqual([
      [1, "GETTABUP", "0 0 -1"],
      [2, "LOADK", "1 -2"],
      [3, "CALL", "0 2 1"],
      [4, "CLOSURE", "0 0"],
      [5, "SETTABUP", "0 -3 0"],
      [6, "RETURN", "0 1"],
      [1, "GETUPVAL", "0 0"],
      [2, "RETURN", "0 2"],
    ]);
    expect(report.instructions[0]?.comment).toBe('_ENV "print"');
    expect(report.instructions[6]).toMatchObject({
      function: "0/0",
      comment: "count",
    });
    const functions = await inspect({ path: paths.lua53 });
    expect(functions.functions[1]?.name_hint).toBe("onTick");
    const constants = await inspect({
      path: paths.lua53,
      view: "constants",
      function: "0",
    });
    expect(constants.constants.map(({ type, value }) => [type, value])).toEqual(
      [
        ["string", "print"],
        ["integer", "42"],
        ["string", "onTick"],
        ["number", "1.5"],
      ],
    );
    const upvalues = await inspect({ path: paths.lua53, view: "upvalues" });
    expect(upvalues.upvalues).toEqual([
      {
        function: "0",
        index: 0,
        name: "_ENV",
        in_stack: true,
        slot: 0,
        kind: null,
      },
      {
        function: "0/0",
        index: 0,
        name: "count",
        in_stack: true,
        slot: 1,
        kind: null,
      },
    ]);
  });

  it("reads 5.4 varints, line info, kinds and per-opcode operands", async () => {
    const report = await inspect({
      path: paths.lua54,
      view: "instructions",
      function: "0",
    });
    expect(report.chunk).toMatchObject({
      dialect: "lua5.4",
      sizes: { instruction: 4, lua_Integer: 8, lua_Number: 8 },
    });
    expect(listing(report)).toEqual([
      [1, "VARARGPREP", "0"],
      [2, "NEWTABLE", "0 0 0"],
      [3, "EXTRAARG", "0"],
      [4, "CLOSURE", "1 0"],
      [5, "SETFIELD", "0 0 1"],
      [6, "LOADI", "2 -5"],
      [7, "JMP", "1"],
      [8, "GETTABUP", "3 0 1"],
      [9, "RETURN0", ""],
    ]);
    expect(report.instructions.map(({ line }) => line)).toEqual([
      1, 1, 1, 2, 2, 3, 3, 4, 4,
    ]);
    expect(report.instructions[6]?.target).toBe(9);
    expect(report.instructions[4]?.comment).toBe('"update"');
    const functions = await inspect({ path: paths.lua54 });
    expect(functions.functions[1]).toMatchObject({
      name_hint: "M.update",
      params: 2,
    });
    const constants = await inspect({
      path: paths.lua54,
      view: "constants",
      query: "0.25",
    });
    expect(constants.constants).toEqual([
      {
        function: "0",
        pool: "k",
        index: 3,
        type: "number",
        value: "0.25",
        binary: false,
      },
    ]);
    const upvalues = await inspect({ path: paths.lua54, view: "upvalues" });
    expect(upvalues.upvalues[0]).toMatchObject({ name: "_ENV", kind: 0 });
  });
});

describe("LuaJIT dumps", () => {
  it("reads prototypes children first and lists them as luajit -bl does", async () => {
    const report = await inspect({ path: paths.jit, view: "instructions" });
    expect(report.chunk).toMatchObject({
      dialect: "luajit2.1",
      version: "2",
      flags: ["fr2"],
      chunk_name: "@game.lua",
      stripped: false,
    });
    expect(listing(report)).toEqual([
      [1, "FNEW", "0 0"],
      [2, "GSET", "0 1"],
      [3, "GGET", "0 2"],
      [4, "KSTR", "1 3"],
      [5, "KNUM", "2 0"],
      [6, "CALL", "0 1 3"],
      [7, "JMP", "0 => 0008"],
      [8, "RET0", "0 1"],
      [1, "KSHORT", "1 -1"],
      [2, "RET0", "0 1"],
    ]);
    expect(
      report.instructions.map(({ comment }) => comment).slice(0, 5),
    ).toEqual(["function 0/0", '"onLoad"', '"print"', '"hello"', "2.5"]);
    expect(report.instructions[6]?.target).toBe(8);
    const functions = await inspect({ path: paths.jit });
    expect(
      functions.functions.map(({ id, name_hint, params, vararg }) => [
        id,
        name_hint,
        params,
        vararg,
      ]),
    ).toEqual([
      ["0", "main", 0, true],
      ["0/0", "onLoad", 1, false],
    ]);
    const constants = await inspect({
      path: paths.jit,
      view: "constants",
      function: "0",
    });
    expect(
      constants.constants.map(({ pool, index, type, value }) => [
        pool,
        index,
        type,
        value,
      ]),
    ).toEqual([
      ["gc", 0, "function", "0/0"],
      ["gc", 1, "string", "onLoad"],
      ["gc", 2, "string", "print"],
      ["gc", 3, "string", "hello"],
      ["num", 0, "number", "2.5"],
      ["num", 1, "number", "7"],
    ]);
    const locals = await inspect({ path: paths.jit, view: "locals" });
    expect(locals.locals).toEqual([
      { function: "0/0", name: "x", start_pc: 0, end_pc: 3 },
    ]);
  });

  it("reads stripped and big-endian dumps", async () => {
    const stripped = await inspect({
      path: paths.jitStripped,
      view: "instructions",
    });
    expect(stripped.chunk).toMatchObject({
      flags: ["strip", "fr2"],
      chunk_name: null,
      stripped: true,
    });
    expect(stripped.instructions.every(({ line }) => line === null)).toBe(true);
    const full = await inspect({ path: paths.jit, view: "instructions" });
    expect(listing(stripped)).toEqual(listing(full));
    const big = await inspect({ path: paths.jitBe, view: "instructions" });
    expect(big.chunk).toMatchObject({
      byte_order: "big",
      flags: ["big-endian", "fr2"],
    });
    expect(listing(big)).toEqual(listing(full));
  });
});

describe("embedded chunks and refusals", () => {
  it("finds chunks inside a data file and reads one by offset", async () => {
    const scan = await inspect({ path: paths.embedded, view: "chunks" });
    expect(scan.chunk).toBeNull();
    expect(
      scan.chunks.map(({ offset, dialect, functions, error }) => [
        offset,
        dialect,
        functions,
        error === null,
      ]),
    ).toEqual([
      [offsets.lua53, "lua5.3", 2, true],
      [offsets.lua53 + dump53(LUA53).length, null, null, false],
      [offsets.jit, "luajit2.1", 2, true],
    ]);
    const jit = await inspect({
      path: paths.embedded,
      chunk_offset: offsets.jit,
    });
    expect(jit.chunk).toMatchObject({
      offset: offsets.jit,
      dialect: "luajit2.1",
      length: dumpJit([JIT_CHILD, JIT_MAIN]).length,
    });
  });

  it("refuses files and selections that are not readable chunks", async () => {
    const cases: Record<string, Buffer> = {
      "source.lua": Buffer.from("print('hello')\n"),
      "luau.bin": Buffer.from([6, 3, 1, 2, 3]),
      "future.luac": Buffer.concat([
        Buffer.from("\x1bLua\x55\x00", "latin1"),
        Buffer.alloc(20),
      ]),
      "truncated.luac": dump53(LUA53).subarray(0, 60),
      "corrupt.luac": Buffer.concat([
        Buffer.from("\x1bLua\x53\x00\x19\x93\n\n\x1a\n", "latin1"),
        Buffer.alloc(40),
      ]),
    };
    for (const [name, bytes] of Object.entries(cases)) {
      const path = join(root, name);
      await writeFile(path, bytes);
      expect(await service.inspect({ path }), name).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisInputError",
          issues: [
            {
              path: ["path"],
              message: expect.stringContaining("Not readable Lua bytecode"),
            },
          ],
        },
      });
    }
    expect(
      JSON.stringify(await service.inspect({ path: paths.embedded })),
    ).toContain(`signatures were found at ${String(offsets.lua53)}`);
    expect(
      await service.inspect({ path: paths.lua51, function: "0/9" }),
    ).toMatchObject({ ok: false, error: { issues: [{ path: ["function"] }] } });
    expect(
      await service.inspect({ path: paths.lua51, chunk_offset: 1_000_000 }),
    ).toMatchObject({
      ok: false,
      error: { issues: [{ path: ["chunk_offset"] }] },
    });
  });
});

/** A folder of Lua sources; each configured compiler builds them (with and without debug info) and lists them. */
const CORPUS = process.env["REA_VERIFY_LUA_SOURCES"];
const COMPILERS = [
  ["lua5.1", 0x51, process.env["REA_VERIFY_LUAC51"]],
  ["lua5.2", 0x52, process.env["REA_VERIFY_LUAC52"]],
  ["lua5.3", 0x53, process.env["REA_VERIFY_LUAC53"]],
  ["lua5.4", 0x54, process.env["REA_VERIFY_LUAC54"]],
  ["luajit2.1", 2, process.env["REA_VERIFY_LUAJIT"]],
] as const;

/** Every row of every view, paging past the 1000-row limit. */
const everything = async (path: string) => {
  const views = [
    "functions",
    "instructions",
    "constants",
    "locals",
    "upvalues",
  ] as const;
  const out: Record<string, unknown[]> = {};
  for (const view of views) {
    const rows: unknown[] = [];
    for (let offset = 0; ; offset += 1000) {
      const report = await inspect({ path, view, offset, limit: 1000 });
      rows.push(...report[view]);
      if (offset + 1000 >= report.page.total) break;
    }
    out[view] = rows;
  }
  return out as unknown as Pick<LuaBytecodeReport, (typeof views)[number]>;
};

describe.skipIf(CORPUS === undefined)(
  "chunks built by real Lua compilers",
  () => {
    it.each(COMPILERS.filter(([, , bin]) => bin !== undefined))(
      "decodes %s chunks as the compiler lists them",
      async (dialect, version, bin) => {
        const { execFile } = await import("node:child_process");
        const { readdir } = await import("node:fs/promises");
        const { promisify } = await import("node:util");
        const run = promisify(execFile);
        const {
          parseLuacListing,
          projectPuc,
          parseLuajitListing,
          projectJit,
          jitStringsOnly,
        } = await import("../../../support/lua/luaListings.js");
        const entries = await readdir(CORPUS ?? "", {
          recursive: true,
          withFileTypes: true,
        });
        const sources = entries
          .filter((entry) => entry.isFile() && entry.name.endsWith(".lua"))
          .map((entry) => join(entry.parentPath, entry.name));
        let compared = 0;
        for (const [index, source] of sources.entries())
          for (const strip of [false, true]) {
            const out = join(
              root,
              `corpus-${String(index)}-${strip ? "s" : "g"}.out`,
            );
            const jit = dialect === "luajit2.1";
            try {
              await run(
                bin ?? "",
                jit
                  ? [strip ? "-bs" : "-bg", source, out]
                  : [...(strip ? ["-s"] : []), "-o", out, source],
                { cwd: root },
              );
            } catch {
              continue; // Not valid for this Lua version.
            }
            const { stdout } = await run(
              bin ?? "",
              jit ? ["-bl", out] : ["-p", "-l", "-l", out],
              // -p: list without writing luac.out; cwd keeps any stray output in the workspace.
              { cwd: root, encoding: "latin1", maxBuffer: 256 * 1024 * 1024 },
            );
            const report = await everything(out);
            if (jit) {
              const theirs = parseLuajitListing(stdout);
              const ours = projectJit(report);
              expect(ours, source).toEqual(jitStringsOnly(theirs, ours));
            } else
              expect(projectPuc(report, version), source).toEqual(
                parseLuacListing(stdout, version),
              );
            compared += 1;
          }
        expect(compared).toBeGreaterThan(0);
      },
      3_600_000,
    );
  },
);
