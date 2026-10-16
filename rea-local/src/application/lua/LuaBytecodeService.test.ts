import { expect, it } from "vitest";

import { createAnalysisExecution } from "../AnalysisProvider.js";
import type { LuaBytecodeReport } from "../../domain/lua/luaBytecode.js";
import { ok } from "../../domain/result.js";
import { LuaBytecodeService } from "./LuaBytecodeService.js";

const PATH = "/games/mod/main.luac";
const DIGEST = "a".repeat(64);
const instruction = (
  fn: string,
): LuaBytecodeReport["instructions"][number] => ({
  function: fn,
  pc: 1,
  line: 1,
  op: "RETURN",
  operands: "0 1",
  comment: null,
  target: null,
  fields: { a: 0, b: 1, c: 0 },
});
const report = (): LuaBytecodeReport => ({
  file: { path: PATH, sha256: DIGEST, bytes: 10 },
  chunk: {
    offset: 0,
    length: 10,
    dialect: "lua5.1",
    version: "0x51",
    format: 0,
    byte_order: "little",
    sizes: { int: 4 },
    flags: [],
    chunk_name: null,
    stripped: true,
  },
  summary: {
    functions: 2,
    instructions: 2,
    constants: 0,
    strings: 0,
    locals: 0,
    upvalues: 0,
    named_functions: 0,
    unknown_opcodes: 0,
  },
  page: {
    view: "instructions",
    function: "0/0",
    query: null,
    offset: 0,
    limit: 1,
    total: 1,
    returned: 1,
  },
  functions: [],
  instructions: [instruction("0/0")],
  constants: [],
  locals: [],
  upvalues: [],
  chunks: [],
  limitations: [],
});
const service = (value: LuaBytecodeReport) =>
  new LuaBytecodeService({
    close: () => Promise.resolve(),
    inspect: () =>
      Promise.resolve(
        ok(
          createAnalysisExecution(
            value,
            { id: "lua", name: "lua", version: "1" },
            { subject: { path: PATH, format: "file", sha256: DIGEST } },
          ),
        ),
      ),
  });
const INPUT = { path: PATH, view: "instructions", function: "0/0", limit: 1 };

it.each([
  { path: "main.luac" },
  { path: PATH, view: "decompile" },
  { path: PATH, function: "main" },
  { path: PATH, chunk_offset: -1 },
  { path: PATH, limit: 0 },
])("rejects invalid selection before effects: %j", async (input) => {
  const unused = new LuaBytecodeService({
    close: () => Promise.resolve(),
    inspect: () => {
      throw new Error("Must not execute");
    },
  });
  expect(await unused.inspect(input)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
});

it.each([
  "path",
  "view",
  "function",
  "rows",
  "page",
  "digest",
  "offset",
  "other view",
])("rejects a report that drifts from the request: %s", async (problem) => {
  const value = report();
  if (problem === "path") value.file.path = "/other.luac";
  if (problem === "view") value.page.view = "constants";
  if (problem === "function") value.instructions = [instruction("0")];
  if (problem === "rows") value.instructions.push(instruction("0/0"));
  if (problem === "page") value.page.offset = 2;
  if (problem === "digest") value.file.sha256 = "b".repeat(64);
  if (problem === "offset" && value.chunk !== null) value.chunk.offset = 4;
  if (problem === "other view")
    value.locals = [{ function: "0/0", name: "x", start_pc: 1, end_pc: 2 }];
  expect(await service(value).inspect(INPUT)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisOutputError" },
  });
});

it("records the chunk as observed Evidence", async () => {
  expect(await service(report()).inspect(INPUT)).toMatchObject({
    ok: true,
    value: { operation: "inspect_lua_bytecode", confidence: "observed" },
  });
});
