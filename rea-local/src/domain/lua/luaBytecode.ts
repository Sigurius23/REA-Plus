import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const text = z.string().nullable();

export const LUA_VIEWS = [
  "functions",
  "instructions",
  "constants",
  "locals",
  "upvalues",
  "chunks",
] as const;

export const LUA_DIALECTS = [
  "lua5.1",
  "lua5.2",
  "lua5.3",
  "lua5.4",
  "luajit2.0",
  "luajit2.1",
] as const;

export const LUA_PAGE_LIMIT = 1000;

export const inspectLuaBytecodeInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute file holding a compiled Lua chunk (luac output, string.dump, luajit -b), or game data with chunks embedded",
    ),
  chunk_offset: count
    .optional()
    .describe(
      "Byte offset of the chunk inside the file; the chunks view lists candidates. Defaults to 0.",
    ),
  view: z
    .enum(LUA_VIEWS)
    .default("functions")
    .describe(
      "functions: the function tree with name hints, lines, parameters and sizes; instructions: the listing with opcodes, luac/luajit-style operands, constants and jump targets; constants; locals; upvalues; chunks: every chunk signature in the file and whether it reads.",
    ),
  function: z
    .string()
    .regex(/^0(\/\d+)*$/u)
    .optional()
    .describe(
      "Function id such as 0 (the main chunk) or 0/2/1; keeps that function's rows",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of names, opcodes, operands, comments or constant values",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(LUA_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

export const luaFunctionSchema = z.strictObject({
  id: z.string(),
  parent: text,
  name_hint: text.describe(
    "Where the code stores the function: a global, table field or named local. A heuristic.",
  ),
  source: text,
  line_defined: count,
  last_line_defined: count,
  params: count,
  vararg: z.boolean(),
  max_stack: count,
  instructions: count,
  constants: count,
  upvalues: count,
  locals: count,
  children: count,
});

export const luaInstructionSchema = z.strictObject({
  function: z.string(),
  pc: count.describe("1-based, as luac -l and luajit -bl number them."),
  line: count.nullable(),
  op: z.string(),
  operands: z
    .string()
    .describe(
      "Operands as luac -l (PUC Lua) or luajit -bl (LuaJIT) prints them.",
    ),
  comment: text.describe(
    "Constants, upvalue names, child functions the instruction refers to.",
  ),
  target: count.nullable().describe("pc a jump or loop instruction goes to."),
  fields: z.record(z.string(), z.number().int()),
});

export const luaConstantSchema = z.strictObject({
  function: z.string(),
  pool: z
    .enum(["k", "gc", "num"])
    .describe(
      "k for PUC Lua; LuaJIT keeps GC objects (gc) and numbers (num) apart.",
    ),
  index: count,
  type: z.enum([
    "nil",
    "boolean",
    "number",
    "integer",
    "string",
    "table",
    "function",
    "int64",
    "uint64",
    "complex",
  ]),
  value: z.string(),
  binary: z.boolean().describe("A string that is not UTF-8, shown as Latin-1."),
});

export const luaLocalSchema = z.strictObject({
  function: z.string(),
  name: z.string(),
  start_pc: count,
  end_pc: count,
});

export const luaUpvalueSchema = z.strictObject({
  function: z.string(),
  index: count,
  name: text,
  in_stack: z.boolean().nullable(),
  slot: count.nullable(),
  kind: count.nullable(),
});

export const luaChunkRowSchema = z.strictObject({
  offset: count,
  dialect: z.enum(LUA_DIALECTS).nullable(),
  length: count.nullable(),
  functions: count.nullable(),
  chunk_name: text,
  error: text,
});

export const luaBytecodeSchema = z.strictObject({
  file: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
  }),
  chunk: z
    .strictObject({
      offset: count,
      length: count,
      dialect: z.enum(LUA_DIALECTS),
      version: z
        .string()
        .describe("Version byte, e.g. 0x51, or the LuaJIT dump version."),
      format: count,
      byte_order: z.enum(["little", "big"]),
      sizes: z.record(z.string(), count),
      flags: z.array(z.string()),
      chunk_name: text,
      stripped: z.boolean(),
    })
    .nullable()
    .describe(
      "Null in the chunks view of a file whose selected offset holds no chunk.",
    ),
  summary: z.strictObject({
    functions: count,
    instructions: count,
    constants: count,
    strings: count,
    locals: count,
    upvalues: count,
    named_functions: count.describe("Functions with a name hint."),
    unknown_opcodes: count.describe(
      "Instructions whose opcode is not in the dialect's table: a modified VM, or not this dialect.",
    ),
  }),
  page: z.strictObject({
    view: z.enum(LUA_VIEWS),
    function: text,
    query: text,
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  functions: z.array(luaFunctionSchema),
  instructions: z.array(luaInstructionSchema),
  constants: z.array(luaConstantSchema),
  locals: z.array(luaLocalSchema),
  upvalues: z.array(luaUpvalueSchema),
  chunks: z.array(luaChunkRowSchema),
  limitations: z.array(z.string()),
});

export type InspectLuaBytecodeInput = z.output<
  typeof inspectLuaBytecodeInputSchema
>;
export type LuaBytecodeReport = z.output<typeof luaBytecodeSchema>;
