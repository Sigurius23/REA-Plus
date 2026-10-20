import type {
  InspectLuaBytecodeInput,
  LuaBytecodeReport,
} from "../domain/lua/luaBytecode.js";
import { readPucChunk } from "./LuaChunk.js";
import { readLuaJitChunk } from "./LuaJitChunk.js";
import { decodeLuaJitCode } from "./LuaJitOpcodes.js";
import { allProtos, type LuaChunk, type LuaProto } from "./LuaModel.js";
import { childNameHints } from "./LuaNames.js";
import { decodePucCode, type LuaInstruction } from "./LuaOpcodes.js";
import {
  findChunkStarts,
  isChunkStart,
  LuaFormatError,
  LuaSelectionError,
} from "./LuaReader.js";

type Report = LuaBytecodeReport;
type View = InspectLuaBytecodeInput["view"];
type Rows = Pick<Report, View>;

const MAX_SCANNED_CHUNKS = 1000;

/** Read the chunk that starts at `start`, whichever VM wrote it. */
export const readChunk = (bytes: Buffer, start: number): LuaChunk => {
  if (!isChunkStart(bytes, start)) {
    const found = findChunkStarts(bytes, 8);
    throw new LuaFormatError(
      found.length === 0
        ? "No Lua or LuaJIT chunk signature (ESC Lua / ESC LJ) in the file; source files and Luau bytecode are not read."
        : `No chunk starts at offset ${String(start)}; signatures were found at ${found.join(", ")} (use chunk_offset).`,
    );
  }
  return bytes[start + 2] === 0x4a
    ? readLuaJitChunk(bytes, start)
    : readPucChunk(bytes, start);
};

interface Decoded {
  readonly chunk: LuaChunk;
  readonly protos: readonly LuaProto[];
  readonly code: ReadonlyMap<string, readonly LuaInstruction[]>;
  readonly hints: ReadonlyMap<string, string>;
}

const decode = (chunk: LuaChunk): Decoded => {
  const jit = chunk.dialect.startsWith("luajit");
  const bitop = chunk.flags.includes("bitop");
  const protos = allProtos(chunk.main);
  const code = new Map<string, readonly LuaInstruction[]>();
  const hints = new Map<string, string>();
  for (const proto of protos) {
    const listing = jit
      ? decodeLuaJitCode(chunk.version, bitop, proto)
      : decodePucCode(chunk.version, proto);
    code.set(proto.id, listing);
    for (const [id, name] of childNameHints(proto, listing, {
      jit,
      version: chunk.version,
    }))
      hints.set(id, name);
  }
  return { chunk, protos, code, hints };
};

const matches = (
  query: string | undefined,
  ...values: readonly (string | null | undefined)[]
): boolean =>
  query === undefined ||
  values.some(
    (value) => value?.toLowerCase().includes(query.toLowerCase()) === true,
  );

const functionRows = (decoded: Decoded): Report["functions"] =>
  decoded.protos.map((proto) => ({
    id: proto.id,
    parent: proto.parent,
    name_hint:
      proto.parent === null ? "main" : (decoded.hints.get(proto.id) ?? null),
    source: proto.source,
    line_defined: proto.lineDefined,
    last_line_defined: proto.lastLineDefined,
    params: proto.params,
    vararg: proto.vararg,
    max_stack: proto.maxStack,
    instructions: proto.code.length,
    constants: proto.constants.length,
    upvalues: proto.upvalues.length,
    locals: proto.locals.length,
    children: proto.children.length,
  }));

const rowsOf = (
  decoded: Decoded,
  input: InspectLuaBytecodeInput,
): readonly unknown[] => {
  const { query } = input;
  const selected = decoded.protos.filter(
    (proto) => input.function === undefined || proto.id === input.function,
  );
  switch (input.view) {
    case "functions":
      return functionRows(decoded).filter(
        (row) =>
          (input.function === undefined || row.id === input.function) &&
          matches(query, row.id, row.name_hint, row.source),
      );
    case "instructions":
      return selected.flatMap((proto) =>
        (decoded.code.get(proto.id) ?? [])
          .filter((ins) => matches(query, ins.op, ins.operands, ins.comment))
          .map((ins) => ({ function: proto.id, ...ins })),
      );
    case "constants":
      return selected.flatMap((proto) =>
        proto.constants
          .filter((k) => matches(query, k.value, k.type))
          .map((k) => ({ function: proto.id, ...k })),
      );
    case "locals":
      return selected.flatMap((proto) =>
        proto.locals
          .filter((local) => matches(query, local.name))
          .map((local) => ({
            function: proto.id,
            name: local.name,
            start_pc: local.startPc,
            end_pc: local.endPc,
          })),
      );
    default:
      return selected.flatMap((proto) =>
        proto.upvalues
          .filter((upvalue) => matches(query, upvalue.name))
          .map((upvalue) => ({
            function: proto.id,
            index: upvalue.index,
            name: upvalue.name,
            in_stack: upvalue.inStack,
            slot: upvalue.slot,
            kind: upvalue.kind,
          })),
      );
  }
};

/** Every chunk signature in the file, read where possible. */
const chunkRows = (
  bytes: Buffer,
  query: string | undefined,
): Report["chunks"] =>
  findChunkStarts(bytes, MAX_SCANNED_CHUNKS)
    .map((offset) => {
      try {
        const chunk = readChunk(bytes, offset);
        return {
          offset,
          dialect: chunk.dialect,
          length: chunk.length,
          functions: allProtos(chunk.main).length,
          chunk_name: chunk.chunkName,
          error: null,
        };
      } catch (cause) {
        if (!(cause instanceof LuaFormatError || cause instanceof RangeError))
          throw cause;
        return {
          offset,
          dialect: null,
          length: null,
          functions: null,
          chunk_name: null,
          error: cause.message,
        };
      }
    })
    .filter((row) => matches(query, row.chunk_name, row.dialect, row.error));

const summaryOf = (decoded: Decoded | null): Report["summary"] => {
  const protos = decoded?.protos ?? [];
  const sum = (pick: (proto: LuaProto) => number) =>
    protos.reduce((total, proto) => total + pick(proto), 0);
  return {
    functions: protos.length,
    instructions: sum((proto) => proto.code.length),
    constants: sum((proto) => proto.constants.length),
    strings: sum(
      (proto) => proto.constants.filter(({ type }) => type === "string").length,
    ),
    locals: sum((proto) => proto.locals.length),
    upvalues: sum((proto) => proto.upvalues.length),
    named_functions: decoded === null ? 0 : decoded.hints.size,
    unknown_opcodes: [...(decoded?.code.values() ?? [])]
      .flat()
      .filter(({ op }) => op.startsWith("UNKNOWN_")).length,
  };
};

const chunkOf = (
  chunk: LuaChunk,
  offset: number,
): NonNullable<Report["chunk"]> => ({
  offset,
  length: chunk.length,
  dialect: chunk.dialect,
  version: chunk.dialect.startsWith("luajit")
    ? String(chunk.version)
    : `0x${chunk.version.toString(16)}`,
  format: chunk.format,
  byte_order: chunk.littleEndian ? "little" : "big",
  sizes: { ...chunk.sizes },
  flags: [...chunk.flags],
  chunk_name: chunk.chunkName,
  stripped: chunk.stripped,
});

/** Decode a chunk (or scan a file for chunks) into the summary and one paged view. */
export const buildLuaReport = (
  file: { readonly bytes: Buffer; readonly sha256: string },
  input: InspectLuaBytecodeInput,
  limitations: readonly string[],
): Report => {
  const offset = input.chunk_offset ?? 0;
  if (offset >= file.bytes.length && input.view !== "chunks")
    throw new LuaSelectionError(
      `chunk_offset ${String(offset)} is past the end of the ${String(file.bytes.length)}-byte file.`,
      "chunk_offset",
    );
  let decoded: Decoded | null = null;
  if (input.view !== "chunks" || isChunkStart(file.bytes, offset)) {
    try {
      decoded = decode(readChunk(file.bytes, offset));
    } catch (cause) {
      if (input.view !== "chunks") throw cause;
    }
  }
  if (
    decoded !== null &&
    input.function !== undefined &&
    !decoded.protos.some(({ id }) => id === input.function)
  )
    throw new LuaSelectionError(
      `No function ${input.function}; the chunk has ${String(decoded.protos.length)} functions, 0 to ${decoded.protos.at(-1)?.id ?? "0"}.`,
      "function",
    );
  const matching =
    input.view === "chunks"
      ? chunkRows(file.bytes, input.query)
      : decoded === null
        ? []
        : rowsOf(decoded, input);
  const page = matching.slice(input.offset, input.offset + input.limit);
  const empty: Rows = {
    functions: [],
    instructions: [],
    constants: [],
    locals: [],
    upvalues: [],
    chunks: [],
  };
  return {
    file: { path: input.path, sha256: file.sha256, bytes: file.bytes.length },
    chunk: decoded === null ? null : chunkOf(decoded.chunk, offset),
    summary: summaryOf(decoded),
    page: {
      view: input.view,
      function: input.function ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    ...empty,
    [input.view]: page,
    limitations: [...limitations],
  };
};
