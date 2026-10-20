import { zstdDecompressSync } from "node:zlib";

import { floatText, GodotFormatError, quoted, Reader } from "./GodotBytes.js";
import {
  GODOT3_TYPES,
  SCRIPT_FORMATS,
  type ScriptFormat,
} from "./GdscriptTables.js";
import { valueText, type GodotValue } from "./GodotValues.js";
import { marshalledVariant } from "./MarshalledVariant.js";

/**
 * Compiled GDScript (.gdc): Godot's tokenizer output, not bytecode. Godot 3
 * writes bytecode 12 (3.0) or 13 (3.1-3.6); Godot 4.3 and later write
 * tokenizer 100 or 101, optionally zstd-compressed. Identifiers are XORed
 * with 0xb6 and constants are marshalled Variants.
 */

export type TokenRole =
  | "identifier"
  | "annotation"
  | "literal"
  | "builtin"
  | "keyword"
  | "newline"
  | "indent"
  | "dedent"
  | "eof"
  | "error";

export interface ScriptToken {
  readonly index: number;
  readonly type: string;
  readonly text: string;
  readonly role: TokenRole;
  readonly line: number | null;
  /** Godot 3 NEWLINE: whitespace before the next line; Godot 4: the column a logical line starts at, less one. */
  readonly indent: number | null;
}

export interface CompiledScript {
  readonly version: number;
  readonly engine: string;
  readonly compressed: boolean;
  readonly identifiers: readonly string[];
  readonly constants: readonly GodotValue[];
  readonly tokens: readonly ScriptToken[];
}

const KEY = 0xb6;

export const isCompiledScript = (bytes: Buffer): boolean =>
  bytes.length >= 8 && bytes.subarray(0, 4).toString("latin1") === "GDSC";

/** A constant as a GDScript literal. */
export const literalText = (value: GodotValue, major: number): string => {
  switch (value.kind) {
    case "nil":
      return "null";
    case "bool":
    case "int":
      return String(value.value);
    case "float":
      return floatText(value.value, false);
    case "string":
      return quoted(value.value);
    case "string_name":
      return `&${quoted(value.value)}`;
    case "node_path":
      return `${major >= 4 ? "^" : "@"}${quoted(value.value)}`;
    default:
      return valueText(value, 1000).text;
  }
};

const count = (reader: Reader, size: number, what: string): number => {
  const value = reader.u32();
  if (value * size > reader.bytes.length - reader.at)
    throw new GodotFormatError(`${String(value)} ${what} cannot fit.`);
  return value;
};

const constants = (reader: Reader, total: number, major: 3 | 4) =>
  Array.from({ length: total }, () => {
    const { value, length } = marshalledVariant(reader.bytes, major, reader.at);
    reader.at += length;
    return value;
  });

const ROLES: Readonly<Record<string, TokenRole>> = {
  IDENTIFIER: "identifier",
  ANNOTATION: "annotation",
  CONSTANT: "literal",
  LITERAL: "literal",
  BUILT_IN_TYPE: "builtin",
  BUILT_IN_FUNC: "builtin",
  NEWLINE: "newline",
  INDENT: "indent",
  DEDENT: "dedent",
  EOF: "eof",
  ERROR: "error",
  VCS_CONFLICT_MARKER: "error",
};

interface Context {
  readonly format: ScriptFormat;
  readonly identifiers: readonly string[];
  readonly constants: readonly GodotValue[];
  readonly major: 3 | 4;
}

const token = (
  context: Context,
  index: number,
  code: number,
  line: number | null,
): ScriptToken => {
  const type =
    context.format.tokens[code & (context.major === 4 ? 0x7f : 0xff)];
  if (type === undefined)
    throw new GodotFormatError(
      `Token ${String(index)} has type ${String(code & 0xff)}, outside the ${context.format.engine} table.`,
    );
  const value = code >>> 8;
  const role = ROLES[type.name] ?? "keyword";
  const lookup = (table: readonly string[], what: string): string => {
    const text = table[value];
    if (text === undefined)
      throw new GodotFormatError(
        `Token ${String(index)} names ${what} ${String(value)}, which does not exist.`,
      );
    return text;
  };
  let text = type.text ?? "";
  if (role === "identifier" || role === "annotation")
    text = lookup(context.identifiers, "identifier");
  else if (role === "literal" || type.name === "ERROR") {
    const constant = context.constants[value];
    if (constant === undefined && role === "literal")
      throw new GodotFormatError(
        `Token ${String(index)} names constant ${String(value)}, which does not exist.`,
      );
    text = constant === undefined ? "" : literalText(constant, context.major);
  } else if (type.name === "BUILT_IN_TYPE") text = lookup(GODOT3_TYPES, "type");
  else if (type.name === "BUILT_IN_FUNC")
    text = lookup(context.format.functions, "built-in function");
  return {
    index,
    type: type.name,
    text,
    role,
    line,
    indent: context.major === 3 && type.name === "NEWLINE" ? value : null,
  };
};

/** Bytecode 12 and 13: identifiers, constants, a token-to-line map, tokens. */
const godot3 = (bytes: Buffer, format: ScriptFormat): CompiledScript => {
  const reader = new Reader(bytes, 8);
  const identifierCount = count(reader, 4, "identifiers");
  const constantCount = count(reader, 4, "constants");
  const lineCount = count(reader, 8, "line entries");
  const tokenCount = count(reader, 1, "tokens");
  const identifiers = Array.from({ length: identifierCount }, () => {
    const raw = reader.take(reader.u32(), "identifier");
    return Buffer.from(raw.map((byte) => byte ^ KEY))
      .toString("utf8")
      .replace(/\0+$/u, "");
  });
  const values = constants(reader, constantCount, 3);
  const lines = new Map<number, number>();
  for (let entry = 0; entry < lineCount; entry += 1) {
    const at = reader.u32();
    lines.set(at, reader.u32() & 0xffffff);
  }
  const context: Context = { format, identifiers, constants: values, major: 3 };
  let line: number | null = null;
  const tokens = Array.from({ length: tokenCount }, (_, index) => {
    const first = reader.bytes[reader.at] ?? 0;
    const code = (first & 0x80) === 0 ? reader.u8() : reader.u32() & ~0x80;
    line = lines.get(index) ?? line;
    return token(context, index, code, line);
  });
  if (reader.at !== bytes.length)
    throw new GodotFormatError(
      `The tokens end at ${String(reader.at)} of ${String(bytes.length)} bytes.`,
    );
  return {
    version: format.version,
    engine: format.engine,
    compressed: false,
    identifiers,
    constants: values,
    tokens,
  };
};

const godot4Body = (bytes: Buffer, maxOutput: number): Buffer => {
  const size = bytes.readUInt32LE(8);
  if (size === 0) return bytes.subarray(12);
  if (size > maxOutput)
    throw new GodotFormatError(
      `The script expands to ${String(size)} bytes, over the limit.`,
    );
  const body = zstdDecompressSync(bytes.subarray(12), {
    maxOutputLength: size,
  });
  if (body.length !== size)
    throw new GodotFormatError(
      `The script expands to ${String(body.length)} bytes, not ${String(size)}.`,
    );
  return body;
};

/** Tokenizer 100 and 101: identifiers as XORed UTF-32, then lines and columns of logical lines. */
const godot4 = (
  bytes: Buffer,
  format: ScriptFormat,
  maxOutput: number,
): CompiledScript => {
  const body = godot4Body(bytes, maxOutput);
  const reader = new Reader(body);
  const identifierCount = count(reader, 4, "identifiers");
  const constantCount = count(reader, 4, "constants");
  const lineCount = count(reader, 16, "line entries");
  if (format.version === 100) reader.u32(); // unused since 4.3, dropped in 101
  const tokenCount = count(reader, 5, "tokens");
  const identifiers = Array.from({ length: identifierCount }, () => {
    const raw = reader.take(count(reader, 4, "characters") * 4, "identifier");
    const units = Buffer.from(raw.map((byte) => byte ^ KEY));
    return Array.from({ length: units.length / 4 }, (_, at) =>
      String.fromCodePoint(units.readUInt32LE(at * 4)),
    ).join("");
  });
  const values = constants(reader, constantCount, 4);
  const starts = new Map<number, number>();
  for (let entry = 0; entry < lineCount; entry += 1) {
    const at = reader.u32();
    reader.u32(); // line; every token carries its own
    starts.set(at, 0);
  }
  for (let entry = 0; entry < lineCount; entry += 1) {
    const at = reader.u32();
    starts.set(at, reader.u32());
  }
  const context: Context = { format, identifiers, constants: values, major: 4 };
  const tokens = Array.from({ length: tokenCount }, (_, index) => {
    const first = reader.bytes[reader.at] ?? 0;
    const code = (first & 0x80) === 0 ? reader.u8() : reader.u32();
    const decoded = token(context, index, code, reader.u32());
    const column = starts.get(index) ?? (index === 0 ? 1 : undefined);
    return column === undefined
      ? decoded
      : { ...decoded, indent: Math.max(0, column - 1) };
  });
  if (reader.at !== body.length)
    throw new GodotFormatError(
      `The tokens end at ${String(reader.at)} of ${String(body.length)} bytes.`,
    );
  return {
    version: format.version,
    engine: format.engine,
    compressed: bytes.readUInt32LE(8) !== 0,
    identifiers,
    constants: values,
    tokens,
  };
};

export const readCompiledScript = (
  bytes: Buffer,
  maxOutput: number,
): CompiledScript => {
  const version = bytes.readUInt32LE(4);
  const format = SCRIPT_FORMATS[version];
  if (format === undefined)
    throw new GodotFormatError(
      `Compiled GDScript version ${String(version)} is not one REA+ reads (12 and 13 from Godot 3, 100 and 101 from Godot 4.3 and later).`,
    );
  return version >= 100
    ? godot4(bytes, format, maxOutput)
    : godot3(bytes, format);
};
