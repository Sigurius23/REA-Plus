/** The decoded form shared by PUC Lua and LuaJIT chunks. */

export type LuaDialect =
  | "lua5.1"
  | "lua5.2"
  | "lua5.3"
  | "lua5.4"
  | "luajit2.0"
  | "luajit2.1";

export type LuaConstantType =
  | "nil"
  | "boolean"
  | "number"
  | "integer"
  | "string"
  | "table"
  | "function"
  | "int64"
  | "uint64"
  | "complex";

export interface LuaConstant {
  /** PUC Lua has one pool (k); LuaJIT keeps GC objects (gc) and numbers (num) apart. */
  readonly pool: "k" | "gc" | "num";
  readonly index: number;
  readonly type: LuaConstantType;
  /** Strings as text, numbers as %.14g, booleans, a child function id, or a table summary. */
  readonly value: string;
  /** The string held bytes that are not UTF-8 and was read as Latin-1. */
  readonly binary: boolean;
}

export interface LuaUpvalue {
  readonly index: number;
  readonly name: string | null;
  /** Captured from the enclosing function's registers rather than its upvalues. */
  readonly inStack: boolean | null;
  readonly slot: number | null;
  /** Lua 5.4 variable kind (0 regular, 1 const, 2 to-be-closed, 3 compile-time constant); LuaJIT immutability. */
  readonly kind: number | null;
}

export interface LuaLocal {
  readonly name: string;
  /** First and one-past-last instruction where the local is live, numbered like the listing (1-based). */
  readonly startPc: number;
  readonly endPc: number;
}

export interface LuaProto {
  readonly id: string;
  readonly parent: string | null;
  source: string | null;
  readonly lineDefined: number;
  readonly lastLineDefined: number;
  readonly params: number;
  readonly vararg: boolean;
  readonly maxStack: number;
  /** Instruction words as stored, in execution order. */
  readonly code: readonly number[];
  /** Source line of each instruction, when the chunk kept line info. */
  readonly lines: readonly (number | null)[];
  readonly constants: readonly LuaConstant[];
  readonly upvalues: readonly LuaUpvalue[];
  readonly locals: readonly LuaLocal[];
  readonly children: LuaProto[];
}

export interface LuaChunk {
  readonly dialect: LuaDialect;
  readonly version: number;
  readonly format: number;
  readonly littleEndian: boolean;
  /** Sizes the header declares: int, size_t, Instruction, lua_Integer, lua_Number. */
  readonly sizes: Readonly<Record<string, number>>;
  /** LuaJIT dump flags (strip, ffi, fr2, bitop) or PUC header facts. */
  readonly flags: readonly string[];
  readonly chunkName: string | null;
  readonly stripped: boolean;
  readonly main: LuaProto;
  /** Bytes the chunk occupies from its start. */
  readonly length: number;
}

/** Every function in depth-first order, main first. */
export const allProtos = (main: LuaProto): LuaProto[] => {
  const out: LuaProto[] = [];
  const visit = (proto: LuaProto) => {
    out.push(proto);
    for (const child of proto.children) visit(child);
  };
  visit(main);
  return out;
};

/** The exact decimal digits of a finite, non-zero double and the power of ten of the first. */
const exactDigits = (
  value: number,
): { readonly digits: string; readonly exponent: number } => {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, Math.abs(value));
  const bits = view.getBigUint64(0);
  const biased = Number((bits >> 52n) & 0x7ffn);
  const fraction = bits & ((1n << 52n) - 1n);
  const mantissa = biased === 0 ? fraction : fraction | (1n << 52n);
  const power = (biased === 0 ? 1 : biased) - 1075;
  // m * 2^p is exactly (m * 5^-p) / 10^-p when p < 0.
  const digits = (
    power >= 0 ? mantissa << BigInt(power) : mantissa * 5n ** BigInt(-power)
  ).toString();
  return { digits, exponent: digits.length - 1 + Math.min(0, power) };
};

const PRECISION = 14;

/** Round exact digits to 14 significant ones, ties to even, as printf does. */
const rounded = (exact: {
  readonly digits: string;
  readonly exponent: number;
}) => {
  let kept = BigInt(exact.digits.slice(0, PRECISION).padEnd(PRECISION, "0"));
  const rest = exact.digits.slice(PRECISION);
  const first = rest[0] ?? "0";
  const tie = first === "5" && !/[1-9]/u.test(rest.slice(1));
  if (first > "5" || (first === "5" && !tie) || (tie && kept % 2n === 1n))
    kept += 1n;
  const digits = kept.toString();
  return digits.length > PRECISION
    ? { digits: digits.slice(0, PRECISION), exponent: exact.exponent + 1 }
    : { digits, exponent: exact.exponent };
};

/** %g's choice between fixed and scientific notation for significant digits d.ddd x 10^exponent. */
const layout = (digits: string, exponent: number): string => {
  const trimmed = digits.replace(/0+$/u, "") || "0";
  if (exponent >= -4 && exponent < PRECISION) {
    if (exponent < 0) return `0.${"0".repeat(-exponent - 1)}${trimmed}`;
    const whole = trimmed.padEnd(exponent + 1, "0");
    const tail = whole.slice(exponent + 1);
    return `${whole.slice(0, exponent + 1)}${tail === "" ? "" : `.${tail}`}`;
  }
  const mantissa =
    trimmed.length > 1 ? `${trimmed.slice(0, 1)}.${trimmed.slice(1)}` : trimmed;
  return `${mantissa}e${exponent < 0 ? "-" : "+"}${String(Math.abs(exponent)).padStart(2, "0")}`;
};

/** C's %.14g, which luac and LuaJIT use to print numbers: ties round to even on the exact value. */
export const formatNumber = (value: number): string => {
  if (Number.isNaN(value)) return "nan";
  if (!Number.isFinite(value)) return value > 0 ? "inf" : "-inf";
  if (value === 0) return Object.is(value, -0) ? "-0" : "0";
  const { digits, exponent } = rounded(exactDigits(value));
  return `${value < 0 ? "-" : ""}${layout(digits, exponent)}`;
};

// ignoreBOM keeps a leading byte-order mark as data instead of dropping it.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Lua strings are bytes; keep UTF-8 text, fall back to Latin-1 for anything else. */
export const decodeLuaString = (
  bytes: Buffer,
): { readonly text: string; readonly binary: boolean } => {
  try {
    return { text: UTF8.decode(bytes), binary: false };
  } catch {
    return { text: bytes.toString("latin1"), binary: true };
  }
};
