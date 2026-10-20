import type { LuaConstant, LuaProto } from "./LuaModel.js";

/**
 * PUC Lua instruction decoding. Operand columns follow luac -l for each
 * version (5.1-5.3 print by operand mode, 5.4 per opcode), so a listing can
 * be compared with luac's line for line.
 */

export interface LuaInstruction {
  /** 1-based, as luac and LuaJIT number instructions. */
  readonly pc: number;
  readonly line: number | null;
  readonly op: string;
  readonly operands: string;
  readonly comment: string | null;
  readonly fields: Readonly<Record<string, number>>;
  /** 1-based pc a jump, loop or for-prep goes to. */
  readonly target: number | null;
}

/** name:BC-modes:format, from each version's lopcodes.c. */
const TABLE_51 =
  "MOVE:RN:ABC LOADK:KN:ABx LOADBOOL:UU:ABC LOADNIL:RN:ABC GETUPVAL:UN:ABC GETGLOBAL:KN:ABx GETTABLE:RK:ABC SETGLOBAL:KN:ABx SETUPVAL:UN:ABC SETTABLE:KK:ABC NEWTABLE:UU:ABC SELF:RK:ABC ADD:KK:ABC SUB:KK:ABC MUL:KK:ABC DIV:KK:ABC MOD:KK:ABC POW:KK:ABC UNM:RN:ABC NOT:RN:ABC LEN:RN:ABC CONCAT:RR:ABC JMP:RN:AsBx EQ:KK:ABC LT:KK:ABC LE:KK:ABC TEST:RU:ABC TESTSET:RU:ABC CALL:UU:ABC TAILCALL:UU:ABC RETURN:UN:ABC FORLOOP:RN:AsBx FORPREP:RN:AsBx TFORLOOP:NU:ABC SETLIST:UU:ABC CLOSE:NN:ABC CLOSURE:UN:ABx VARARG:UN:ABC";
const TABLE_52 =
  "MOVE:RN:ABC LOADK:KN:ABx LOADKX:NN:ABx LOADBOOL:UU:ABC LOADNIL:UN:ABC GETUPVAL:UN:ABC GETTABUP:UK:ABC GETTABLE:RK:ABC SETTABUP:KK:ABC SETUPVAL:UN:ABC SETTABLE:KK:ABC NEWTABLE:UU:ABC SELF:RK:ABC ADD:KK:ABC SUB:KK:ABC MUL:KK:ABC DIV:KK:ABC MOD:KK:ABC POW:KK:ABC UNM:RN:ABC NOT:RN:ABC LEN:RN:ABC CONCAT:RR:ABC JMP:RN:AsBx EQ:KK:ABC LT:KK:ABC LE:KK:ABC TEST:NU:ABC TESTSET:RU:ABC CALL:UU:ABC TAILCALL:UU:ABC RETURN:UN:ABC FORLOOP:RN:AsBx FORPREP:RN:AsBx TFORCALL:NU:ABC TFORLOOP:RN:AsBx SETLIST:UU:ABC CLOSURE:UN:ABx VARARG:UN:ABC EXTRAARG:UU:Ax";
const TABLE_53 =
  "MOVE:RN:ABC LOADK:KN:ABx LOADKX:NN:ABx LOADBOOL:UU:ABC LOADNIL:UN:ABC GETUPVAL:UN:ABC GETTABUP:UK:ABC GETTABLE:RK:ABC SETTABUP:KK:ABC SETUPVAL:UN:ABC SETTABLE:KK:ABC NEWTABLE:UU:ABC SELF:RK:ABC ADD:KK:ABC SUB:KK:ABC MUL:KK:ABC MOD:KK:ABC POW:KK:ABC DIV:KK:ABC IDIV:KK:ABC BAND:KK:ABC BOR:KK:ABC BXOR:KK:ABC SHL:KK:ABC SHR:KK:ABC UNM:RN:ABC BNOT:RN:ABC NOT:RN:ABC LEN:RN:ABC CONCAT:RR:ABC JMP:RN:AsBx EQ:KK:ABC LT:KK:ABC LE:KK:ABC TEST:NU:ABC TESTSET:RU:ABC CALL:UU:ABC TAILCALL:UU:ABC RETURN:UN:ABC FORLOOP:RN:AsBx FORPREP:RN:AsBx TFORCALL:NU:ABC TFORLOOP:RN:AsBx SETLIST:UU:ABC CLOSURE:UN:ABx VARARG:UN:ABC EXTRAARG:UU:Ax";

/** Lua 5.4: name:operands as luac.c prints them (ck is C with a "k" suffix when k is set). */
const TABLE_54 =
  "MOVE:a,b LOADI:a,sbx LOADF:a,sbx LOADK:a,bx LOADKX:a LOADFALSE:a LFALSESKIP:a LOADTRUE:a LOADNIL:a,b GETUPVAL:a,b SETUPVAL:a,b GETTABUP:a,b,c GETTABLE:a,b,c GETI:a,b,c GETFIELD:a,b,c SETTABUP:a,b,ck SETTABLE:a,b,ck SETI:a,b,ck SETFIELD:a,b,ck NEWTABLE:a,b,c SELF:a,b,ck ADDI:a,b,sc ADDK:a,b,c SUBK:a,b,c MULK:a,b,c MODK:a,b,c POWK:a,b,c DIVK:a,b,c IDIVK:a,b,c BANDK:a,b,c BORK:a,b,c BXORK:a,b,c SHRI:a,b,sc SHLI:a,b,sc ADD:a,b,c SUB:a,b,c MUL:a,b,c MOD:a,b,c POW:a,b,c DIV:a,b,c IDIV:a,b,c BAND:a,b,c BOR:a,b,c BXOR:a,b,c SHL:a,b,c SHR:a,b,c MMBIN:a,b,c MMBINI:a,sb,c,k MMBINK:a,b,c,k UNM:a,b BNOT:a,b NOT:a,b LEN:a,b CONCAT:a,b CLOSE:a TBC:a JMP:sj EQ:a,b,k LT:a,b,k LE:a,b,k EQK:a,b,k EQI:a,sb,k LTI:a,sb,k LEI:a,sb,k GTI:a,sb,k GEI:a,sb,k TEST:a,k TESTSET:a,b,k CALL:a,b,c TAILCALL:a,b,ck RETURN:a,b,ck RETURN0: RETURN1:a FORLOOP:a,bx FORPREP:a,bx TFORPREP:a,bx TFORCALL:a,c TFORLOOP:a,bx SETLIST:a,b,c CLOSURE:a,bx VARARG:a,c VARARGPREP:a EXTRAARG:ax";

interface OpInfo {
  readonly name: string;
  readonly b: string;
  readonly c: string;
  readonly format: string;
  readonly operands: readonly string[];
}

const parse = (table: string): OpInfo[] =>
  table.split(" ").map((entry) => {
    const [name = "", modes = "", format = ""] = entry.split(":");
    return {
      name,
      b: modes[0] ?? "N",
      c: modes[1] ?? "N",
      format,
      operands: [],
    };
  });

const parse54 = (table: string): OpInfo[] =>
  table.split(" ").map((entry) => {
    const [name = "", operands = ""] = entry.split(":");
    return {
      name,
      b: "",
      c: "",
      format: "",
      operands: operands === "" ? [] : operands.split(","),
    };
  });

export const OPCODES: Readonly<Record<number, readonly OpInfo[]>> = {
  0x51: parse(TABLE_51),
  0x52: parse(TABLE_52),
  0x53: parse(TABLE_53),
  0x54: parse54(TABLE_54),
};

/** Fields of a 5.1-5.3 instruction word. */
const fields53 = (word: number) => {
  const bx = (word >>> 14) & 0x3ffff;
  return {
    op: word & 0x3f,
    a: (word >>> 6) & 0xff,
    c: (word >>> 14) & 0x1ff,
    b: (word >>> 23) & 0x1ff,
    bx,
    sbx: bx - 131071,
    ax: (word >>> 6) & 0x3ffffff,
  };
};

/** Fields of a 5.4 instruction word. */
const fields54 = (word: number) => {
  const bx = (word >>> 15) & 0x1ffff;
  const ax = (word >>> 7) & 0x1ffffff;
  const b = (word >>> 16) & 0xff;
  const c = (word >>> 24) & 0xff;
  return {
    op: word & 0x7f,
    a: (word >>> 7) & 0xff,
    k: (word >>> 15) & 1,
    b,
    c,
    bx,
    sbx: bx - 65535,
    ax,
    sj: ax - 16777215,
    sb: b - 127,
    sc: c - 127,
  };
};

const quote = (value: string) =>
  `"${value.replace(/[\\"\n\r\t]/gu, (char) => ({ "\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t" })[char] ?? char)}"`;

/** A constant as a listing shows it: strings quoted, everything else as stored. */
export const showConstant = (constant: LuaConstant | undefined): string =>
  constant === undefined
    ? "?"
    : constant.type === "string"
      ? quote(constant.value)
      : constant.value;

const RK = 1 << 8;

/** Operands as luac 5.1-5.3 prints them: constant operands as -1-index. */
const operands53 = (
  version: number,
  info: OpInfo,
  f: ReturnType<typeof fields53>,
): string => {
  const rk = (value: number) => (value & RK ? -1 - (value & ~RK) : value);
  switch (info.format) {
    case "ABC":
      return [
        String(f.a),
        ...(info.b === "N" ? [] : [String(rk(f.b))]),
        ...(info.c === "N" ? [] : [String(rk(f.c))]),
      ].join(" ");
    case "ABx":
      if (version === 0x51)
        return `${String(f.a)} ${String(info.b === "K" ? -1 - f.bx : f.bx)}`;
      return [
        String(f.a),
        ...(info.b === "K"
          ? [String(-1 - f.bx)]
          : info.b === "U"
            ? [String(f.bx)]
            : []),
      ].join(" ");
    case "AsBx":
      return version === 0x51 && info.name === "JMP"
        ? String(f.sbx)
        : `${String(f.a)} ${String(f.sbx)}`;
    default:
      return String(-1 - f.ax);
  }
};

const JUMPS_53 = new Set(["JMP", "FORLOOP", "FORPREP", "TFORLOOP"]);

const comment53 = (
  proto: LuaProto,
  info: OpInfo,
  f: ReturnType<typeof fields53>,
): string | null => {
  const k = (value: number) => showConstant(proto.constants[value & ~RK]);
  const upvalue = (index: number) => proto.upvalues[index]?.name ?? "-";
  switch (info.name) {
    case "LOADK":
      return k(f.bx);
    case "GETGLOBAL":
    case "SETGLOBAL":
      return proto.constants[f.bx]?.value ?? "?";
    case "GETUPVAL":
    case "SETUPVAL":
      return upvalue(f.b);
    case "GETTABUP":
      return `${upvalue(f.b)}${f.c & RK ? ` ${k(f.c)}` : ""}`;
    case "SETTABUP":
      return `${upvalue(f.a)}${f.b & RK ? ` ${k(f.b)}` : ""}${f.c & RK ? ` ${k(f.c)}` : ""}`;
    case "CLOSURE":
      return `function ${proto.id}/${String(f.bx)}`;
    default: {
      const constants = [f.b, f.c].filter(
        (value, index) =>
          (index === 0 ? info.b : info.c) === "K" && (value & RK) !== 0,
      );
      return constants.length > 0 ? constants.map(k).join(" ") : null;
    }
  }
};

const operands54 = (info: OpInfo, f: ReturnType<typeof fields54>): string =>
  info.operands
    .map((name) => {
      if (name === "ck") return `${String(f.c)}${f.k ? "k" : ""}`;
      return String(f[name as keyof typeof f]);
    })
    .join(" ");

const K_OPERANDS_54: Readonly<Record<string, string>> = {
  LOADK: "bx",
  GETFIELD: "c",
  GETTABUP: "c",
  SETFIELD: "b",
  ADDK: "c",
  SUBK: "c",
  MULK: "c",
  MODK: "c",
  POWK: "c",
  DIVK: "c",
  IDIVK: "c",
  BANDK: "c",
  BORK: "c",
  BXORK: "c",
  EQK: "b",
  MMBINK: "b",
};

const comment54 = (
  proto: LuaProto,
  info: OpInfo,
  f: ReturnType<typeof fields54>,
): string | null => {
  const upvalue = (index: number) => proto.upvalues[index]?.name ?? "-";
  const parts: string[] = [];
  if (
    info.name === "GETUPVAL" ||
    info.name === "SETUPVAL" ||
    info.name === "GETTABUP"
  )
    parts.push(upvalue(f.b));
  if (info.name === "SETTABUP")
    parts.push(upvalue(f.a), showConstant(proto.constants[f.b]));
  const keyed = K_OPERANDS_54[info.name];
  if (keyed !== undefined)
    parts.push(showConstant(proto.constants[f[keyed as "b" | "c" | "bx"]]));
  if (f.k && /^SET(TABUP|TABLE|I|FIELD)$|^SELF$/u.test(info.name))
    parts.push(showConstant(proto.constants[f.c]));
  if (info.name === "CLOSURE")
    parts.push(`function ${proto.id}/${String(f.bx)}`);
  return parts.length > 0 ? parts.join(" ") : null;
};

const target54 = (
  name: string,
  pc: number,
  f: ReturnType<typeof fields54>,
): number | null => {
  // pc is 0-based; targets are reported 1-based like the listing.
  if (name === "JMP") return pc + f.sj + 2;
  if (name === "FORLOOP" || name === "TFORLOOP") return pc - f.bx + 2;
  if (name === "FORPREP") return pc + f.bx + 3;
  if (name === "TFORPREP") return pc + f.bx + 2;
  return null;
};

/** Decode one PUC Lua function's code into listing rows. */
export const decodePucCode = (
  version: number,
  proto: LuaProto,
): LuaInstruction[] => {
  const table = OPCODES[version] ?? [];
  return proto.code.map((word, pc) => {
    const line = proto.lines[pc] ?? null;
    if (version === 0x54) {
      const f = fields54(word);
      const info = table[f.op];
      if (info === undefined) return unknown(pc, line, f.op, word);
      const used = Object.fromEntries(
        info.operands
          .map((name) => (name === "ck" ? "c" : name))
          .map((name) => [name, f[name as keyof typeof f]]),
      );
      return {
        pc: pc + 1,
        line,
        op: info.name,
        operands: operands54(info, f),
        comment: comment54(proto, info, f),
        fields: {
          ...used,
          ...(info.operands.includes("ck") ? { k: f.k } : {}),
        },
        target: target54(info.name, pc, f),
      };
    }
    const f = fields53(word);
    const info = table[f.op];
    if (info === undefined) return unknown(pc, line, f.op, word);
    const fields =
      info.format === "ABC"
        ? { a: f.a, b: f.b, c: f.c }
        : info.format === "ABx"
          ? { a: f.a, bx: f.bx }
          : info.format === "AsBx"
            ? { a: f.a, sbx: f.sbx }
            : { ax: f.ax };
    return {
      pc: pc + 1,
      line,
      op: info.name,
      operands: operands53(version, info, f),
      comment: comment53(proto, info, f),
      fields,
      target:
        JUMPS_53.has(info.name) && info.format === "AsBx"
          ? pc + f.sbx + 2
          : null,
    };
  });
};

const unknown = (
  pc: number,
  line: number | null,
  op: number,
  word: number,
): LuaInstruction => ({
  pc: pc + 1,
  line,
  op: `UNKNOWN_${String(op)}`,
  operands: `0x${(word >>> 0).toString(16).padStart(8, "0")}`,
  comment: null,
  fields: {},
  target: null,
});
