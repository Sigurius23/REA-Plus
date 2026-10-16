import { formatNumber, type LuaProto } from "./LuaModel.js";
import { showConstant, type LuaInstruction } from "./LuaOpcodes.js";

/**
 * LuaJIT instruction decoding with the operand columns of jit/bc.lua (what
 * luajit -bl prints): A when the opcode has one, then B and C, or D, or the
 * jump target.
 */

/** name:A:B:C/D modes from lj_bc.h, up to JMP; dumps never contain the FUNC* headers. */
const COMMON_HEAD =
  "ISLT:var:___:var ISGE:var:___:var ISLE:var:___:var ISGT:var:___:var ISEQV:var:___:var ISNEV:var:___:var ISEQS:var:___:str ISNES:var:___:str ISEQN:var:___:num ISNEN:var:___:num ISEQP:var:___:pri ISNEP:var:___:pri ISTC:dst:___:var ISFC:dst:___:var IST:___:___:var ISF:___:___:var";
const COMMON_ARITH =
  "MOV:dst:___:var NOT:dst:___:var UNM:dst:___:var LEN:dst:___:var ADDVN:dst:var:num SUBVN:dst:var:num MULVN:dst:var:num DIVVN:dst:var:num MODVN:dst:var:num ADDNV:dst:var:num SUBNV:dst:var:num MULNV:dst:var:num DIVNV:dst:var:num MODNV:dst:var:num ADDVV:dst:var:var SUBVV:dst:var:var MULVV:dst:var:var DIVVV:dst:var:var MODVV:dst:var:var POW:dst:var:var CAT:dst:rbase:rbase KSTR:dst:___:str KCDATA:dst:___:cdata KSHORT:dst:___:lits KNUM:dst:___:num KPRI:dst:___:pri KNIL:base:___:base UGET:dst:___:uv USETV:uv:___:var USETS:uv:___:str USETN:uv:___:num USETP:uv:___:pri UCLO:rbase:___:jump FNEW:dst:___:func TNEW:dst:___:lit TDUP:dst:___:tab GGET:dst:___:str GSET:var:___:str TGETV:dst:var:var TGETS:dst:var:str TGETB:dst:var:lit";
const COMMON_TAIL =
  "CALLM:base:lit:lit CALL:base:lit:lit CALLMT:base:___:lit CALLT:base:___:lit ITERC:base:lit:lit ITERN:base:lit:lit VARG:base:lit:lit ISNEXT:base:___:jump RETM:base:___:lit RET:rbase:___:lit RET0:rbase:___:lit RET1:rbase:___:lit FORI:base:___:jump JFORI:base:___:jump FORL:base:___:jump IFORL:base:___:jump JFORL:base:___:lit ITERL:base:___:jump IITERL:base:___:jump JITERL:base:___:lit LOOP:rbase:___:jump ILOOP:rbase:___:jump JLOOP:rbase:___:lit JMP:rbase:___:jump";

/** LuaJIT 2.0 (dump version 1). */
const TABLE_20 = [
  COMMON_HEAD,
  COMMON_ARITH,
  "TSETV:var:var:var TSETS:var:var:str TSETB:var:var:lit TSETM:base:___:num",
  COMMON_TAIL,
].join(" ");
/** LuaJIT 2.1 (dump version 2): type checks, TGETR/TSETR, and the bit operators of BITOP dumps. */
const TABLE_21 = [
  COMMON_HEAD,
  "ISTYPE:var:___:lit ISNUM:var:___:lit",
  COMMON_ARITH,
  "TGETR:dst:var:var TSETV:var:var:var TSETS:var:var:str TSETB:var:var:lit TSETM:base:___:num TSETR:var:var:var",
  COMMON_TAIL,
  "BNOT:dst:___:var BAND:dst:var:var BOR:dst:var:var BXOR:dst:var:var BSHL:dst:var:var BSHR:dst:var:var BSAR:dst:var:var",
].join(" ");

interface JitOp {
  readonly name: string;
  readonly a: string;
  readonly b: string;
  readonly d: string;
}

const parse = (table: string): JitOp[] =>
  table.split(" ").map((entry) => {
    const [name = "", a = "", b = "", d = ""] = entry.split(":");
    return { name, a, b, d };
  });

const OPS_20 = parse(TABLE_20);
const OPS_21 = parse(TABLE_21);
const JMP_21 = OPS_21.findIndex(({ name }) => name === "JMP");

const PRIMITIVES = ["nil", "false", "true"];

const comment = (
  proto: LuaProto,
  op: JitOp,
  a: number,
  d: number,
): string | null => {
  const gc = (index: number) =>
    proto.constants.find((k) => k.pool === "gc" && k.index === index);
  const num = (index: number) =>
    proto.constants.find((k) => k.pool === "num" && k.index === index);
  const uv = (index: number) => proto.upvalues[index]?.name ?? "";
  let value: string | null = null;
  if (op.d === "str") value = showConstant(gc(d));
  else if (op.d === "num") {
    const constant = num(d);
    // TSETM's number is the array start biased by 2^52, as bc.lua shows it.
    value =
      constant === undefined
        ? "?"
        : op.name === "TSETM"
          ? formatNumber(Number(constant.value) - 2 ** 52)
          : constant.value;
  } else if (op.d === "func") value = `function ${gc(d)?.value ?? "?"}`;
  else if (op.d === "uv") value = uv(d);
  else if (op.d === "pri") value = PRIMITIVES[d] ?? null;
  else if (op.d === "tab") value = gc(d)?.value ?? null;
  else if (op.d === "cdata") value = gc(d)?.value ?? null;
  if (op.a === "uv") return value === null ? uv(a) : `${uv(a)} ; ${value}`;
  return value;
};

/** Decode one LuaJIT prototype's code into listing rows. */
export const decodeLuaJitCode = (
  version: number,
  bitop: boolean,
  proto: LuaProto,
): LuaInstruction[] => {
  const table = version === 1 ? OPS_20 : OPS_21;
  return proto.code.map((word, index) => {
    const pc = index + 1;
    const opcode = word & 0xff;
    const a = (word >>> 8) & 0xff;
    const d = (word >>> 16) & 0xffff;
    const op =
      version === 2 && !bitop && opcode > JMP_21 ? undefined : table[opcode];
    const line = proto.lines[index] ?? null;
    if (op === undefined)
      return {
        pc,
        line,
        op: `UNKNOWN_${String(opcode)}`,
        operands: `0x${(word >>> 0).toString(16).padStart(8, "0")}`,
        comment: null,
        fields: {},
        target: null,
      };
    const parts: string[] = op.a === "___" ? [] : [String(a)];
    const fields: Record<string, number> = op.a === "___" ? {} : { a };
    let target: number | null = null;
    if (op.d === "jump") {
      target = pc + d - 0x7fff;
      parts.push(`=> ${String(target).padStart(4, "0")}`);
      fields["d"] = d - 0x7fff;
    } else if (op.b !== "___") {
      parts.push(String(word >>> 24), String(d & 0xff));
      fields["b"] = word >>> 24;
      fields["c"] = d & 0xff;
    } else if (op.d !== "___") {
      const shown = op.d === "lits" && d > 32767 ? d - 65536 : d;
      parts.push(String(shown));
      fields["d"] = shown;
    }
    return {
      pc,
      line,
      op: op.name,
      operands: parts.join(" "),
      comment: comment(proto, op, a, op.b === "___" ? d : d & 0xff),
      fields,
      target,
    };
  });
};
