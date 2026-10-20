import type { LuaLocal, LuaProto } from "./LuaModel.js";
import type { LuaInstruction } from "./LuaOpcodes.js";

/**
 * Name hints for functions. Bytecode keeps no function names, but the
 * instruction after a closure usually stores it: a global (SETGLOBAL,
 * SETTABUP _ENV, GSET), a table field (SETTABLE, SETFIELD, TSETS) or a local
 * whose debug name is known. Hints are a reading aid, not a recovered name.
 */

const MAX_TRACE = 16;
const READS_A =
  /^(SET|TSET|GSET|USET|IS|EQ|LT|LE|GT|GE|TEST|RET|JMP|FOR|TFOR|CLOSE|TBC)/u;

/** The register-th active local at a listing pc, as luaF_getlocalname and LuaJIT's debug_varname count them. */
export const localName = (
  locals: readonly LuaLocal[],
  register: number,
  pc: number,
): string | null => {
  let slot = register;
  for (const local of locals) {
    if (local.startPc > pc) break;
    if (pc < local.endPc) {
      if (slot === 0) return local.name;
      slot -= 1;
    }
  }
  return null;
};

const constantText = (
  proto: LuaProto,
  pool: "k" | "gc",
  index: number | undefined,
): string | null => {
  if (index === undefined) return null;
  const constant = proto.constants.find(
    (k) => k.pool === pool && k.index === index,
  );
  return constant?.type === "string" ? constant.value : null;
};

const RK = 1 << 8;

/** How each dialect names what a register holds and where a closure goes. */
interface Rules {
  readonly closure: (
    ins: LuaInstruction,
  ) => { register: number; child: number } | null;
  /** The name a store of `register` right after the closure gives it. */
  readonly store: (
    ins: LuaInstruction,
    register: number,
    table: (reg: number) => string,
  ) => string | null;
  /** The name of what `ins` loads into its destination register, if it is a named load. */
  readonly load: (
    ins: LuaInstruction,
    table: (reg: number) => string,
  ) => { register: number; name: string } | null;
}

const pucRules = (proto: LuaProto, version: number): Rules => {
  const k = (index: number | undefined) => constantText(proto, "k", index);
  const rk = (value: number | undefined) =>
    value !== undefined && value & RK ? k(value & ~RK) : null;
  const upvalue = (index: number | undefined) =>
    index === undefined ? null : (proto.upvalues[index]?.name ?? null);
  const global = (upName: string | null, key: string | null) =>
    key === null ? null : upName === "_ENV" ? key : `${upName ?? "?"}.${key}`;
  const f = (ins: LuaInstruction, name: string) => ins.fields[name];
  return {
    closure: (ins) =>
      ins.op === "CLOSURE"
        ? { register: f(ins, "a") ?? -1, child: f(ins, "bx") ?? -1 }
        : null,
    store: (ins, register, table) => {
      if (
        version === 0x51 &&
        ins.op === "SETGLOBAL" &&
        f(ins, "a") === register
      )
        return k(f(ins, "bx"));
      if (version === 0x54) {
        if (
          ins.op === "SETTABUP" &&
          f(ins, "c") === register &&
          f(ins, "k") === 0
        )
          return global(upvalue(f(ins, "a")), k(f(ins, "b")));
        if (
          ins.op === "SETFIELD" &&
          f(ins, "c") === register &&
          f(ins, "k") === 0
        ) {
          const key = k(f(ins, "b"));
          return key === null ? null : `${table(f(ins, "a") ?? -1)}.${key}`;
        }
        return null;
      }
      if (ins.op === "SETTABUP" && f(ins, "c") === register)
        return global(upvalue(f(ins, "a")), rk(f(ins, "b")));
      if (ins.op === "SETTABLE" && f(ins, "c") === register) {
        const key = rk(f(ins, "b"));
        return key === null ? null : `${table(f(ins, "a") ?? -1)}.${key}`;
      }
      return null;
    },
    load: (ins, table) => {
      const a = f(ins, "a");
      if (a === undefined) return null;
      if (ins.op === "GETGLOBAL") return nameOf(a, k(f(ins, "bx")));
      if (ins.op === "GETUPVAL") return nameOf(a, upvalue(f(ins, "b")));
      if (ins.op === "GETTABUP")
        return nameOf(
          a,
          global(
            upvalue(f(ins, "b")),
            version === 0x54 ? k(f(ins, "c")) : rk(f(ins, "c")),
          ),
        );
      if (ins.op === "GETFIELD")
        return nameOf(a, joined(table(f(ins, "b") ?? -1), k(f(ins, "c"))));
      if (ins.op === "GETTABLE" && version <= 0x53)
        return nameOf(a, joined(table(f(ins, "b") ?? -1), rk(f(ins, "c"))));
      return null;
    },
  };
};

const jitRules = (proto: LuaProto): Rules => {
  const gc = (index: number | undefined) => constantText(proto, "gc", index);
  const upvalue = (index: number | undefined) =>
    index === undefined ? null : (proto.upvalues[index]?.name ?? null);
  const f = (ins: LuaInstruction, name: string) => ins.fields[name];
  return {
    closure: (ins) =>
      ins.op === "FNEW"
        ? { register: f(ins, "a") ?? -1, child: f(ins, "d") ?? -1 }
        : null,
    store: (ins, register, table) => {
      if (ins.op === "GSET" && f(ins, "a") === register) return gc(f(ins, "d"));
      if (ins.op === "TSETS" && f(ins, "a") === register) {
        const key = gc(f(ins, "c"));
        return key === null ? null : `${table(f(ins, "b") ?? -1)}.${key}`;
      }
      return null;
    },
    load: (ins, table) => {
      const a = f(ins, "a");
      if (a === undefined) return null;
      if (ins.op === "GGET") return nameOf(a, gc(f(ins, "d")));
      if (ins.op === "UGET") return nameOf(a, upvalue(f(ins, "d")));
      if (ins.op === "TGETS")
        return nameOf(a, joined(table(f(ins, "b") ?? -1), gc(f(ins, "c"))));
      return null;
    },
  };
};

const nameOf = (register: number, name: string | null) =>
  name === null ? null : { register, name };
const joined = (base: string, key: string | null) =>
  key === null ? null : `${base}.${key}`;

/**
 * Hints for each child of `proto`, by child index. LuaJIT children are
 * matched to FNEW in order, since FNEW's operand indexes GC constants.
 */
export const childNameHints = (
  proto: LuaProto,
  code: readonly LuaInstruction[],
  dialect: { readonly jit: boolean; readonly version: number },
): Map<string, string> => {
  const rules = dialect.jit
    ? jitRules(proto)
    : pucRules(proto, dialect.version);
  const hints = new Map<string, string>();
  const tableAt =
    (at: number, depth: number) =>
    (register: number): string => {
      const local = localName(proto.locals, register, at + 1);
      if (local !== null) return local;
      if (depth > 2) return "?";
      for (
        let index = at - 1;
        index >= Math.max(0, at - MAX_TRACE);
        index -= 1
      ) {
        const ins = code[index];
        if (ins === undefined) break;
        const loaded = rules.load(ins, tableAt(index, depth + 1));
        if (loaded !== null && loaded.register === register) return loaded.name;
        // Stores and tests read A; anything else that names it as A overwrote it.
        if (ins.fields["a"] === register && !READS_A.test(ins.op)) return "?";
      }
      return "?";
    };
  code.forEach((ins, index) => {
    const closure = rules.closure(ins);
    if (closure === null) return;
    const childId = dialect.jit
      ? (proto.constants.find(
          (k) =>
            k.pool === "gc" &&
            k.index === closure.child &&
            k.type === "function",
        )?.value ?? null)
      : `${proto.id}/${String(closure.child)}`;
    if (childId === null) return;
    // Lua 5.1 follows CLOSURE with one MOVE or GETUPVAL per captured upvalue.
    const skip =
      !dialect.jit && dialect.version === 0x51
        ? (proto.children[closure.child]?.upvalues.length ?? 0)
        : 0;
    const next = code[index + 1 + skip];
    const stored =
      next === undefined
        ? null
        : rules.store(next, closure.register, tableAt(index + 1 + skip, 0));
    const name =
      stored ?? localName(proto.locals, closure.register, ins.pc + 1);
    if (name !== null) hints.set(childId, name);
  });
  return hints;
};
