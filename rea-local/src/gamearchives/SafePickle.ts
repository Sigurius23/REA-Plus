import { GameArchiveError } from "./GameArchiveTypes.js";

/** Values a data-only pickle can hold; `bytes` stay as buffers. */
export type PickleValue =
  | null
  | boolean
  | bigint
  | string
  | Buffer
  | PickleValue[]
  | readonly PickleValue[]
  | Map<PickleValue, PickleValue>;

const MARK = Symbol("mark");

/** The only callables a pickle may name: Python 3's ways of spelling `bytes`. */
interface AllowedCallable {
  readonly callable: "codecs.encode" | "bytes";
}

type StackItem = PickleValue | typeof MARK | AllowedCallable;

const ALLOWED_GLOBALS: Readonly<Record<string, AllowedCallable>> = {
  "_codecs\nencode": { callable: "codecs.encode" },
  "__builtin__\nbytes": { callable: "bytes" },
  "builtins\nbytes": { callable: "bytes" },
};

const MAX_ITEMS = 10_000_000;

const fail = (message: string): never => {
  throw new GameArchiveError(`Index pickle: ${message}`);
};

const isCallable = (item: StackItem): item is AllowedCallable =>
  typeof item === "object" &&
  item !== null &&
  !Array.isArray(item) &&
  !Buffer.isBuffer(item) &&
  !(item instanceof Map) &&
  "callable" in item;

/** Little-endian two's-complement integers, as LONG1/LONG4 store them. */
const signedInteger = (raw: Buffer): bigint => {
  if (raw.length === 0) return 0n;
  let result = 0n;
  for (let index = raw.length - 1; index >= 0; index -= 1)
    result = (result << 8n) | BigInt(raw[index] ?? 0);
  return ((raw[raw.length - 1] ?? 0) & 0x80) !== 0
    ? result - (1n << BigInt(raw.length * 8))
    : result;
};

/** A pickle virtual machine limited to data opcodes. */
class SafePickleReader {
  private readonly stack: StackItem[] = [];
  private readonly memo = new Map<number, StackItem>();
  private at = 0;
  private items = 0;
  private readonly handlers: Readonly<Record<number, () => void>>;

  constructor(private readonly data: Buffer) {
    this.handlers = {
      ...this.structureOps(),
      ...this.scalarOps(),
      ...this.mutationOps(),
      ...this.callableOps(),
    };
  }

  private need(length: number): number {
    if (length < 0 || this.at + length > this.data.length) fail("truncated");
    const start = this.at;
    this.at += length;
    return start;
  }

  private u8 = () => this.data[this.need(1)] ?? 0;
  private u32 = () => this.data.readUInt32LE(this.need(4));
  private u64 = () => {
    const value = this.data.readBigUInt64LE(this.need(8));
    if (value > BigInt(this.data.length)) fail("length past the end");
    return Number(value);
  };

  private bytes(length: number): Buffer {
    const start = this.need(length);
    return this.data.subarray(start, start + length);
  }

  private line(): string {
    const end = this.data.indexOf(0x0a, this.at);
    if (end < 0) fail("unterminated line");
    const text = this.data.toString("latin1", this.at, end);
    this.at = end + 1;
    return text;
  }

  private push(item: StackItem): void {
    this.items += 1;
    if (this.items > MAX_ITEMS) fail("too many items");
    this.stack.push(item);
  }

  private pop(): StackItem {
    return this.stack.length === 0
      ? fail("stack underflow")
      : (this.stack.pop() as StackItem);
  }

  private top(): StackItem {
    return this.stack[this.stack.length - 1] ?? fail("stack underflow");
  }

  private value(item: StackItem): PickleValue {
    return item === MARK || isCallable(item) ? fail("expected a value") : item;
  }

  private popMark(): PickleValue[] {
    const index = this.stack.lastIndexOf(MARK);
    if (index < 0) fail("missing mark");
    const values = this.stack.splice(index + 1).map((item) => this.value(item));
    this.stack.pop();
    return values;
  }

  private list(target: StackItem): PickleValue[] {
    return Array.isArray(target)
      ? (target as PickleValue[])
      : fail("append target is not a list");
  }

  private setItems(target: StackItem, pairs: readonly PickleValue[]): void {
    if (!(target instanceof Map)) fail("SETITEM target is not a dict");
    const map = target as Map<PickleValue, PickleValue>;
    for (let index = 0; index + 1 < pairs.length; index += 2)
      map.set(pairs[index] ?? null, pairs[index + 1] ?? null);
  }

  private structureOps(): Record<number, () => void> {
    return {
      0x80: () => void this.u8(), // PROTO
      0x95: () => void this.u64(), // FRAME
      0x28: () => this.stack.push(MARK), // MARK
      0x7d: () => this.push(new Map()), // EMPTY_DICT
      0x5d: () => this.push([]), // EMPTY_LIST
      0x29: () => this.push([]), // EMPTY_TUPLE
      0x64: () => {
        // DICT
        const map = new Map<PickleValue, PickleValue>();
        this.setItems(map, this.popMark());
        this.push(map);
      },
      0x6c: () => this.push(this.popMark()), // LIST
      0x74: () => this.push(this.popMark()), // TUPLE
      0x85: () => this.push([this.value(this.pop())]), // TUPLE1
      0x86: () => {
        const second = this.value(this.pop());
        this.push([this.value(this.pop()), second]);
      },
      0x87: () => {
        const third = this.value(this.pop());
        const second = this.value(this.pop());
        this.push([this.value(this.pop()), second, third]);
      },
    };
  }

  private scalarOps(): Record<number, () => void> {
    const text = (length: number) => this.bytes(length).toString("utf8");
    const raw = (length: number) => Buffer.from(this.bytes(length));
    return {
      0x58: () => this.push(text(this.u32())), // BINUNICODE
      0x8c: () => this.push(text(this.u8())), // SHORT_BINUNICODE
      0x8d: () => this.push(text(this.u64())), // BINUNICODE8
      0x54: () => this.push(raw(this.u32())), // BINSTRING
      0x55: () => this.push(raw(this.u8())), // SHORT_BINSTRING
      0x42: () => this.push(raw(this.u32())), // BINBYTES
      0x43: () => this.push(raw(this.u8())), // SHORT_BINBYTES
      0x8e: () => this.push(raw(this.u64())), // BINBYTES8
      0x4a: () => this.push(BigInt(this.data.readInt32LE(this.need(4)))), // BININT
      0x4b: () => this.push(BigInt(this.u8())), // BININT1
      0x4d: () => this.push(BigInt(this.data.readUInt16LE(this.need(2)))), // BININT2
      0x8a: () => this.push(signedInteger(this.bytes(this.u8()))), // LONG1
      0x8b: () => this.push(signedInteger(this.bytes(this.u32()))), // LONG4
      0x4e: () => this.push(null), // NONE
      0x88: () => this.push(true), // NEWTRUE
      0x89: () => this.push(false), // NEWFALSE
    };
  }

  private mutationOps(): Record<number, () => void> {
    return {
      0x61: () => {
        // APPEND
        const item = this.value(this.pop());
        this.list(this.top()).push(item);
      },
      0x65: () => {
        // APPENDS
        const values = this.popMark();
        this.list(this.top()).push(...values);
      },
      0x73: () => {
        // SETITEM
        const item = this.value(this.pop());
        const key = this.value(this.pop());
        this.setItems(this.top(), [key, item]);
      },
      0x75: () => {
        // SETITEMS
        const pairs = this.popMark();
        this.setItems(this.top(), pairs);
      },
      0x94: () => this.memo.set(this.memo.size, this.top()), // MEMOIZE
      0x71: () => this.memo.set(this.u8(), this.top()), // BINPUT
      0x72: () => this.memo.set(this.u32(), this.top()), // LONG_BINPUT
      0x68: () => this.push(this.memo.get(this.u8()) ?? fail("unknown memo")), // BINGET
      0x6a: () => this.push(this.memo.get(this.u32()) ?? fail("unknown memo")), // LONG_BINGET
    };
  }

  private allowed(name: string): AllowedCallable {
    return (
      ALLOWED_GLOBALS[name] ??
      fail(`refusing global ${name.replace("\n", ".")}`)
    );
  }

  private callableOps(): Record<number, () => void> {
    return {
      0x63: () => this.push(this.allowed(`${this.line()}\n${this.line()}`)), // GLOBAL
      0x93: () => {
        // STACK_GLOBAL
        const name = this.value(this.pop());
        const module = this.value(this.pop());
        this.push(this.allowed(`${String(module)}\n${String(name)}`));
      },
      0x52: () => {
        // REDUCE
        const args = this.pop();
        this.push(this.reduce(this.pop(), args));
      },
    };
  }

  /** `bytes()` and `_codecs.encode(text, "latin1")`, how Python 3 pickles bytes at protocol 2. */
  private reduce(callable: StackItem, args: StackItem): PickleValue {
    if (!isCallable(callable))
      return fail("REDUCE of a value that is not an allowed callable");
    const list = Array.isArray(args)
      ? (args as readonly PickleValue[])
      : fail("REDUCE without a tuple");
    if (callable.callable === "bytes" && list.length === 0)
      return Buffer.alloc(0);
    const [text, encoding] = list;
    if (
      callable.callable === "codecs.encode" &&
      typeof text === "string" &&
      (encoding === "latin1" || encoding === "latin-1")
    )
      return Buffer.from(text, "latin1");
    return fail("REDUCE with unexpected arguments");
  }

  run(): PickleValue {
    while (this.at < this.data.length) {
      const opcode = this.u8();
      if (opcode === 0x2e) {
        // STOP
        if (this.stack.length !== 1) fail("stack not balanced at STOP");
        return this.value(this.stack[0] ?? null);
      }
      const handle =
        this.handlers[opcode] ??
        fail(`unsupported opcode 0x${opcode.toString(16)}`);
      handle();
    }
    return fail("missing STOP");
  }
}

/**
 * Decode a pickle built only from containers, strings, bytes and integers,
 * as Ren'Py writes archive indexes. Any opcode that could import or call
 * code beyond Python's own `bytes` spellings is refused, never executed.
 */
export const decodeSafePickle = (data: Buffer): PickleValue =>
  new SafePickleReader(data).run();
