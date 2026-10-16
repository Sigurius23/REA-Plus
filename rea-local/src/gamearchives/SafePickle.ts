import { GameArchiveError } from "./GameArchiveTypes.js";

/** A class the pickle names; it is recorded, never imported. */
export class PickleClass {
  constructor(
    readonly module: string,
    readonly name: string,
  ) {}

  get qualifiedName(): string {
    return `${this.module}.${this.name}`;
  }
}

/** An instance of an allowed class: constructor arguments and state, inert. */
export class PickleObject {
  /** Merged `__dict__` and `__slots__` state from BUILD. */
  readonly fields = new Map<string, PickleValue>();
  /** List-like contents (APPEND on list subclasses). */
  readonly items: PickleValue[] = [];
  /** Dict-like contents (SETITEM on dict subclasses). */
  readonly entries = new Map<PickleValue, PickleValue>();
  /** BUILD state that is not a dict or (dict, slots) pair. */
  state: PickleValue = null;

  constructor(
    readonly type: PickleClass,
    readonly args: readonly PickleValue[],
  ) {}
}

/** Values a pickle can hold here; `bytes` stay as buffers. */
export type PickleValue =
  | null
  | boolean
  | bigint
  | string
  | Buffer
  | PickleValue[]
  | readonly PickleValue[]
  | Map<PickleValue, PickleValue>
  | PickleClass
  | PickleObject;

export interface SafePickleOptions {
  /**
   * Classes that may be recorded as inert objects. Without it only data and
   * Python's two spellings of `bytes` decode.
   */
  readonly objects?: (module: string, name: string) => boolean;
  /** Prefix for error messages. */
  readonly label?: string;
}

const MARK = Symbol("mark");
type StackItem = PickleValue | typeof MARK;

const BYTES_GLOBALS = new Set([
  "_codecs.encode",
  "__builtin__.bytes",
  "builtins.bytes",
]);

const BUILTIN_MODULES = new Set(["builtins", "__builtin__"]);
const MAX_ITEMS = 50_000_000;

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

const asList = (value: PickleValue | undefined): PickleValue[] =>
  Array.isArray(value)
    ? [...(value as readonly PickleValue[])]
    : value instanceof PickleObject
      ? [...value.items]
      : [];

/** A pickle virtual machine limited to data opcodes and inert objects. */
class SafePickleReader {
  private readonly stack: StackItem[] = [];
  private readonly memo = new Map<number, StackItem>();
  private at = 0;
  private items = 0;
  private readonly handlers: Readonly<Record<number, () => void>>;

  constructor(
    private readonly data: Buffer,
    private readonly options: SafePickleOptions,
  ) {
    this.handlers = {
      ...this.structureOps(),
      ...this.scalarOps(),
      ...this.mutationOps(),
      ...this.objectOps(),
    };
  }

  fail(message: string): never {
    throw new GameArchiveError(
      `${this.options.label ?? "Index pickle"}: ${message}`,
    );
  }

  private need(length: number): number {
    if (length < 0 || this.at + length > this.data.length)
      this.fail("truncated");
    const start = this.at;
    this.at += length;
    return start;
  }

  private u8 = () => this.data[this.need(1)] ?? 0;
  private u32 = () => this.data.readUInt32LE(this.need(4));
  private u64 = () => {
    const value = this.data.readBigUInt64LE(this.need(8));
    if (value > BigInt(this.data.length)) this.fail("length past the end");
    return Number(value);
  };

  private bytes(length: number): Buffer {
    const start = this.need(length);
    return this.data.subarray(start, start + length);
  }

  private line(): string {
    const end = this.data.indexOf(0x0a, this.at);
    if (end < 0) this.fail("unterminated line");
    const text = this.data.toString("latin1", this.at, end);
    this.at = end + 1;
    return text;
  }

  private push(item: StackItem): void {
    this.items += 1;
    if (this.items > MAX_ITEMS) this.fail("too many items");
    this.stack.push(item);
  }

  private pop(): StackItem {
    return this.stack.length === 0
      ? this.fail("stack underflow")
      : (this.stack.pop() as StackItem);
  }

  private top(): StackItem {
    return this.stack[this.stack.length - 1] ?? this.fail("stack underflow");
  }

  private value(item: StackItem): PickleValue {
    return item === MARK ? this.fail("expected a value") : item;
  }

  private popMark(): PickleValue[] {
    const index = this.stack.lastIndexOf(MARK);
    if (index < 0) this.fail("missing mark");
    const values = this.stack.splice(index + 1).map((item) => this.value(item));
    this.stack.pop();
    return values;
  }

  private append(target: StackItem, values: readonly PickleValue[]): void {
    if (target instanceof PickleObject) target.items.push(...values);
    else if (Array.isArray(target)) (target as PickleValue[]).push(...values);
    else this.fail("append target is not a list");
  }

  private setItems(target: StackItem, pairs: readonly PickleValue[]): void {
    const map =
      target instanceof PickleObject
        ? target.entries
        : target instanceof Map
          ? (target as Map<PickleValue, PickleValue>)
          : this.fail("SETITEM target is not a dict");
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
      0x8f: () => this.push([]), // EMPTY_SET
      0x91: () => this.push(this.popMark()), // FROZENSET
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
      0x47: () => this.push(this.data.readDoubleBE(this.need(8)).toString()), // BINFLOAT, as text
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
        this.append(this.top(), [item]);
      },
      0x65: () => {
        // APPENDS
        const values = this.popMark();
        this.append(this.top(), values);
      },
      0x90: () => {
        // ADDITEMS
        const values = this.popMark();
        this.append(this.top(), values);
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
      0x68: () =>
        this.push(this.memo.get(this.u8()) ?? this.fail("unknown memo")), // BINGET
      0x6a: () =>
        this.push(this.memo.get(this.u32()) ?? this.fail("unknown memo")), // LONG_BINGET
    };
  }

  /** Only `bytes` spellings, plus classes the caller allows, may be named. */
  private named(module: string, name: string): PickleClass {
    const qualified = `${module}.${name}`;
    if (
      BYTES_GLOBALS.has(qualified) ||
      this.options.objects?.(module, name) === true
    )
      return new PickleClass(module, name);
    return this.fail(`refusing global ${qualified}`);
  }

  private objectOps(): Record<number, () => void> {
    return {
      0x63: () => this.push(this.named(this.line(), this.line())), // GLOBAL
      0x93: () => {
        // STACK_GLOBAL
        const name = this.value(this.pop());
        const module = this.value(this.pop());
        if (typeof module !== "string" || typeof name !== "string")
          this.fail("STACK_GLOBAL without names");
        this.push(this.named(module as string, name as string));
      },
      0x52: () => {
        // REDUCE
        const args = asList(this.value(this.pop()));
        this.push(this.construct(this.pop(), args, true));
      },
      0x81: () => {
        // NEWOBJ
        const args = asList(this.value(this.pop()));
        this.push(this.construct(this.pop(), args, false));
      },
      0x92: () => {
        // NEWOBJ_EX
        this.pop();
        const args = asList(this.value(this.pop()));
        this.push(this.construct(this.pop(), args, false));
      },
      0x62: () => {
        // BUILD
        const state = this.value(this.pop());
        this.build(this.top(), state);
      },
    };
  }

  /** Python 3 spells `bytes` as `bytes()` or `_codecs.encode(text, "latin1")`. */
  private bytesCall(name: string, args: readonly PickleValue[]): Buffer {
    const [text, encoding] = args;
    if (name === "bytes" && args.length === 0) return Buffer.alloc(0);
    if (
      name === "encode" &&
      typeof text === "string" &&
      (encoding === "latin1" || encoding === "latin-1")
    )
      return Buffer.from(text, "latin1");
    return this.fail(`${name} with unexpected arguments`);
  }

  /** Built-in containers and copyreg's reconstructor, or null for other classes. */
  private container(
    { module, name }: PickleClass,
    args: readonly PickleValue[],
    reduce: boolean,
  ): PickleValue | undefined {
    if (BUILTIN_MODULES.has(module)) {
      if (["list", "tuple", "set", "frozenset"].includes(name))
        return reduce ? asList(args[0]) : [];
      if (name === "dict")
        return args[0] instanceof Map ? new Map(args[0]) : new Map();
    }
    if (
      module === "collections" &&
      (name === "defaultdict" || name === "OrderedDict")
    )
      return new Map();
    if (
      (module === "copy_reg" || module === "copyreg") &&
      name === "_reconstructor"
    ) {
      const [type] = args;
      return type instanceof PickleClass
        ? new PickleObject(type, [])
        : this.fail("_reconstructor without a class");
    }
    return undefined;
  }

  /** Record a call to an allowed class without running anything. */
  private construct(
    callable: StackItem,
    args: readonly PickleValue[],
    reduce: boolean,
  ): PickleValue {
    if (!(callable instanceof PickleClass))
      return this.fail("call of a value that is not a named class");
    if (BYTES_GLOBALS.has(callable.qualifiedName))
      return this.bytesCall(callable.name, args);
    return (
      this.container(callable, args, reduce) ?? new PickleObject(callable, args)
    );
  }

  private build(target: StackItem, state: PickleValue): void {
    if (!(target instanceof PickleObject))
      return this.fail("BUILD on a value that is not an object");
    const merge = (part: PickleValue | undefined) => {
      if (part instanceof Map)
        for (const [key, entry] of part)
          if (typeof key === "string") target.fields.set(key, entry);
    };
    if (state instanceof Map) merge(state);
    else if (
      Array.isArray(state) &&
      state.length === 2 &&
      (state[0] === null || state[0] instanceof Map) &&
      state[1] instanceof Map
    ) {
      merge(state[0] as PickleValue);
      merge(state[1] as PickleValue);
    } else target.state = state;
  }

  run(): PickleValue {
    while (this.at < this.data.length) {
      const opcode = this.u8();
      if (opcode === 0x2e) {
        // STOP
        if (this.stack.length !== 1) this.fail("stack not balanced at STOP");
        return this.value(this.stack[0] ?? null);
      }
      const handle =
        this.handlers[opcode] ??
        this.fail(`unsupported opcode 0x${opcode.toString(16)}`);
      handle();
    }
    return this.fail("missing STOP");
  }
}

/**
 * Decode a pickle without executing it. By default only containers,
 * strings, bytes and integers decode (as Ren'Py writes archive indexes);
 * `options.objects` admits named classes as inert records. Every other
 * global is refused.
 */
export const decodeSafePickle = (
  data: Buffer,
  options: SafePickleOptions = {},
): PickleValue => new SafePickleReader(data, options).run();
