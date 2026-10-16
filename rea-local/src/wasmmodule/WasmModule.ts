import {
  blockType,
  skipImmediates,
  WasmFormatError,
  WasmReader,
} from "./WasmReader.js";

/**
 * A decoded WebAssembly core module: the section table, the type, import,
 * function, export and global spaces, code bodies with their direct calls,
 * data segments and custom sections, including the name and producers
 * sections toolchains write. Nothing is compiled or run.
 */

export const SECTION_NAMES = [
  "custom",
  "type",
  "import",
  "function",
  "table",
  "memory",
  "global",
  "export",
  "start",
  "element",
  "code",
  "data",
  "datacount",
  "tag",
] as const;

export type ExternalKind = "function" | "table" | "memory" | "global" | "tag";
const KINDS: readonly ExternalKind[] = [
  "function",
  "table",
  "memory",
  "global",
  "tag",
];

export interface Section {
  readonly id: number;
  readonly name: string;
  readonly offset: number;
  readonly size: number;
  entries: number | null;
}

export interface Import {
  readonly module: string;
  readonly name: string;
  readonly kind: ExternalKind;
  readonly type: string;
  readonly index: number;
}

export interface Body {
  readonly offset: number;
  readonly size: number;
  readonly locals: number;
  /** Direct callee index → call sites. */
  readonly calls: Map<number, number>;
  indirect: number;
  decoded: boolean;
}

export interface DataSegment {
  readonly mode: "active" | "passive";
  readonly memory: number | null;
  readonly address: number | null;
  readonly offset: number;
  readonly size: number;
}

export interface Memory {
  readonly minimum: number;
  readonly maximum: number | null;
  readonly shared: boolean;
  readonly memory64: boolean;
}

export interface Module {
  readonly sections: Section[];
  readonly types: string[];
  readonly imports: Import[];
  /** Type index of each defined (non-imported) function. */
  readonly functions: number[];
  readonly exports: { name: string; kind: ExternalKind; index: number }[];
  readonly bodies: Body[];
  readonly data: DataSegment[];
  readonly custom: { name: string; offset: number; size: number }[];
  readonly memories: Memory[];
  tables: number;
  globals: number;
  start: number | null;
  readonly names: {
    module: string | null;
    functions: Map<number, string>;
    data: Map<number, string>;
  };
  readonly producers: { field: string; name: string; version: string }[];
  readonly features: string[];
}

const kindOf = (byte: number): ExternalKind => {
  const kind = KINDS[byte];
  if (kind === undefined)
    throw new WasmFormatError(`Unknown external kind ${String(byte)}.`);
  return kind;
};

const signature = (
  params: readonly string[],
  results: readonly string[],
): string =>
  `(${params.join(", ")}) -> ${results.length === 0 ? "()" : results.length === 1 ? (results[0] ?? "") : `(${results.join(", ")})`}`;

/** Composite types: func, struct and array (the latter two from the GC proposal). */
const compositeType = (reader: WasmReader): string => {
  const form = reader.u8();
  if (form === 0x60)
    return signature(
      reader.vector((r) => r.valueType()),
      reader.vector((r) => r.valueType()),
    );
  if (form === 0x5f) {
    const fields = reader.vector((r) => {
      const type = r.valueType();
      r.u8();
      return type;
    });
    return `struct { ${fields.join(", ")} }`;
  }
  if (form === 0x5e) {
    const type = reader.valueType();
    reader.u8();
    return `array ${type}`;
  }
  throw new WasmFormatError(`Unknown type form 0x${form.toString(16)}.`);
};

const subType = (reader: WasmReader): string => {
  const byte = reader.bytes[reader.at] ?? 0;
  if (byte === 0x50 || byte === 0x4f) {
    reader.at += 1;
    reader.vector((r) => r.u32());
  }
  return compositeType(reader);
};

const readTypes = (reader: WasmReader): string[] => {
  const types: string[] = [];
  reader.vector((r) => {
    if ((r.bytes[r.at] ?? 0) === 0x4e) {
      r.at += 1;
      for (const type of r.vector((inner) => subType(inner))) types.push(type);
    } else types.push(subType(r));
  });
  return types;
};

const tableType = (reader: WasmReader): string => {
  const element = reader.valueType();
  const limits = reader.limits();
  return `${element} ${String(limits.minimum)}${limits.maximum === null ? "" : `..${String(limits.maximum)}`}`;
};

const memoryText = (memory: Memory): string =>
  `${memory.memory64 ? "i64 " : ""}${String(memory.minimum)}${memory.maximum === null ? "" : `..${String(memory.maximum)}`} pages${memory.shared ? " shared" : ""}`;

const readImports = (reader: WasmReader, module: Module): void => {
  const counters: Record<ExternalKind, number> = {
    function: 0,
    table: 0,
    memory: 0,
    global: 0,
    tag: 0,
  };
  reader.vector((r) => {
    const from = r.name();
    const name = r.name();
    const kind = kindOf(r.u8());
    let type: string;
    if (kind === "function") type = module.types[r.u32()] ?? "?";
    else if (kind === "table") type = tableType(r);
    else if (kind === "memory") {
      const memory = r.limits();
      module.memories.push(memory);
      type = memoryText(memory);
    } else if (kind === "global") {
      const value = r.valueType();
      type = r.u8() === 1 ? `mut ${value}` : value;
    } else {
      r.u8();
      type = module.types[r.u32()] ?? "?";
    }
    module.imports.push({
      module: from,
      name,
      kind,
      type,
      index: counters[kind],
    });
    counters[kind] += 1;
  });
};

/** Walk a function body's instructions, recording direct and indirect calls. */
const readBody = (reader: WasmReader, offset: number, size: number): Body => {
  const locals = reader.vector((r) => {
    const count = r.u32();
    r.valueType();
    return count;
  });
  const body: Body = {
    offset,
    size,
    locals: locals.reduce((sum, count) => sum + count, 0),
    calls: new Map(),
    indirect: 0,
    decoded: true,
  };
  try {
    while (!reader.done) {
      const opcode = reader.u8();
      if (opcode === 0x10 || opcode === 0x12) {
        const callee = reader.u32();
        body.calls.set(callee, (body.calls.get(callee) ?? 0) + 1);
      } else if (
        opcode === 0x11 ||
        opcode === 0x13 ||
        opcode === 0x14 ||
        opcode === 0x15
      ) {
        body.indirect += 1;
        skipImmediates(reader, opcode);
      } else if (opcode === 0x02 || opcode === 0x03 || opcode === 0x04)
        blockType(reader);
      else skipImmediates(reader, opcode);
    }
  } catch (cause) {
    if (!(cause instanceof WasmFormatError)) throw cause;
    body.decoded = false;
  }
  return body;
};

const readCode = (reader: WasmReader, module: Module): void => {
  reader.vector((r) => {
    const size = r.u32();
    const start = r.at;
    if (start + size > r.end)
      throw new WasmFormatError("A function body runs past the code section.");
    module.bodies.push(
      readBody(new WasmReader(r.bytes, start, start + size), start, size),
    );
    r.at = start + size;
  });
};

const readData = (reader: WasmReader, module: Module): void => {
  reader.vector((r) => {
    const flags = r.u32();
    const memory = flags === 2 ? r.u32() : flags === 1 ? null : 0;
    const address = flags === 1 ? null : r.constant();
    const size = r.u32();
    module.data.push({
      mode: flags === 1 ? "passive" : "active",
      memory,
      address,
      offset: r.at,
      size,
    });
    r.skip(size);
  });
};

const nameMap = (reader: WasmReader, into: Map<number, string>): void => {
  reader.vector((r) => {
    const index = r.u32();
    into.set(index, r.name());
  });
};

/** The "name" custom section: module, function and data segment names. */
const readNames = (reader: WasmReader, module: Module): void => {
  while (!reader.done) {
    const id = reader.u8();
    const size = reader.u32();
    const end = reader.at + size;
    const sub = new WasmReader(reader.bytes, reader.at, end);
    if (id === 0) module.names.module = sub.name();
    else if (id === 1) nameMap(sub, module.names.functions);
    else if (id === 9) nameMap(sub, module.names.data);
    reader.at = end;
  }
};

const readCustom = (reader: WasmReader, module: Module): void => {
  const name = reader.name();
  module.custom.push({ name, offset: reader.at, size: reader.end - reader.at });
  try {
    if (name === "name") readNames(reader, module);
    else if (name === "producers")
      reader.vector((r) => {
        const field = r.name();
        for (const value of r.vector((inner) => ({
          name: inner.name(),
          version: inner.name(),
        })))
          module.producers.push({ field, ...value });
      });
    else if (name === "target_features")
      reader.vector((r) => {
        const prefix = String.fromCharCode(r.u8());
        module.features.push(`${prefix}${r.name()}`);
      });
  } catch (cause) {
    // A malformed name or producers section is metadata only; the module stays readable.
    if (!(cause instanceof WasmFormatError)) throw cause;
  }
};

const readExports = (reader: WasmReader, module: Module): void => {
  reader.vector((r) => {
    const name = r.name();
    const kind = kindOf(r.u8());
    module.exports.push({ name, kind, index: r.u32() });
  });
};

const SECTION_READERS: Readonly<
  Record<number, (reader: WasmReader, module: Module) => number | void>
> = {
  1: (r, m) => {
    m.types.push(...readTypes(r));
    return m.types.length;
  },
  2: (r, m) => {
    readImports(r, m);
    return m.imports.length;
  },
  3: (r, m) => {
    m.functions.push(...r.vector((inner) => inner.u32()));
    return m.functions.length;
  },
  4: (r, m) => {
    m.tables = r.u32();
    return m.tables;
  },
  5: (r, m) => {
    m.memories.push(...r.vector((inner) => inner.limits()));
    return m.memories.length;
  },
  6: (r, m) => {
    m.globals = r.u32();
    return m.globals;
  },
  7: (r, m) => {
    readExports(r, m);
    return m.exports.length;
  },
  8: (r, m) => {
    m.start = r.u32();
  },
  10: (r, m) => {
    readCode(r, m);
    return m.bodies.length;
  },
  11: (r, m) => {
    readData(r, m);
    return m.data.length;
  },
};

/** Decode a core module; component-model binaries and other versions are refused. */
export const readModule = (bytes: Buffer): Module => {
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0x6d736100)
    throw new WasmFormatError("Missing the \\0asm magic number.");
  const version = bytes.readUInt32LE(4);
  if (version !== 1)
    throw new WasmFormatError(
      version === 0x1000d
        ? "A component-model binary, not a core module."
        : `Unsupported version ${String(version)}.`,
    );
  const module: Module = {
    sections: [],
    types: [],
    imports: [],
    functions: [],
    exports: [],
    bodies: [],
    data: [],
    custom: [],
    memories: [],
    tables: 0,
    globals: 0,
    start: null,
    names: { module: null, functions: new Map(), data: new Map() },
    producers: [],
    features: [],
  };
  const reader = new WasmReader(bytes, 8, bytes.length);
  while (!reader.done) {
    const id = reader.u8();
    const size = reader.u32();
    const offset = reader.at;
    if (offset + size > bytes.length)
      throw new WasmFormatError(`Section ${String(id)} runs past the module.`);
    const body = new WasmReader(bytes, offset, offset + size);
    const section: Section = {
      id,
      name: SECTION_NAMES[id] ?? `unknown(${String(id)})`,
      offset,
      size,
      entries: null,
    };
    if (id === 0) {
      readCustom(body, module);
      module.sections.push({
        ...section,
        name: module.custom.at(-1)?.name ?? "custom",
      });
    } else {
      const counted = SECTION_READERS[id]?.(body, module);
      section.entries = typeof counted === "number" ? counted : null;
      module.sections.push(section);
    }
    reader.at = offset + size;
  }
  if (module.bodies.length !== module.functions.length)
    throw new WasmFormatError(
      `The code section has ${String(module.bodies.length)} bodies for ${String(module.functions.length)} functions.`,
    );
  return module;
};
