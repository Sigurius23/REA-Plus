/**
 * Godot files written byte by byte from the engine's sources: binary
 * resources (resource_format_binary.cpp), scene bundles (packed_scene.cpp),
 * compiled GDScript (gdscript_tokenizer*.cpp), marshalled Variants
 * (marshalls.cpp), project.binary, FileAccessCompressed and
 * FileAccessEncrypted.
 */
import { createCipheriv, createHash } from "node:crypto";
import { deflateSync, gzipSync, zstdCompressSync } from "node:zlib";

type Part = Buffer | readonly number[];
const cat = (...parts: readonly Part[]): Buffer =>
  Buffer.concat(
    parts.map((part) => (Buffer.isBuffer(part) ? part : Buffer.from(part))),
  );
const sized = (size: number, write: (buffer: Buffer) => void): Buffer => {
  const out = Buffer.alloc(size);
  write(out);
  return out;
};
export const u32 = (value: number) =>
  sized(4, (b) => b.writeUInt32LE(value >>> 0));
const i32 = (value: number) => sized(4, (b) => b.writeInt32LE(value));
const u16 = (value: number) => sized(2, (b) => b.writeUInt16LE(value));
const u64 = (value: bigint) => sized(8, (b) => b.writeBigUInt64LE(value));
const i64 = (value: bigint) => sized(8, (b) => b.writeBigInt64LE(value));
const f32 = (value: number) => sized(4, (b) => b.writeFloatLE(value));
const f64 = (value: number) => sized(8, (b) => b.writeDoubleLE(value));
const pad4 = (length: number) => Buffer.alloc((4 - (length % 4)) % 4);

/** A binary resource string: length counting a NUL, then UTF-8 and the NUL. */
const rstr = (text: string) => {
  const bytes = cat(Buffer.from(text, "utf8"), [0]);
  return cat(u32(bytes.length), bytes);
};

// ---- Variants in binary resources ----
export const rv = {
  nil: () => u32(1),
  bool: (value: boolean) => cat(u32(2), u32(value ? 1 : 0)),
  int: (value: number) => cat(u32(3), i32(value)),
  int64: (value: bigint) => cat(u32(40), i64(value)),
  float: (value: number) => cat(u32(4), f32(value)),
  double: (value: number) => cat(u32(41), f64(value)),
  string: (text: string) => cat(u32(5), rstr(text)),
  stringName: (text: string) => cat(u32(44), rstr(text)),
  vector2: (x: number, y: number) => cat(u32(10), f32(x), f32(y)),
  vector3i: (x: number, y: number, z: number) =>
    cat(u32(47), i32(x), i32(y), i32(z)),
  color: (...rgba: number[]) => cat(u32(20), ...rgba.map(f32)),
  transform2d: (...parts: number[]) => cat(u32(18), ...parts.map(f32)),
  /** Names and subnames are string-table indexes. */
  nodePath: (names: number[], subnames: number[], absolute = false) =>
    cat(
      u32(22),
      u16(names.length),
      u16(subnames.length | (absolute ? 0x8000 : 0)),
      ...[...names, ...subnames].map(u32),
    ),
  none: () => cat(u32(24), u32(0)),
  internal: (index: number) => cat(u32(24), u32(2), u32(index)),
  external: (index: number) => cat(u32(24), u32(3), u32(index)),
  dictionary: (entries: readonly (readonly [Buffer, Buffer])[]) =>
    cat(u32(26), u32(entries.length), ...entries.flat()),
  array: (items: readonly Buffer[]) =>
    cat(u32(30), u32(items.length), ...items),
  bytes: (values: number[]) =>
    cat(u32(31), u32(values.length), values, pad4(values.length)),
  int32s: (values: number[]) =>
    cat(u32(32), u32(values.length), ...values.map(i32)),
  float32s: (values: number[]) =>
    cat(u32(33), u32(values.length), ...values.map(f32)),
  strings: (values: string[]) =>
    cat(u32(34), u32(values.length), ...values.map(rstr)),
  vector2s: (flat: number[]) =>
    cat(u32(37), u32(flat.length / 2), ...flat.map(f32)),
};

export interface FixtureResource {
  readonly path: string;
  readonly type: string;
  /** String-table index of each property name, and its encoded value. */
  readonly properties: readonly (readonly [number, Buffer])[];
}

/** FileAccessCompressed: magic, mode, block size, total, block sizes, blocks. */
export const compressedFile = (
  magic: "RSCC" | "GCPF",
  data: Buffer,
  mode: 0 | 1 | 2 | 3 = 2,
  blockSize = 4096,
): Buffer => {
  const count = Math.floor(data.length / blockSize) + 1;
  const blocks = Array.from({ length: count }, (_, index) => {
    const block = data.subarray(index * blockSize, (index + 1) * blockSize);
    if (mode === 0) return fastLzLiterals(block);
    if (mode === 1) return deflateSync(block);
    if (mode === 3) return gzipSync(block);
    return zstdCompressSync(block);
  });
  return cat(
    Buffer.from(magic),
    u32(mode),
    u32(blockSize),
    u32(data.length),
    ...blocks.map((b) => u32(b.length)),
    ...blocks,
  );
};

/** FastLZ level 1 made only of literal runs (control byte = run length - 1). */
export const fastLzLiterals = (data: Buffer): Buffer => {
  const out: number[] = [];
  for (let at = 0; at < data.length; at += 32) {
    const run = data.subarray(at, at + 32);
    out.push(run.length - 1, ...run);
  }
  return Buffer.from(out);
};

/**
 * var_to_bytes("abcabcabcabc") in FastLZ level 1: an 11-byte literal run
 * (type, length, "abc"), then a 9-byte match reaching back 3.
 */
export const FASTLZ_MATCH = Buffer.from([
  0x0a, 4, 0, 0, 0, 12, 0, 0, 0, 0x61, 0x62, 0x63, 0xe0, 0x00, 0x02,
]);

export const binaryResource = (options: {
  readonly major: number;
  readonly minor: number;
  readonly format: number;
  readonly type: string;
  /** 1 named ids, 2 uids, 4 real64, 8 script class. */
  readonly flags: number;
  readonly uid?: bigint;
  readonly scriptClass?: string;
  readonly strings: readonly string[];
  readonly external: readonly {
    readonly type: string;
    readonly path: string;
    readonly uid?: bigint;
  }[];
  readonly internal: readonly FixtureResource[];
  readonly compress?: boolean;
}): Buffer => {
  const uids = (options.flags & 2) !== 0;
  const head = cat(
    u32(0),
    u32(0),
    u32(options.major),
    u32(options.minor),
    u32(options.format),
    rstr(options.type),
    u64(0n),
    u32(options.flags),
    u64(options.uid ?? 0n),
    (options.flags & 8) === 0 ? [] : rstr(options.scriptClass ?? ""),
    Buffer.alloc(11 * 4),
    u32(options.strings.length),
    ...options.strings.map(rstr),
    u32(options.external.length),
    ...options.external.map((ext) =>
      cat(rstr(ext.type), rstr(ext.path), uids ? u64(ext.uid ?? 0n) : []),
    ),
    u32(options.internal.length),
  );
  const bodies = options.internal.map((resource) =>
    cat(
      rstr(resource.type),
      u32(resource.properties.length),
      ...resource.properties.flatMap(([name, value]) => [u32(name), value]),
    ),
  );
  const table = options.internal
    .map((resource) => rstr(resource.path).length + 8)
    .reduce((a, b) => a + b, 0);
  let at = (options.compress === true ? 0 : 4) + head.length + table;
  const offsets = bodies.map((body) => {
    const offset = at;
    at += body.length;
    return offset;
  });
  const stream = cat(
    head,
    ...options.internal.map((resource, index) =>
      cat(rstr(resource.path), u64(BigInt(offsets[index] ?? 0))),
    ),
    ...bodies,
    Buffer.from("RSRC"),
  );
  return options.compress === true
    ? compressedFile("RSCC", stream)
    : cat(Buffer.from("RSRC"), stream);
};

// ---- Scene bundles ----
const NAME = (index: number, order: number) => index | ((order + 1) << 18);

export interface FixtureNode {
  readonly parent: number;
  readonly type: number;
  readonly name: number;
  readonly instance?: number;
  readonly properties?: readonly (readonly [number, number])[];
  readonly groups?: readonly number[];
}

/** The _bundled dictionary: names, variants, and nodes and connections as int arrays. */
export const sceneBundle = (options: {
  readonly names: readonly string[];
  readonly variants: readonly Buffer[];
  readonly nodes: readonly FixtureNode[];
  readonly connections: readonly (readonly number[])[];
  readonly nodePaths?: readonly Buffer[];
}): Buffer => {
  const nodes = options.nodes.flatMap((node, order) => [
    node.parent,
    node.parent < 0 ? 0x7fffffff : 0,
    node.type,
    NAME(node.name, order),
    node.instance ?? -1,
    node.properties?.length ?? 0,
    ...(node.properties ?? []).flat(),
    node.groups?.length ?? 0,
    ...(node.groups ?? []),
  ]);
  const key = (text: string) => rv.string(text);
  return rv.dictionary([
    [key("names"), rv.strings([...options.names])],
    [key("variants"), rv.array(options.variants)],
    [key("node_count"), rv.int(options.nodes.length)],
    [key("nodes"), rv.int32s(nodes)],
    [key("conn_count"), rv.int(options.connections.length)],
    [key("conns"), rv.int32s(options.connections.flat())],
    [key("node_paths"), rv.array(options.nodePaths ?? [])],
    [key("editable_instances"), rv.array([])],
    [key("version"), rv.int(3)],
  ]);
};

// ---- Marshalled Variants (store_var, var_to_bytes, script constants) ----
const mstr = (text: string) => {
  const bytes = Buffer.from(text, "utf8");
  return cat(u32(bytes.length), bytes, pad4(bytes.length));
};
export const mv = {
  nil: () => u32(0),
  bool: (value: boolean) => cat(u32(1), u32(value ? 1 : 0)),
  int: (value: number) => cat(u32(2), i32(value)),
  int64: (value: bigint) => cat(u32(2 | (1 << 16)), i64(value)),
  float: (value: number) => cat(u32(3), f32(value)),
  double: (value: number) => cat(u32(3 | (1 << 16)), f64(value)),
  string: (text: string) => cat(u32(4), mstr(text)),
  vector2: (x: number, y: number) => cat(u32(5), f32(x), f32(y)),
  /** Godot 4 numbering from here; Godot 3 uses 18 and 19 for Dictionary and Array. */
  stringName: (text: string) => cat(u32(21), mstr(text)),
  nodePath4: (names: string[], subnames: string[]) =>
    cat(
      u32(22),
      u32((names.length | 0x80000000) >>> 0),
      u32(subnames.length),
      u32(0),
      ...[...names, ...subnames].map(mstr),
    ),
  dictionary: (
    entries: readonly (readonly [Buffer, Buffer])[],
    major: 3 | 4 = 4,
  ) => cat(u32(major === 4 ? 27 : 18), u32(entries.length), ...entries.flat()),
  array: (items: readonly Buffer[], major: 3 | 4 = 4) =>
    cat(u32(major === 4 ? 28 : 19), u32(items.length), ...items),
  typedArray: (builtin: number, items: readonly Buffer[]) =>
    cat(u32(28 | (1 << 16)), u32(builtin), u32(items.length), ...items),
  packedInt32: (values: number[], major: 3 | 4 = 4) =>
    cat(u32(major === 4 ? 30 : 21), u32(values.length), ...values.map(i32)),
  object: (type: string, properties: readonly (readonly [string, Buffer])[]) =>
    cat(
      u32(24),
      mstr(type),
      u32(properties.length),
      ...properties.flatMap(([name, value]) => [mstr(name), value]),
    ),
};

/** store_var: each value preceded by its length. */
export const storeVar = (values: readonly Buffer[]): Buffer =>
  cat(...values.flatMap((value) => [u32(value.length), value]));

/** project.binary: ECFG, a count, then each key and value with lengths. */
export const projectBinary = (
  settings: readonly (readonly [string, Buffer])[],
): Buffer =>
  cat(
    Buffer.from("ECFG"),
    u32(settings.length),
    ...settings.flatMap(([key, value]) => [
      u32(Buffer.byteLength(key)),
      Buffer.from(key),
      u32(value.length),
      value,
    ]),
  );

// ---- Compiled GDScript ----
const XOR = (bytes: Buffer) => Buffer.from(bytes.map((byte) => byte ^ 0xb6));

/** Bytecode 13 (Godot 3.1-3.6): token codes carry their value above bit 8. */
export const godot3Script = (options: {
  readonly version?: 12 | 13;
  readonly identifiers: readonly string[];
  readonly constants: readonly Buffer[];
  readonly lines: readonly (readonly [number, number])[];
  readonly tokens: readonly number[];
}): Buffer =>
  cat(
    Buffer.from("GDSC"),
    u32(options.version ?? 13),
    u32(options.identifiers.length),
    u32(options.constants.length),
    u32(options.lines.length),
    u32(options.tokens.length),
    ...options.identifiers.map((name) => {
      const bytes = cat(Buffer.from(name, "utf8"), [0]);
      return cat(u32(bytes.length), XOR(bytes));
    }),
    ...options.constants,
    ...options.lines.flatMap(([token, line]) => [u32(token), u32(line)]),
    ...options.tokens.map((code) =>
      code > 0x7f ? u32((code | 0x80) >>> 0) : Buffer.from([code]),
    ),
  );

export const token3 = (type: number, value = 0) => type | (value << 8);

/** Tokenizer 100/101 (Godot 4.3+): UTF-32 identifiers, logical-line starts, then (type, line) tokens. */
export const godot4Script = (options: {
  readonly version: 100 | 101;
  readonly identifiers: readonly string[];
  readonly constants: readonly Buffer[];
  /** token index, line and column of each logical line after the first */
  readonly starts: readonly (readonly [number, number, number])[];
  readonly tokens: readonly (readonly [number, number, number?])[];
  readonly compress?: boolean;
}): Buffer => {
  const body = cat(
    u32(options.identifiers.length),
    u32(options.constants.length),
    u32(options.starts.length),
    options.version === 100 ? u32(0) : [],
    u32(options.tokens.length),
    ...options.identifiers.map((name) => {
      const points = [...name].map((char) => u32(char.codePointAt(0) ?? 0));
      return cat(u32(points.length), XOR(cat(...points)));
    }),
    ...options.constants,
    ...options.starts.flatMap(([token, line]) => [u32(token), u32(line)]),
    ...options.starts.flatMap(([token, , column]) => [u32(token), u32(column)]),
    ...options.tokens.map(([type, line, value]) =>
      cat(u32((type | ((value ?? 0) << 8) | 0x80) >>> 0), u32(line)),
    ),
  );
  return options.compress === true
    ? cat(
        Buffer.from("GDSC"),
        u32(options.version),
        u32(body.length),
        zstdCompressSync(body),
      )
    : cat(Buffer.from("GDSC"), u32(options.version), u32(0), body);
};

// ---- FileAccessEncrypted ----
const md5 = (data: Buffer) => createHash("md5").update(data).digest();
const padded = (data: Buffer) =>
  cat(data, Buffer.alloc((16 - (data.length % 16)) % 16));
const encrypt = (
  algorithm: string,
  key: Buffer,
  iv: Buffer | null,
  data: Buffer,
) => {
  const cipher = createCipheriv(algorithm, key, iv);
  cipher.setAutoPadding(false);
  return cat(cipher.update(padded(data)), cipher.final());
};

/** Godot 3: GDEC, mode 1, MD5, length, AES-256-ECB. */
export const gdec3 = (data: Buffer, key: Buffer): Buffer =>
  cat(
    Buffer.from("GDEC"),
    u32(1),
    md5(data),
    u64(BigInt(data.length)),
    encrypt("aes-256-ecb", key, null, data),
  );

/** Godot 4: GDEC, MD5, length, IV, AES-256-CFB. */
export const gdec4 = (
  data: Buffer,
  key: Buffer,
  iv = Buffer.alloc(16, 7),
): Buffer =>
  cat(
    Buffer.from("GDEC"),
    md5(data),
    u64(BigInt(data.length)),
    iv,
    encrypt("aes-256-cfb", key, iv, data),
  );

/** The key open_encrypted_with_pass derives: the ASCII of the password's MD5 hex. */
export const passwordKey = (password: string): Buffer =>
  Buffer.from(createHash("md5").update(password).digest("hex"), "ascii");
