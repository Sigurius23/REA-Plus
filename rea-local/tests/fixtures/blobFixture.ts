/**
 * The same small save game written in each format the blob decoder reads,
 * by encoders written from each format's specification: Protocol Buffers'
 * wire format, MessagePack, CBOR (RFC 8949), BSON 1.1, Java NBT and an
 * Anvil region file, plus an uncompressed LZ4 frame.
 */
import { deflateSync } from "node:zlib";

const concat = (...parts: (Buffer | number[])[]) =>
  Buffer.concat(
    parts.map((part) => (Buffer.isBuffer(part) ? part : Buffer.from(part))),
  );

// ---- Protocol Buffers ----
export const varint = (value: bigint | number): number[] => {
  let rest = BigInt.asUintN(64, BigInt(value));
  const out: number[] = [];
  do {
    const byte = Number(rest & 0x7fn);
    rest >>= 7n;
    out.push(rest > 0n ? byte | 0x80 : byte);
  } while (rest > 0n);
  return out;
};
const tag = (field: number, wire: number) => varint((field << 3) | wire);
const ld = (field: number, bytes: Buffer) =>
  concat(tag(field, 2), varint(bytes.length), bytes);

/** player "Ana", level 42, hp -7 (int32), zig -3 (sint32), ratio 0.5 (float), items {name, count} x2, pos group, flags packed. */
export const protobufSave = (): Buffer => {
  const float = Buffer.alloc(4);
  float.writeFloatLE(0.5);
  const item = (name: string, count: number) =>
    concat(ld(1, Buffer.from(name)), tag(2, 0), varint(count));
  return concat(
    ld(1, Buffer.from("Ana")),
    tag(2, 0),
    varint(42),
    tag(3, 0),
    varint(-7),
    tag(4, 0),
    varint(5),
    tag(7, 5),
    float,
    ld(9, item("sword", 1)),
    ld(9, item("potion", 12)),
    tag(12, 3),
    tag(13, 0),
    varint(5),
    tag(14, 0),
    varint(9),
    tag(12, 4),
    ld(10, Buffer.from([1, 2, 0xac, 0x02])),
  );
};

// ---- MessagePack ----
type Value =
  | null
  | boolean
  | number
  | bigint
  | string
  | Buffer
  | Value[]
  | readonly (readonly [string, Value])[]
  | { readonly float: number };

const isEntries = (
  value: Value,
): value is readonly (readonly [string, Value])[] =>
  Array.isArray(value) &&
  value.length > 0 &&
  Array.isArray(value[0]) &&
  typeof value[0][0] === "string" &&
  value[0].length === 2 &&
  (value as unknown[]).every(
    (entry) => Array.isArray(entry) && entry.length === 2,
  );

/** A map or array header: the fix form below 16 entries, else the 16-bit form. */
const container = (fix: number, wide: number, count: number): number[] =>
  count < 16 ? [fix | count] : [wide, count >> 8, count & 0xff];

export const msgpack = (value: Value): Buffer => {
  if (value === null) return Buffer.from([0xc0]);
  if (typeof value === "boolean") return Buffer.from([value ? 0xc3 : 0xc2]);
  if (typeof value === "number") {
    if (value >= 0 && value < 128) return Buffer.from([value]);
    if (value < 0 && value >= -32) return Buffer.from([value & 0xff]);
    const out = Buffer.alloc(5);
    out[0] = 0xd2;
    out.writeInt32BE(value, 1);
    return out;
  }
  if (typeof value === "bigint") {
    const out = Buffer.alloc(9);
    out[0] = 0xd3;
    out.writeBigInt64BE(value, 1);
    return out;
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return concat(
      bytes.length < 32 ? [0xa0 | bytes.length] : [0xd9, bytes.length],
      bytes,
    );
  }
  if (Buffer.isBuffer(value)) return concat([0xc4, value.length], value);
  if ("float" in value) {
    const out = Buffer.alloc(9);
    out[0] = 0xcb;
    out.writeDoubleBE(value.float, 1);
    return out;
  }
  if (isEntries(value))
    return concat(
      container(0x80, 0xde, value.length),
      ...value.flatMap(([key, item]) => [msgpack(key), msgpack(item)]),
    );
  return concat(
    container(0x90, 0xdc, (value as Value[]).length),
    ...(value as Value[]).map(msgpack),
  );
};

// ---- CBOR ----
const head = (major: number, value: number): number[] =>
  value < 24
    ? [(major << 5) | value]
    : value < 256
      ? [(major << 5) | 24, value]
      : [(major << 5) | 25, value >> 8, value & 0xff];

export const cbor = (value: Value): Buffer => {
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "number")
    return Buffer.from(value >= 0 ? head(0, value) : head(1, -1 - value));
  if (typeof value === "bigint") {
    const out = Buffer.alloc(9);
    out[0] = 0x1b;
    out.writeBigUInt64BE(value, 1);
    return out;
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return concat(head(3, bytes.length), bytes);
  }
  if (Buffer.isBuffer(value)) return concat(head(2, value.length), value);
  if ("float" in value) {
    const out = Buffer.alloc(9);
    out[0] = 0xfb;
    out.writeDoubleBE(value.float, 1);
    return out;
  }
  if (isEntries(value))
    return concat(
      head(5, value.length),
      ...value.flatMap(([key, item]) => [cbor(key), cbor(item)]),
    );
  return concat(
    head(4, (value as Value[]).length),
    ...(value as Value[]).map(cbor),
  );
};

/** The save as a MessagePack/CBOR value. */
export const SAVE: Value = [
  ["player", "Ana"],
  ["level", 42],
  ["hp", -7],
  ["gold", 123456789012n],
  ["ratio", { float: 0.5 }],
  ["alive", true],
  ["pet", null],
  [
    "items",
    [
      [
        ["name", "sword"],
        ["count", 1],
      ],
      [
        ["name", "potion"],
        ["count", 12],
      ],
    ],
  ],
  ["blob", Buffer.from([0, 0xff])],
];

// ---- BSON ----
const cstring = (text: string) => concat(Buffer.from(text), [0]);
const int32 = (value: number) => {
  const out = Buffer.alloc(4);
  out.writeInt32LE(value);
  return out;
};
export const bsonDocument = (elements: readonly Buffer[]): Buffer => {
  const body = concat(...elements, [0]);
  return concat(int32(body.length + 4), body);
};
export const bson = {
  string: (name: string, text: string) =>
    concat(
      [0x02],
      cstring(name),
      int32(Buffer.byteLength(text) + 1),
      cstring(text),
    ),
  int32: (name: string, value: number) =>
    concat([0x10], cstring(name), int32(value)),
  int64: (name: string, value: bigint) => {
    const out = Buffer.alloc(8);
    out.writeBigInt64LE(value);
    return concat([0x12], cstring(name), out);
  },
  double: (name: string, value: number) => {
    const out = Buffer.alloc(8);
    out.writeDoubleLE(value);
    return concat([0x01], cstring(name), out);
  },
  bool: (name: string, value: boolean) =>
    concat([0x08], cstring(name), [value ? 1 : 0]),
  null: (name: string) => concat([0x0a], cstring(name)),
  document: (name: string, elements: readonly Buffer[]) =>
    concat([0x03], cstring(name), bsonDocument(elements)),
  array: (name: string, elements: readonly Buffer[]) =>
    concat([0x04], cstring(name), bsonDocument(elements)),
  binary: (name: string, data: Buffer) =>
    concat([0x05], cstring(name), int32(data.length), [0], data),
  objectId: (name: string, hex: string) =>
    concat([0x07], cstring(name), Buffer.from(hex, "hex")),
};

export const bsonSave = (): Buffer =>
  bsonDocument([
    bson.string("player", "Ana"),
    bson.int32("level", 42),
    bson.int64("gold", 123456789012n),
    bson.double("ratio", 0.5),
    bson.bool("alive", true),
    bson.null("pet"),
    bson.array("items", [
      bson.document("0", [
        bson.string("name", "sword"),
        bson.int32("count", 1),
      ]),
      bson.document("1", [
        bson.string("name", "potion"),
        bson.int32("count", 12),
      ]),
    ]),
    bson.binary("blob", Buffer.from([0, 0xff])),
    bson.objectId("_id", "5f43a1b2c3d4e5f601234567"),
  ]);

// ---- NBT: Java writes big-endian, Bedrock little-endian ----
const sized = (size: number, write: (buffer: Buffer) => void) => {
  const out = Buffer.alloc(size);
  write(out);
  return out;
};

/** NBT tag writers for one byte order. */
export const nbtWriter = (little: boolean) => {
  const u16 = (value: number) =>
    sized(2, (b) => (little ? b.writeUInt16LE(value) : b.writeUInt16BE(value)));
  const i32 = (value: number) =>
    sized(4, (b) => (little ? b.writeInt32LE(value) : b.writeInt32BE(value)));
  const name = (text: string) => {
    const bytes = Buffer.from(text);
    return concat(u16(bytes.length), bytes);
  };
  return {
    byte: (key: string, value: number) =>
      concat([1], name(key), [value & 0xff]),
    short: (key: string, value: number) =>
      concat(
        [2],
        name(key),
        sized(2, (b) =>
          little ? b.writeInt16LE(value) : b.writeInt16BE(value),
        ),
      ),
    int: (key: string, value: number) => concat([3], name(key), i32(value)),
    long: (key: string, value: bigint) =>
      concat(
        [4],
        name(key),
        sized(8, (b) =>
          little ? b.writeBigInt64LE(value) : b.writeBigInt64BE(value),
        ),
      ),
    double: (key: string, value: number) =>
      concat(
        [6],
        name(key),
        sized(8, (b) =>
          little ? b.writeDoubleLE(value) : b.writeDoubleBE(value),
        ),
      ),
    string: (key: string, value: string) => concat([8], name(key), name(value)),
    intArray: (key: string, values: readonly number[]) =>
      concat([11], name(key), i32(values.length), ...values.map(i32)),
    compoundList: (key: string, items: readonly Buffer[][]) =>
      concat(
        [9],
        name(key),
        [10],
        i32(items.length),
        ...items.map((tags) => concat(...tags, [0])),
      ),
    compound: (key: string, tags: readonly Buffer[]) =>
      concat([10], name(key), ...tags, [0]),
  };
};

/** A level save: Java byte order by default, Bedrock's with little=true. */
export const nbtSave = (little = false): Buffer => {
  const nbt = nbtWriter(little);
  return nbt.compound("", [
    nbt.compound("Data", [
      nbt.string("LevelName", "Ana's World"),
      nbt.long("Time", 24000n),
      nbt.int("SpawnX", -120),
      nbt.byte("hardcore", 0),
      nbt.double("BorderSize", 6e7),
      nbt.intArray("Seeds", [1, -2, 3]),
      nbt.compoundList("Players", [
        [nbt.string("Name", "Ana"), nbt.short("Health", 20)],
        [nbt.string("Name", "Bo"), nbt.short("Health", 7)],
      ]),
    ]),
  ]);
};

/** Bedrock's level.dat: storage version and payload length (little-endian), then little-endian NBT. */
export const bedrockLevel = (): Buffer => {
  const body = nbtSave(true);
  return concat(
    sized(4, (b) => b.writeUInt32LE(10)),
    sized(4, (b) => b.writeUInt32LE(body.length)),
    body,
  );
};

/** An Anvil region file holding the NBT save as chunks 0 (x0 z0) and 33 (x1 z1), zlib-compressed. */
export const regionFile = (): Buffer => {
  const sector = (index: number, payload: Buffer) => {
    const data = concat(
      sized(4, (b) => b.writeUInt32BE(payload.length + 1)),
      [2],
      payload,
    );
    const padded = Buffer.alloc(Math.ceil(data.length / 4096) * 4096);
    data.copy(padded);
    return { index, padded };
  };
  const chunks = [
    sector(0, deflateSync(nbtSave())),
    sector(33, deflateSync(nbtSave())),
  ];
  const header = Buffer.alloc(8192);
  let next = 2;
  for (const chunk of chunks) {
    header.writeUInt32BE(
      (next << 8) | (chunk.padded.length / 4096),
      chunk.index * 4,
    );
    header.writeUInt32BE(1_700_000_000, 4096 + chunk.index * 4);
    next += chunk.padded.length / 4096;
  }
  return concat(header, ...chunks.map(({ padded }) => padded));
};

/** An LZ4 frame whose single block is stored uncompressed (high bit of the block size). */
export const lz4Stored = (data: Buffer): Buffer =>
  concat(
    [0x04, 0x22, 0x4d, 0x18, 0x60, 0x40, 0x82],
    sized(4, (b) => b.writeUInt32LE((data.length | 0x80000000) >>> 0)),
    data,
    [0, 0, 0, 0],
  );
