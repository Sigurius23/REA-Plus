import type { DataBlobReport } from "../../../src/domain/blob/dataBlob.js";

/**
 * Helpers that turn inspect_data_blob trees into what independent tools
 * print: protoc --decode_raw's text format, and a canonical JSON shared with
 * a Python script that decodes the same bytes with the msgpack, cbor2 and
 * bson libraries.
 */

type Row = DataBlobReport["tree"][number];

/** Children of each row, by path, rebuilt from the flat depth-first listing. */
const tree = (rows: readonly Row[]) => {
  const children = new Map<string, Row[]>();
  const stack: Row[] = [];
  for (const row of rows) {
    while (stack.length > 0 && (stack.at(-1)?.depth ?? 0) >= row.depth)
      stack.pop();
    const parent = stack.at(-1);
    if (parent !== undefined)
      children.set(parent.path, [...(children.get(parent.path) ?? []), row]);
    stack.push(row);
  }
  return children;
};

/** protobuf's CEscape: C escapes, octal for everything outside printable ASCII. */
const cescape = (bytes: Buffer): string =>
  [...bytes]
    .map((byte) => {
      const named: Readonly<Record<number, string>> = {
        10: "\\n",
        13: "\\r",
        9: "\\t",
        34: '\\"',
        39: "\\'",
        92: "\\\\",
      };
      if (named[byte] !== undefined) return named[byte];
      return byte < 0x20 || byte >= 0x7f
        ? `\\${byte.toString(8).padStart(3, "0")}`
        : String.fromCharCode(byte);
    })
    .join("");

/** The text protoc --decode_raw prints for the same message. */
export const protocText = (rows: readonly Row[]): string => {
  const children = tree(rows);
  const render = (row: Row, indent: string): string => {
    if (row.type === "message" || row.type === "group")
      return `${indent}${String(row.key)} {\n${(children.get(row.path) ?? []).map((child) => render(child, `${indent}  `)).join("")}${indent}}\n`;
    if (row.type === "varint")
      return `${indent}${String(row.key)}: ${row.value ?? ""}\n`;
    if (row.type === "fixed32" || row.type === "fixed64")
      return `${indent}${String(row.key)}: ${row.alternatives["hex"] ?? ""}\n`;
    const raw =
      row.type === "string"
        ? Buffer.from(row.value ?? "", "utf8")
        : Buffer.from(row.value ?? "", "hex");
    return `${indent}${String(row.key)}: "${cescape(raw)}"\n`;
  };
  const root = rows[0];
  return root === undefined
    ? ""
    : (children.get(root.path) ?? [])
        .map((child) => render(child, ""))
        .join("");
};

/** The canonical JSON the Python reference script writes for a value. */
export const canonical = (rows: readonly Row[]): unknown => {
  const children = tree(rows);
  const convert = (row: Row): unknown => {
    const kids = children.get(row.path) ?? [];
    switch (row.type) {
      case "nil":
      case "null":
        return null;
      case "bool":
        return row.value === "true";
      case "int":
      case "int32":
      case "int64":
        return { i: row.value };
      case "float":
      case "double":
        return { f: row.value };
      case "string":
        return row.value;
      case "bytes":
      case "str-bytes":
      case "binary 0":
        return { b: row.value };
      case "array":
        return kids.map(convert);
      case "map":
      case "document":
        return { m: kids.map((kid) => [String(kid.key), convert(kid)]) };
      default:
        return { unknown: row.type };
    }
  };
  const root = rows[0];
  return root === undefined ? null : convert(root);
};

/** Writes random nested values as MessagePack, CBOR and BSON plus the canonical JSON of each, decoded by the libraries. */
export const PYTHON_SAMPLES = String.raw`
import json, os, random, sys
import msgpack, cbor2, bson
out, count, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rng = random.Random(seed)
def scalar():
    kind = rng.choice(["int", "bigint", "neg", "float", "str", "bytes", "bool", "none"])
    if kind == "int": return rng.randint(0, 300)
    if kind == "bigint": return rng.choice([2**31, 2**32 + 5, 2**53 + 1, 2**63 - 1])
    if kind == "neg": return -rng.choice([1, 31, 32, 33, 128, 129, 2**15, 2**31, 2**63])
    if kind == "float": return rng.choice([0.5, -2.25, 1e300, 3.14159, 0.1, 1/3])
    if kind == "str": return rng.choice(["", "hp", "Ana", "héllo", "日本", "x" * rng.randint(30, 300)])
    if kind == "bytes": return bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 40)))
    if kind == "bool": return rng.random() < 0.5
    return None
def value(depth, str_keys):
    if depth >= 4 or rng.random() < 0.35: return scalar()
    if rng.random() < 0.5: return [value(depth + 1, str_keys) for _ in range(rng.randint(0, 20))]
    return {(f"k{rng.randint(0, 99)}" if str_keys or rng.random() < 0.7 else rng.randint(-5, 500)): value(depth + 1, str_keys) for _ in range(rng.randint(0, 18))}
def canon(v):
    if v is None or isinstance(v, bool): return v
    if isinstance(v, int): return {"i": str(v)}
    if isinstance(v, float): return {"f": repr(v)}
    if isinstance(v, str): return v
    if isinstance(v, (bytes, bytearray)): return {"b": bytes(v).hex()}
    if isinstance(v, list): return [canon(x) for x in v]
    if isinstance(v, dict): return {"m": [[k if isinstance(k, str) else f"int:{k}", canon(x)] for k, x in v.items()]}
    raise TypeError(type(v))
os.makedirs(out, exist_ok=True)
for i in range(count):
    v = value(0, False)
    packed = msgpack.packb(v, use_bin_type=True)
    open(f"{out}/v{i}.msgpack", "wb").write(packed)
    open(f"{out}/v{i}.msgpack.json", "w").write(json.dumps(canon(msgpack.unpackb(packed, raw=False, strict_map_key=False))))
    encoded = cbor2.dumps(v)
    open(f"{out}/v{i}.cbor", "wb").write(encoded)
    open(f"{out}/v{i}.cbor.json", "w").write(json.dumps(canon(cbor2.loads(encoded))))
    d = value(1, True)
    d = d if isinstance(d, dict) else {"value": d}
    try:
        data = bson.encode(d)
    except Exception:
        continue
    open(f"{out}/v{i}.bson", "wb").write(data)
    open(f"{out}/v{i}.bson.json", "w").write(json.dumps(canon(bson.decode(data))))
`;

/** A small deterministic generator, so the protoc lane is reproducible. */
export const random = (seed: number) => {
  let state = seed >>> 0 || 1;
  return (bound: number): number => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) % bound;
  };
};

const varint = (value: bigint): number[] => {
  let rest = BigInt.asUintN(64, value);
  const out: number[] = [];
  do {
    const byte = Number(rest & 0x7fn);
    rest >>= 7n;
    out.push(rest > 0n ? byte | 0x80 : byte);
  } while (rest > 0n);
  return out;
};

/** A random protobuf message with nested messages, groups, packed fields, text and opaque bytes. */
export const randomMessage = (
  next: (bound: number) => number,
  depth = 0,
): Buffer => {
  const parts: Buffer[] = [];
  const fields = [1, 2, 3, 4, 5, 15, 16, 100, 2047, 536870911];
  for (let count = next(7); count > 0; count -= 1) {
    const field = fields[next(fields.length)] ?? 1;
    const tag = (wire: number) => varint(BigInt(field) * 8n + BigInt(wire));
    const kind = depth < 4 ? next(9) : next(3);
    const bytes = (length: number) =>
      Buffer.from(Array.from({ length }, () => next(256)));
    if (kind === 0)
      parts.push(
        Buffer.from([
          ...tag(0),
          ...varint(BigInt(next(1 << 30)) * BigInt(next(1 << 30))),
        ]),
      );
    else if (kind === 1) {
      const text = Buffer.from(
        ["Ana", "potion", "héllo", "日本語"][next(4)] ?? "x",
      );
      parts.push(
        Buffer.concat([
          Buffer.from([...tag(2), ...varint(BigInt(text.length))]),
          text,
        ]),
      );
    } else if (kind === 2) {
      const data = bytes(1 + next(12));
      parts.push(
        Buffer.concat([
          Buffer.from([...tag(2), ...varint(BigInt(data.length))]),
          data,
        ]),
      );
    } else if (kind === 3)
      parts.push(Buffer.concat([Buffer.from(tag(5)), bytes(4)]));
    else if (kind === 4)
      parts.push(Buffer.concat([Buffer.from(tag(1)), bytes(8)]));
    else if (kind === 5) {
      const inner = randomMessage(next, depth + 1);
      parts.push(
        Buffer.concat([
          Buffer.from([...tag(2), ...varint(BigInt(inner.length))]),
          inner,
        ]),
      );
    } else if (kind === 6)
      parts.push(
        Buffer.concat([
          Buffer.from(tag(3)),
          randomMessage(next, depth + 1),
          Buffer.from(tag(4)),
        ]),
      );
    else if (kind === 7)
      parts.push(
        Buffer.from([...tag(0), ...varint(-BigInt(1 + next(1 << 30)))]),
      );
    else parts.push(Buffer.from([...tag(2), 0]));
  }
  return Buffer.concat(parts);
};
