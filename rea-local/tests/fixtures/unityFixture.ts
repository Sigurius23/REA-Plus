import { encodeLz4Block, encodeLzmaLiterals } from "./unityCompression.js";

/**
 * Unity serialized files and UnityFS bundles built in source. The player
 * file mirrors a Unity 2022.3 standalone build (format 22, no type trees);
 * the bundle file mirrors a 2019.4 Android asset bundle (format 17, type
 * trees). Layouts follow UnityPy 1.25's reader and writer.
 */

class Writer {
  private readonly chunks: Buffer[] = [];
  length = 0;

  constructor(readonly little: boolean) {}

  private push(bytes: Buffer): this {
    this.chunks.push(bytes);
    this.length += bytes.length;
    return this;
  }

  bytes(bytes: Buffer | readonly number[]): this {
    return this.push(Buffer.from(bytes));
  }

  u8(value: number): this {
    return this.push(Buffer.from([value]));
  }

  private number(size: number, write: (bytes: Buffer) => void): this {
    const bytes = Buffer.alloc(size);
    write(bytes);
    return this.push(bytes);
  }

  u16(value: number): this {
    return this.number(2, (b) =>
      this.little ? b.writeUInt16LE(value) : b.writeUInt16BE(value),
    );
  }

  i16(value: number): this {
    return this.number(2, (b) =>
      this.little ? b.writeInt16LE(value) : b.writeInt16BE(value),
    );
  }

  u32(value: number): this {
    return this.number(4, (b) =>
      this.little ? b.writeUInt32LE(value) : b.writeUInt32BE(value),
    );
  }

  i32(value: number): this {
    return this.number(4, (b) =>
      this.little ? b.writeInt32LE(value) : b.writeInt32BE(value),
    );
  }

  f32(value: number): this {
    return this.number(4, (b) =>
      this.little ? b.writeFloatLE(value) : b.writeFloatBE(value),
    );
  }

  i64(value: bigint): this {
    return this.number(8, (b) =>
      this.little ? b.writeBigInt64LE(value) : b.writeBigInt64BE(value),
    );
  }

  u64(value: bigint): this {
    return this.number(8, (b) =>
      this.little ? b.writeBigUInt64LE(value) : b.writeBigUInt64BE(value),
    );
  }

  cString(value: string): this {
    return this.push(Buffer.from(`${value}\0`, "utf8"));
  }

  align(boundary: number): this {
    const pad = (boundary - (this.length % boundary)) % boundary;
    return this.push(Buffer.alloc(pad));
  }

  /** Unity `string`: i32 length, UTF-8 bytes, aligned to four. */
  string(value: string): this {
    const bytes = Buffer.from(value, "utf8");
    return this.i32(bytes.length).bytes(bytes).align(4);
  }

  pointer(fileId: number, pathId: bigint): this {
    return this.i32(fileId).i64(pathId);
  }

  build(): Buffer {
    return Buffer.concat(this.chunks);
  }
}

/** One type-tree field; `align` sets the 0x4000 meta flag. */
interface TreeNode {
  readonly type: string;
  readonly name: string;
  readonly size: number;
  readonly array?: boolean;
  readonly align?: boolean;
  readonly children?: readonly TreeNode[];
}

const prim = (
  type: string,
  name: string,
  size: number,
  align = false,
): TreeNode => ({
  type,
  name,
  size,
  align,
});

const arrayOf = (element: TreeNode, align = true): TreeNode => ({
  type: "Array",
  name: "Array",
  size: -1,
  array: true,
  align,
  children: [prim("int", "size", 4), { ...element, name: "data" }],
});

const str = (name: string): TreeNode => ({
  type: "string",
  name,
  size: -1,
  children: [arrayOf(prim("char", "data", 1))],
});

const vector = (
  name: string,
  element: TreeNode,
  type = "vector",
): TreeNode => ({
  type,
  name,
  size: -1,
  children: [arrayOf(element)],
});

const pptr = (target: string, name: string): TreeNode => ({
  type: `PPtr<${target}>`,
  name,
  size: 12,
  children: [prim("int", "m_FileID", 4), prim("SInt64", "m_PathID", 8)],
});

const struct = (
  type: string,
  name: string,
  children: readonly TreeNode[],
): TreeNode => ({
  type,
  name,
  size: -1,
  children,
});

const assetInfo = (name: string) =>
  struct("AssetInfo", name, [
    prim("int", "preloadIndex", 4),
    prim("int", "preloadSize", 4),
    pptr("Object", "asset"),
  ]);

/** Type trees for the bundle file, as Unity 2019.4 writes them. */
const TREES = {
  assetBundle: struct("AssetBundle", "Base", [
    str("m_Name"),
    vector("m_PreloadTable", pptr("Object", "data")),
    vector(
      "m_Container",
      struct("pair", "data", [str("first"), assetInfo("second")]),
      "map",
    ),
    assetInfo("m_MainAsset"),
    prim("unsigned int", "m_RuntimeCompatibility", 4),
    str("m_AssetBundleName"),
    vector("m_Dependencies", str("data")),
    prim("bool", "m_IsStreamedSceneAssetBundle", 1, true),
  ]),
  texture: struct("Texture2D", "Base", [
    str("m_Name"),
    prim("int", "m_Width", 4),
    prim("int", "m_Height", 4),
    struct("TypelessData", "image data", [
      prim("int", "size", 4),
      prim("UInt8", "data", 1),
    ]),
  ]),
  gameObject: struct("GameObject", "Base", [
    vector(
      "m_Component",
      struct("ComponentPair", "data", [pptr("Component", "component")]),
    ),
    prim("unsigned int", "m_Layer", 4),
    str("m_Name"),
    prim("UInt16", "m_Tag", 2),
    prim("bool", "m_IsActive", 1, true),
  ]),
  behaviour: struct("MonoBehaviour", "Base", [
    pptr("GameObject", "m_GameObject"),
    prim("UInt8", "m_Enabled", 1, true),
    pptr("MonoScript", "m_Script"),
    str("m_Name"),
    prim("float", "speed", 4),
    vector("inventory", str("data")),
  ]),
  script: struct("MonoScript", "Base", [
    str("m_Name"),
    prim("int", "m_ExecutionOrder", 4),
    struct(
      "Hash128",
      "m_PropertiesHash",
      Array.from({ length: 16 }, (_, index) =>
        prim("UInt8", `bytes[${String(index)}]`, 1),
      ),
    ),
    str("m_ClassName"),
    str("m_Namespace"),
    str("m_AssemblyName"),
  ]),
} as const;

/** Unity's common-string offsets (UnityPy 1.25) used for a few node strings. */
const COMMON: Readonly<Record<string, number>> = {
  m_Name: 427,
  string: 840,
  Array: 49,
  char: 81,
  int: 222,
  SInt64: 814,
  data: 106,
  size: 795,
};

const writeTypeTree = (writer: Writer, root: TreeNode, version: number) => {
  const flat: { node: TreeNode; level: number }[] = [];
  const walk = (node: TreeNode, level: number) => {
    flat.push({ node, level });
    for (const child of node.children ?? []) walk(child, level + 1);
  };
  walk(root, 0);
  const local: string[] = [];
  const offsets = new Map<string, number>();
  let used = 0;
  const offset = (text: string): number => {
    const common = COMMON[text];
    if (common !== undefined) return (0x8000_0000 | common) >>> 0;
    const known = offsets.get(text);
    if (known !== undefined) return known;
    offsets.set(text, used);
    local.push(text);
    used += Buffer.byteLength(text) + 1;
    return used - Buffer.byteLength(text) - 1;
  };
  const table = new Writer(writer.little);
  flat.forEach(({ node, level }, index) => {
    table
      .u16(1)
      .u8(level)
      .u8(node.array === true ? 1 : 0)
      .u32(offset(node.type))
      .u32(offset(node.name))
      .i32(node.size)
      .i32(index)
      .i32(node.align === true ? 0x4000 : 0);
    if (version >= 19) table.u64(0n);
  });
  const strings = Buffer.from(
    local.map((text) => `${text}\0`).join(""),
    "utf8",
  );
  writer
    .i32(flat.length)
    .i32(strings.length)
    .bytes(table.build())
    .bytes(strings);
};

interface FixtureType {
  readonly classId: number;
  readonly scriptTypeIndex?: number;
  readonly tree?: TreeNode;
}

interface FixtureObject {
  readonly pathId: bigint;
  readonly type: number;
  readonly data: Buffer;
}

interface SerializedFixture {
  readonly version: 17 | 22;
  readonly little: boolean;
  readonly unityVersion: string;
  readonly platform: number;
  readonly typeTree: boolean;
  readonly types: readonly FixtureType[];
  readonly objects: readonly FixtureObject[];
  readonly scripts: readonly { fileIndex: number; pathId: bigint }[];
  readonly externals: readonly { path: string; guid: Buffer }[];
}

const buildSerializedFile = (spec: SerializedFixture): Buffer => {
  const header = spec.version >= 22 ? 48 : 20;
  const meta = new Writer(spec.little);
  meta.bytes(Buffer.alloc(header));
  meta
    .cString(spec.unityVersion)
    .i32(spec.platform)
    .u8(spec.typeTree ? 1 : 0);
  meta.i32(spec.types.length);
  for (const type of spec.types) {
    meta
      .i32(type.classId)
      .u8(0)
      .i16(type.scriptTypeIndex ?? -1);
    if (type.classId === 114) meta.bytes(Buffer.alloc(16, 0x11));
    meta.bytes(Buffer.alloc(16, 0x22));
    if (spec.typeTree && type.tree !== undefined) {
      writeTypeTree(meta, type.tree, spec.version);
      if (spec.version >= 21) meta.i32(0);
    }
  }
  const data: Buffer[] = [];
  let dataLength = 0;
  meta.i32(spec.objects.length);
  const starts = spec.objects.map((object) => {
    const start = dataLength;
    const padded = Buffer.concat([
      object.data,
      Buffer.alloc((8 - (object.data.length % 8)) % 8),
    ]);
    data.push(padded);
    dataLength += padded.length;
    return start;
  });
  spec.objects.forEach((object, index) => {
    meta.align(4).i64(object.pathId);
    if (spec.version >= 22) meta.i64(BigInt(starts[index] ?? 0));
    else meta.u32(starts[index] ?? 0);
    meta.u32(object.data.length).i32(object.type);
  });
  meta.i32(spec.scripts.length);
  for (const script of spec.scripts)
    meta.i32(script.fileIndex).align(4).i64(script.pathId);
  meta.i32(spec.externals.length);
  for (const external of spec.externals)
    meta.cString("").bytes(external.guid).i32(0).cString(external.path);
  if (spec.version >= 20) meta.i32(0);
  meta.cString("");
  const metadataSize = meta.length - header;
  meta.align(16);
  const dataOffset = meta.length;
  const file = Buffer.concat([meta.build(), ...data]);
  const head = new Writer(false);
  if (spec.version >= 22)
    head
      .u32(0)
      .u32(0)
      .u32(spec.version)
      .u32(0)
      .u8(spec.little ? 0 : 1)
      .bytes([0, 0, 0])
      .u32(metadataSize)
      .u64(BigInt(file.length))
      .u64(BigInt(dataOffset))
      .u64(0n);
  else
    head
      .u32(metadataSize)
      .u32(file.length)
      .u32(spec.version)
      .u32(dataOffset)
      .u8(spec.little ? 0 : 1)
      .bytes([0, 0, 0]);
  head.build().copy(file, 0);
  return file;
};

/** "Library/unity default resources" carries this well-known GUID. */
const DEFAULT_RESOURCES_GUID = Buffer.from(
  "00000000000000000e00000000000000",
  "hex",
);

/** Path IDs and names shared by the player fixture and its tests. */
export const PLAYER_FILE = Object.freeze({
  name: "level1",
  unityVersion: "2022.3.4f1",
  player: 1n,
  transform: 2n,
  controller: 3n,
  script: 4n,
  spawner: 5n,
  texture: 6n,
  resources: 7n,
  settings: 8n,
  externalScript: 11500000n,
});

/** A Unity 2022.3 standalone scene file without type trees. */
export const createPlayerSerializedFile = (): Buffer => {
  const w = () => new Writer(true);
  const P = PLAYER_FILE;
  return buildSerializedFile({
    version: 22,
    little: true,
    unityVersion: P.unityVersion,
    platform: 19,
    typeTree: false,
    types: [1, 4, 114, 115, 28, 147, 104].map((classId) => ({ classId })),
    objects: [
      {
        pathId: P.player,
        type: 0,
        data: w()
          .i32(3)
          .pointer(0, P.transform)
          .pointer(0, P.controller)
          .pointer(0, P.spawner)
          .u32(0)
          .string("Player")
          .u16(0)
          .u8(1)
          .build(),
      },
      {
        pathId: P.transform,
        type: 1,
        // m_GameObject, rotation, position, scale, constrain flag, children, father.
        data: w()
          .pointer(0, P.player)
          .f32(0)
          .f32(0)
          .f32(0)
          .f32(1)
          .f32(0)
          .f32(1)
          .f32(-5)
          .f32(1)
          .f32(1)
          .f32(1)
          .u8(0)
          .align(4)
          .i32(0)
          .pointer(0, 0n)
          .build(),
      },
      {
        pathId: P.controller,
        type: 2,
        data: w()
          .pointer(0, P.player)
          .u8(1)
          .align(4)
          .pointer(0, P.script)
          .string("")
          .f32(3.5)
          .build(),
      },
      {
        pathId: P.script,
        type: 3,
        data: w()
          .string("PlayerController")
          .i32(0)
          .bytes(Buffer.alloc(16, 0xab))
          .string("PlayerController")
          .string("Game.Characters")
          .string("Assembly-CSharp.dll")
          .build(),
      },
      {
        pathId: P.spawner,
        type: 2,
        data: w()
          .pointer(0, P.player)
          .u8(1)
          .align(4)
          .pointer(1, P.externalScript)
          .string("Spawner")
          .build(),
      },
      {
        pathId: P.texture,
        type: 4,
        data: w().string("hero_diffuse").i32(256).i32(256).build(),
      },
      {
        pathId: P.resources,
        type: 5,
        data: w()
          .i32(3)
          .string("textures/hero")
          .pointer(0, P.texture)
          .string("scripts/player")
          .pointer(0, P.script)
          .string("ui/atlas")
          .pointer(2, 99n)
          .i32(0)
          .build(),
      },
      { pathId: P.settings, type: 6, data: Buffer.alloc(24, 0x5a) },
    ],
    scripts: [{ fileIndex: 0, pathId: P.script }],
    externals: [
      { path: "globalgamemanagers.assets", guid: Buffer.alloc(16) },
      { path: "Library/unity default resources", guid: DEFAULT_RESOURCES_GUID },
    ],
  });
};

export const BUNDLE_FILE = Object.freeze({
  name: "CAB-0123456789abcdef0123456789abcdef",
  resource: "CAB-0123456789abcdef0123456789abcdef.resS",
  unityRevision: "2019.4.40f1",
  bundle: 1n,
  texture: -5012345678901234567n,
  hero: 3n,
  behaviour: 4n,
  script: 5n,
});

/** A Unity 2019.4 Android bundle's serialized file, with type trees. */
export const createBundleSerializedFile = (little = true): Buffer => {
  const w = () => new Writer(little);
  const B = BUNDLE_FILE;
  return buildSerializedFile({
    version: 17,
    little,
    unityVersion: B.unityRevision,
    platform: 13,
    typeTree: true,
    types: [
      { classId: 142, tree: TREES.assetBundle },
      { classId: 28, tree: TREES.texture },
      { classId: 1, tree: TREES.gameObject },
      { classId: 114, scriptTypeIndex: 0, tree: TREES.behaviour },
      { classId: 115, tree: TREES.script },
    ],
    objects: [
      {
        pathId: B.bundle,
        type: 0,
        data: w()
          .string("characters/hero")
          .i32(3)
          .pointer(0, B.hero)
          .pointer(0, B.behaviour)
          .pointer(0, B.texture)
          .i32(2)
          .string("assets/characters/hero.prefab")
          .i32(0)
          .i32(2)
          .pointer(0, B.hero)
          .string("assets/characters/hero.png")
          .i32(2)
          .i32(1)
          .pointer(0, B.texture)
          .i32(0)
          .i32(0)
          .pointer(0, 0n)
          .u32(1)
          .string("characters/hero")
          .i32(1)
          .string("shared/shaders")
          .u8(0)
          .align(4)
          .build(),
      },
      {
        pathId: B.texture,
        type: 1,
        data: w()
          .string("hero")
          .i32(2)
          .i32(2)
          .i32(16)
          .bytes(Buffer.alloc(16, 0x7f))
          .build(),
      },
      {
        pathId: B.hero,
        type: 2,
        data: w()
          .i32(1)
          .pointer(0, B.behaviour)
          .u32(0)
          .string("Hero")
          .u16(0)
          .u8(1)
          .align(4)
          .build(),
      },
      {
        pathId: B.behaviour,
        type: 3,
        data: w()
          .pointer(0, B.hero)
          .u8(1)
          .align(4)
          .pointer(0, B.script)
          .string("")
          .f32(3.5)
          .i32(2)
          .string("sword")
          .string("shield")
          .build(),
      },
      {
        pathId: B.script,
        type: 4,
        data: w()
          .string("HeroController")
          .i32(0)
          .bytes(Buffer.alloc(16, 0xcd))
          .string("HeroController")
          .string("Game")
          .string("Assembly-CSharp.dll")
          .build(),
      },
    ],
    scripts: [{ fileIndex: 0, pathId: B.script }],
    externals: [],
  });
};

export type BundleCompression = "none" | "lz4" | "lzma";

const COMPRESSION_FLAGS: Readonly<Record<BundleCompression, number>> = {
  none: 0,
  lzma: 1,
  lz4: 3,
};

const compress = (method: BundleCompression, data: Buffer): Buffer =>
  method === "lz4"
    ? encodeLz4Block(data)
    : method === "lzma"
      ? encodeLzmaLiterals(data)
      : data;

/** Wrap directory nodes in a UnityFS container. */
export const createUnityFsBundle = (options: {
  readonly nodes: readonly { path: string; data: Buffer; flags: number }[];
  readonly compression: BundleCompression;
  readonly blockSize?: number;
  readonly atEnd?: boolean;
  readonly formatVersion?: 6 | 7;
}): Buffer => {
  const stream = Buffer.concat(options.nodes.map(({ data }) => data));
  const blockSize = options.blockSize ?? stream.length;
  const blocks: { raw: number; packed: Buffer }[] = [];
  for (let at = 0; at < stream.length; at += blockSize) {
    const raw = stream.subarray(at, at + blockSize);
    blocks.push({
      raw: raw.length,
      packed: compress(options.compression, raw),
    });
  }
  const info = new Writer(false).bytes(Buffer.alloc(16)).i32(blocks.length);
  for (const block of blocks)
    info
      .u32(block.raw)
      .u32(block.packed.length)
      .u16(COMPRESSION_FLAGS[options.compression]);
  info.i32(options.nodes.length);
  let offset = 0n;
  for (const node of options.nodes) {
    info
      .i64(offset)
      .i64(BigInt(node.data.length))
      .u32(node.flags)
      .cString(node.path);
    offset += BigInt(node.data.length);
  }
  const rawInfo = info.build();
  const packedInfo = compress(options.compression, rawInfo);
  const version = options.formatVersion ?? 7;
  const flags =
    COMPRESSION_FLAGS[options.compression] |
    0x40 |
    (options.atEnd === true ? 0x80 : 0);
  const header = new Writer(false)
    .cString("UnityFS")
    .u32(version)
    .cString("5.x.x")
    // 2019.4.15 and later align the header; format 6 predates that.
    .cString(version >= 7 ? BUNDLE_FILE.unityRevision : "2018.4.36f1");
  const data = Buffer.concat(blocks.map(({ packed }) => packed));
  const sizeAt = header.length;
  header.u64(0n).u32(packedInfo.length).u32(rawInfo.length).u32(flags);
  if (version >= 7) header.align(16);
  const parts =
    options.atEnd === true ? [data, packedInfo] : [packedInfo, data];
  const file = Buffer.concat([header.build(), ...parts]);
  file.writeBigUInt64BE(BigInt(file.length), sizeAt);
  return file;
};

/** The bundle fixture: one serialized file plus its .resS payload. */
export const createHeroBundle = (
  compression: BundleCompression,
  options: { blockSize?: number; atEnd?: boolean; formatVersion?: 6 | 7 } = {},
): Buffer =>
  createUnityFsBundle({
    compression,
    ...options,
    nodes: [
      { path: BUNDLE_FILE.name, data: createBundleSerializedFile(), flags: 4 },
      { path: BUNDLE_FILE.resource, data: Buffer.alloc(96, 0x42), flags: 0 },
    ],
  });
