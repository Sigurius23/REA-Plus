import type {
  InspectUnityAssetsInput,
  UnityAssets,
  UnityContainerEntry,
  UnityObject,
  UnityScript,
  UnitySerializedFile,
} from "../domain/unity/unityAssets.js";
import { readSerializedHeader, type SerializedType } from "./SerializedFile.js";
import { formatFail } from "./UnityBinary.js";
import {
  BufferSource,
  BundleStream,
  readUnityBundle,
  type ByteSource,
  type UnityBundle,
} from "./UnityBundle.js";
import {
  listValue,
  loadSerializedFile,
  type LoadedFile,
  type ObjectRecord,
} from "./UnityObjects.js";
import { BUILD_TARGETS } from "./UnityStrings.js";
import {
  basename,
  containerOf,
  ObjectIndex,
  objectsOf,
  scriptsOf,
} from "./UnityViews.js";
import { CLASS_NAMES } from "./UnityTables.js";

/** A filter that does not apply to the selected view. */
export class UnityViewMismatch extends Error {}

const MAX_TYPES_REPORTED = 500;
const MAX_CLASSES_REPORTED = 200;
const NODE_SERIALIZED = 0x4;

const hex = (value: number) => `0x${value.toString(16)}`;

interface Loaded {
  readonly bundle: UnityBundle | null;
  readonly stream: BundleStream | null;
  readonly files: readonly LoadedFile[];
  readonly nodeKinds: ReadonlyMap<
    string,
    "serialized_file" | "resource" | "other"
  >;
}

const nodeKind = (
  source: ByteSource,
  node: UnityBundle["nodes"][number],
): "serialized_file" | "resource" | "other" => {
  if (/\.(resS|resource)$/iu.test(node.path)) return "resource";
  if ((node.flags & NODE_SERIALIZED) !== 0) return "serialized_file";
  if (node.size < 20) return "other";
  const head = source.read(node.offset, Math.min(node.size, 48));
  return readSerializedHeader(head, node.size) === null
    ? "other"
    : "serialized_file";
};

const load = (bytes: Buffer, path: string): Loaded => {
  if (bytes.subarray(0, 8).toString("latin1") === "UnityFS\0") {
    const bundle = readUnityBundle(bytes);
    const stream = new BundleStream(bytes, bundle);
    const nodeKinds = new Map(
      bundle.nodes.map((node) => [node.path, nodeKind(stream, node)] as const),
    );
    const files = bundle.nodes
      .filter((node) => nodeKinds.get(node.path) === "serialized_file")
      .map((node) =>
        loadSerializedFile(node.path, stream, node.offset, node.size),
      );
    return { bundle, stream, files, nodeKinds };
  }
  if (readSerializedHeader(bytes.subarray(0, 48), bytes.length) === null)
    formatFail(
      "Not a UnityFS bundle or a Unity serialized file (formats 9-22).",
    );
  const source = new BufferSource(bytes);
  return {
    bundle: null,
    stream: null,
    files: [loadSerializedFile(basename(path), source, 0, bytes.length)],
    nodeKinds: new Map(),
  };
};

/** A serialized file whose metadata could not be parsed. */
const unreadableFileReport = (loaded: LoadedFile): UnitySerializedFile => ({
  name: loaded.name,
  format_version: 0,
  unity_version: "",
  target_platform: { id: null, name: null },
  big_endian: false,
  type_tree: false,
  objects: 0,
  types: [],
  types_truncated: false,
  externals: [],
  script_references: 0,
  reference_types: 0,
  names: { read: 0, unread: 0, failed: 0 },
  error: loaded.error,
});

const serializedFileReport = (loaded: LoadedFile): UnitySerializedFile => {
  const file = loaded.file;
  if (file === null) return unreadableFileReport(loaded);
  const perType = new Map<SerializedType | null, number>();
  for (const { object } of loaded.records)
    perType.set(object.type, (perType.get(object.type) ?? 0) + 1);
  const count = (status: ObjectRecord["status"]) =>
    loaded.records.filter((record) => record.status === status).length;
  return {
    name: loaded.name,
    format_version: file.formatVersion,
    unity_version: file.unityVersion,
    target_platform: {
      id: file.targetPlatform,
      name:
        file.targetPlatform === null
          ? null
          : (BUILD_TARGETS[file.targetPlatform] ?? null),
    },
    big_endian: file.bigEndian,
    type_tree: file.typeTree,
    objects: loaded.records.length,
    types: file.types.slice(0, MAX_TYPES_REPORTED).map((type) => ({
      class_id: type.classId,
      class_name: type.tree?.type ?? CLASS_NAMES[type.classId] ?? null,
      script_type_index: type.scriptTypeIndex,
      stripped: type.stripped,
      objects: perType.get(type) ?? 0,
    })),
    types_truncated: file.types.length > MAX_TYPES_REPORTED,
    externals: file.externals.map((external, index) => ({
      file_id: index + 1,
      path: external.path,
      guid: external.guid,
      type: external.type,
    })),
    script_references: file.scriptReferences.length,
    reference_types: file.refTypes,
    names: {
      read: count("read"),
      unread: count("unread"),
      failed: count("failed"),
    },
    error: null,
  };
};

const classesOf = (objects: readonly UnityObject[]) => {
  const counts = new Map<
    number,
    { class_id: number; class_name: string | null; objects: number }
  >();
  for (const object of objects) {
    const entry = counts.get(object.class_id) ?? {
      class_id: object.class_id,
      class_name: object.class_name,
      objects: 0,
    };
    entry.objects += 1;
    counts.set(object.class_id, entry);
  }
  return [...counts.values()]
    .sort(
      (left, right) =>
        right.objects - left.objects || left.class_id - right.class_id,
    )
    .slice(0, MAX_CLASSES_REPORTED);
};

const includes = (needle: string, ...values: (string | null | undefined)[]) =>
  values.some((value) => value?.toLowerCase().includes(needle) === true);

const page = <T>(items: readonly T[], input: InspectUnityAssetsInput) =>
  items.slice(input.offset, input.offset + input.limit);

const bundleReport = (loaded: Loaded): UnityAssets["bundle"] => {
  const { bundle, stream } = loaded;
  if (bundle === null || stream === null) return null;
  const methods = new Map<string, number>();
  for (const block of bundle.blocks)
    methods.set(block.compression, (methods.get(block.compression) ?? 0) + 1);
  return {
    format_version: bundle.formatVersion,
    unity_version: bundle.unityVersion,
    unity_revision: bundle.unityRevision,
    flags: hex(bundle.flags),
    blocks_info: {
      compression: bundle.blocksInfo.compression,
      at_end: bundle.blocksInfo.atEnd,
      compressed_bytes: bundle.blocksInfo.compressedSize,
      bytes: bundle.blocksInfo.size,
    },
    blocks: {
      count: bundle.blocks.length,
      compressed_bytes: bundle.blocks.reduce(
        (sum, block) => sum + block.compressedSize,
        0,
      ),
      bytes: bundle.streamSize,
      compression: [...methods].map(([method, count]) => ({
        method: method as UnityBundleCompression,
        count,
      })),
    },
    nodes: bundle.nodes.map((node) => ({
      path: node.path,
      offset: node.offset,
      size: node.size,
      flags: hex(node.flags),
      kind: loaded.nodeKinds.get(node.path) ?? "other",
    })),
    decoded_bytes: stream.decodedBytes,
  };
};

type UnityBundleCompression = NonNullable<
  UnityAssets["bundle"]
>["blocks_info"]["compression"];

interface ViewRows {
  readonly objects: readonly UnityObject[];
  readonly container: readonly UnityContainerEntry[];
  readonly scripts: readonly UnityScript[];
}

/** Entries of the selected view that pass class_name and query. */
const matchingRows = (
  input: InspectUnityAssetsInput,
  {
    index,
    loaded,
    allObjects,
  }: {
    readonly index: ObjectIndex;
    readonly loaded: Loaded;
    readonly allObjects: readonly UnityObject[];
  },
): ViewRows => {
  const wantedClass = input.class_name?.toLowerCase();
  const needle = input.query?.toLowerCase();
  const classMatches = (name: string | null) =>
    wantedClass === undefined || name?.toLowerCase() === wantedClass;
  const queryMatches = (...values: (string | null | undefined)[]) =>
    needle === undefined || includes(needle, ...values);
  const none = { objects: [], container: [], scripts: [] };
  if (input.view === "objects")
    return {
      ...none,
      objects: allObjects.filter(
        (object) =>
          classMatches(object.class_name) &&
          queryMatches(
            object.name,
            object.game_object?.name,
            object.script?.class_name,
          ),
      ),
    };
  if (input.view === "container")
    return {
      ...none,
      container: containerOf(index, loaded.files).filter(
        (entry) =>
          classMatches(entry.class_name) &&
          queryMatches(entry.asset_path, entry.name),
      ),
    };
  return {
    ...none,
    scripts: scriptsOf(allObjects, loaded.files).filter((script) =>
      queryMatches(script.class_name, script.namespace, script.assembly),
    ),
  };
};

/** Build the report for one bundle or serialized file. */
export const buildUnityAssetsReport = (
  bytes: Buffer,
  input: InspectUnityAssetsInput,
  identity: { readonly sha256: string },
  limitations: readonly string[],
): UnityAssets => {
  if (input.view === "scripts" && input.class_name !== undefined)
    throw new UnityViewMismatch(
      "class_name filters the objects and container views; the scripts view lists MonoScripts only.",
    );
  const loaded = load(bytes, input.path);
  const index = new ObjectIndex(loaded.files);
  const allObjects = objectsOf(index, loaded.files);
  const rows = matchingRows(input, { index, loaded, allObjects });
  const pageObjects = page(rows.objects, input);
  const pageContainer = page(rows.container, input);
  const pageScripts = page(rows.scripts, input);
  const total =
    rows.objects.length + rows.container.length + rows.scripts.length;
  return {
    file: {
      path: input.path,
      sha256: identity.sha256,
      bytes: bytes.length,
      format: loaded.bundle === null ? "serialized_file" : "unityfs",
    },
    bundle: bundleReport(loaded),
    serialized_files: loaded.files.map(serializedFileReport),
    classes: classesOf(allObjects),
    dependencies: loaded.files.flatMap((file) =>
      file.records
        .filter((record) => record.object.classId === 142)
        .flatMap((record) =>
          listValue(record.fields.get("m_Dependencies")).filter(
            (value): value is string => typeof value === "string",
          ),
        ),
    ),
    page: {
      view: input.view,
      class_name: input.class_name ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total,
      returned: pageObjects.length + pageContainer.length + pageScripts.length,
    },
    objects: pageObjects,
    container: pageContainer,
    scripts: pageScripts,
    limitations: [...limitations],
  };
};
