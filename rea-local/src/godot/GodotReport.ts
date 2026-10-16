import {
  DEFAULT_GODOT_VIEW,
  type GodotFileReport,
  type InspectGodotFileInput,
} from "../domain/godot/godotFile.js";
import { GodotFormatError, GodotSelectionError } from "./GodotBytes.js";
import { scriptSource } from "./GdscriptSource.js";
import {
  isCompiledScript,
  readCompiledScript,
  type CompiledScript,
} from "./GdscriptTokens.js";
import {
  isGodotResource,
  readGodotResource,
  type GodotResourceFile,
} from "./GodotResource.js";
import {
  connectionRows,
  nodeRows,
  propertyRows,
  resourceRows,
  valueRows,
} from "./GodotRows.js";
import { readScene, type SceneTree } from "./GodotScene.js";
import { selectGodotBytes, type Environment } from "./GodotSelect.js";
import type { GodotValue } from "./GodotValues.js";
import { variantStream, type VariantEncoding } from "./MarshalledVariant.js";

const MAX_OUTPUT = 1024 * 1024 * 1024;

type Kind = GodotFileReport["kind"];
type View = GodotFileReport["page"]["view"];

const VIEWS: Readonly<Record<Kind, readonly View[]>> = {
  resource: ["resources", "properties"],
  scene: ["nodes", "connections", "resources", "properties"],
  script: ["source", "tokens"],
  variant: ["values"],
};

interface Decoded {
  readonly kind: Kind;
  readonly resource: GodotResourceFile | null;
  readonly scene: SceneTree | null;
  readonly script: CompiledScript | null;
  readonly variant: {
    readonly engine: "3" | "4";
    readonly values: readonly GodotValue[];
    readonly encoding: VariantEncoding;
    readonly alsoReadsAs: "3" | "4" | null;
  } | null;
}

const none = { resource: null, scene: null, script: null, variant: null };

const sceneOf = (file: GodotResourceFile): SceneTree | null => {
  const main = file.resources.at(-1);
  if (file.header.type !== "PackedScene" || main?.type !== "PackedScene")
    return null;
  const bundled = main.properties.find(({ name }) => name === "_bundled");
  return bundled?.value.kind === "dictionary" ? readScene(bundled.value) : null;
};

const variants = (
  data: Buffer,
  engine: InspectGodotFileInput["engine"],
): Decoded => {
  const engines = engine === "auto" ? (["4", "3"] as const) : [engine];
  const failures: string[] = [];
  const read = engines.flatMap((major) => {
    try {
      return [{ major, ...variantStream(data, major === "4" ? 4 : 3) }];
    } catch (cause) {
      if (!(cause instanceof GodotFormatError)) throw cause;
      failures.push(`Godot ${major}: ${cause.message}`);
      return [];
    }
  });
  const [first, second] = read;
  if (first === undefined)
    throw new GodotFormatError(
      `Not a binary resource, compiled GDScript or store_var data (${failures.join("; ")})`,
    );
  return {
    ...none,
    kind: "variant",
    variant: {
      engine: first.major,
      values: first.values,
      encoding: first.encoding,
      alsoReadsAs: second?.major ?? null,
    },
  };
};

const decode = (data: Buffer, input: InspectGodotFileInput): Decoded => {
  if (isGodotResource(data)) {
    const resource = readGodotResource(data, MAX_OUTPUT);
    const scene = sceneOf(resource);
    return {
      ...none,
      kind: scene === null ? "resource" : "scene",
      resource,
      scene,
    };
  }
  if (isCompiledScript(data))
    return {
      ...none,
      kind: "script",
      script: readCompiledScript(data, MAX_OUTPUT),
    };
  return variants(data, input.engine);
};

const insideNode = (path: string, node: string): boolean =>
  node === "." || path === node || path.startsWith(`${node}/`);

/** Rows of the view after the resource and node selections. */
const selectedRows = (
  decoded: Decoded,
  view: View,
  input: InspectGodotFileInput,
): readonly object[] => {
  const { resource, scene, script, variant } = decoded;
  switch (view) {
    case "resources":
      return resourceRows(resource!).filter(
        ({ id }) => input.resource === undefined || id === input.resource,
      );
    case "properties":
      return propertyRows(resource!, scene).filter(
        (row) =>
          (input.resource === undefined ||
            (row.owner_kind === "resource" && row.owner === input.resource)) &&
          (input.node === undefined ||
            (row.owner_kind === "node" && row.owner === input.node)),
      );
    case "nodes":
      return nodeRows(scene!).filter(
        ({ path }) => input.node === undefined || insideNode(path, input.node),
      );
    case "connections":
      return connectionRows(scene!).filter(
        ({ from, to }) =>
          input.node === undefined || from === input.node || to === input.node,
      );
    case "source":
      return scriptSource(script!.tokens);
    case "tokens":
      return script!.tokens.map(({ index, line, type, text }) => ({
        index,
        line,
        type,
        text,
      }));
    default:
      return valueRows(variant!.values);
  }
};

const checkSelection = (
  decoded: Decoded,
  view: View,
  input: InspectGodotFileInput,
): void => {
  if (!VIEWS[decoded.kind].includes(view))
    throw new GodotSelectionError(
      `The ${view} view does not apply to a ${decoded.kind}; use ${VIEWS[decoded.kind].join(", ")}.`,
      "view",
    );
  if (
    input.resource !== undefined &&
    !decoded.resource?.resources.some(({ id }) => id === input.resource)
  )
    throw new GodotSelectionError(
      decoded.resource === null
        ? "resource selects a sub-resource of a binary resource or scene."
        : `No internal resource has id ${input.resource}.`,
      "resource",
    );
  if (
    input.node !== undefined &&
    !decoded.scene?.nodes.some(({ path }) => path === input.node)
  )
    throw new GodotSelectionError(
      decoded.scene === null
        ? "node selects a node of a scene."
        : `The scene has no node at ${input.node}.`,
      "node",
    );
};

const headers = (decoded: Decoded) => {
  const { resource, script, variant } = decoded;
  const header = resource?.header;
  return {
    resource:
      resource === null || header === undefined
        ? null
        : {
            engine: `${String(header.major)}.${String(header.minor)}`,
            format: header.format,
            type: header.type,
            uid: header.uid,
            script_class: header.scriptClass,
            big_endian: header.bigEndian,
            real64: header.real64,
            flags: [
              ...header.flags,
              ...(header.compressed === null
                ? []
                : [`compressed_${header.compressed}`]),
            ],
            external: resource.external.length,
            internal: resource.resources.length,
            trailer: resource.trailer,
          },
    script:
      script === null
        ? null
        : {
            version: script.version,
            engine: script.engine,
            compressed: script.compressed,
            identifiers: script.identifiers.length,
            constants: script.constants.length,
            tokens: script.tokens.length,
          },
    variant:
      variant === null
        ? null
        : {
            engine: variant.engine,
            values: variant.values.length,
            encoding: variant.encoding,
            also_reads_as: variant.alsoReadsAs,
          },
  };
};

const summary = (decoded: Decoded) => {
  const { resource, scene, script, variant } = decoded;
  return {
    resources:
      resource === null
        ? 0
        : resource.external.length + resource.resources.length,
    properties: resource === null ? 0 : propertyRows(resource, scene).length,
    nodes: scene?.nodes.length ?? 0,
    connections: scene?.connections.length ?? 0,
    lines: script === null ? 0 : scriptSource(script.tokens).length,
    tokens: script?.tokens.length ?? 0,
    values: variant === null ? 0 : valueRows(variant.values).length,
    errors:
      resource?.resources.filter(({ error }) => error !== null).length ?? 0,
  };
};

export const buildGodotFileReport = (
  file: { readonly bytes: Buffer; readonly sha256: string },
  input: InspectGodotFileInput,
  environment: Environment,
  limitations: readonly string[],
): GodotFileReport => {
  const selected = selectGodotBytes(file.bytes, input, environment, MAX_OUTPUT);
  const decoded = decode(selected.data, input);
  const view = input.view ?? DEFAULT_GODOT_VIEW[decoded.kind];
  checkSelection(decoded, view, input);
  const query = input.query?.toLowerCase();
  const matching = selectedRows(decoded, view, input).filter(
    (row) =>
      query === undefined || JSON.stringify(row).toLowerCase().includes(query),
  );
  const page = matching.slice(input.offset, input.offset + input.limit);
  const empty = {
    resources: [],
    properties: [],
    nodes: [],
    connections: [],
    source: [],
    tokens: [],
    values: [],
  };
  return {
    file: { path: input.path, sha256: file.sha256, bytes: file.bytes.length },
    entry: selected.entry,
    layers: selected.layers,
    kind: decoded.kind,
    ...headers(decoded),
    summary: summary(decoded),
    page: {
      view,
      resource: input.resource ?? null,
      node: input.node ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    ...empty,
    [view]: page,
    limitations: [...limitations],
  } as GodotFileReport;
};
