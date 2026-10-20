import { basename } from "node:path";

import type {
  InspectX64dbgDatabaseInput,
  X64dbgDatabaseReport,
} from "../domain/x64dbg/x64dbgDatabase.js";
import { sectionAtAddress, type ImageLayout } from "../patterns/ImageLayout.js";
import {
  formatHex,
  hexOf,
  listOf,
  objectOf,
  objectsOf,
  textOf,
  type JsonObject,
} from "./X64dbgDatabase.js";

type Report = X64dbgDatabaseReport;
type View = InspectX64dbgDatabaseInput["view"];
type Rows = Pick<Report, View>;
type Placed = { file_offset: number | null; section: string | null };

/** The module binary the caller selected, to place module-relative addresses. */
export interface ModuleImage {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: Buffer;
  readonly layout: ImageLayout;
}

const BREAKPOINT_TYPES = [
  "software",
  "hardware",
  "memory",
  "dll",
  "exception",
] as const;

class Placer {
  constructor(private readonly image: ModuleImage | null) {}

  get name(): string | null {
    return this.image === null ? null : basename(this.image.path).toLowerCase();
  }

  /** File offset and section of a module-relative address in module_path. */
  place(module: string | null, rva: bigint | null): Placed {
    const { image } = this;
    if (
      image === null ||
      module === null ||
      rva === null ||
      module.toLowerCase() !== this.name
    )
      return { file_offset: null, section: null };
    const base = image.layout.imageBase;
    if (base === null) return { file_offset: null, section: null };
    const section = sectionAtAddress(image.layout, base + rva);
    if (section === undefined) return { file_offset: null, section: null };
    return {
      file_offset: section.fileOffset + Number(base + rva - section.address),
      section: section.name,
    };
  }

  bytesAt(offset: number, length: number): Buffer | null {
    const bytes = this.image?.bytes;
    return bytes === undefined || offset + length > bytes.length
      ? null
      : bytes.subarray(offset, offset + length);
  }
}

const entries = (
  root: JsonObject,
  key: string,
  placer: Placer,
): Report["labels"] =>
  listOf(root, key).map(({ item, auto }) => {
    const module = textOf(item["module"]);
    const address = hexOf(item["address"]);
    return {
      module,
      address: formatHex(address ?? 0n),
      manual: !auto && item["manual"] === true,
      text: textOf(item["text"]),
      ...placer.place(module, address),
    };
  });

const ranges = (
  root: JsonObject,
  key: string,
  placer: Placer,
): Report["functions"] =>
  listOf(root, key).map(({ item, auto }) => {
    const module = textOf(item["module"]);
    const start = hexOf(item["start"] ?? item["address"]);
    const instructions = hexOf(item["icount"]);
    const parent = hexOf(item["parent"]);
    const depth = item["depth"];
    return {
      module,
      start: formatHex(start ?? 0n),
      end: formatHex(hexOf(item["end"]) ?? start ?? 0n),
      manual: !auto && item["manual"] === true,
      instructions: instructions === null ? null : Number(instructions),
      parent: parent === null || parent === 0n ? null : formatHex(parent),
      depth:
        typeof depth === "number" && Number.isInteger(depth) && depth >= 0
          ? depth
          : null,
      ...placer.place(module, start),
    };
  });

/** The original bytes x64dbg read under a software breakpoint, low byte first. */
const originalBytes = (value: bigint): Buffer =>
  Buffer.from([Number(value & 0xffn), Number((value >> 8n) & 0xffn)]);

const breakpoints = (root: JsonObject, placer: Placer): Report["breakpoints"] =>
  objectsOf(root["breakpoints"]).map((item) => {
    const module = textOf(item["module"]);
    const address = hexOf(item["address"]);
    const type =
      typeof item["type"] === "number"
        ? (BREAKPOINT_TYPES[item["type"]] ?? "unknown")
        : "unknown";
    const old = type === "software" ? hexOf(item["oldbytes"]) : null;
    const placed = placer.place(module, address);
    const actual =
      placed.file_offset === null || old === null
        ? null
        : placer.bytesAt(placed.file_offset, 2);
    return {
      module,
      address: formatHex(address ?? 0n),
      type,
      enabled: item["enabled"] === true,
      name: textOf(item["name"]),
      break_condition: textOf(item["breakCondition"]),
      log_text: textOf(item["logText"]),
      log_condition: textOf(item["logCondition"]),
      command_text: textOf(item["commandText"]),
      command_condition: textOf(item["commandCondition"]),
      fast_resume: item["fastResume"] === true,
      silent: item["silent"] === true,
      old_bytes: old === null ? null : originalBytes(old).toString("hex"),
      bytes_match:
        actual === null || old === null
          ? null
          : actual.equals(originalBytes(old)),
      ...placed,
    };
  });

const xrefs = (root: JsonObject, placer: Placer): Report["xrefs"] =>
  objectsOf(root["xrefs"]).map((item) => {
    const module = textOf(item["module"]);
    const address = hexOf(item["address"]);
    return {
      module,
      address: formatHex(address ?? 0n),
      references: objectsOf(item["references"]).map((reference) => ({
        address: formatHex(hexOf(reference["addr"]) ?? 0n),
        type: Number(hexOf(reference["type"]) ?? 0n),
      })),
      ...placer.place(module, address),
    };
  });

const watches = (root: JsonObject): Report["watch"] =>
  objectsOf(root["watch"]).map((item) => ({
    name: textOf(item["Name"]),
    expression: textOf(item["Expression"]) ?? "",
    data_type: textOf(item["DataType"]),
    watchdog: textOf(item["WatchdogMode"]),
  }));

const matches = (
  query: string | undefined,
  values: readonly (string | null)[],
): boolean =>
  query === undefined ||
  values.some(
    (value) => value?.toLowerCase().includes(query.toLowerCase()) === true,
  );

const searchable = (row: object): (string | null)[] =>
  Object.values(row).filter(
    (value): value is string | null =>
      value === null || typeof value === "string",
  );

/** Database metadata, with every module any entry names. */
const databaseOf = (
  root: JsonObject,
  database: Pick<
    Report["database"],
    "path" | "sha256" | "bytes" | "compressed" | "json_bytes"
  >,
  all: Rows,
): Report["database"] => {
  const modules = new Set<string>();
  for (const rows of Object.values(all) as readonly object[][])
    for (const row of rows)
      if ("module" in row && typeof row.module === "string")
        modules.add(row.module);
  const plugins = objectOf(root["plugins"]);
  return {
    ...database,
    hash_algorithm: textOf(root["hashAlgorithm"]),
    debuggee_hash: textOf(root["hash"]),
    sections: Object.keys(root).sort(),
    modules: [...modules].sort(),
    notes: textOf(root["notes"]),
    init_script: textOf(root["initscript"]),
    plugins: plugins === null ? [] : Object.keys(plugins).sort(),
  };
};

/** Build the summary and one paged, filtered view. */
export const buildX64dbgReport = (
  root: JsonObject,
  input: InspectX64dbgDatabaseInput,
  read: {
    readonly database: Pick<
      Report["database"],
      "path" | "sha256" | "bytes" | "compressed" | "json_bytes"
    >;
    readonly image: ModuleImage | null;
  },
  limitations: readonly string[],
): Report => {
  const { database, image } = read;
  const placer = new Placer(image);
  const all: Rows = {
    labels: entries(root, "labels", placer),
    comments: entries(root, "comments", placer),
    bookmarks: entries(root, "bookmarks", placer),
    functions: ranges(root, "functions", placer),
    arguments: ranges(root, "arguments", placer),
    loops: ranges(root, "loops", placer),
    breakpoints: breakpoints(root, placer),
    xrefs: xrefs(root, placer),
    watch: watches(root),
  };
  const module = input.module?.toLowerCase();
  const matching = (all[input.view] as readonly object[]).filter(
    (row) =>
      (module === undefined ||
        ("module" in row && String(row.module).toLowerCase() === module)) &&
      matches(input.query, searchable(row)),
  );
  const page = matching.slice(input.offset, input.offset + input.limit);
  return {
    database: databaseOf(root, database, all),
    module_file:
      image === null
        ? null
        : {
            path: image.path,
            name: basename(image.path),
            sha256: image.sha256,
            format: image.layout.format,
            image_base:
              image.layout.imageBase === null
                ? null
                : formatHex(image.layout.imageBase),
          },
    summary: {
      labels: all.labels.length,
      comments: all.comments.length,
      bookmarks: all.bookmarks.length,
      functions: all.functions.length,
      arguments: all.arguments.length,
      loops: all.loops.length,
      breakpoints: all.breakpoints.length,
      xrefs: all.xrefs.length,
      watch: all.watch.length,
      mismatched_breakpoints:
        image === null
          ? null
          : all.breakpoints.filter(({ bytes_match }) => bytes_match === false)
              .length,
    },
    page: {
      view: input.view,
      module: input.module ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    labels: [],
    comments: [],
    bookmarks: [],
    functions: [],
    arguments: [],
    loops: [],
    breakpoints: [],
    xrefs: [],
    watch: [],
    [input.view]: page,
    limitations: [...limitations],
  };
};
