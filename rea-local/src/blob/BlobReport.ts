import { createHash } from "node:crypto";

import type {
  DataBlobReport,
  InspectDataBlobInput,
} from "../domain/blob/dataBlob.js";
import { decodePayload, type BlobFormat } from "./BlobFormats.js";
import { peelLayers } from "./BlobLayers.js";
import { flatten, type FlatNode } from "./BlobPaths.js";
import {
  BlobFormatError,
  BlobSelectionError,
  measure,
  type BlobNode,
} from "./BlobTree.js";
import { regionChunkPayload, regionChunks, regionTree } from "./McaRegion.js";

type Report = DataBlobReport;

const MAX_OUTPUT = 1024 * 1024 * 1024;
const MIN_RUN = 6;

/** Printable ASCII runs, for a payload no format decodes. */
const printableRuns = (bytes: Buffer): Report["strings"] => {
  const runs: Report["strings"] = [];
  let start = -1;
  const flush = (end: number) => {
    if (start >= 0 && end - start >= MIN_RUN)
      runs.push({
        path: `@${String(start)}`,
        offset: start,
        value: bytes.toString("latin1", start, Math.min(end, start + 1000)),
      });
    start = -1;
  };
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = bytes[index] ?? 0;
    const printable = byte >= 0x20 && byte < 0x7f;
    if (printable && start < 0) start = index;
    else if (!printable) flush(index);
  }
  flush(bytes.length);
  return runs;
};

const matches = (
  query: string | undefined,
  ...values: readonly (string | null)[]
): boolean =>
  query === undefined ||
  values.some(
    (value) => value?.toLowerCase().includes(query.toLowerCase()) === true,
  );

/** The rows of the selected subtree, cut to max_depth below it. */
const subtree = (
  rows: readonly FlatNode[],
  input: InspectDataBlobInput,
): FlatNode[] => {
  const start =
    input.node === undefined
      ? 0
      : rows.findIndex(({ path }) => path === input.node);
  if (start < 0)
    throw new BlobSelectionError(
      `No node ${input.node ?? ""}; paths look like $.name, $[0] or $.5[1].`,
      "node",
    );
  const base = rows[start];
  if (base === undefined) return [];
  const out: FlatNode[] = [base];
  for (const row of rows.slice(start + 1)) {
    if (row.depth <= base.depth) break;
    out.push(row);
  }
  return out.filter(
    ({ depth }) =>
      input.max_depth === undefined || depth - base.depth <= input.max_depth,
  );
};

/** Decode the selected payload: a region file, one region chunk, or a blob in any supported format. */
const decode = (
  bytes: Buffer,
  input: InspectDataBlobInput,
): {
  root: BlobNode | null;
  name: Report["format"]["name"];
  candidates: Report["candidates"];
  payload: Buffer;
} => {
  const regions =
    input.format === "mca" ||
    (input.format === "auto" && input.layers === undefined)
      ? regionChunks(bytes)
      : null;
  if (input.format === "mca" && regions === null)
    throw new BlobFormatError(
      "Not a Minecraft region file: no readable chunk locations.",
    );
  if (input.region_chunk !== undefined) {
    if (regions === null)
      throw new BlobSelectionError(
        "region_chunk needs a Minecraft region file.",
        "region_chunk",
      );
    const chunk = regions.find(({ index }) => index === input.region_chunk);
    if (chunk === undefined)
      throw new BlobSelectionError(
        `Region chunk ${String(input.region_chunk)} is not present; ${String(regions.length)} chunks are.`,
        "region_chunk",
      );
    const payload = regionChunkPayload(bytes, chunk, MAX_OUTPUT);
    const { root, candidates } = decodePayload(payload, "nbt");
    if (root === null)
      throw new BlobFormatError(
        `Region chunk ${String(chunk.index)} is not NBT: ${candidates[0]?.error ?? ""}`,
      );
    return { root, name: "nbt", candidates, payload };
  }
  if (regions !== null)
    return {
      root: regionTree(regions, bytes.length),
      name: "mca",
      candidates: [],
      payload: bytes,
    };
  const forced =
    input.format === "auto" || input.format === "mca"
      ? undefined
      : (input.format as BlobFormat);
  const { root, format, candidates } = decodePayload(bytes, forced);
  if (forced !== undefined && root === null)
    throw new BlobFormatError(`Not ${forced}: ${candidates[0]?.error ?? ""}`);
  return { root, name: format ?? "raw", candidates, payload: bytes };
};

/** Tree rows and string leaves of the selected subtree, or printable runs of an undecoded payload. */
const listings = (
  decoded: { readonly root: BlobNode | null; readonly payload: Buffer },
  input: InspectDataBlobInput,
): { tree: Report["tree"]; strings: Report["strings"] } => {
  if (decoded.root === null)
    return {
      tree: [],
      strings: printableRuns(decoded.payload).filter(({ value }) =>
        matches(input.query, value),
      ),
    };
  const selected = subtree(flatten(decoded.root), input);
  const tree = selected
    .filter(({ path, node }) =>
      matches(
        input.query,
        path,
        typeof node.key === "number" ? String(node.key) : node.key,
        node.type,
        node.value,
      ),
    )
    .map(({ path, depth, node }) => ({
      path,
      depth,
      key: node.key,
      type: node.type,
      value: node.value,
      alternatives: { ...node.alternatives },
      offset: node.offset,
      length: node.length,
      children: node.children.length,
    }));
  const strings = selected
    .filter(({ node }) => node.type === "string")
    .map(({ path, node }) => ({
      path,
      offset: node.offset,
      value: node.value ?? "",
    }))
    .filter(({ path, value }) => matches(input.query, path, value));
  return { tree, strings };
};

/** Peel layers, decode, and page through the tree or its strings. */
export const buildDataBlobReport = (
  file: { readonly bytes: Buffer; readonly sha256: string },
  input: InspectDataBlobInput,
  limitations: readonly string[],
): Report => {
  const start = input.range_offset ?? 0;
  if (start > file.bytes.length)
    throw new BlobSelectionError(
      `range_offset ${String(start)} is past the ${String(file.bytes.length)}-byte file.`,
      "range_offset",
    );
  const end =
    input.range_length === undefined
      ? file.bytes.length
      : start + input.range_length;
  if (end > file.bytes.length)
    throw new BlobSelectionError(
      `The range runs past the ${String(file.bytes.length)}-byte file.`,
      "range_length",
    );
  const { bytes, layers } = peelLayers(
    file.bytes.subarray(start, end),
    input.layers,
    MAX_OUTPUT,
  );
  const decoded = decode(bytes, input);
  const { tree, strings } = listings(decoded, input);
  const matching: readonly unknown[] = input.view === "tree" ? tree : strings;
  const page = matching.slice(input.offset, input.offset + input.limit);
  const measured =
    decoded.root === null
      ? { nodes: 0, depth: 0, strings: strings.length }
      : measure(decoded.root);
  return {
    file: { path: input.path, sha256: file.sha256, bytes: file.bytes.length },
    range: { offset: start, length: end - start },
    layers,
    payload: {
      bytes: decoded.payload.length,
      sha256: createHash("sha256").update(decoded.payload).digest("hex"),
    },
    format: {
      name: decoded.name,
      forced: input.format !== "auto",
      region_chunk: input.region_chunk ?? null,
    },
    candidates: decoded.candidates,
    summary: {
      nodes: measured.nodes,
      depth: measured.depth,
      strings: measured.strings,
    },
    page: {
      view: input.view,
      node: input.node ?? null,
      max_depth: input.max_depth ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    tree: input.view === "tree" ? (page as Report["tree"]) : [],
    strings: input.view === "strings" ? (page as Report["strings"]) : [],
    limitations: [...limitations],
  };
};
