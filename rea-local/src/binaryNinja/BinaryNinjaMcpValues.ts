import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { realpath } from "node:fs/promises";

import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { ExternalMcpCallResult } from "../externalMcp/ExternalMcpConnection.js";

export type FunctionRecord = {
  readonly address: string;
  readonly name: string;
  readonly arch?: string;
};
export type StringRecord = { readonly address: string; readonly value: string };

export const MAX_PAGE_SIZE = 500;
export const MAX_COLLECTION_ITEMS = 100_000;
export const MAX_COLLECTION_PAGES = 2_048;
const MAX_RAW_TEXT_BYTES = 262_144;

export const record = (value: unknown): Record<string, unknown> | undefined =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;

export const getString = (
  value: unknown,
  keys: readonly string[],
): string | undefined => {
  const object = record(value);
  if (object === undefined) return undefined;
  for (const key of keys) {
    const candidate = object[key];
    if (typeof candidate === "string" && candidate.length > 0) return candidate;
  }
  return undefined;
};

export const getBoolean = (
  value: unknown,
  keys: readonly string[],
): boolean | undefined => {
  const object = record(value);
  if (object === undefined) return undefined;
  for (const key of keys)
    if (typeof object[key] === "boolean") return object[key] as boolean;
  return undefined;
};

export const getNumber = (
  value: unknown,
  keys: readonly string[],
): number | undefined => {
  const object = record(value);
  if (object === undefined) return undefined;
  for (const key of keys)
    if (typeof object[key] === "number" && Number.isSafeInteger(object[key]))
      return object[key] as number;
  return undefined;
};

export const getArray = (
  value: unknown,
  keys: readonly string[],
): readonly unknown[] | undefined => {
  if (Array.isArray(value)) return value;
  const object = record(value);
  if (object === undefined) return undefined;
  for (const key of keys)
    if (Array.isArray(object[key])) return object[key] as readonly unknown[];
  return undefined;
};

const stringValue = (value: unknown): JsonValue => {
  if (typeof value !== "string") return jsonValueSchema.parse(value);
  if (Buffer.byteLength(value, "utf8") > MAX_RAW_TEXT_BYTES)
    throw new AnalysisProtocolError(
      "Binary Ninja MCP returned a text observation above REA+'s 256 KiB adapter cap.",
    );
  try {
    return jsonValueSchema.parse(JSON.parse(value));
  } catch {
    return value;
  }
};

export const decodeCallResult = (result: ExternalMcpCallResult): JsonValue => {
  if (result.isError === true) {
    const messages = (result.content ?? []).flatMap((item) => {
      const text = getString(item, ["text"]);
      return text === undefined ? [] : [text];
    });
    throw new AnalysisProtocolError(
      `Binary Ninja MCP tool failed: ${messages.join("\n") || "upstream returned isError"}`,
    );
  }
  if (result.structuredContent !== undefined)
    return jsonValueSchema.parse(result.structuredContent);
  const content = result.content ?? [];
  const textBlocks = content.flatMap((item) => {
    const object = record(item);
    return object?.type === "text" && typeof object.text === "string"
      ? [object.text]
      : [];
  });
  if (textBlocks.length === 0)
    throw new AnalysisProtocolError(
      "Binary Ninja MCP returned no structured or textual observation.",
    );
  const values = textBlocks.map((text) => stringValue(text));
  return values.length === 1 ? (values[0] ?? null) : values;
};

export const sha256File = async (path: string): Promise<string> => {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
};

export const normalizeAddress = (value: unknown): string | undefined => {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) return undefined;
    return `0x${BigInt(value).toString(16)}`;
  }
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!/^(?:0x)?[0-9a-f]+$/iu.test(trimmed)) return undefined;
  try {
    return `0x${BigInt(trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed : `0x${trimmed}`).toString(16)}`;
  } catch {
    return undefined;
  }
};

export const functionRecords = (value: unknown): FunctionRecord[] => {
  const items = getArray(value, ["functions"]);
  if (items === undefined)
    throw new AnalysisProtocolError(
      "Binary Ninja function output schema did not identify a functions array.",
    );
  return items.map((item) => {
    const row = record(item);
    const rawAddress = row?.address;
    const address =
      typeof rawAddress === "string" ? normalizeAddress(rawAddress) : undefined;
    const name = typeof row?.name === "string" ? row.name : undefined;
    const arch = typeof row?.arch === "string" ? row.arch : undefined;
    if (address === undefined || name === undefined || name.length === 0)
      throw new AnalysisProtocolError(
        "Binary Ninja function output schema returned a row without a precise string address and name.",
      );
    return { address, name, ...(arch === undefined ? {} : { arch }) };
  });
};

export const stringRecords = (value: unknown): StringRecord[] => {
  const items = getArray(value, ["strings"]);
  if (items === undefined)
    throw new AnalysisProtocolError(
      "Binary Ninja string output schema did not identify a strings array.",
    );
  return items.map((item) => {
    const row = record(item);
    const rawAddress = row?.address;
    const address =
      typeof rawAddress === "string" ? normalizeAddress(rawAddress) : undefined;
    const string = typeof row?.value === "string" ? row.value : undefined;
    if (address === undefined || string === undefined)
      throw new AnalysisProtocolError(
        "Binary Ninja string output schema returned a row without a precise string address and value.",
      );
    return { address, value: string };
  });
};

export interface CollectionPage {
  readonly count: number;
  readonly total: number;
  readonly nextOffset: number | null;
  readonly truncated: boolean;
}

/** Validate Binary Ninja's documented count/total/nextOffset/truncated envelope. */
export const collectionPage = (
  value: unknown,
  currentOffset: number,
  observedCount: number,
): CollectionPage => {
  const object = record(value);
  const count = getNumber(value, ["count"]);
  const total = getNumber(value, ["total"]);
  const truncated = object?.truncated;
  const rawNextOffset = object?.nextOffset;
  const nextOffset =
    rawNextOffset === null
      ? null
      : typeof rawNextOffset === "number" &&
          Number.isSafeInteger(rawNextOffset) &&
          rawNextOffset >= 0
        ? rawNextOffset
        : undefined;
  if (
    object === undefined ||
    count === undefined ||
    total === undefined ||
    typeof truncated !== "boolean" ||
    nextOffset === undefined
  )
    throw new AnalysisProtocolError(
      "Binary Ninja inventory omitted documented count, total, nextOffset, or truncated pagination metadata.",
    );
  if (count < 0 || total < 0 || count !== observedCount)
    throw new AnalysisProtocolError(
      "Binary Ninja inventory count does not match the returned page.",
    );
  const endOffset = currentOffset + count;
  if (
    !Number.isSafeInteger(currentOffset) ||
    currentOffset < 0 ||
    !Number.isSafeInteger(endOffset) ||
    endOffset > total
  )
    throw new AnalysisProtocolError(
      "Binary Ninja inventory page exceeds its reported total.",
    );
  if (truncated) {
    if (
      nextOffset === null ||
      nextOffset <= currentOffset ||
      nextOffset !== endOffset ||
      nextOffset >= total
    )
      throw new AnalysisProtocolError(
        "Binary Ninja marked an inventory truncated without the exact advancing offset for the next page.",
      );
  } else if (
    endOffset !== total ||
    (nextOffset !== null && nextOffset !== endOffset)
  )
    throw new AnalysisProtocolError(
      "Binary Ninja marked an inventory complete before its reported total was reached.",
    );
  return { count, total, nextOffset: truncated ? nextOffset : null, truncated };
};

export const functionText = (value: JsonValue): string | null => {
  if (typeof value === "string") return value;
  if (value === null) return null;
  const object = record(value);
  if (object === undefined)
    throw new AnalysisProtocolError(
      "Binary Ninja pseudocode response has an unsupported shape.",
    );
  for (const key of [
    "pseudocode",
    "pseudoCode",
    "pseudo_c",
    "code",
    "decompiled",
    "text",
  ]) {
    const field = object[key];
    if (typeof field === "string") return field;
  }
  const lines = getArray(value, [
    "lines",
    "pseudocodeLines",
    "pseudoCodeLines",
  ]);
  if (lines !== undefined)
    return lines
      .map((line) => getString(line, ["text", "code"]) ?? String(line))
      .join("\n");
  throw new AnalysisProtocolError(
    "Binary Ninja pseudocode response omitted its code text.",
  );
};

export const assemblyText = (value: JsonValue): string => {
  if (typeof value === "string") return value;
  const object = record(value);
  if (object === undefined)
    throw new AnalysisProtocolError(
      "Binary Ninja disassembly response has an unsupported shape.",
    );
  for (const key of ["disassembly", "assembly", "text", "code"]) {
    const field = object[key];
    if (typeof field === "string") return field;
  }
  const lines = getArray(value, ["lines", "instructions"]);
  if (lines === undefined)
    throw new AnalysisProtocolError(
      "Binary Ninja disassembly response omitted its instruction lines.",
    );
  return lines
    .map((line) => {
      const address = getString(line, ["address", "addr", "start"]);
      const text = getString(line, ["instruction", "text", "disassembly"]);
      if (address === undefined || text === undefined)
        throw new AnalysisProtocolError(
          "Binary Ninja disassembly returned a line without address and instruction text.",
        );
      return `${address}: ${text}`;
    })
    .join("\n");
};

export const findOpenItem = async (
  value: JsonValue,
  expectedPath: string,
  preferredHandle?: string,
): Promise<{ readonly handle: string; readonly path: string } | undefined> => {
  const items = findObjects(value, [
    "openItems",
    "open_items",
    "items",
    "files",
  ]);
  for (const item of items) {
    const handle = getString(item, [
      "openItem",
      "open_item",
      "openItemHandle",
      "open_item_handle",
      "handle",
    ]);
    const path = getString(item, [
      "path",
      "filePath",
      "file_path",
      "filename",
      "fileName",
      "inputPath",
      "input_path",
    ]);
    if (
      handle !== undefined &&
      path !== undefined &&
      (preferredHandle === undefined || handle === preferredHandle) &&
      (await sameFilePath(path, expectedPath))
    )
      return { handle, path };
  }
  return undefined;
};

export const chooseBinaryView = (
  value: JsonValue,
): { readonly handle: string } | undefined => {
  const items = findObjects(value, [
    "binaryViews",
    "binary_views",
    "views",
    "items",
  ]);
  const candidates = items.flatMap((item) => {
    const handle = getString(item, [
      "binaryView",
      "binary_view",
      "binaryViewHandle",
      "binary_view_handle",
      "handle",
    ]);
    if (handle === undefined) return [];
    return [
      {
        handle,
        recommended: getBoolean(item, ["recommended"]),
        available: getBoolean(item, ["available"]),
      },
    ];
  });
  const selected =
    candidates.find(
      ({ recommended, available }) =>
        recommended === true && available !== false,
    ) ?? candidates.find(({ available }) => available !== false);
  return selected === undefined ? undefined : { handle: selected.handle };
};

const findObjects = (
  value: unknown,
  keys: readonly string[],
): Record<string, unknown>[] => {
  const found: Record<string, unknown>[] = [];
  const visit = (candidate: unknown, depth: number): void => {
    if (depth > 8 || candidate === null || typeof candidate !== "object")
      return;
    if (Array.isArray(candidate)) {
      for (const item of candidate) {
        const itemRecord = record(item);
        if (itemRecord !== undefined) found.push(itemRecord);
        visit(item, depth + 1);
      }
      return;
    }
    const object = candidate as Record<string, unknown>;
    for (const key of keys) {
      const collection = object[key];
      if (Array.isArray(collection))
        for (const item of collection) {
          const itemRecord = record(item);
          if (itemRecord !== undefined) found.push(itemRecord);
        }
    }
    for (const child of Object.values(object)) visit(child, depth + 1);
  };
  visit(value, 0);
  return found;
};

export const findString = (
  value: unknown,
  keys: readonly string[],
): string | undefined => {
  const visit = (candidate: unknown, depth: number): string | undefined => {
    if (depth > 8 || candidate === null || typeof candidate !== "object")
      return undefined;
    if (Array.isArray(candidate)) {
      for (const item of candidate) {
        const nested = visit(item, depth + 1);
        if (nested !== undefined) return nested;
      }
      return undefined;
    }
    const object = candidate as Record<string, unknown>;
    const direct = getString(object, keys);
    if (direct !== undefined) return direct;
    for (const nestedValue of Object.values(object)) {
      const nested = visit(nestedValue, depth + 1);
      if (nested !== undefined) return nested;
    }
    return undefined;
  };
  return visit(value, 0);
};

export const findDeepValue = (
  value: unknown,
  keys: readonly string[],
): unknown => {
  const object = record(value);
  if (object === undefined) return undefined;
  for (const key of keys) if (key in object) return object[key];
  for (const child of Object.values(object)) {
    const nested = findDeepValue(child, keys);
    if (nested !== undefined) return nested;
  }
  return undefined;
};

export const compareAddresses = (left: string, right: string): number => {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
};

const pathMatches = (left: string, right: string): boolean =>
  process.platform === "win32"
    ? left.replaceAll("/", "\\").toLowerCase() ===
      right.replaceAll("/", "\\").toLowerCase()
    : left === right;

export const sameFilePath = async (
  left: string,
  right: string,
): Promise<boolean> => {
  try {
    return pathMatches(await realpath(left), await realpath(right));
  } catch {
    return pathMatches(left, right);
  }
};

export const formatToolList = (names: readonly string[]): string =>
  names.length === 0 ? "<empty>" : names.slice(0, 80).join(", ");
