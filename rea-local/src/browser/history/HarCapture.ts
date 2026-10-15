import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";
import { isSafeNumber, LosslessNumber } from "lossless-json";
import { visitHarJson } from "./HarJson.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import {
  WEB_NETWORK_CAPTURE_LIMITS,
  type WebNetworkCapture,
  type WebNetworkCaptureRecord,
} from "../../domain/webNetworkCapture.js";
import { CaptureFormatError } from "./CaptureFormatError.js";
import {
  CaptureRedaction,
  captureObject,
  capturePointer,
} from "./CaptureRedaction.js";
import {
  createHarValidationContext,
  schemaFailure,
  type HarSchemaNode,
  type HarSchemaSet,
  type HarSchemaFailure,
} from "./HarSchema.js";
import { HAR_CAPTURE_PROVIDER_IDENTITY } from "./CaptureRelease.js";

type DecodedCapture = Omit<
  WebNetworkCapture,
  "artifact" | "format" | "runtime_attribution" | "limitations"
>;
type Projection = Pick<
  WebNetworkCaptureRecord,
  "reported" | "numeric_literals" | "binary_fields" | "redactions"
>;

/**
 * Decode retained HAR bytes as UTF-8. HAR 1.2 lets writers emit a byte-order
 * mark and requires readers to ignore it, so one leading BOM is skipped.
 */
export const decodeHarText = (bytes: Uint8Array): string => {
  try {
    // ignoreBOM: false (the default) is what skips the mark; true keeps it.
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new CaptureFormatError("format", "HAR is not valid UTF-8 JSON.");
  }
};

/**
 * Validate the complete HAR while retaining full producer objects only for
 * requested records. Unselected entries are projected to the pinned schema's
 * fields, validated one at a time, and discarded.
 */
export const decodeHarCapture = (
  text: string,
  sensitiveValues: readonly string[],
  recordOrdinals?: readonly number[],
): DecodedCapture => {
  const validation = createHarValidationContext();
  const entrySchema = validation.schemas.entry;
  const rootSchema = validation.schemas.har;
  if (entrySchema === undefined || rootSchema === undefined)
    throw new Error("Pinned HAR entry or root schema is unavailable.");
  const requested =
    recordOrdinals === undefined ? undefined : new Set(recordOrdinals);
  const recordsExcluded = ["log", "entries"].some((key) =>
    sensitiveValues.some((literal) => key.includes(literal)),
  );
  const containerBuilder = new HarValueBuilder("full", validation.schemas);
  const selectedRecords = new Map<number, unknown>();
  let entriesArraySeen = false;
  let insideEntriesArray = false;
  let totalRecords = 0;
  let activeEntry:
    | {
        readonly ordinal: number;
        readonly pointer: string;
        readonly builder: HarValueBuilder;
        readonly retained: boolean;
      }
    | undefined;
  let firstStandardFailure: HarSchemaFailure | undefined;
  let firstCompatibleFailure: HarSchemaFailure | undefined;
  let firstBase64Failure: CaptureFormatError | undefined;

  const startEntry = (pointer: string): void => {
    const ordinal = entryOrdinal(pointer);
    if (ordinal === undefined)
      throw new TypeError("HAR entry parser received a non-ordinal pointer.");
    if (activeEntry !== undefined)
      throw new TypeError("HAR entry parser opened overlapping records.");
    const retained =
      !recordsExcluded && (requested === undefined || requested.has(ordinal));
    const builder = new HarValueBuilder(
      retained ? "full" : "schema",
      validation.schemas,
      entrySchema,
    );
    activeEntry = { ordinal, pointer, builder, retained };
    totalRecords = Math.max(totalRecords, ordinal + 1);
  };

  const finishEntry = (): void => {
    const current = activeEntry;
    if (current === undefined)
      throw new TypeError("HAR entry parser completed a missing record.");
    activeEntry = undefined;
    const raw = current.builder.value;
    if (!current.builder.hasValue)
      throw new TypeError("HAR entry parser completed without a JSON value.");
    const schemaValue =
      current.builder.mode === "full"
        ? projectHarValidationValue(raw, [entrySchema], validation.schemas)
        : raw;

    const standard = validation.validateEntry(
      schemaValue,
      current.ordinal,
      false,
    );
    if (firstStandardFailure === undefined && standard !== undefined)
      firstStandardFailure = standard;

    const compatible = containsNullPostDataText(schemaValue)
      ? validation.validateEntry(schemaValue, current.ordinal, true)
      : standard;
    if (firstCompatibleFailure === undefined && compatible !== undefined)
      firstCompatibleFailure = compatible;

    try {
      assertEntryBase64(schemaValue);
    } catch (cause: unknown) {
      if (
        firstBase64Failure === undefined &&
        cause instanceof CaptureFormatError
      )
        firstBase64Failure = cause;
      else if (!(cause instanceof CaptureFormatError)) throw cause;
    }

    if (current.retained) selectedRecords.set(current.ordinal, raw);
  };

  const feedEntryContainer = (
    kind: "object" | "array",
    pointer: string,
  ): void => {
    if (activeEntry === undefined && entryOrdinal(pointer) !== undefined)
      startEntry(pointer);
    const current = activeEntry;
    if (current === undefined)
      throw new TypeError(
        "HAR entry parser received a value outside a record.",
      );
    if (kind === "object") current.builder.objectBegin(pointer);
    else current.builder.arrayBegin(pointer);
  };

  const feedEntryLiteral = (
    value: unknown,
    pointer: string,
    offset: number,
    length: number,
  ): void => {
    if (activeEntry === undefined && entryOrdinal(pointer) !== undefined)
      startEntry(pointer);
    const current = activeEntry;
    if (current === undefined)
      throw new TypeError(
        "HAR entry parser received a literal outside a record.",
      );
    current.builder.literal(
      value,
      pointer,
      text.slice(offset, offset + length),
    );
    if (pointer === current.pointer) finishEntry();
  };

  visitHarJson(text, {
    onObjectBegin: (pointer) => {
      if (insideEntriesArray) feedEntryContainer("object", pointer);
      else containerBuilder.objectBegin(pointer);
    },
    onObjectProperty: (key, pointer) => {
      if (insideEntriesArray) {
        if (activeEntry !== undefined)
          activeEntry.builder.property(key, pointer);
      } else containerBuilder.property(key, pointer);
    },
    onObjectEnd: (pointer) => {
      if (insideEntriesArray) {
        const current = activeEntry;
        if (current === undefined)
          throw new TypeError("HAR entry parser ended an unopened object.");
        current.builder.objectEnd(pointer);
        if (pointer === current.pointer) finishEntry();
      } else containerBuilder.objectEnd(pointer);
    },
    onArrayBegin: (pointer) => {
      if (pointer === "/log/entries" && !entriesArraySeen) {
        entriesArraySeen = true;
        insideEntriesArray = true;
        containerBuilder.literal(null, pointer, "null");
      } else if (insideEntriesArray) feedEntryContainer("array", pointer);
      else containerBuilder.arrayBegin(pointer);
    },
    onArrayEnd: (pointer) => {
      if (insideEntriesArray && pointer === "/log/entries") {
        if (activeEntry !== undefined)
          throw new TypeError("HAR entry array ended inside a record.");
        insideEntriesArray = false;
      } else if (insideEntriesArray) {
        const current = activeEntry;
        if (current === undefined)
          throw new TypeError("HAR entry parser ended an unopened array.");
        current.builder.arrayEnd(pointer);
        if (pointer === current.pointer) finishEntry();
      } else containerBuilder.arrayEnd(pointer);
    },
    onLiteralValue: (value, pointer, offset, length) => {
      if (insideEntriesArray) feedEntryLiteral(value, pointer, offset, length);
      else
        containerBuilder.literal(
          value,
          pointer,
          text.slice(offset, offset + length),
        );
    },
  });

  if (insideEntriesArray || activeEntry !== undefined)
    throw new TypeError("HAR entry parser did not complete its array.");
  if (!containerBuilder.hasValue)
    throw new CaptureFormatError("format", "HAR is malformed JSON.");
  const rawContainer = containerBuilder.value;
  const validationContainer = projectHarValidationValue(
    rawContainer,
    [rootSchema],
    validation.schemas,
  );
  if (
    entriesArraySeen &&
    captureObject(validationContainer) &&
    captureObject(validationContainer.log)
  )
    validationContainer.log.entries = [];
  const documentFailure = validation.validateDocument(validationContainer);
  if (documentFailure !== undefined) throw schemaFailure(documentFailure);
  if (
    !captureObject(rawContainer) ||
    !captureObject(rawContainer.log) ||
    !entriesArraySeen
  )
    throw new CaptureFormatError("format", "HAR must contain log.entries.");

  const creator = rawContainer.log.creator;
  const isMitmproxyCompatibilityProfile =
    captureObject(creator) &&
    creator.name === "mitmproxy" &&
    creator.version === "12.2.3";
  const entryFailure = isMitmproxyCompatibilityProfile
    ? firstCompatibleFailure
    : firstStandardFailure;
  if (entryFailure !== undefined) throw schemaFailure(entryFailure);
  if (rawContainer.log.version !== "1.2")
    throw new CaptureFormatError(
      "unsupported",
      "Only the pinned HAR 1.2 schema profile is supported.",
      "/log/version",
    );
  if (firstBase64Failure !== undefined) throw firstBase64Failure;

  const container = projectHar(rawContainer, sensitiveValues, true);
  const records: WebNetworkCaptureRecord[] = [];
  const selectedOrdinals =
    recordOrdinals === undefined ? undefined : recordOrdinals;
  const appendRecord = (ordinal: number): void => {
    if (ordinal >= totalRecords) return;
    const projection: Projection = recordsExcluded
      ? {
          reported: null,
          numeric_literals: [],
          binary_fields: [],
          redactions: [{ pointer: "", reason: "explicit-sensitive-value" }],
        }
      : (() => {
          if (!selectedRecords.has(ordinal))
            throw new TypeError("HAR decoder omitted a requested record.");
          const raw = selectedRecords.get(ordinal);
          return projectHar(raw, sensitiveValues, true);
        })();
    records.push({
      ordinal,
      location: recordsExcluded
        ? { kind: "unknown", reason: "explicit-sensitive-value" }
        : { kind: "json-pointer", pointer: `/log/entries/${ordinal}` },
      ...projection,
      limitations: [
        "HAR text is producer-decoded Unicode. Original body bytes remain unknown unless content explicitly uses valid base64; declared sizes are preserved independently of retained bytes. mitmproxy 12.2.3 SaveHar may report null optional postData.text; that null is retained and omitted only from the upstream validation copy.",
        ...(recordsExcluded
          ? [
              "This record's payload and sidecars are excluded because its structural ancestor property was explicitly marked sensitive.",
            ]
          : []),
      ],
    });
  };
  if (selectedOrdinals === undefined) {
    for (let ordinal = 0; ordinal < totalRecords; ordinal++)
      appendRecord(ordinal);
  } else {
    for (const ordinal of selectedOrdinals) appendRecord(ordinal);
  }

  return {
    decoder: { ...HAR_CAPTURE_PROVIDER_IDENTITY },
    container: {
      reported: container.reported,
      numeric_literals: container.numeric_literals,
      redactions: container.redactions,
      records_pointer: recordsExcluded ? null : "/log/entries",
    },
    total_records: totalRecords,
    records,
  };
};

const typeNames = (schema: HarSchemaNode): readonly string[] => {
  const type = schema.type;
  return typeof type === "string"
    ? [type]
    : Array.isArray(type)
      ? type.filter((item): item is string => typeof item === "string")
      : [];
};

const expandSchemaPlan = (
  plan: readonly HarSchemaNode[],
  schemas: HarSchemaSet,
  resolving = new Set<string>(),
): HarSchemaNode[] => {
  const expanded: HarSchemaNode[] = [];
  for (const schema of plan) {
    const reference = schema.$ref;
    if (typeof reference === "string") {
      const name = reference.slice(0, reference.indexOf(".json#"));
      const target = schemas[name];
      if (target === undefined || resolving.has(name))
        throw new TypeError(
          `Pinned HAR schema reference is unavailable: ${reference}`,
        );
      const next = new Set(resolving);
      next.add(name);
      expanded.push(...expandSchemaPlan([target], schemas, next));
      continue;
    }
    const alternatives = schema.oneOf;
    if (Array.isArray(alternatives)) {
      for (const alternative of alternatives)
        if (captureObject(alternative))
          expanded.push(...expandSchemaPlan([alternative], schemas, resolving));
      continue;
    }
    expanded.push(schema);
  }
  return expanded;
};

const propertySchemaPlan = (
  plan: readonly HarSchemaNode[],
  key: string,
  schemas: HarSchemaSet,
): HarSchemaNode[] => {
  const children: HarSchemaNode[] = [];
  for (const schema of expandSchemaPlan(plan, schemas)) {
    const properties = schema.properties;
    if (captureObject(properties) && Object.hasOwn(properties, key)) {
      const child = properties[key];
      if (captureObject(child)) children.push(child);
    } else if (captureObject(schema.additionalProperties))
      children.push(schema.additionalProperties);
  }
  return expandSchemaPlan(children, schemas);
};

const itemSchemaPlan = (
  plan: readonly HarSchemaNode[],
  schemas: HarSchemaSet,
): HarSchemaNode[] => {
  const children = expandSchemaPlan(plan, schemas).flatMap((schema) =>
    captureObject(schema.items) ? [schema.items] : [],
  );
  return expandSchemaPlan(children, schemas);
};

const supportsContainer = (
  plan: readonly HarSchemaNode[],
  kind: "object" | "array",
  schemas: HarSchemaSet,
): boolean =>
  expandSchemaPlan(plan, schemas).some((schema) => {
    const types = typeNames(schema);
    return kind === "object"
      ? types.includes("object") ||
          captureObject(schema.properties) ||
          Array.isArray(schema.required) ||
          captureObject(schema.additionalProperties)
      : types.includes("array") || captureObject(schema.items);
  });

const projectHarValidationValue = (
  value: unknown,
  plan: readonly HarSchemaNode[],
  schemas: HarSchemaSet,
): unknown => {
  if (value instanceof LosslessNumber)
    return isSafeNumber(value.value) ? Number(value.value) : null;
  if (Array.isArray(value)) {
    if (!supportsContainer(plan, "array", schemas)) return [];
    const items = itemSchemaPlan(plan, schemas);
    return items.length === 0
      ? []
      : value.map((child) => projectHarValidationValue(child, items, schemas));
  }
  if (captureObject(value)) {
    if (!supportsContainer(plan, "object", schemas)) return {};
    return Object.fromEntries(
      Object.entries(value).flatMap(([key, child]) => {
        const childPlan = propertySchemaPlan(plan, key, schemas);
        return childPlan.length === 0
          ? []
          : [[key, projectHarValidationValue(child, childPlan, schemas)]];
      }),
    );
  }
  return value;
};

type Retention = "full" | "schema" | "opaque" | "discard";
type Disposition = {
  readonly retention: "full" | "schema" | "discard";
  readonly schemaPlan: readonly HarSchemaNode[];
  readonly attach: boolean;
  readonly key?: string;
};
type BuilderFrame =
  | {
      readonly kind: "object";
      readonly pointer: string;
      readonly retention: Retention;
      readonly schemaPlan: readonly HarSchemaNode[];
      readonly attachment: Disposition;
      readonly members: Map<string, unknown>;
      pending?: Disposition;
    }
  | {
      readonly kind: "array";
      readonly pointer: string;
      readonly retention: Retention;
      readonly schemaPlan: readonly HarSchemaNode[];
      readonly attachment: Disposition;
      readonly items: unknown[];
    };

/** Build one selected value, or a schema-only validation shell for one unselected entry. */
class HarValueBuilder {
  readonly #frames: BuilderFrame[] = [];
  #hasValue = false;
  #value: unknown;
  constructor(
    readonly mode: "full" | "schema",
    readonly schemas: HarSchemaSet,
    readonly rootSchema?: HarSchemaNode,
  ) {}

  get hasValue(): boolean {
    return this.#hasValue;
  }

  get value(): unknown {
    return this.#value;
  }

  property(key: string, _pointer: string): void {
    const frame = this.#frames.at(-1);
    if (frame?.kind !== "object")
      throw new TypeError(
        "HAR value builder received a property outside an object.",
      );
    if (frame.retention === "full")
      frame.pending = { retention: "full", schemaPlan: [], attach: true, key };
    else if (frame.retention === "schema") {
      const schemaPlan = propertySchemaPlan(
        frame.schemaPlan,
        key,
        this.schemas,
      );
      frame.pending =
        schemaPlan.length === 0
          ? { retention: "discard", schemaPlan: [], attach: false, key }
          : { retention: "schema", schemaPlan, attach: true, key };
    } else
      frame.pending = {
        retention: "discard",
        schemaPlan: [],
        attach: false,
        key,
      };
  }

  objectBegin(pointer: string): void {
    this.beginContainer("object", pointer);
  }

  arrayBegin(pointer: string): void {
    this.beginContainer("array", pointer);
  }

  literal(value: unknown, pointer: string, literal: string): void {
    const attachment = this.nextDisposition();
    if (!attachment.attach) return;
    let materialized = value;
    if (typeof value === "number") {
      materialized =
        attachment.retention === "full"
          ? new LosslessNumber(literal)
          : isSafeNumber(literal)
            ? Number(literal)
            : null;
    } else if (
      value !== null &&
      typeof value !== "boolean" &&
      typeof value !== "string"
    )
      throw new TypeError("JSON visitor emitted an unsupported literal.");
    this.attach(materialized, attachment);
  }

  objectEnd(pointer: string): void {
    const frame = this.#frames.pop();
    if (frame?.kind !== "object" || frame.pointer !== pointer)
      throw new TypeError("HAR value builder ended an unexpected object.");
    if (frame.pending !== undefined)
      throw new TypeError(
        "HAR value builder ended an object with an incomplete property.",
      );
    if (frame.retention === "discard") return;
    const value =
      frame.retention === "opaque" ? {} : Object.fromEntries(frame.members);
    this.attach(value, frame.attachment);
  }

  arrayEnd(pointer: string): void {
    const frame = this.#frames.pop();
    if (frame?.kind !== "array" || frame.pointer !== pointer)
      throw new TypeError("HAR value builder ended an unexpected array.");
    if (frame.retention === "discard") return;
    const value = frame.retention === "opaque" ? [] : frame.items;
    this.attach(value, frame.attachment);
  }

  private beginContainer(kind: "object" | "array", pointer: string): void {
    const attachment = this.nextDisposition();
    let retention: Retention = attachment.retention;
    if (
      retention === "schema" &&
      !supportsContainer(attachment.schemaPlan, kind, this.schemas)
    )
      retention = "opaque";
    this.#frames.push(
      kind === "object"
        ? {
            kind,
            pointer,
            retention,
            schemaPlan: attachment.schemaPlan,
            attachment,
            members: new Map(),
          }
        : {
            kind,
            pointer,
            retention,
            schemaPlan: attachment.schemaPlan,
            attachment,
            items: [],
          },
    );
  }

  private nextDisposition(): Disposition {
    const parent = this.#frames.at(-1);
    if (parent === undefined) {
      if (this.#hasValue)
        throw new TypeError("HAR value builder received multiple root values.");
      if (this.mode === "full")
        return { retention: "full", schemaPlan: [], attach: true };
      if (this.rootSchema === undefined)
        throw new TypeError("HAR validation builder has no root schema.");
      return {
        retention: "schema",
        schemaPlan: [this.rootSchema],
        attach: true,
      };
    }
    if (parent.kind === "object") {
      const pending = parent.pending;
      if (pending === undefined)
        throw new TypeError(
          "HAR value builder omitted an object property identity.",
        );
      delete parent.pending;
      return pending;
    }
    if (parent.retention === "full")
      return { retention: "full", schemaPlan: [], attach: true };
    if (parent.retention === "schema") {
      const schemaPlan = itemSchemaPlan(parent.schemaPlan, this.schemas);
      return schemaPlan.length === 0
        ? { retention: "discard", schemaPlan: [], attach: false }
        : { retention: "schema", schemaPlan, attach: true };
    }
    return { retention: "discard", schemaPlan: [], attach: false };
  }

  private attach(value: unknown, attachment: Disposition): void {
    if (!attachment.attach) return;
    const parent = this.#frames.at(-1);
    if (parent === undefined) {
      if (this.#hasValue)
        throw new TypeError("HAR value builder received multiple root values.");
      this.#value = value;
      this.#hasValue = true;
      return;
    }
    if (parent.retention === "discard" || parent.retention === "opaque") return;
    if (parent.kind === "array") parent.items.push(value);
    else {
      if (attachment.key === undefined)
        throw new TypeError(
          "HAR value builder omitted an object property identity.",
        );
      parent.members.set(attachment.key, value);
    }
  }
}

const entryOrdinal = (pointer: string): number | undefined => {
  const match = /^\/log\/entries\/(0|[1-9]\d*)$/.exec(pointer);
  if (match === null) return undefined;
  const ordinal = Number(match[1]);
  return Number.isSafeInteger(ordinal) ? ordinal : undefined;
};

const containsNullPostDataText = (entry: unknown): boolean =>
  captureObject(entry) &&
  captureObject(entry.request) &&
  captureObject(entry.request.postData) &&
  Object.hasOwn(entry.request.postData, "text") &&
  entry.request.postData.text === null;

const assertEntryBase64 = (entry: unknown): void => {
  if (
    !captureObject(entry) ||
    !captureObject(entry.response) ||
    !captureObject(entry.response.content) ||
    entry.response.content.encoding !== "base64" ||
    typeof entry.response.content.text !== "string"
  )
    return;
  assertCanonicalHarBase64(
    entry.response.content.text,
    "/response/content/text",
  );
};

const assertCanonicalHarBase64 = (value: string, pointer: string): void => {
  let length = 0;
  let padding = 0;
  let lastDataCharacter = -1;
  for (let index = 0; index < value.length; index++) {
    const character = value.charCodeAt(index);
    if (
      character === 0x09 ||
      character === 0x0a ||
      character === 0x0d ||
      character === 0x20
    )
      continue;
    length++;
    if (character === 0x3d) {
      padding++;
      if (padding > 2) throw invalidBase64(pointer);
      continue;
    }
    if (padding !== 0) throw invalidBase64(pointer);
    const sextet = base64Sextet(character);
    if (sextet < 0) throw invalidBase64(pointer);
    lastDataCharacter = sextet;
  }
  if (length % 4 !== 0 || (padding !== 0 && length < 4))
    throw invalidBase64(pointer);
  if (
    (padding === 1 && (length - padding) % 4 !== 3) ||
    (padding === 2 && (length - padding) % 4 !== 2) ||
    (padding === 1 && (lastDataCharacter & 0b11) !== 0) ||
    (padding === 2 && (lastDataCharacter & 0b1111) !== 0)
  )
    throw invalidBase64(pointer);
};

const base64Sextet = (character: number): number => {
  if (character >= 0x41 && character <= 0x5a) return character - 0x41;
  if (character >= 0x61 && character <= 0x7a) return character - 0x61 + 26;
  if (character >= 0x30 && character <= 0x39) return character - 0x30 + 52;
  if (character === 0x2b) return 62;
  if (character === 0x2f) return 63;
  return -1;
};

const invalidBase64 = (pointer: string): CaptureFormatError =>
  new CaptureFormatError(
    "format",
    "HAR content declares base64 but its text is not valid canonical base64 (ASCII whitespace is allowed).",
    pointer,
  );

const projectHar = (
  value: unknown,
  sensitiveValues: readonly string[],
  redact: boolean,
): Projection => {
  const redactor = new CaptureRedaction(sensitiveValues);
  const numeric_literals: Projection["numeric_literals"] = [];
  const binary_fields: Projection["binary_fields"] = [];
  const visit = (
    item: unknown,
    pointer: string,
    depth: number,
    parent?: Readonly<Record<string, unknown>>,
  ): JsonValue => {
    if (depth > WEB_NETWORK_CAPTURE_LIMITS.depth)
      throw new CaptureFormatError(
        "input-limit",
        `HAR exceeds the ${WEB_NETWORK_CAPTURE_LIMITS.depth}-level complete-evidence nesting budget.`,
        pointer,
      );
    if (
      redact &&
      parent !== undefined &&
      redactor.harCredential(pointer, parent)
    )
      return redactor.credential(pointer);
    if (item instanceof LosslessNumber) {
      if (redact && redactor.text(item.value, pointer) === null) return null;
      numeric_literals.push({
        pointer,
        producer_type: "json-number",
        literal: item.value,
      });
      return isSafeNumber(item.value) ? Number(item.value) : null;
    }
    if (typeof item === "string") {
      if (
        redact &&
        pointer === "/response/content/text" &&
        parent?.encoding === "base64"
      ) {
        const bytes = decodeHarBase64(item, pointer);
        const contentBase64 = bytes.toString("base64");
        const sha256 = createHash("sha256").update(bytes).digest("hex");
        const hidden =
          redactor.sensitiveBytes(bytes) ||
          sensitiveValues.some(
            (literal) =>
              item.includes(literal) ||
              contentBase64.includes(literal) ||
              sha256.includes(literal),
          );
        binary_fields.push(
          hidden
            ? {
                pointer,
                representation: "har-base64-content",
                state: "redacted",
                content_base64: null,
                bytes: null,
                sha256: null,
              }
            : {
                pointer,
                representation: "har-base64-content",
                state: "retained",
                content_base64: contentBase64,
                bytes: bytes.length,
                sha256,
              },
        );
        if (hidden) {
          redactor.redactions.push({
            pointer,
            reason: "explicit-sensitive-value",
          });
          return null;
        }
      }
      return redact
        ? redactor.text(
            item,
            pointer,
            redactor.harTransportUrl(pointer, parent),
          )
        : item;
    }
    if (item === null || typeof item === "boolean") return item;
    if (Array.isArray(item))
      return item.map((child, index) =>
        visit(child, capturePointer(pointer, String(index)), depth + 1),
      );
    if (captureObject(item))
      return Object.fromEntries(
        Object.entries(item).flatMap(([key, child]) => {
          if (
            redact &&
            sensitiveValues.some((literal) => key.includes(literal))
          ) {
            const beforeNumbers = numeric_literals.length;
            const beforeBinaries = binary_fields.length;
            const beforeRedactions = redactor.redactions.length;
            visit(child, capturePointer(pointer, key), depth + 1, item);
            numeric_literals.splice(beforeNumbers);
            binary_fields.splice(beforeBinaries);
            redactor.redactions.splice(beforeRedactions);
            redactor.redactions.push({
              pointer,
              reason: "explicit-sensitive-value",
              scope: "property-name",
            });
            return [];
          }
          return [
            [key, visit(child, capturePointer(pointer, key), depth + 1, item)],
          ];
        }),
      );
    throw new CaptureFormatError(
      "format",
      "HAR parser returned a non-JSON value.",
      pointer,
    );
  };
  return {
    reported: visit(value, "", 0),
    numeric_literals,
    binary_fields,
    redactions: redactor.redactions,
  };
};

const decodeHarBase64 = (value: string, pointer: string): Buffer => {
  const compact = value.replace(/[\t\n\r ]/g, "");
  assertCanonicalHarBase64(value, pointer);
  const bytes = Buffer.from(compact, "base64");
  if (bytes.toString("base64") !== compact) throw invalidBase64(pointer);
  return bytes;
};
