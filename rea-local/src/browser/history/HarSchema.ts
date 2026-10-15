import { createRequire } from "node:module";
import { Ajv, type ValidateFunction } from "ajv";
import { z } from "zod";
import { CaptureFormatError } from "./CaptureFormatError.js";

export type HarSchemaNode = Readonly<Record<string, unknown>>;
export type HarSchemaSet = Readonly<Record<string, HarSchemaNode>>;

export interface HarSchemaFailure {
  readonly keyword: string;
  readonly pointer: string;
}

export interface HarValidationContext {
  readonly schemas: HarSchemaSet;
  validateDocument(value: unknown): HarSchemaFailure | undefined;
  validateEntry(
    value: unknown,
    ordinal: number,
    allowMitmproxyAbsentPostDataText: boolean,
  ): HarSchemaFailure | undefined;
}

/** Validate with the unchanged, pinned upstream HAR 1.2 draft-06 schemas. */
export const createHarValidationContext = (): HarValidationContext => {
  const require = createRequire(import.meta.url);
  const schemas = z
    .record(z.string(), z.record(z.string(), z.unknown()))
    .parse(require("har-schema"));
  const ajv = new Ajv({ strict: false, allErrors: false, ownProperties: true });
  ajv.addMetaSchema(require("ajv/dist/refs/json-schema-draft-06.json"));
  const plugin: unknown = require("ajv-formats");
  if (typeof plugin !== "function")
    throw new Error("Pinned AJV formats plugin is unavailable");
  plugin(ajv);
  for (const schema of Object.values(schemas)) ajv.addSchema(schema);
  const documentValidator = ajv.getSchema("har.json#");
  const entryValidator = ajv.getSchema("entry.json#");
  if (documentValidator === undefined || entryValidator === undefined)
    throw new Error("Pinned HAR root or entry schema is unavailable");

  return {
    schemas,
    validateDocument: (value) => {
      allowMitmproxyAbsentPostData(value);
      return failure(documentValidator, value, "");
    },
    validateEntry: (value, ordinal, allowAbsentText) => {
      const postData = allowAbsentText
        ? nullablePostDataText(value)
        : undefined;
      if (postData !== undefined) delete postData.text;
      try {
        return failure(entryValidator, value, `/log/entries/${ordinal}`);
      } finally {
        if (postData !== undefined) postData.text = null;
      }
    },
  };
};

/** Preserve the legacy validator for callers which validate a fully materialized HAR. */
export const createHarValidator = (): ((value: unknown) => void) => {
  const context = createHarValidationContext();
  return (value) => {
    const problem = context.validateDocument(value);
    if (problem !== undefined) throw schemaFailure(problem);
  };
};

const failure = (
  validate: ValidateFunction,
  value: unknown,
  prefix: string,
): HarSchemaFailure | undefined => {
  if (validate(value)) return undefined;
  const error = validate.errors?.[0];
  return {
    keyword: error?.keyword ?? "unknown constraint",
    pointer: `${prefix}${error?.instancePath ?? ""}`,
  };
};

export const schemaFailure = (problem: HarSchemaFailure): CaptureFormatError =>
  new CaptureFormatError(
    "format",
    `HAR schema validation failed: ${problem.keyword}.`,
    problem.pointer,
  );

/** Observed SaveHar 12.2.3 compatibility: validate omitted optional text while retaining reported null. */
const allowMitmproxyAbsentPostData = (value: unknown): void => {
  const parsed = z
    .object({
      log: z.object({
        creator: z.object({
          name: z.literal("mitmproxy"),
          version: z.literal("12.2.3"),
        }),
        entries: z.array(z.unknown()),
      }),
    })
    .safeParse(value);
  if (
    !parsed.success ||
    typeof value !== "object" ||
    value === null ||
    !("log" in value)
  )
    return;
  const log = value.log;
  if (
    typeof log !== "object" ||
    log === null ||
    !("entries" in log) ||
    !Array.isArray(log.entries)
  )
    return;
  for (const entry of log.entries) {
    const postData = nullablePostDataText(entry);
    if (postData !== undefined) delete postData.text;
  }
};

const nullablePostDataText = (
  entry: unknown,
): Record<string, unknown> | undefined => {
  if (typeof entry !== "object" || entry === null || !("request" in entry))
    return undefined;
  const request = entry.request;
  if (
    typeof request !== "object" ||
    request === null ||
    !("postData" in request)
  )
    return undefined;
  const postData = request.postData;
  return typeof postData === "object" &&
    postData !== null &&
    "text" in postData &&
    postData.text === null
    ? (postData as Record<string, unknown>)
    : undefined;
};
