import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const address = z.string().regex(/^0x[0-9a-f]+$/);
const pairOf = <Schema extends z.ZodType>(schema: Schema) =>
  z.tuple([schema, schema]);

export const DIFF_VIEWS = [
  "summary",
  "functions",
  "unmatched",
  "function",
] as const;
export const DIFF_STATUSES = [
  "identical",
  "changed",
  "removed",
  "added",
] as const;
export const DIFF_METHODS = [
  "name",
  "identical",
  "mnemonics",
  "fingerprint",
  "call-graph",
  "call-order",
  "similarity",
] as const;
export const DIFF_PAGE_LIMIT = 1000;
export const DIFF_MAX_FUNCTIONS = 20_000;
/** Listing rows the function view returns at most. */
export const DIFF_LISTING_LIMIT = 4000;

export const diffBinariesInputSchema = z.strictObject({
  left: z.string().min(1).describe("Absolute path of the older build"),
  right: z.string().min(1).describe("Absolute path of the newer build"),
  view: z
    .enum(DIFF_VIEWS)
    .default("summary")
    .describe(
      "summary: counts and the least similar changed functions; functions: matched pairs; unmatched: functions only in one build; function: one function's instruction diff",
    ),
  status: z
    .enum(DIFF_STATUSES)
    .optional()
    .describe(
      "Keep identical or changed pairs (functions view), or removed or added functions (unmatched view)",
    ),
  function: z
    .string()
    .min(1)
    .max(512)
    .optional()
    .describe(
      "For the function view: an address or name in either build, such as 0x401a30 or fcn.00401a30",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe("Case-insensitive substring of function names or addresses"),
  names: z
    .boolean()
    .default(true)
    .describe(
      "Match functions with the same non-generated name first; turn off when names cannot be trusted",
    ),
  threshold: z
    .number()
    .min(0.3)
    .max(1)
    .default(0.5)
    .describe("Lowest content similarity for a call-graph or similarity match"),
  max_functions: z
    .number()
    .int()
    .min(1)
    .max(DIFF_MAX_FUNCTIONS)
    .default(3000)
    .describe("Functions analyzed per build, in the provider's listing order"),
  offset: count.default(0).describe("Rows to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(DIFF_PAGE_LIMIT)
    .default(100)
    .describe("Rows to return"),
});
export type DiffBinariesInput = z.output<typeof diffBinariesInputSchema>;

const buildSchema = z.strictObject({
  path: z.string(),
  sha256: digest,
  format: z.string(),
  analysis_provider: z.string(),
  analysis_profile: digest.nullable(),
  functions_listed: count,
  functions_analyzed: count,
  functions_failed: count,
  truncated: z.boolean(),
});

const functionRef = z.strictObject({ address, name: z.string() });
const limited = z.array(z.string());

export const diffPairRowSchema = z.strictObject({
  left: functionRef,
  right: functionRef,
  status: z.enum(["identical", "changed"]),
  method: z.enum(DIFF_METHODS),
  similarity: z.number().min(0).max(1),
  call_graph_agreement: z.number().min(0).max(1).nullable(),
  instructions: pairOf(count),
  blocks: pairOf(count),
  edges: pairOf(count),
  lines_added: count,
  lines_removed: count,
  calls_added: limited,
  calls_removed: limited,
  strings_added: limited,
  strings_removed: limited,
  constants_added: limited,
  constants_removed: limited,
});

export const diffUnmatchedRowSchema = z.strictObject({
  status: z.enum(["removed", "added"]),
  address,
  name: z.string(),
  instructions: count,
  blocks: count,
  calls: limited,
  strings: limited,
});

export const diffListingRowSchema = z.strictObject({
  change: z.enum(["same", "removed", "added"]),
  left: z.string().nullable(),
  right: z.string().nullable(),
});

export const binaryDiffSchema = z.strictObject({
  left: buildSchema,
  right: buildSchema,
  summary: z.strictObject({
    matched: count,
    identical: count,
    changed: count,
    removed: count,
    added: count,
    by_method: z.record(z.enum(DIFF_METHODS), count),
    similarity_complete: z.boolean(),
  }),
  page: z.strictObject({
    view: z.enum(DIFF_VIEWS),
    status: z.enum(DIFF_STATUSES).nullable(),
    function: z.string().nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  functions: z.array(diffPairRowSchema),
  unmatched: z.array(diffUnmatchedRowSchema),
  listing: z.array(diffListingRowSchema),
  listing_truncated: z.boolean(),
});
export type BinaryDiffReport = z.output<typeof binaryDiffSchema>;
export type DiffPairRow = z.output<typeof diffPairRowSchema>;
export type DiffUnmatchedRow = z.output<typeof diffUnmatchedRowSchema>;
export type DiffListingRow = z.output<typeof diffListingRowSchema>;
