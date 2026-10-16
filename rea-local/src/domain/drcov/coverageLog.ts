import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const hex = z.string().regex(/^0x[0-9a-f]{1,16}$/);

export const COVERAGE_BLOCK_PAGE_LIMIT = 5000;

export const inspectCoverageLogInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute drcov coverage log (DynamoRIO drcov, or a Frida/Lighthouse-compatible tracer).",
    ),
  baseline_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Absolute drcov log of a run without the behavior of interest; blocks whose bytes it already covered are excluded.",
    ),
  module: z
    .string()
    .min(1)
    .max(4096)
    .optional()
    .describe(
      "Module whose basic blocks to list: its exact path or file name, such as GameAssembly.dll. Omit to summarize modules only.",
    ),
  offset: count.default(0).describe("Blocks to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(COVERAGE_BLOCK_PAGE_LIMIT)
    .default(500)
    .describe("Blocks to return"),
});

const logIdentity = z.strictObject({
  path: z.string().min(1),
  sha256: digest,
  bytes: count,
  drcov_version: z.number().int().positive(),
  flavor: z.string(),
  module_table_version: z.number().int().positive(),
  block_table: z.enum(["binary", "text"]),
  block_entries: count,
});

export const coverageModuleSchema = z.strictObject({
  path: z.string(),
  segments: count,
  runtime_base: hex.describe("Lowest segment start in the traced process."),
  runtime_end: hex,
  unique_blocks: count,
  covered_bytes: count,
  new_blocks: count
    .nullable()
    .describe(
      "Blocks with bytes the baseline did not cover; null without a baseline.",
    ),
  baseline_covered_bytes: count.nullable(),
});

export const coverageBlockSchema = z.strictObject({
  image_offset: hex.describe(
    "Offset from the module's first mapped segment; stable across ASLR and runs.",
  ),
  static_address: hex
    .nullable()
    .describe(
      "Link-time address (segment preferred base plus offset), comparable with static disassembly; null when the log has no preferred_base column.",
    ),
  runtime_address: hex,
  size: count,
  segment_id: count,
});

export const coverageLogSchema = z.strictObject({
  log: logIdentity,
  baseline: logIdentity.nullable(),
  modules: z
    .array(coverageModuleSchema)
    .describe("Modules with at least one covered block, by unique blocks."),
  selected_module: z
    .strictObject({
      path: z.string(),
      segments: z.array(
        z.strictObject({
          id: count,
          runtime_start: hex,
          runtime_end: hex,
          file_offset: hex.nullable(),
          preferred_base: hex.nullable(),
        }),
      ),
    })
    .nullable(),
  page: z.strictObject({
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  blocks: z.array(coverageBlockSchema),
  limitations: z.array(z.string()),
});

export type InspectCoverageLogInput = z.output<
  typeof inspectCoverageLogInputSchema
>;
export type CoverageModule = z.output<typeof coverageModuleSchema>;
export type CoverageBlock = z.output<typeof coverageBlockSchema>;
export type CoverageLog = z.output<typeof coverageLogSchema>;
