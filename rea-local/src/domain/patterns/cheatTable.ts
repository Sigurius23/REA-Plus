import { z } from "zod";

import { imageFileSchema, patternResultSchema } from "./bytePatterns.js";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const hex = z.string().regex(/^0x[0-9a-f]{1,16}$/);

export const inspectCheatTableInputSchema = z.strictObject({
  path: z.string().min(1).describe("Absolute Cheat Engine table (.CT) path"),
  binary_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Absolute module the table targets (for example a new GameAssembly.dll build) to re-scan its AOB signatures and check its assert bytes.",
    ),
});

export const cheatTableSchema = z.strictObject({
  table: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    table_version: count.nullable(),
    entries_total: count,
    entries_truncated: z.boolean(),
  }),
  entries: z.array(
    z.strictObject({
      id: z.string().nullable(),
      path: z
        .array(z.string())
        .describe("Group descriptions down to this entry."),
      description: z.string(),
      type: z
        .string()
        .nullable()
        .describe("CE VariableType, such as 4 Bytes or Auto Assembler Script."),
      address: z.string().nullable().describe("Address expression as stored."),
      module: z.string().nullable(),
      module_offset: hex.nullable(),
      offsets: z
        .array(z.string())
        .describe(
          "Pointer offsets as stored; Cheat Engine applies them from last to first.",
        ),
      group: z.boolean(),
      hotkeys: count,
      children: count,
      script_lines: count.nullable(),
    }),
  ),
  scripts: z.array(
    z.strictObject({
      entry_id: z.string().nullable(),
      description: z.string(),
      aob_scans: z.array(
        z.strictObject({
          kind: z.string(),
          symbol: z.string(),
          module: z.string().nullable(),
          pattern: z.string(),
        }),
      ),
      asserts: z.array(
        z.strictObject({
          address: z.string(),
          module: z.string().nullable(),
          offset: hex.nullable(),
          bytes: z.string(),
        }),
      ),
      registered_symbols: z.array(z.string()),
      allocations: count,
    }),
  ),
  symbols: z.array(z.strictObject({ name: z.string(), address: z.string() })),
  structures: z.array(
    z.strictObject({
      name: z.string(),
      elements: z.array(
        z.strictObject({
          offset: count,
          type: z.string().nullable(),
          size: count.nullable(),
          description: z.string(),
        }),
      ),
    }),
  ),
  lua: z.strictObject({ bytes: count, lines: count }).nullable(),
  binary_check: z
    .strictObject({
      file: imageFileSchema,
      aob_scans: z.array(
        patternResultSchema.extend({
          entry_id: z.string().nullable(),
          symbol: z.string(),
          applies: z
            .boolean()
            .describe(
              "False when the scan names a different module than binary_path.",
            ),
          error: z.string().nullable(),
        }),
      ),
      asserts: z.array(
        z.strictObject({
          entry_id: z.string().nullable(),
          address: z.string(),
          expected: z.string(),
          actual: z.string().nullable(),
          matches: z.boolean().nullable(),
          reason: z.string().nullable(),
        }),
      ),
    })
    .nullable(),
  limitations: z.array(z.string()),
});

export type InspectCheatTableInput = z.output<
  typeof inspectCheatTableInputSchema
>;
export type CheatTableReport = z.output<typeof cheatTableSchema>;
