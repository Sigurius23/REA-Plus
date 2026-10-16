import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const hex = z.string().regex(/^0x[0-9a-f]{1,16}$/);

export const BYTE_PATTERN_MATCH_LIMIT = 1000;

export const bytePatternSchema = z.strictObject({
  name: z.string().min(1).max(120).optional(),
  pattern: z
    .string()
    .min(1)
    .max(1024)
    .describe(
      "Bytes as hex pairs with ?? (or ?) wildcards and nibble wildcards like 4?, such as '48 8B 05 ?? ?? ?? ?? 48 85 C0'.",
    ),
});

export const scanBytePatternsInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe("Absolute local PE, ELF, Mach-O or raw binary path"),
  patterns: z.array(bytePatternSchema).min(1).max(64),
  scope: z
    .enum(["executable", "all"])
    .default("executable")
    .describe(
      "executable scans code sections when the format declares them; all scans every file-backed section, or the whole file when unmapped.",
    ),
  max_matches: z
    .number()
    .int()
    .min(1)
    .max(BYTE_PATTERN_MATCH_LIMIT)
    .default(16)
    .describe("Matches to return per pattern; all matches are counted."),
});

export const imageFileSchema = z.strictObject({
  path: z.string().min(1),
  sha256: digest,
  bytes: count,
  format: z.enum(["pe", "elf", "macho", "raw"]),
  architecture: z.string().nullable(),
  image_base: hex.nullable(),
  layout_error: z
    .string()
    .nullable()
    .describe(
      "Why recognised headers could not be mapped; the file was scanned raw.",
    ),
  sections: z.array(
    z.strictObject({
      name: z.string(),
      file_offset: count,
      size: count,
      address: hex,
      executable: z.boolean(),
    }),
  ),
});

export const patternResultSchema = z.strictObject({
  name: z.string().nullable(),
  pattern: z.string().describe("Canonical form of the parsed pattern."),
  length: count,
  total_matches: count,
  complete: z
    .boolean()
    .describe("False when counting stopped at 100000 matches."),
  matches: z.array(
    z.strictObject({
      file_offset: count,
      address: hex.nullable(),
      rva: hex
        .nullable()
        .describe("Address minus the image base (PE RVA or Mach-O offset)."),
      section: z.string().nullable(),
      bytes: z.string().regex(/^(?:[0-9a-f]{2})*$/),
      displacements: z
        .array(
          z.strictObject({
            pattern_offset: count,
            value: z.number().int(),
            target: hex.nullable(),
            target_section: z.string().nullable(),
          }),
        )
        .describe(
          "Each run of exactly four ?? bytes read as a little-endian rel32, resolved from the end of the run (call/jmp rel32 and RIP-relative operands without a trailing immediate).",
        ),
    }),
  ),
});

export const bytePatternScanSchema = z.strictObject({
  file: imageFileSchema,
  scanned: z.strictObject({
    scope: z.enum(["executable", "all", "file"]),
    regions: z.array(z.string()),
    bytes: count,
  }),
  results: z.array(patternResultSchema),
  limitations: z.array(z.string()),
});

export type ScanBytePatternsInput = z.output<
  typeof scanBytePatternsInputSchema
>;
export type BytePatternScan = z.output<typeof bytePatternScanSchema>;
export type PatternResult = z.output<typeof patternResultSchema>;
