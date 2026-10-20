import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const hex = z.string().regex(/^0x[0-9A-F]+$/u);

export const X64DBG_VIEWS = [
  "labels",
  "comments",
  "bookmarks",
  "functions",
  "arguments",
  "loops",
  "breakpoints",
  "xrefs",
  "watch",
] as const;

export const X64DBG_PAGE_LIMIT = 1000;

export const inspectX64dbgDatabaseInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute x64dbg database (.dd32 or .dd64, plain JSON or x64dbg's LZ4-compressed form)",
    ),
  view: z
    .enum(X64DBG_VIEWS)
    .default("labels")
    .describe(
      "labels, comments, bookmarks: annotated addresses; functions, arguments, loops: annotated ranges; breakpoints: software, hardware, memory, DLL and exception breakpoints with conditions and log/command text; xrefs: recorded cross-references; watch: watch expressions.",
    ),
  module: z
    .string()
    .min(1)
    .max(260)
    .optional()
    .describe("Keep entries of this module (case-insensitive file name)"),
  module_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Absolute path of the module binary (PE, ELF or Mach-O) whose file name the entries name: adds file offsets and sections, and checks breakpoint original bytes against it",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring of text, names, conditions, expressions or modules",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(X64DBG_PAGE_LIMIT)
    .default(100)
    .describe("Matching entries to return"),
});

const placed = {
  module: z
    .string()
    .nullable()
    .describe("Module file name; addresses are relative to its base."),
  file_offset: count
    .nullable()
    .describe(
      "File offset in module_path, when it was given and maps the address.",
    ),
  section: z.string().nullable(),
};

export const x64dbgEntrySchema = z.strictObject({
  ...placed,
  address: hex,
  manual: z.boolean().describe("Set by the user rather than by analysis."),
  text: z.string().nullable(),
});

export const x64dbgRangeSchema = z.strictObject({
  ...placed,
  start: hex,
  end: hex,
  manual: z.boolean(),
  instructions: count.nullable(),
  parent: hex.nullable(),
  depth: count.nullable().describe("Loop nesting depth."),
});

export const x64dbgBreakpointSchema = z.strictObject({
  ...placed,
  address: hex,
  type: z.enum([
    "software",
    "hardware",
    "memory",
    "dll",
    "exception",
    "unknown",
  ]),
  enabled: z.boolean(),
  name: z.string().nullable(),
  break_condition: z.string().nullable(),
  log_text: z.string().nullable(),
  log_condition: z.string().nullable(),
  command_text: z.string().nullable(),
  command_condition: z.string().nullable(),
  fast_resume: z.boolean(),
  silent: z.boolean(),
  old_bytes: z
    .string()
    .nullable()
    .describe("Original bytes under a software breakpoint, as hex."),
  bytes_match: z
    .boolean()
    .nullable()
    .describe(
      "Whether module_path still has the original byte at that offset; null when not checked.",
    ),
});

export const x64dbgXrefSchema = z.strictObject({
  ...placed,
  address: hex,
  references: z.array(z.strictObject({ address: hex, type: count })),
});

export const x64dbgWatchSchema = z.strictObject({
  name: z.string().nullable(),
  expression: z.string(),
  data_type: z.string().nullable(),
  watchdog: z.string().nullable(),
});

export const x64dbgDatabaseSchema = z.strictObject({
  database: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    compressed: z.boolean().describe("Stored in x64dbg's LZ4 legacy frame."),
    json_bytes: count,
    hash_algorithm: z.string().nullable(),
    debuggee_hash: z.string().nullable(),
    sections: z.array(z.string()).describe("Top-level keys present."),
    modules: z.array(z.string()).describe("Modules entries refer to."),
    notes: z.string().nullable(),
    init_script: z.string().nullable(),
    plugins: z.array(z.string()).describe("Plugins that stored data."),
  }),
  module_file: z
    .strictObject({
      path: z.string(),
      name: z.string(),
      sha256: digest,
      format: z.enum(["pe", "elf", "macho", "raw"]),
      image_base: hex.nullable(),
    })
    .nullable(),
  summary: z.strictObject({
    labels: count,
    comments: count,
    bookmarks: count,
    functions: count,
    arguments: count,
    loops: count,
    breakpoints: count,
    xrefs: count,
    watch: count,
    mismatched_breakpoints: count.nullable(),
  }),
  page: z.strictObject({
    view: z.enum(X64DBG_VIEWS),
    module: z.string().nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  labels: z.array(x64dbgEntrySchema),
  comments: z.array(x64dbgEntrySchema),
  bookmarks: z.array(x64dbgEntrySchema),
  functions: z.array(x64dbgRangeSchema),
  arguments: z.array(x64dbgRangeSchema),
  loops: z.array(x64dbgRangeSchema),
  breakpoints: z.array(x64dbgBreakpointSchema),
  xrefs: z.array(x64dbgXrefSchema),
  watch: z.array(x64dbgWatchSchema),
  limitations: z.array(z.string()),
});

export type InspectX64dbgDatabaseInput = z.output<
  typeof inspectX64dbgDatabaseInputSchema
>;
export type X64dbgDatabaseReport = z.output<typeof x64dbgDatabaseSchema>;
