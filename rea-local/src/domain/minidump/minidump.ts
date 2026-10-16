import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const hex = z.string().regex(/^0x[0-9a-f]{1,16}$/);
const timestamp = z
  .string()
  .nullable()
  .describe("UTC ISO-8601 time from a 32-bit time_t; null when zero.");

export const MINIDUMP_STACK_SCAN_LIMIT = 256;

export const inspectMinidumpInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe("Absolute minidump path (Windows .dmp, Breakpad or Crashpad)"),
  thread_id: z
    .number()
    .int()
    .nonnegative()
    .optional()
    .describe(
      "Thread whose registers and stack to report; defaults to the exception thread.",
    ),
  stack_scan_limit: z
    .number()
    .int()
    .min(0)
    .max(MINIDUMP_STACK_SCAN_LIMIT)
    .default(32)
    .describe("Most stack slots pointing into modules to report."),
});

/** An address resolved to the module image containing it. */
const moduleOffset = z
  .strictObject({ module: z.string(), offset: hex })
  .nullable();

export const minidumpModuleSchema = z.strictObject({
  name: z.string().describe("Path the process loaded the module from."),
  base: hex,
  size: count,
  end: hex,
  timestamp,
  checksum: z.string().regex(/^0x[0-9a-f]{8}$/),
  file_version: z.string().nullable(),
  product_version: z.string().nullable(),
  code_id: z
    .string()
    .nullable()
    .describe(
      "PE image identity (TimeDateStamp then SizeOfImage) for symbol servers; Windows dumps only.",
    ),
  debug: z
    .strictObject({
      format: z.enum(["RSDS", "NB10", "ELF build ID", "unknown"]),
      file: z.string().nullable().describe("PDB or debug file name."),
      guid: z.string().nullable(),
      age: count.nullable(),
      debug_id: z
        .string()
        .nullable()
        .describe("Symbol-server debug identifier (GUID and age)."),
      build_id: z.string().nullable(),
    })
    .nullable(),
});

export const minidumpThreadSchema = z.strictObject({
  id: count,
  name: z.string().nullable(),
  crashed: z.boolean(),
  suspend_count: count,
  priority: z.number().int(),
  teb: hex.describe("Thread environment block (or TLS pointer on Breakpad)."),
  stack: z.strictObject({ start: hex, size: count }),
  instruction_pointer: hex.nullable(),
  stack_pointer: hex.nullable(),
  instruction_module: moduleOffset,
});

export const minidumpSchema = z.strictObject({
  dump: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: count,
    created: timestamp,
    flags: hex.describe("MINIDUMP_TYPE flags."),
    streams: z.array(
      z.strictObject({
        type: z.string().describe("Stream name, or its hex type."),
        bytes: count,
        status: z.enum(["decoded", "not-decoded", "malformed"]),
        message: z.string().nullable(),
      }),
    ),
  }),
  system: z
    .strictObject({
      architecture: z.string(),
      os: z.string(),
      os_version: z.string(),
      service_pack: z.string().nullable(),
      processors: count,
      cpu_vendor: z.string().nullable(),
    })
    .nullable(),
  process: z.strictObject({
    process_id: count.nullable(),
    created: timestamp,
  }),
  exception: z
    .strictObject({
      thread_id: count,
      code: z.string().regex(/^0x[0-9a-f]{8}$/),
      name: z.string().nullable(),
      flags: z.string().regex(/^0x[0-9a-f]{8}$/),
      address: hex.describe(
        "ExceptionAddress: the faulting instruction on Windows, the faulting data address for Breakpad signals.",
      ),
      parameters: z.array(hex),
      access: z
        .strictObject({
          kind: z.enum(["read", "write", "execute"]),
          address: hex,
        })
        .nullable()
        .describe("Windows access-violation or in-page-error details."),
      instruction_pointer: hex.nullable(),
      instruction_module: moduleOffset,
      registers: z
        .record(z.string(), hex)
        .nullable()
        .describe("General-purpose registers at the exception."),
    })
    .nullable(),
  selected_thread: z
    .strictObject({
      id: count,
      registers: z.record(z.string(), hex).nullable(),
      stack_scan: z
        .array(
          z.strictObject({
            slot: hex.describe("Stack address holding the value."),
            value: hex,
            module: z.string(),
            offset: hex,
          }),
        )
        .describe(
          "Stack slots holding addresses inside module images, nearest the stack pointer first: return-address candidates, not an unwound call stack.",
        ),
    })
    .nullable(),
  threads: z.array(minidumpThreadSchema),
  modules: z.array(minidumpModuleSchema),
  unloaded_modules: z.array(
    z.strictObject({
      name: z.string(),
      base: hex,
      size: count,
      timestamp,
    }),
  ),
  memory: z.strictObject({
    ranges: count,
    bytes: count,
    full_memory: z
      .boolean()
      .describe("Memory64List present, as in full-memory dumps."),
  }),
  limitations: z.array(z.string()),
});

export type InspectMinidumpInput = z.output<typeof inspectMinidumpInputSchema>;
export type Minidump = z.output<typeof minidumpSchema>;
export type MinidumpModule = z.output<typeof minidumpModuleSchema>;
export type MinidumpThread = z.output<typeof minidumpThreadSchema>;
