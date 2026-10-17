import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const address = z.string().regex(/^0x[0-9a-f]+$/);

export const LIBRARY_VIEWS = ["summary", "functions"] as const;
export const IDENTIFICATION_STATUSES = [
  "unique",
  "resolved",
  "ambiguous",
] as const;
export const LIBRARY_PAGE_LIMIT = 1000;
export const MAX_LIBRARIES = 64;

export const identifyLibraryFunctionsInputSchema = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe(
      "Absolute ELF or PE executable or shared library to identify functions in",
    ),
  libraries: z
    .array(z.string().min(1))
    .min(1)
    .max(MAX_LIBRARIES)
    .describe(
      "Absolute static libraries (.a, .lib) or relocatable objects (.o, .obj) the binary may have linked, such as libc.a or zlib's libz.a",
    ),
  min_bytes: z
    .number()
    .int()
    .min(8)
    .max(4096)
    .default(16)
    .describe(
      "Fewest fixed (non-relocated) bytes a function needs to get a signature",
    ),
  include_local: z
    .boolean()
    .default(true)
    .describe("Also sign the libraries' static (file-local) functions"),
  view: z
    .enum(LIBRARY_VIEWS)
    .default("summary")
    .describe(
      "summary: counts per library; functions: the identified functions",
    ),
  status: z
    .enum(IDENTIFICATION_STATUSES)
    .optional()
    .describe(
      "Keep functions identified by a unique signature, resolved among same-byte candidates, or still ambiguous",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe("Case-insensitive substring of names, members or addresses"),
  offset: count.default(0).describe("Rows to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(LIBRARY_PAGE_LIMIT)
    .default(200)
    .describe("Rows to return"),
});
export type IdentifyLibraryFunctionsInput = z.output<
  typeof identifyLibraryFunctionsInputSchema
>;

export const identifiedFunctionSchema = z.strictObject({
  address,
  end: address,
  names: z.array(z.string()).min(1),
  status: z.enum(IDENTIFICATION_STATUSES),
  library: z.string(),
  member: z.string(),
  local: z.boolean(),
  fixed_bytes: count,
  references: z.strictObject({
    confirmed: count,
    contradicted: count,
    unchecked: count,
  }),
});

export const libraryIdentificationSchema = z.strictObject({
  file: z.strictObject({
    path: z.string(),
    sha256: digest,
    size: count,
    format: z.enum(["elf", "pe"]),
    machine: z.string(),
  }),
  libraries: z.array(
    z.strictObject({
      path: z.string(),
      kind: z.enum(["archive", "object"]),
      format: z.enum(["elf", "coff", "unknown"]),
      machine: z.string(),
      members: count,
      unreadable_members: count,
      functions: count,
      short_functions: count,
      signatures: count,
      identified: count,
    }),
  ),
  summary: z.strictObject({
    identified: count,
    unique: count,
    resolved: count,
    ambiguous: count,
    code_bytes: count,
    identified_bytes: count,
  }),
  page: z.strictObject({
    view: z.enum(LIBRARY_VIEWS),
    status: z.enum(IDENTIFICATION_STATUSES).nullable(),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count,
    returned: count,
  }),
  functions: z.array(identifiedFunctionSchema),
});
export type LibraryIdentificationReport = z.output<
  typeof libraryIdentificationSchema
>;
