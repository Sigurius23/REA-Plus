import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.number().int().nonnegative();
const hex32 = z.string().regex(/^0x[0-9a-f]{8}$/);
const hex16 = z.string().regex(/^0x[0-9a-f]{4}$/);
/** A native virtual address in the selected IL2CPP binary. */
const address = z.string().regex(/^0x[0-9a-f]{1,16}$/);

/** Paged views over one metadata file; each call returns one view. */
export const IL2CPP_METADATA_VIEWS = [
  "classes",
  "string_literals",
  "interop",
  "assemblies",
] as const;

export const IL2CPP_METADATA_PAGE_LIMIT = 200;

export const inspectIl2CppMetadataInputSchema = z.strictObject({
  metadata_path: z
    .string()
    .min(1)
    .describe("Absolute local global-metadata.dat path"),
  binary_path: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Absolute IL2CPP native binary for the same build (GameAssembly.dll/.so/.dylib, libil2cpp.so or UnityFramework). Recovers method addresses in the classes view and reverse-P/Invoke wrappers in the interop view.",
    ),
  code_registration: address
    .optional()
    .describe(
      "Il2CppCodeRegistration virtual address for stripped binaries, such as 0x1a2b3c0; requires binary_path.",
    ),
  view: z
    .enum(IL2CPP_METADATA_VIEWS)
    .default("classes")
    .describe(
      "classes: types with fields and methods; string_literals: managed ldstr literals; interop: P/Invoke and reverse-P/Invoke methods; assemblies: managed assemblies with versions and references.",
    ),
  query: z
    .string()
    .min(1)
    .max(256)
    .optional()
    .describe(
      "Case-insensitive substring filter: class, field or method names; literal text; interop method, image or DLL; assembly or image name.",
    ),
  offset: count.default(0).describe("Matching entries to skip"),
  limit: z
    .number()
    .int()
    .min(1)
    .max(IL2CPP_METADATA_PAGE_LIMIT)
    .default(25)
    .describe("Matching entries to return"),
});

const fileIdentity = z.strictObject({
  path: z.string().min(1),
  sha256: digest,
  bytes: count,
});

export const il2cppClassSchema = z.strictObject({
  index: count,
  name: z.string().nullable().describe("Namespace-qualified type name."),
  namespace: z.string().nullable(),
  short_name: z.string().nullable(),
  base: z.string().nullable(),
  base_type_index: count.nullable(),
  flags: hex32.describe("ECMA-335 TypeAttributes."),
  token: hex32,
  interfaces: z.array(
    z.strictObject({
      type_index: z.number().int(),
      name: z.string().nullable(),
    }),
  ),
  field_count: count,
  method_count: count,
  member_scope: z
    .enum(["all", "matching"])
    .describe(
      "matching: the class name did not match the query, so only members whose names match are listed.",
    ),
  fields: z.array(
    z.strictObject({
      index: count,
      name: z.string().nullable(),
      type: z.string().nullable(),
      type_index: z.number().int(),
      token: hex32,
    }),
  ),
  methods: z.array(
    z.strictObject({
      index: count,
      name: z.string().nullable(),
      full_name: z
        .string()
        .nullable()
        .describe("Owner-qualified name with the parameter count."),
      parameter_count: count,
      address: address
        .nullable()
        .describe(
          "Native entry in binary_path; null without a binary, when recovery failed, or for methods without code (abstract, generic definitions).",
        ),
      token: hex32,
      flags: hex16.describe("ECMA-335 MethodAttributes."),
      iflags: hex16,
      attributes: z.string().nullable(),
    }),
  ),
});

export const il2cppStringLiteralSchema = z.strictObject({
  index: count,
  file_offset: count.describe("Offset of the literal bytes in metadata_path."),
  bytes: count,
  text: z.string().describe("UTF-8 decoding; invalid sequences become U+FFFD."),
  utf8_valid: z.boolean(),
  hex: z
    .string()
    .regex(/^(?:[0-9a-f]{2})*$/)
    .nullable()
    .describe("Exact bytes when they are not valid UTF-8."),
});

export const il2cppInteropSchema = z.strictObject({
  kind: z.enum(["pinvoke", "reverse_pinvoke"]),
  image: z.string(),
  method: z.string(),
  token: hex32,
  flags: hex16,
  iflags: hex16,
  attribute: z.enum(["MonoPInvokeCallback", "UnmanagedCallersOnly"]).nullable(),
  dll: z.string().nullable(),
  entry: z.string().nullable(),
  wrapper_address: address.nullable(),
  wrapper_index: count.nullable(),
  confidence: z.number().int().min(0).max(100),
});

export const il2cppAssemblySchema = z.strictObject({
  name: z.string(),
  version: z.string(),
  culture: z.string(),
  public_key_token: z
    .string()
    .regex(/^[0-9a-f]{16}$/)
    .nullable(),
  image: z.string(),
  image_index: z.number().int(),
  token: hex32,
  flags: hex32,
  hash_algorithm: hex32,
  references: z.array(
    z.strictObject({ name: z.string(), version: z.string() }),
  ),
});

export const il2cppMetadataSchema = z.strictObject({
  metadata: fileIdentity.extend({
    wire_version: z.number().int().positive(),
    unity_range: z
      .string()
      .nullable()
      .describe("Unity editor releases that emit this wire version."),
  }),
  native_binary: fileIdentity.nullable(),
  counts: z.strictObject({ types: count, methods: count, fields: count }),
  native: z
    .strictObject({
      method_addresses_recovered: z.boolean(),
      source: z
        .enum(["symbol", "override", "heuristic", "none"])
        .describe(
          "How Il2CppCodeRegistration was located: exported symbol, caller override, or section scan.",
        ),
      code_registration: address.nullable(),
      metadata_registration: address.nullable(),
      method_pointers: address.nullable(),
      code_gen_modules: address.nullable(),
      tables: z.array(z.strictObject({ name: z.string(), address, count })),
    })
    .nullable()
    .describe(
      "Native registration recovery; classes view with binary_path only.",
    ),
  page: z.strictObject({
    view: z.enum(IL2CPP_METADATA_VIEWS),
    query: z.string().nullable(),
    offset: count,
    limit: count,
    total: count.describe("Entries matching the query."),
    returned: count,
  }),
  classes: z.array(il2cppClassSchema),
  string_literals: z.array(il2cppStringLiteralSchema),
  interop: z.array(il2cppInteropSchema),
  assemblies: z.array(il2cppAssemblySchema),
  tool_profile: z.strictObject({
    tool: z.literal("r2unity"),
    version: z.string(),
    verified_version: z.string(),
    executable_path: z.string().min(1),
    executable_sha256: digest,
    arguments: z.array(z.array(z.string())),
    timeout_ms: z.number().int().positive(),
    output_budget_bytes: z.number().int().positive(),
    cached: z
      .boolean()
      .describe(
        "Reused this server's earlier r2unity output for the same digests.",
      ),
  }),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
});

export type InspectIl2CppMetadataInput = z.output<
  typeof inspectIl2CppMetadataInputSchema
>;
export type Il2CppMetadataView = (typeof IL2CPP_METADATA_VIEWS)[number];
export type Il2CppClass = z.output<typeof il2cppClassSchema>;
export type Il2CppStringLiteral = z.output<typeof il2cppStringLiteralSchema>;
export type Il2CppInterop = z.output<typeof il2cppInteropSchema>;
export type Il2CppAssembly = z.output<typeof il2cppAssemblySchema>;
export type Il2CppMetadata = z.output<typeof il2cppMetadataSchema>;
