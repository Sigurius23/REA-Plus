import { z } from "zod";
import { localPathStringSchema } from "../localPath.js";

const target = {
  path: localPathStringSchema.describe(
    "Local APK path; the target is never executed",
  ),
};
const classTarget = {
  ...target,
  class_name: z.string().min(1).describe("Exact fully qualified class name"),
};

/** Caller intent for static Android inspection, independent of its engine. */
export const androidInputSchemas = {
  inspect_android_package: z.strictObject(target),
  search_android_classes: z.strictObject({
    ...target,
    query: z
      .string()
      .describe("Case-sensitive class-name substring; empty lists all classes"),
  }),
  inspect_android_class: z.strictObject(classTarget),
  inspect_android_method: z.strictObject({
    ...classTarget,
    method_name: z.string().min(1),
    overload_index: z
      .number()
      .int()
      .nonnegative()
      .optional()
      .describe(
        "Explicit index among same-name methods; required when ambiguous",
      ),
  }),
  trace_android_references: z.strictObject({
    ...classTarget,
    method_name: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Omit for class references; ambiguous overloaded methods are unsupported",
      ),
  }),
} as const;

/** Supported static Android operations. */
export type AndroidOperation = keyof typeof androidInputSchemas;
/** Validated Android requests carry their selected operation. */
export type AndroidRequest = {
  [Name in AndroidOperation]: {
    operation: Name;
    input: z.infer<(typeof androidInputSchemas)[Name]>;
  };
}[AndroidOperation];

/** Validate operation and input together so their types remain correlated. */
export const androidRequestSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("inspect_android_package"),
    input: androidInputSchemas.inspect_android_package,
  }),
  z.strictObject({
    operation: z.literal("search_android_classes"),
    input: androidInputSchemas.search_android_classes,
  }),
  z.strictObject({
    operation: z.literal("inspect_android_class"),
    input: androidInputSchemas.inspect_android_class,
  }),
  z.strictObject({
    operation: z.literal("inspect_android_method"),
    input: androidInputSchemas.inspect_android_method,
  }),
  z.strictObject({
    operation: z.literal("trace_android_references"),
    input: androidInputSchemas.trace_android_references,
  }),
]);

const textCoverage = z.strictObject({
  status: z.enum(["complete", "partial"]),
  text: z.string(),
  reported_total_bytes: z.number().int().nonnegative().nullable(),
});
const valueCoverage = z
  .enum(["complete", "partial"])
  .describe(
    "partial when a projection limit cut annotations, values, or field inits",
  );
const method = z.strictObject({
  name: z.string(),
  reported_signature: z.string(),
  overload_index: z.number().int().nonnegative(),
  is_constructor: z.boolean(),
  dex_descriptor: z.null(),
});
const engine = z.strictObject({
  name: z.string().min(1),
  version: z.string().nullable(),
  artifact_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
  source_revision: z.string().nullable(),
  worker_count: z.number().int().positive(),
  heap_limit_mib: z.number().int().positive().nullable(),
});
const common = { engine };

/** Encoded dex annotation values, projected without resolving any class. */
export type AndroidEncodedValue =
  | { readonly kind: "null"; readonly value: null }
  | {
      readonly kind: "boolean" | "byte" | "short" | "int";
      readonly value: number;
    }
  | { readonly kind: "long"; readonly value: number | string }
  | { readonly kind: "float" | "double"; readonly value: number | string }
  | {
      readonly kind: "string" | "char" | "type" | "other";
      readonly value: string;
    }
  | {
      readonly kind: "field";
      readonly value: {
        readonly class: string;
        readonly name: string;
        readonly type: string;
      };
    }
  | {
      readonly kind: "method";
      readonly value: {
        readonly class: string;
        readonly name: string;
        readonly params: string[];
        readonly return: string;
      };
    }
  | { readonly kind: "array"; readonly value: AndroidEncodedValue[] }
  | { readonly kind: "annotation"; readonly value: AndroidAnnotation };

/** One declared dex annotation with its encoded named values. */
export type AndroidAnnotation = {
  readonly class: string;
  readonly visibility: "build" | "runtime" | "system";
  values: Record<string, AndroidEncodedValue>;
};

const encodedValueSchema: z.ZodType<AndroidEncodedValue> = z.lazy(() =>
  z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("null"), value: z.null() }),
    z.strictObject({
      kind: z.enum(["boolean", "byte", "short", "int"]),
      value: z.number().int().safe(),
    }),
    z.strictObject({
      kind: z.literal("long"),
      value: z.union([z.number(), z.string()]),
    }),
    z.strictObject({
      kind: z.enum(["float", "double"]),
      value: z.union([z.number(), z.string()]),
    }),
    z.strictObject({
      kind: z.enum(["string", "char", "type", "other"]),
      value: z.string(),
    }),
    z.strictObject({
      kind: z.literal("field"),
      value: z.strictObject({
        class: z.string().min(1),
        name: z.string().min(1),
        type: z.string().min(1),
      }),
    }),
    z.strictObject({
      kind: z.literal("method"),
      value: z.strictObject({
        class: z.string().min(1),
        name: z.string().min(1),
        params: z.array(z.string()),
        return: z.string().min(1),
      }),
    }),
    z.strictObject({
      kind: z.literal("array"),
      value: z.array(encodedValueSchema),
    }),
    z.strictObject({ kind: z.literal("annotation"), value: annotationSchema }),
  ]),
);

const annotationSchema: z.ZodType<AndroidAnnotation> = z.lazy(() =>
  z.strictObject({
    class: z.string().min(1),
    visibility: z.enum(["build", "runtime", "system"]),
    values: z.record(z.string(), encodedValueSchema),
  }),
);

/** Parsed annotation schemas and encoded initial values are named for adapters. */
export const androidAnnotationSchema = annotationSchema;
export const androidStaticInitSchema = z.strictObject({
  name: z.string().min(1),
  reported_type: z.string(),
  constant: encodedValueSchema,
});

/** Portable observations with explicit decompiler and identity limitations. */
export const androidResultSchemas = {
  inspect_android_package: z.strictObject({
    ...common,
    package_name: z.string().nullable(),
    version_name: z.string().nullable(),
    version_code: z.string().nullable(),
    min_sdk: z.string().nullable(),
    target_sdk: z.string().nullable(),
    permissions: z.array(z.string()),
    manifest: textCoverage,
    class_count: z.number().int().nonnegative(),
    resource_count: z.number().int().nonnegative(),
    signature_verification: z.literal("not_performed"),
  }),
  search_android_classes: z.strictObject({
    ...common,
    query: z.string(),
    total_classes: z.number().int().nonnegative(),
    matches: z.array(z.string()),
    shared_names: z
      .array(z.string())
      .describe(
        "Matches that JADX gives to more than one class, such as obfuscated classes renamed from Kotlin metadata. inspect_android_class reports their raw identities as ambiguous.",
      ),
    coverage: z.literal("complete"),
  }),
  inspect_android_class: z.strictObject({
    ...common,
    class_name: z.string(),
    methods: z.array(method),
    fields: z.array(
      z.strictObject({ name: z.string(), reported_type: z.string() }),
    ),
    inner_classes: z.array(z.string()),
    annotations: z.array(annotationSchema),
    static_inits: z.array(androidStaticInitSchema),
    value_coverage: valueCoverage,
  }),
  inspect_android_method: z.strictObject({
    ...common,
    class_name: z.string(),
    method: method,
    overload_count: z.number().int().positive(),
    representation: z.enum(["java", "smali"]),
    body_status: z.enum(["available", "not_available"]),
    fell_back: z.boolean(),
    markers: z.array(z.string()),
    source: textCoverage,
    annotations: z.array(annotationSchema),
    value_coverage: valueCoverage,
  }),
  trace_android_references: z.strictObject({
    ...common,
    class_name: z.string(),
    method_name: z.string().nullable(),
    total: z.number().int().nonnegative(),
    references: z.array(
      z.strictObject({
        kind: z.string(),
        name: z.string(),
        reported_full_name: z.string(),
        containing_class: z.string(),
        top_class: z.string(),
        source_line: z.null(),
        dex_offset: z.null(),
      }),
    ),
    coverage: z.literal("complete"),
  }),
} as const;
