import { z } from "zod";

const digest = z.string().regex(/^[a-f0-9]{64}$/);

/** A Java binary class name such as com.example.Main or com.example.Outer$Inner. */
export const jvmBinaryNameSchema = z
  .string()
  .min(1)
  .max(1024)
  .regex(
    /^[\p{L}\p{Nl}_$][\p{L}\p{Nl}\p{Nd}_$]*(?:\.[\p{L}\p{Nl}_$][\p{L}\p{Nl}\p{Nd}_$]*)*$/u,
    "Expected a dotted Java binary class name, such as com.example.Main",
  );

/** Selection is explicit: a JAR is only inventoried unless classes are named. */
export const inspectJvmArtifactInputSchema = z.strictObject({
  path: z.string().min(1).describe("Absolute local .class file or JAR path"),
  classes: z
    .array(jvmBinaryNameSchema)
    .default([])
    .describe(
      "Binary class names to decompile from a JAR, such as com.example.Main or com.example.Outer$Inner. Empty lists a JAR's classes without decompiling; a .class file is always decompiled.",
    ),
});

const classVersion = z.strictObject({
  major: z.number().int().nonnegative(),
  minor: z.number().int().nonnegative(),
  java_release: z
    .number()
    .int()
    .positive()
    .nullable()
    .describe("Java SE release for class-file major versions 45 and later."),
});

/** Decompiled Java is CFR's reconstruction, never original source. */
export const jvmArtifactSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digest,
    bytes: z.number().int().nonnegative(),
    kind: z.enum(["class", "jar"]),
  }),
  classes: z
    .array(
      z.strictObject({
        name: jvmBinaryNameSchema,
        entry: z
          .string()
          .nullable()
          .describe("JAR entry path; null for a standalone .class file."),
        bytes: z.number().int().nonnegative().nullable(),
      }),
    )
    .describe("Every class entry in the artifact, in entry order."),
  decompiled: z.array(
    z.strictObject({
      top_level_class: jvmBinaryNameSchema,
      requested: z.array(jvmBinaryNameSchema),
      class_sha256: digest,
      class_version: classVersion,
      source_path: z.string().min(1),
      text: z.string(),
      sha256: digest,
      representation: z.literal("cfr-decompiled-java"),
      cfr_reported_failures: z
        .boolean()
        .describe(
          "CFR embedded a decompilation failure comment in this source.",
        ),
    }),
  ),
  tool_profile: z.strictObject({
    decompiler: z.literal("CFR"),
    release: z.literal("0.152"),
    jar_path: z.string().min(1),
    jar_sha256: digest,
    java_command: z.string().min(1),
    java_version: z.string(),
    arguments: z.array(z.string()),
    timeout_ms: z.number().int().positive(),
    output_budget_bytes: z.number().int().positive(),
  }),
  runtime_execution: z.literal("not-performed"),
  limitations: z.array(z.string()),
});

export type InspectJvmArtifactInput = z.output<
  typeof inspectJvmArtifactInputSchema
>;
export type JvmArtifact = z.output<typeof jvmArtifactSchema>;
