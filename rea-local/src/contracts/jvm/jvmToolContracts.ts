import {
  inspectJvmArtifactInputSchema,
  jvmArtifactSchema,
} from "../../domain/jvm/jvmArtifact.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Optional caller-supplied CFR capability with target-free CLI/MCP parity. */
export const JVM_TOOL_CONTRACTS = [
  {
    name: "inspect_jvm_artifact",
    ...toolContractMetadata("inspect_jvm_artifact"),
    kind: "artifact-provider",
    description:
      "Inventory an explicit local JAR or .class file and decompile caller-selected classes to Java with caller-supplied CFR 0.152. Returns the artifact SHA-256, every class entry, and per-class bytecode digest, class-file version and decompiled source inline as Evidence; nested classes return their outermost class's source. A .class file is always decompiled; a JAR is only listed unless classes are named. Configure absolute REA_CFR_JAR and Java via JAVA_HOME or PATH. Bytecode is never loaded or executed; decompiled Java is a reconstruction, not original source.",
    inputSchema: inspectJvmArtifactInputSchema,
    outputSchema: evidenceResultOf(jvmArtifactSchema),
    examples: [
      {
        title: "Decompile one class from a local JAR",
        input: {
          path: "/artifacts/mod.jar",
          classes: ["com.example.mod.LicenseCheck"],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
