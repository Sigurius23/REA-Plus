import {
  il2cppMetadataSchema,
  inspectIl2CppMetadataInputSchema,
} from "../../domain/il2cpp/il2cppMetadata.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Optional caller-supplied r2unity capability with target-free CLI/MCP parity. */
export const IL2CPP_TOOL_CONTRACTS = [
  {
    name: "inspect_il2cpp_metadata",
    ...toolContractMetadata("inspect_il2cpp_metadata"),
    kind: "artifact-provider",
    description:
      "Read a Unity IL2CPP global-metadata.dat with caller-supplied r2unity 1.2 and return one filtered, paged view as Evidence: classes (namespace-qualified types with base, interfaces, fields and methods), string_literals (managed ldstr literals with file offsets), interop (P/Invoke and [MonoPInvokeCallback]/[UnmanagedCallersOnly] methods) or assemblies (managed assemblies, versions and references). Add the build's native binary_path (GameAssembly.dll/.so/.dylib, libil2cpp.so or UnityFramework) to recover each method's native address through Il2CppCodeRegistration, then inspect those addresses with a binary provider. Configure absolute REA_R2UNITY_PATH. Repeated pages reuse this server's parsed listing for the same file digests. Neither file is executed; names are metadata identifiers, not source.",
    inputSchema: inspectIl2CppMetadataInputSchema,
    outputSchema: evidenceResultOf(il2cppMetadataSchema),
    examples: [
      {
        title: "Find license checks and their native addresses",
        input: {
          metadata_path:
            "/games/Example/Example_Data/il2cpp_data/Metadata/global-metadata.dat",
          binary_path: "/games/Example/GameAssembly.so",
          view: "classes",
          query: "license",
        },
      },
      {
        title: "Search managed string literals",
        input: {
          metadata_path:
            "/games/Example/Example_Data/il2cpp_data/Metadata/global-metadata.dat",
          view: "string_literals",
          query: "https://",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
