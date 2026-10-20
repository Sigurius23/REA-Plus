import {
  inspectUnityAssetsInputSchema,
  unityAssetsSchema,
} from "../../domain/unity/unityAssets.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free Unity asset reader with CLI/MCP parity; Unity is never launched. */
export const UNITY_TOOL_CONTRACTS = [
  {
    name: "inspect_unity_assets",
    ...toolContractMetadata("inspect_unity_assets"),
    kind: "artifact-provider",
    description:
      "Read a Unity asset bundle (UnityFS with LZ4, LZ4HC, LZMA or uncompressed blocks) or a player serialized file (level0, sharedassets0.assets, resources.assets, globalgamemanagers) and return Evidence: bundle blocks and directory, each serialized file's Unity version, platform, types and external references, then one paged view. objects lists path IDs, classes, offsets, names, owning GameObjects and MonoBehaviour scripts; container maps AssetBundle asset paths and Resources.Load paths to objects; scripts lists MonoScripts with namespaces and assemblies and how many MonoBehaviours use each. Filter with class_name and query. Works with or without type trees; asset payloads are not decoded and nothing is loaded into Unity.",
    inputSchema: inspectUnityAssetsInputSchema,
    outputSchema: evidenceResultOf(unityAssetsSchema),
    examples: [
      {
        title: "List the asset paths a bundle provides",
        input: {
          path: "/game/StreamingAssets/ui_atlas.bundle",
          view: "container",
        },
      },
      {
        title: "Find which scripts a scene uses",
        input: { path: "/game/Game_Data/level1", view: "scripts" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
