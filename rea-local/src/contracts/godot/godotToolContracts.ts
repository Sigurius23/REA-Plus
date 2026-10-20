import {
  godotFileSchema,
  inspectGodotFileInputSchema,
} from "../../domain/godot/godotFile.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free Godot file reader with CLI/MCP parity; nothing is loaded or run. */
export const GODOT_TOOL_CONTRACTS = [
  {
    name: "inspect_godot_file",
    ...toolContractMetadata("inspect_godot_file"),
    kind: "artifact-provider",
    description:
      "Decode the binary files Godot 3 and 4 games ship, without loading or running them, and return Evidence. Binary resources and scenes (.res, .scn, and the exported forms of .tres/.tscn, plain or RSCC-compressed): engine version, type, UID, external resources by path, sub-resources and every stored property in Godot's text notation; for a scene, its node tree with types, instanced scenes, groups and properties, and its signal connections. Compiled GDScript (.gdc from Godot 3.0-3.6 and 4.3+, and Godot 3 .gde with the key): the token stream and the source rebuilt on its original line numbers. Saves written with store_var, open_compressed (GCPF) or open_encrypted (GDEC, with the key or password named by environment variable): every value with its path. Reads a loose file, or an entry inside a .pck or an executable with an embedded pack, following .remap files from the original .gd/.tscn path.",
    inputSchema: inspectGodotFileInputSchema,
    outputSchema: evidenceResultOf(godotFileSchema),
    examples: [
      {
        title: "Rebuild a compiled script straight from a game's pack",
        input: {
          path: "/games/MyGame/MyGame.pck",
          entry: "res://scripts/player.gd",
        },
      },
      {
        title: "List a scene's nodes",
        input: {
          path: "/games/MyGame/MyGame.pck",
          entry: "res://scenes/level_1.tscn",
          view: "nodes",
        },
      },
      {
        title: "Read an encrypted save with the game's password",
        input: {
          path: "/home/me/.local/share/godot/app_userdata/MyGame/save.dat",
          password_env: "MYGAME_SAVE_PASSWORD",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
