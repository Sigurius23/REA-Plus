import {
  gameArchiveSchema,
  inspectGameArchiveInputSchema,
} from "../../domain/gamearchives/gameArchive.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free game archive reader with CLI/MCP parity; nothing is extracted. */
export const GAME_ARCHIVE_TOOL_CONTRACTS = [
  {
    name: "inspect_game_archive",
    ...toolContractMetadata("inspect_game_archive"),
    kind: "artifact-provider",
    description:
      "List a game engine archive and return Evidence: a Godot .pck (formats 1-3, or a pack embedded in an exported game executable), a Ren'Py .rpa, a Valve _dir.vpk/.vpk, a Doom IWAD/PWAD, or an Unreal Engine .pak (versions 1-11, Zlib/Gzip/Zstd entries decoded, Oodle listed). Reports format, version, Godot engine version and flags, entry counts and bytes by extension, then a page of entries with paths, sizes, offsets, encryption and removal flags, sibling VPK chunks, WAD maps and namespaces, and stored MD5/CRC32/SHA-1 checksums recomputed where the bytes are local. Pass entry to preview one file (SHA-256 plus up to 64 KiB as text or hex), such as a .gd script, project.godot, a .rpy script or a map lump. Ren'Py index pickles are decoded without executing code; nothing is extracted, mounted or run.",
    inputSchema: inspectGameArchiveInputSchema,
    outputSchema: evidenceResultOf(gameArchiveSchema),
    examples: [
      {
        title: "List the scripts in a Godot game's pack",
        input: { path: "/games/MyGame/MyGame.pck", extension: "gd" },
      },
      {
        title: "Read one Ren'Py script from an archive",
        input: { path: "/games/vn/game/scripts.rpa", entry: "script.rpy" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
