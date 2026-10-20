import {
  gameMakerDataSchema,
  inspectGameMakerDataInputSchema,
} from "../../domain/gamemaker/gameMakerData.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free GameMaker data reader with CLI/MCP parity; nothing is run. */
export const GAMEMAKER_TOOL_CONTRACTS = [
  {
    name: "inspect_gamemaker_data",
    ...toolContractMetadata("inspect_gamemaker_data"),
    kind: "artifact-provider",
    description:
      "Read a GameMaker data file (data.win, game.unx, game.droid, game.ios, an audiogroupN.dat, or a FORM appended to a runner) and return Evidence for modding a GameMaker game: GEN8 name, display name, bytecode version, the stored version and the minimum runtime implied by the chunk set, VM or YYC, window, flags and build time, counts, then one paged view. chunks lists the IFF chunk table; resources lists sounds, sprites, scripts, objects, rooms, sequences and the other named resources with version-stable fields (sprite size and origin, object sprite, room size, instances and creation code, script code entry, sound file and audio group); code lists GML bytecode entries with length, locals, arguments and shared 2.3 function bodies; strings lists the string table; symbols lists functions and variables with occurrence counts; textures lists texture pages as PNG, QOI or BZ2-QOI with size; audio lists embedded WAV and Ogg files with the sounds that play them. Filter with kind and query. Every string reference must land on a STRG entry, so misread layouts fail instead of returning garbage. Bytecode is listed, never run.",
    inputSchema: inspectGameMakerDataInputSchema,
    outputSchema: evidenceResultOf(gameMakerDataSchema),
    examples: [
      {
        title: "Identify a GameMaker build and its chunks",
        input: { path: "/games/gm/data.win" },
      },
      {
        title: "List a game's objects and their sprites",
        input: {
          path: "/games/gm/data.win",
          view: "resources",
          kind: "object",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
