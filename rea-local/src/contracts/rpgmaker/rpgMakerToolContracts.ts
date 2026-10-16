import {
  inspectRpgMakerProjectInputSchema,
  rpgMakerProjectSchema,
} from "../../domain/rpgmaker/rpgMakerProject.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free RPG Maker MV/MZ reader with CLI/MCP parity; nothing is run. */
export const RPG_MAKER_TOOL_CONTRACTS = [
  {
    name: "inspect_rpgmaker_project",
    ...toolContractMetadata("inspect_rpgmaker_project"),
    kind: "artifact-provider",
    description:
      "Read an RPG Maker MV or MZ game or project folder and return Evidence for modding, translating or save editing: engine and core version, title, start map, the asset encryption key with a key recovered from an encrypted PNG and whether they match, counts, then one paged view. maps lists maps with events, dialogue counts, Transfer Player targets and common-event calls; dialogue lists Show Text (speaker and face), Show Choices, scrolling text and comments per event page; switches lists named switches and variables with the event commands and page conditions that read or write them; database lists actors, items, skills and the other tables with notes, notetags and fields; plugins lists plugins.js entries with parameters and script digests; assets lists images, audio and movies, checks each encrypted file against the key, and with asset decrypts one file for its digest and image size; saves decodes save/ files (MV LZString, MZ zlib) into party, gold, items, switches and variables with database names. Filter with map, table and query. plugins.js is parsed as data and nothing in the game is executed.",
    inputSchema: inspectRpgMakerProjectInputSchema,
    outputSchema: evidenceResultOf(rpgMakerProjectSchema),
    examples: [
      {
        title: "Map an RPG Maker game's maps and encryption",
        input: { path: "/games/rpg" },
      },
      {
        title: "Extract one map's dialogue for translation",
        input: { path: "/games/rpg", view: "dialogue", map: 3 },
      },
      {
        title: "Read a save's party, gold and switches",
        input: { path: "/games/rpg", view: "saves" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
