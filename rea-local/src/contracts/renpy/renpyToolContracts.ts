import {
  inspectRenpyScriptInputSchema,
  renpyScriptSchema,
} from "../../domain/renpy/renpyScript.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free Ren'Py script reader with CLI/MCP parity; nothing is run. */
export const RENPY_TOOL_CONTRACTS = [
  {
    name: "inspect_renpy_script",
    ...toolContractMetadata("inspect_renpy_script"),
    kind: "artifact-provider",
    description:
      "Read a compiled Ren'Py script (.rpyc) and return Evidence for modding or translating a visual novel: source files, statement counts, speakers, translation languages, then one paged view. labels lists labels with their jumps, calls, dialogue and menu counts; dialogue lists say statements with speaker, text, source line and the translation identifier `translate <language> <identifier>:` uses; menus lists choices with conditions and jump/call targets; definitions lists define, default, image, screen, transform and style names with their Python values; translations lists translate blocks and strings per language. Filter with label and query. The pickled script is decoded as inert data: Ren'Py classes are recorded, never imported or executed.",
    inputSchema: inspectRenpyScriptInputSchema,
    outputSchema: evidenceResultOf(renpyScriptSchema),
    examples: [
      {
        title: "Map a visual novel's labels and branches",
        input: { path: "/games/vn/game/script.rpyc" },
      },
      {
        title: "Extract one route's dialogue for translation",
        input: {
          path: "/games/vn/game/script.rpyc",
          view: "dialogue",
          label: "route_a",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
