import {
  inspectX64dbgDatabaseInputSchema,
  x64dbgDatabaseSchema,
} from "../../domain/x64dbg/x64dbgDatabase.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free x64dbg database reader with CLI/MCP parity; nothing is debugged. */
export const X64DBG_TOOL_CONTRACTS = [
  {
    name: "inspect_x64dbg_database",
    ...toolContractMetadata("inspect_x64dbg_database"),
    kind: "artifact-provider",
    description:
      "Read an x64dbg program database (.dd32/.dd64 from x64dbg's db folder, plain JSON or LZ4-compressed) and return Evidence of a reverse-engineering session: notes, init script, the modules entries refer to, plugins with saved data, counts, then one paged view. labels, comments and bookmarks list annotated module-relative addresses; functions, arguments and loops list annotated ranges with instruction counts; breakpoints lists software, hardware, memory, DLL and exception breakpoints with conditions, log and command text and the original bytes under software breakpoints; xrefs lists recorded cross-references; watch lists watch expressions. Filter with module and query. With module_path, entries of that module gain file offsets and sections, and software breakpoints are checked against the file's bytes, so a game update that moved the code shows up as mismatches.",
    inputSchema: inspectX64dbgDatabaseInputSchema,
    outputSchema: evidenceResultOf(x64dbgDatabaseSchema),
    examples: [
      {
        title: "List the labels from an x64dbg session",
        input: { path: "/x64dbg/db/game.exe.dd64" },
      },
      {
        title: "Check saved breakpoints against a new game build",
        input: {
          path: "/x64dbg/db/game.exe.dd64",
          view: "breakpoints",
          module_path: "/games/game/game.exe",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
