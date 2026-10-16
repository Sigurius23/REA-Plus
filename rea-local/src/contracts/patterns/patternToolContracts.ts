import {
  bytePatternScanSchema,
  scanBytePatternsInputSchema,
} from "../../domain/patterns/bytePatterns.js";
import {
  cheatTableSchema,
  inspectCheatTableInputSchema,
} from "../../domain/patterns/cheatTable.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free AOB signature scanner with CLI/MCP parity. */
export const PATTERN_TOOL_CONTRACTS = [
  {
    name: "scan_byte_patterns",
    ...toolContractMetadata("scan_byte_patterns"),
    kind: "artifact-provider",
    description:
      "Scan a local PE, ELF, Mach-O or raw binary for array-of-bytes signatures in Cheat Engine/IDA syntax ('48 8B 05 ?? ?? ?? ?? 48 85 C0', nibble wildcards like 4?) and return Evidence per pattern: total matches and, up to max_matches, each file offset, link-time address, RVA, section and matched bytes. Each run of exactly four ?? bytes is also resolved as a rel32 displacement to its target address and section, which re-finds static pointers and call targets after a game update. Code sections are scanned by default; nothing is executed.",
    inputSchema: scanBytePatternsInputSchema,
    outputSchema: evidenceResultOf(bytePatternScanSchema),
    examples: [
      {
        title: "Re-find a static pointer after an update",
        input: {
          path: "/games/Example/GameAssembly.dll",
          patterns: [
            {
              name: "GameManager.instance",
              pattern: "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40",
            },
          ],
        },
      },
    ],
  },
  {
    name: "inspect_cheat_table",
    ...toolContractMetadata("inspect_cheat_table"),
    kind: "artifact-provider",
    description:
      "Read a Cheat Engine table (.CT) without running it and return Evidence: every entry with its group path, value type, address expression (split into module+offset when static), pointer offsets, hotkey and child counts; each Auto Assembler script's aobscan/aobscanmodule/aobscanregion signatures, assert(module+offset, bytes) checks, registered symbols and allocations; user symbols, dissected structures and the table Lua size. Add binary_path (the module of a new game build) to re-scan every signature and compare every assert's bytes, showing which cheats still apply after an update.",
    inputSchema: inspectCheatTableInputSchema,
    outputSchema: evidenceResultOf(cheatTableSchema),
    examples: [
      {
        title: "Check a table against an updated build",
        input: {
          path: "/tables/Example.CT",
          binary_path: "/games/Example/GameAssembly.dll",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
