import {
  inspectMinidumpInputSchema,
  minidumpSchema,
} from "../../domain/minidump/minidump.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free minidump reader with CLI/MCP parity; no debugger is configured. */
export const MINIDUMP_TOOL_CONTRACTS = [
  {
    name: "inspect_minidump",
    ...toolContractMetadata("inspect_minidump"),
    kind: "artifact-provider",
    description:
      "Read a crash minidump (Windows .dmp from WER, procdump, WinDbg or a game's crash reporter, or a Breakpad/Crashpad dump from Linux, macOS or Android) and return Evidence: OS and CPU, the exception (named NTSTATUS, signal or Mach code, with access kind and address for access violations) and the faulting instruction as module+offset, registers, every thread's instruction and stack pointers, loaded and unloaded modules with versions and PDB/ELF debug and code identifiers for symbol lookup, memory coverage, and a return-address scan of the exception thread's stack. Pass thread_id to inspect another thread. The dump is parsed, never loaded into a debugger; take module+offset addresses to a binary provider.",
    inputSchema: inspectMinidumpInputSchema,
    outputSchema: evidenceResultOf(minidumpSchema),
    examples: [
      {
        title: "Explain a game crash dump",
        input: { path: "/crashes/Game_2026-10-15.dmp" },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
