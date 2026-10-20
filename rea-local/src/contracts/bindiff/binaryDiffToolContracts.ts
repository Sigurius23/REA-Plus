import {
  binaryDiffSchema,
  diffBinariesInputSchema,
} from "../../domain/bindiff/binaryDiff.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Whole-binary patch diffing over the configured analysis provider, with CLI/MCP parity. */
export const BINARY_DIFF_TOOL_CONTRACTS = [
  {
    name: "diff_binaries",
    ...toolContractMetadata("diff_binaries"),
    kind: "artifact-provider",
    description:
      "Diff two builds of a native binary (a patch, a game update, two firmware releases) function by function, BinDiff/Diaphora-style, and return Evidence. Both builds are analyzed by the configured deep provider (Ghidra, IDA, Binary Ninja, Hopper, radare2 or Rizin), every function's report is reduced to address-independent features, and functions are matched by unique names, identical or same-mnemonic instructions, shared strings and constants with the same control-flow shape, call-graph neighbours of matched pairs, and overall similarity gated by call-graph agreement. Returns matched pairs with similarity, method, instruction/block/edge counts, changed lines, and added or removed calls, strings and constants; functions only in one build; and an aligned instruction diff for one function. Works on stripped builds.",
    inputSchema: diffBinariesInputSchema,
    outputSchema: evidenceResultOf(binaryDiffSchema),
    examples: [
      {
        title: "Summarize what changed between two releases",
        input: { left: "/builds/game-1.0.exe", right: "/builds/game-1.1.exe" },
      },
      {
        title: "List the functions that only the new build has",
        input: {
          left: "/builds/game-1.0.exe",
          right: "/builds/game-1.1.exe",
          view: "unmatched",
          status: "added",
        },
      },
      {
        title: "Show one changed function's instruction diff",
        input: {
          left: "/builds/game-1.0.exe",
          right: "/builds/game-1.1.exe",
          view: "function",
          function: "0x401a30",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
