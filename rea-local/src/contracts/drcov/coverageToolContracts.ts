import {
  coverageLogSchema,
  inspectCoverageLogInputSchema,
} from "../../domain/drcov/coverageLog.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Target-free drcov reader with CLI/MCP parity; no tracer is configured. */
export const COVERAGE_TOOL_CONTRACTS = [
  {
    name: "inspect_coverage_log",
    ...toolContractMetadata("inspect_coverage_log"),
    kind: "artifact-provider",
    description:
      "Read a drcov basic-block coverage log (DynamoRIO `drrun -t drcov`, or Frida and other Lighthouse-compatible tracers) and return the covered modules with unique blocks and covered bytes as Evidence. Name a module (exact path or file name) to page its executed blocks as image offsets, link-time static addresses and runtime addresses; take those addresses to a binary provider. Add baseline_path, a log of the same program without the behavior of interest, to keep only blocks whose bytes the baseline never executed: differential coverage that locates the code behind one action. Logs are parsed, never replayed; supports drcov versions 2 and 3, module tables 2-5, and binary or text block tables.",
    inputSchema: inspectCoverageLogInputSchema,
    outputSchema: evidenceResultOf(coverageLogSchema),
    examples: [
      {
        title: "Find the code that ran only when jumping",
        input: {
          path: "/traces/drcov.game.jump.log",
          baseline_path: "/traces/drcov.game.idle.log",
          module: "GameAssembly.so",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
