import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";

import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { BinaryDiffPort } from "../application/bindiff/BinaryDiffPort.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { DiffBinariesInput } from "../domain/bindiff/binaryDiff.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  collectFunctions,
  type DiffAnalysisSession,
  type FunctionInventory,
} from "./BinaryDiffCollector.js";
import { matchFunctions } from "./BinaryDiffMatcher.js";
import { diffReport, diffTables, type DiffTables } from "./BinaryDiffReport.js";

const OPERATION = "diff_binaries";

export const BINARY_DIFF_PROVIDER_IDENTITY = {
  id: "binary-diff",
  name: "REA+ binary diff",
  version: "1",
} as const;
/** Builds and diffs kept for paging through views without re-analysis. */
const CACHED_INVENTORIES = 4;
const CACHED_DIFFS = 4;

const LIMITATIONS = [
  "Matches are inferences from each build's function analysis by the same provider: unique names, identical or same-mnemonic instructions, shared strings and constants with the same control-flow shape, call-graph neighbours of matched pairs, then overall similarity. A pair is not proof that both functions come from the same source.",
  "Instructions are compared with addresses, jump targets and provider-generated labels abstracted. Register allocation, scheduling and inlining differences count as changed lines.",
  "A function the provider found in only one build, or split or merged differently, appears as removed or added.",
  "Call changes compare callees through the match; strings, constants and calls list at most 16 items each.",
];

const sha256Of = (path: string): Promise<string> =>
  new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    createReadStream(path)
      .on("data", (chunk) => hash.update(chunk))
      .on("error", reject)
      .on("end", () => resolve(hash.digest("hex")));
  });

const remember = <Value>(
  cache: Map<string, Value>,
  key: string,
  value: Value,
  size: number,
) => {
  cache.delete(key);
  cache.set(key, value);
  for (const oldest of cache.keys()) {
    if (cache.size <= size) break;
    cache.delete(oldest);
  }
};

/**
 * Diff two builds through the configured analysis provider: each build is
 * opened in its own session, every listed function analyzed, and the two
 * function sets matched.
 */
export class BinaryDiffInspector implements BinaryDiffPort {
  readonly #inventories = new Map<string, FunctionInventory>();
  readonly #diffs = new Map<string, DiffTables>();

  constructor(
    private readonly createSession: () => Promise<
      Result<DiffAnalysisSession, AnalysisError>
    >,
  ) {}

  async close(): Promise<void> {
    this.#inventories.clear();
    this.#diffs.clear();
  }

  async inspect(
    input: DiffBinariesInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const left = await this.#inventory(input.left, input, options?.signal);
    if (!left.ok) return left;
    const right = await this.#inventory(input.right, input, options?.signal);
    if (!right.ok) return right;
    if (left.value.provider.id !== right.value.provider.id)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["right"],
            reason: "invalid_value",
            message: `The builds were routed to different providers (${left.value.provider.id} and ${right.value.provider.id}); diff builds of the same format.`,
          },
        ]),
      );
    const key = [
      left.value.sha256,
      right.value.sha256,
      String(input.names),
      String(input.threshold),
      String(input.max_functions),
    ].join(":");
    let tables = this.#diffs.get(key);
    if (tables === undefined) {
      tables = diffTables(
        left.value,
        right.value,
        matchFunctions(left.value.functions, right.value.functions, {
          names: input.names,
          threshold: input.threshold,
        }),
      );
    }
    remember(this.#diffs, key, tables, CACHED_DIFFS);
    const report = diffReport(left.value, right.value, tables, input);
    if (input.view === "function" && report.page.total === 0)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["function"],
            reason:
              input.function === undefined
                ? "missing_argument"
                : "invalid_value",
            message:
              input.function === undefined
                ? "The function view needs a function address or name."
                : `No analyzed function in either build has the address or name ${input.function}.`,
          },
        ]),
      );
    return ok(
      createAnalysisExecution(report, BINARY_DIFF_PROVIDER_IDENTITY, {
        limitations: [
          ...LIMITATIONS,
          ...this.#coverage(left.value, "older"),
          ...this.#coverage(right.value, "newer"),
          ...(tables.similarityComplete
            ? []
            : [
                "The similarity pass stopped after 4,000,000 candidate pairs; some remaining functions were not compared.",
              ]),
          ...new Set([...left.value.limitations, ...right.value.limitations]),
        ],
        locations: [
          { kind: "artifact-path", path: left.value.path },
          { kind: "artifact-path", path: right.value.path },
        ],
        subject: {
          path: right.value.path,
          sha256: right.value.sha256,
          format: right.value.format,
        },
      }),
    );
  }

  #coverage(inventory: FunctionInventory, side: string): string[] {
    return [
      ...(inventory.truncated
        ? [
            `Only the first ${String(inventory.functions.length + inventory.failed.length)} of ${String(inventory.listed)} functions of the ${side} build were analyzed (max_functions).`,
          ]
        : []),
      ...(inventory.failed.length === 0
        ? []
        : [
            `${String(inventory.failed.length)} functions of the ${side} build could not be analyzed and are left out, such as ${inventory.failed
              .slice(0, 3)
              .map(({ name }) => name)
              .join(", ")}.`,
          ]),
    ];
  }

  async #inventory(
    path: string,
    input: DiffBinariesInput,
    signal: AbortSignal | undefined,
  ): Promise<Result<FunctionInventory, AnalysisError>> {
    let digest: string;
    try {
      digest = await sha256Of(path);
    } catch {
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: [path === input.left ? "left" : "right"],
            reason: "invalid_value",
            message: `Cannot read ${path}.`,
          },
        ]),
      );
    }
    const key = `${digest}:${String(input.max_functions)}`;
    const cached = this.#inventories.get(key);
    if (cached !== undefined && cached.path === path) return ok(cached);
    if (signal?.aborted === true)
      return err(new AnalysisCancelledError(OPERATION));
    const session = await this.createSession();
    if (!session.ok) return session;
    const collected = await collectFunctions(session.value, path, {
      maxFunctions: input.max_functions,
      ...(signal === undefined ? {} : { signal }),
    });
    if (collected.ok)
      remember(this.#inventories, key, collected.value, CACHED_INVENTORIES);
    return collected;
  }
}
