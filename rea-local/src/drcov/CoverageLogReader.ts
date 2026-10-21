import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { artifactInspectorFailure } from "../application/ArtifactInspection.js";
import type { CoverageLogPort } from "../application/drcov/CoverageLogPort.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  coverageLogSchema,
  type CoverageLog,
  type InspectCoverageLogInput,
} from "../domain/drcov/coverageLog.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  baselineRanges,
  drcovModules,
  newBlocks,
  summarizeModules,
  toHex,
  type DrcovModule,
} from "./DrcovCoverage.js";
import { DrcovFormatError, parseDrcovLog, type DrcovLog } from "./DrcovLog.js";

const OPERATION = "inspect_coverage_log";
/** Largest drcov log read into memory (about 64 million block entries). */
const MAX_LOG_BYTES = 512 * 1024 * 1024;

export const COVERAGE_LOG_PROVIDER_IDENTITY = {
  id: "drcov-coverage-log",
  name: "REA+ drcov coverage log reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "drcov records which basic blocks executed at least once, not how often or in what order; a block's size is DynamoRIO's dynamic block, which can differ from a disassembler's static block.",
  "Baseline comparison matches modules by exact path and blocks by image offset, so both runs must load the same module file; a rebuilt or patched module makes offsets incomparable.",
  "static_address needs the module table's preferred_base column (DynamoRIO 7.0 and later on Linux); otherwise use image_offset with the module's image base in your disassembler.",
  "The log is a caller-supplied record; REA+ did not trace the process and cannot confirm the traced binary matches a file on this host.",
];

type Field = "path" | "baseline_path" | "module";

class CoverageInputRejected extends Error {
  constructor(
    readonly field: Field,
    message: string,
  ) {
    super(message);
  }
}

interface ReadLog {
  readonly identity: CoverageLog["log"];
  readonly modules: readonly DrcovModule[];
}

const readLog = async (
  path: string,
  field: "path" | "baseline_path",
  signal?: AbortSignal,
): Promise<ReadLog> => {
  const selected = await readStableArtifact(path, MAX_LOG_BYTES, signal);
  let log: DrcovLog;
  try {
    log = parseDrcovLog(selected.bytes);
  } catch (cause: unknown) {
    if (cause instanceof DrcovFormatError)
      throw new CoverageInputRejected(
        field,
        `Not a supported drcov log: ${cause.message}`,
      );
    throw cause;
  }
  return {
    identity: {
      path,
      sha256: selected.sha256,
      bytes: selected.bytes.length,
      drcov_version: log.version,
      flavor: log.flavor,
      module_table_version: log.moduleTableVersion,
      block_table: log.blockTable,
      block_entries: log.blockStarts.length,
    },
    modules: drcovModules(log),
  };
};

const fileName = (path: string): string => path.split(/[\\/]/u).at(-1) ?? path;

/** Exact path first, then file name; ambiguity is an input error. */
const selectModule = (
  modules: readonly DrcovModule[],
  wanted: string,
): DrcovModule => {
  const exact = modules.filter(({ path }) => path === wanted);
  const candidates =
    exact.length > 0
      ? exact
      : modules.filter(({ path }) => fileName(path) === wanted);
  const [module] = candidates;
  if (candidates.length === 1 && module !== undefined) return module;
  const listed = [...new Set(modules.map(({ path }) => path))]
    .slice(0, 20)
    .join(", ");
  throw new CoverageInputRejected(
    "module",
    candidates.length === 0
      ? `No traced module is named ${wanted}. Modules include: ${listed}`
      : `${wanted} names ${String(candidates.length)} modules; pass the exact path: ${candidates
          .map(({ path }) => path)
          .join(", ")}`,
  );
};

const failure = artifactInspectorFailure({
  operation: OPERATION,
  fieldErrors: [{ error: CoverageInputRejected }],
  formatErrors: [],
  notReadable: "Not a readable coverage log",
});

/** Read caller-selected drcov logs; nothing is traced or executed. */
export class CoverageLogReader implements CoverageLogPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectCoverageLogInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const log = await readLog(input.path, "path", signal);
      const baseline =
        input.baseline_path === undefined
          ? null
          : await readLog(input.baseline_path, "baseline_path", signal);
      if (baseline !== null && baseline.identity.sha256 === log.identity.sha256)
        throw new CoverageInputRejected(
          "baseline_path",
          "The baseline is the same log; every block would be excluded.",
        );
      const ranges =
        baseline === null ? null : baselineRanges(baseline.modules);
      const module =
        input.module === undefined
          ? null
          : selectModule(log.modules, input.module);
      const blocks = module === null ? [] : newBlocks(module, ranges);
      const page = blocks.slice(input.offset, input.offset + input.limit);
      const report: CoverageLog = coverageLogSchema.parse({
        log: log.identity,
        baseline: baseline?.identity ?? null,
        modules: summarizeModules(log.modules, ranges),
        selected_module:
          module === null
            ? null
            : {
                path: module.path,
                segments: module.segments.map((segment) => ({
                  id: segment.id,
                  runtime_start: toHex(segment.start),
                  runtime_end: toHex(segment.end),
                  file_offset:
                    segment.fileOffset === null
                      ? null
                      : toHex(segment.fileOffset),
                  preferred_base:
                    segment.preferredBase === null
                      ? null
                      : toHex(segment.preferredBase),
                })),
              },
        page: {
          offset: input.offset,
          limit: input.limit,
          total: blocks.length,
          returned: page.length,
        },
        blocks: page.map(({ offset: _offset, ...block }) => block),
        limitations: LIMITATIONS,
      });
      return ok(
        createAnalysisExecution(report, COVERAGE_LOG_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: log.identity.sha256,
          },
          locations: [
            { kind: "artifact-path", path: input.path },
            ...(input.baseline_path === undefined
              ? []
              : [
                  { kind: "artifact-path" as const, path: input.baseline_path },
                ]),
          ],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(input.path)(cause));
    }
  }
}
