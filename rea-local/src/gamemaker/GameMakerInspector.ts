import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { GameMakerDataPort } from "../application/gamemaker/GameMakerDataPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  gameMakerDataSchema,
  type InspectGameMakerDataInput,
} from "../domain/gamemaker/gameMakerData.js";
import { err, ok, type Result } from "../domain/result.js";
import { GameMakerFormatError } from "./GameMakerForm.js";
import { buildGameMakerReport } from "./GameMakerReport.js";

const OPERATION = "inspect_gamemaker_data";
const MAX_DATA_BYTES = 2 * 1024 * 1024 * 1024;

export const GAMEMAKER_PROVIDER_IDENTITY = {
  id: "gamemaker-data-reader",
  name: "REA+ GameMaker data reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads GameMaker Studio 1.4 to GameMaker 2024+ data files (bytecode 13-17): data.win, game.unx, game.droid, game.ios, audiogroupN.dat, or a FORM appended to a runner. GameMaker 8 executables use a different format and are not read.",
  "GameMaker Studio 2 and later store 2.0.0.0 as their version; minimum_version is inferred from which chunks exist, as UndertaleModTool does.",
  "Resource fields are limited to those at the same offsets in every version. Bytecode is listed with sizes and arguments, not disassembled or decompiled; use UndertaleModTool for that.",
  "Sounds in audio groups other than 0 play entries from audiogroupN.dat; inspect that file for them.",
];

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, { cause });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof GameMakerFormatError || cause instanceof RangeError
          ? `Not a readable GameMaker data file: ${reason}`
          : reason,
    },
  ]);
};

/** Read a caller-selected GameMaker data file; bytecode is listed, never run. */
export class GameMakerInspector implements GameMakerDataPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectGameMakerDataInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_DATA_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const report = gameMakerDataSchema.parse(
        buildGameMakerReport(selected.bytes, input, selected, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, GAMEMAKER_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations: report.limitations,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(cause, input.path));
    }
  }
}
