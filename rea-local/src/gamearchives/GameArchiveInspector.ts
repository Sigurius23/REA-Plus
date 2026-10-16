import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { GameArchivePort } from "../application/gamearchives/GameArchivePort.js";
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
  gameArchiveSchema,
  type InspectGameArchiveInput,
} from "../domain/gamearchives/gameArchive.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  buildGameArchiveReport,
  GameArchiveEntryNotFound,
} from "./GameArchiveReport.js";
import { GameArchiveError } from "./GameArchiveTypes.js";

const OPERATION = "inspect_game_archive";
/** Archives (or executables embedding a pack) are read into memory up to this size. */
const MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;

export const GAME_ARCHIVE_PROVIDER_IDENTITY = {
  id: "game-archive-reader",
  name: "REA+ game archive reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads Godot packs (formats 1-3, standalone or appended to an exported executable), Ren'Py RPA-2.0/3.0/3.2/4.0 archives, Valve VPK 1/2 directories and Doom IWAD/PWAD files; other engines' archives are refused.",
  "Ren'Py indexes are Python pickles; REA+ decodes only containers, strings, bytes and integers and refuses anything that would import or call code.",
  "Encrypted Godot directories and files are reported but not decrypted; VPK data in sibling _NNN.vpk chunks is not read, so those entries have no preview or checksum check.",
  "Nothing is extracted, mounted or executed; previews return at most 64 KiB of one entry.",
];

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof GameArchiveEntryNotFound)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["entry"], reason: "invalid_value", message: reason },
    ]);
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
        cause instanceof GameArchiveError
          ? `Not a readable game archive: ${reason}`
          : reason,
    },
  ]);
};

/** Read caller-selected game archives; nothing is extracted or run. */
export class GameArchiveInspector implements GameArchivePort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectGameArchiveInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_ARCHIVE_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const report = gameArchiveSchema.parse(
        buildGameArchiveReport(selected.bytes, input, selected, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, GAME_ARCHIVE_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(cause, input.path));
    }
  }
}
