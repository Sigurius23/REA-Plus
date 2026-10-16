import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { GodotFilePort } from "../application/godot/GodotFilePort.js";
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
  godotFileSchema,
  type InspectGodotFileInput,
} from "../domain/godot/godotFile.js";
import { err, ok, type Result } from "../domain/result.js";
import { GodotFormatError, GodotSelectionError } from "./GodotBytes.js";
import { buildGodotFileReport } from "./GodotReport.js";
import type { Environment } from "./GodotSelect.js";

const OPERATION = "inspect_godot_file";
const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;

export const GODOT_FILE_PROVIDER_IDENTITY = {
  id: "godot-file-reader",
  name: "REA+ Godot file reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads Godot 3 and 4 binary resources and scenes, compiled GDScript (bytecode 12 and 13 from Godot 3, tokenizer 100 and 101 from Godot 4.3 and later), and store_var data, without loading or running them. Text resources (.tres, .tscn) and plain .gd scripts are already readable and are not parsed.",
  "Compiled GDScript keeps tokens, not comments or formatting: source is rebuilt on the original line numbers with regenerated spacing and tab indentation. Godot 3.1 and 3.2+ share bytecode 13 but not the built-in function table; 3.2+ names are used.",
  "Encrypted files (GDEC) need the game's key or password, named through key_env or password_env; REA+ does not recover keys. Encrypted pack entries and directories are not decrypted.",
  "Property values are shown as Godot's text format writes them, cut at 4000 characters; external resources are named by path, sub-resources by id.",
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
  if (cause instanceof GodotSelectionError)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: [cause.field], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof GodotFormatError || cause instanceof RangeError
          ? `Not a readable Godot file: ${reason}`
          : reason,
    },
  ]);
};

/** Decode a caller-selected Godot file or pack entry; nothing is loaded or run. */
export class GodotFileInspector implements GodotFilePort {
  constructor(private readonly environment: Environment = {}) {}

  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectGodotFileInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_FILE_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const report = godotFileSchema.parse(
        buildGodotFileReport(selected, input, this.environment, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, GODOT_FILE_PROVIDER_IDENTITY, {
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
