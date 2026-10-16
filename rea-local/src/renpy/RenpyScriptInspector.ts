import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { RenpyScriptPort } from "../application/renpy/RenpyScriptPort.js";
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
  renpyScriptSchema,
  type InspectRenpyScriptInput,
} from "../domain/renpy/renpyScript.js";
import { err, ok, type Result } from "../domain/result.js";
import { RenpyScriptError } from "./RenpyScript.js";
import { buildRenpyScriptReport } from "./RenpyScriptReport.js";

const OPERATION = "inspect_renpy_script";
const MAX_SCRIPT_BYTES = 256 * 1024 * 1024;

export const RENPY_SCRIPT_PROVIDER_IDENTITY = {
  id: "renpy-script-reader",
  name: "REA+ Ren'Py script reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads compiled Ren'Py scripts (.rpyc): RPC2 files from Ren'Py 6.18 to 8.x, preferring slot 2 where dialogue carries translation identifiers, and older zlib-only files.",
  "The script is a Python pickle; REA+ records renpy.* and store.* classes as inert data and never imports or runs them. Any other class is refused.",
  "Text is reported as written in the script, with text tags, {{ and %% escapes kept; screen language, ATL and Python blocks are counted and named but not decompiled to source.",
  "Archived scripts must be read out of their .rpa first (inspect_game_archive previews entries; nothing is extracted).",
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
        cause instanceof RenpyScriptError
          ? `Not a readable Ren'Py script: ${reason}`
          : reason,
    },
  ]);
};

/** Read caller-selected .rpyc files; nothing is unpickled into live objects. */
export class RenpyScriptInspector implements RenpyScriptPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectRenpyScriptInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_SCRIPT_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const report = renpyScriptSchema.parse(
        buildRenpyScriptReport(selected.bytes, input, selected, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, RENPY_SCRIPT_PROVIDER_IDENTITY, {
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
