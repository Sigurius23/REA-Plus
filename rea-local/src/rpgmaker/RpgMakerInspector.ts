import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { RpgMakerProjectPort } from "../application/rpgmaker/RpgMakerProjectPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  rpgMakerProjectSchema,
  type InspectRpgMakerProjectInput,
} from "../domain/rpgmaker/rpgMakerProject.js";
import { err, ok, type Result } from "../domain/result.js";
import { LzStringError } from "./LzString.js";
import { locateProject, RpgMakerFormatError } from "./RpgMakerFiles.js";
import { loadProject } from "./RpgMakerProject.js";
import { buildRpgMakerReport } from "./RpgMakerReport.js";

const OPERATION = "inspect_rpgmaker_project";

export const RPG_MAKER_PROVIDER_IDENTITY = {
  id: "rpgmaker-project-reader",
  name: "REA+ RPG Maker MV/MZ project reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads RPG Maker MV and MZ games and projects: the JSON database, maps, plugins.js, asset folders and save/ files. XP, VX and VX Ace (Ruby Marshal data) are not read.",
  "plugins.js is parsed as the editor's JSON list and never run; plugin scripts are hashed, not analysed. Plugins can change how data, text codes and saves behave.",
  "Switch and variable sites cover event commands and page or trigger conditions; Script commands and plugin commands that touch them are not interpreted.",
  "Assets are decrypted with the engine's scheme only (RPGMV header, first 16 bytes XORed with the key); games packed into an executable or encrypted by a plugin must be unpacked first.",
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
        cause instanceof RpgMakerFormatError || cause instanceof LzStringError
          ? `Not a readable RPG Maker MV/MZ game: ${reason}`
          : reason,
    },
  ]);
};

/** Read a caller-selected MV/MZ game folder; nothing in it is executed. */
export class RpgMakerInspector implements RpgMakerProjectPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectRpgMakerProjectInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const location = await locateProject(input.path);
      const project = await loadProject(location, signal);
      const report = rpgMakerProjectSchema.parse(
        await buildRpgMakerReport(project, input, LIMITATIONS),
      );
      signal?.throwIfAborted();
      return ok(
        createAnalysisExecution(report, RPG_MAKER_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "directory",
            sha256: report.project.data_sha256,
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
