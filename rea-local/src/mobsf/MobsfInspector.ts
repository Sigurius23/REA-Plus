import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { MobsfReportPort } from "../application/mobsf/MobsfReportPort.js";
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
  mobsfReportSchema,
  type InspectMobsfReportInput,
} from "../domain/mobsf/mobsfReport.js";
import { err, ok, type Result } from "../domain/result.js";
import { RegularFileChangedError } from "../filesystem/RegularFile.js";
import { hashStableFile } from "../filesystem/StableFileHash.js";
import { buildMobsfReport, MobsfFormatError } from "./MobsfReport.js";

const OPERATION = "inspect_mobsf_report";
const MAX_REPORT_BYTES = 256 * 1024 * 1024;

export const MOBSF_PROVIDER_IDENTITY = {
  id: "mobsf-report-reader",
  name: "REA+ MobSF report reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads MobSF static-analysis JSON reports (the 3.1 layout and the 3.6 to 4.x layout); MobSF is not run or contacted, and the app itself is not analysed again.",
  "Findings, scores and detections are MobSF's: they reflect its rules and the version that wrote the report, not REA+ observations of the app.",
  "Severities are mapped onto high, warning, info and secure (good becomes secure, medium warning, insecure high); mobsf_severity keeps MobSF's label.",
  "Weak hardening checks of native libraries and frameworks are listed as hardening findings, and of the main iOS binary as macho findings, which MobSF's own scorecard limits to six checks.",
  "Strings, NIAP analysis, malware behaviour (Quark), SBOM, store details and scan logs are not read. Secrets are listed as MobSF found them in the app.",
];

class AppPathError extends Error {
  override readonly name = "AppPathError";
}

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "integrity") ||
    cause instanceof RegularFileChangedError
  )
    return new AnalysisArtifactChangedError(OPERATION, path, reason, { cause });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  if (cause instanceof AppPathError)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["app_path"], reason: "invalid_value", message: reason },
    ]);
  return new AnalysisInputError(OPERATION, { cause }, [
    {
      path: ["path"],
      reason: "invalid_value",
      message:
        cause instanceof MobsfFormatError
          ? `Not a readable MobSF report: ${reason}`
          : reason,
    },
  ]);
};

/** Parse a caller-selected MobSF report, optionally checked against the app it names. */
export class MobsfInspector implements MobsfReportPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectMobsfReportInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_REPORT_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const appFile =
        input.app_path === undefined
          ? null
          : await hashStableFile(input.app_path, signal).then(
              ({ sha256 }) => ({ path: input.app_path ?? "", sha256 }),
              (cause: unknown) => {
                if (
                  cause instanceof RegularFileChangedError ||
                  (cause instanceof Error && cause.name === "AbortError")
                )
                  throw cause;
                throw new AppPathError(
                  `The app file cannot be read: ${cause instanceof Error ? cause.message : String(cause)}`,
                  { cause },
                );
              },
            );
      signal?.throwIfAborted();
      const report = mobsfReportSchema.parse(
        buildMobsfReport(selected, input, appFile, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, MOBSF_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [
            { kind: "artifact-path", path: input.path },
            ...(appFile === null
              ? []
              : [{ kind: "artifact-path" as const, path: appFile.path }]),
          ],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(cause, input.path));
    }
  }
}
