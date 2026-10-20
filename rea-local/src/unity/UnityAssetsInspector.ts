import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { UnityAssetsPort } from "../application/unity/UnityAssetsPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  unityAssetsSchema,
  type InspectUnityAssetsInput,
} from "../domain/unity/unityAssets.js";
import { UnityCompressionError } from "./Lz4Block.js";
import {
  buildUnityAssetsReport,
  UnityViewMismatch,
} from "./UnityAssetsReport.js";
import { UnityFormatError } from "./UnityBinary.js";

const OPERATION = "inspect_unity_assets";
/** Bundles and serialized files are read into memory up to this size. */
const MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024;

export const UNITY_ASSETS_PROVIDER_IDENTITY = {
  id: "unity-asset-reader",
  name: "REA+ Unity asset reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "Reads UnityFS bundles (format 6-8, plus format 9 following UnityPy's block layout) and serialized files of formats 9-22 (Unity 5 to Unity 6.0); UnityWeb/UnityRaw bundles, UnityCN-encrypted bundles, LZHAM blocks and format 23+ type trees are refused.",
  "Object fields come from the file's type trees when present. Player builds usually omit them; REA+ then reads names, owners, scripts and containers only for classes with a stable layout (NamedObject subclasses, GameObject, common components, MonoBehaviour, MonoScript, AssetBundle and ResourceManager) and counts the rest as unread.",
  "MonoBehaviour script fields, textures, meshes, audio and other asset payloads are not decoded; references into other files are reported by path and resolved only when that file is inside the same bundle.",
  "Nothing is loaded into Unity, executed or written back.",
];

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof UnityViewMismatch)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: ["class_name"], reason: "invalid_value", message: reason },
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
        cause instanceof UnityFormatError ||
        cause instanceof UnityCompressionError
          ? `Not readable Unity asset data: ${reason}`
          : reason,
    },
  ]);
};

/** Read caller-selected Unity bundles and serialized files; nothing is loaded or run. */
export class UnityAssetsInspector implements UnityAssetsPort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectUnityAssetsInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_ASSET_BYTES,
        signal,
      );
      signal?.throwIfAborted();
      const report = unityAssetsSchema.parse(
        buildUnityAssetsReport(selected.bytes, input, selected, LIMITATIONS),
      );
      return ok(
        createAnalysisExecution(report, UNITY_ASSETS_PROVIDER_IDENTITY, {
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
