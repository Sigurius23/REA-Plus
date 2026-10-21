import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { UnityAssetsPort } from "../application/unity/UnityAssetsPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  unityAssetsSchema,
  type InspectUnityAssetsInput,
} from "../domain/unity/unityAssets.js";
import type { Result } from "../domain/result.js";
import { UnityCompressionError } from "./Lz4Block.js";
import {
  buildUnityAssetsReport,
  UnityViewMismatch,
} from "./UnityAssetsReport.js";
import { UnityFormatError } from "./UnityBinary.js";

const OPERATION = "inspect_unity_assets";

export const UNITY_ASSETS_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "unity-asset-reader",
  name: "REA+ Unity asset reader",
  version: "1",
};

const LIMITATIONS = [
  "Reads UnityFS bundles (format 6-8, plus format 9 following UnityPy's block layout) and serialized files of formats 9-22 (Unity 5 to Unity 6.0); UnityWeb/UnityRaw bundles, UnityCN-encrypted bundles, LZHAM blocks and format 23+ type trees are refused.",
  "Object fields come from the file's type trees when present. Player builds usually omit them; REA+ then reads names, owners, scripts and containers only for classes with a stable layout (NamedObject subclasses, GameObject, common components, MonoBehaviour, MonoScript, AssetBundle and ResourceManager) and counts the rest as unread.",
  "MonoBehaviour script fields, textures, meshes, audio and other asset payloads are not decoded; references into other files are reported by path and resolved only when that file is inside the same bundle.",
  "Nothing is loaded into Unity, executed or written back.",
];

const SPEC = {
  operation: OPERATION,
  identity: UNITY_ASSETS_PROVIDER_IDENTITY,
  /** Bundles and serialized files are read into memory up to this size. */
  maxFileBytes: 2 * 1024 * 1024 * 1024,
  schema: unityAssetsSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: UnityViewMismatch, field: "class_name" }],
  formatErrors: [UnityFormatError, UnityCompressionError],
  notReadable: "Not readable Unity asset data",
} as const;

/** Read caller-selected Unity bundles and serialized files; nothing is loaded or run. */
export const createUnityAssetsInspector = (): UnityAssetsPort => {
  const inspect = inspectSingleArtifact<InspectUnityAssetsInput>(
    SPEC,
    (selected, input, limitations) =>
      buildUnityAssetsReport(selected.bytes, input, selected, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectUnityAssetsInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> =>
      inspect(input, options),
  };
};
