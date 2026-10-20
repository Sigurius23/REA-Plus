import { createHash } from "node:crypto";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import canonicalize from "canonicalize";

const load = (root, path) => import(pathToFileURL(join(root, path)).href);

/** Sort tool/provider names alphabetically. */
export const names = (contracts) =>
  contracts
    .map(({ name }) => name)
    .sort((left, right) => left.localeCompare(right));

/** Return the stable digest for a generated catalog projection. */
export const digest = (value) => {
  const encoded = canonicalize(value);
  if (encoded === undefined)
    throw new TypeError("Catalog projection is not canonical JSON");
  return createHash("sha256").update(encoded).digest("hex");
};

/** Throw when two name lists diverge. */
export const assertSameNames = (label, actual, expected) => {
  const actualSet = new Set(actual);
  const expectedSet = new Set(expected);
  const missing = [...expectedSet].filter((name) => !actualSet.has(name));
  const extra = [...actualSet].filter((name) => !expectedSet.has(name));
  if (missing.length === 0 && extra.length === 0) return;
  throw new Error(
    `${label} drifted (missing: ${missing.join(", ") || "none"}; extra: ${extra.join(", ") || "none"})`,
  );
};

const SOURCE_PATHS = {
  packageMetadata: "dist/generatedPackageMetadata.js",
  catalogIdentity: "dist/catalogIdentity.js",
  cliCommandNames: "dist/cliCommandNames.js",
  cli: "dist/cli.js",
  toolContracts: "dist/contracts/toolContracts.js",
  officialContracts: "dist/contracts/officialToolContracts.js",
  enhancedContracts: "dist/contracts/enhancedToolContracts.js",
  sessionContracts: "dist/contracts/sessionToolContracts.js",
  externalMcpContracts:
    "dist/contracts/externalMcp/externalMcpToolContracts.js",
  mobileRuntimeContracts:
    "dist/contracts/mobileRuntime/mobileRuntimeToolContracts.js",
  binaryDiagnosticsContracts:
    "dist/contracts/native/binaryDiagnosticsToolContracts.js",
  pwntoolsProvider: "dist/native/pwntools/PwntoolsRelease.js",
  nativeContracts: "dist/contracts/native/nativeToolContracts.js",
  wasmContracts: "dist/contracts/wasm/wasmToolContracts.js",
  wasmProvider: "dist/wasm/WabtRelease.js",
  jvmContracts: "dist/contracts/jvm/jvmToolContracts.js",
  jvmProvider: "dist/jvm/CfrRelease.js",
  il2cppContracts: "dist/contracts/il2cpp/il2cppToolContracts.js",
  il2cppProvider: "dist/il2cpp/R2UnityRelease.js",
  coverageContracts: "dist/contracts/drcov/coverageToolContracts.js",
  coverageProvider: "dist/drcov/CoverageLogReader.js",
  minidumpContracts: "dist/contracts/minidump/minidumpToolContracts.js",
  minidumpProvider: "dist/minidump/MinidumpInspector.js",
  logicContracts: "dist/contracts/logic/logicToolContracts.js",
  logicProvider: "dist/logic/LogicCaptureInspector.js",
  patternContracts: "dist/contracts/patterns/patternToolContracts.js",
  patternProvider: "dist/patterns/PatternScanProvider.js",
  cheatTableProvider: "dist/patterns/CheatTableInspector.js",
  unityContracts: "dist/contracts/unity/unityToolContracts.js",
  unityProvider: "dist/unity/UnityAssetsInspector.js",
  gameArchiveContracts:
    "dist/contracts/gamearchives/gameArchiveToolContracts.js",
  gameArchiveProvider: "dist/gamearchives/GameArchiveInspector.js",
  renpyContracts: "dist/contracts/renpy/renpyToolContracts.js",
  renpyProvider: "dist/renpy/RenpyScriptInspector.js",
  rpgMakerContracts: "dist/contracts/rpgmaker/rpgMakerToolContracts.js",
  rpgMakerProvider: "dist/rpgmaker/RpgMakerInspector.js",
  gameMakerContracts: "dist/contracts/gamemaker/gameMakerToolContracts.js",
  gameMakerProvider: "dist/gamemaker/GameMakerInspector.js",
  x64dbgContracts: "dist/contracts/x64dbg/x64dbgToolContracts.js",
  x64dbgProvider: "dist/x64dbg/X64dbgInspector.js",
  wasmModuleContracts: "dist/contracts/wasmmodule/wasmModuleToolContracts.js",
  wasmModuleProvider: "dist/wasmmodule/WasmModuleInspector.js",
  mobsfContracts: "dist/contracts/mobsf/mobsfToolContracts.js",
  mobsfProvider: "dist/mobsf/MobsfInspector.js",
  luaContracts: "dist/contracts/lua/luaToolContracts.js",
  luaProvider: "dist/lua/LuaInspector.js",
  dataBlobContracts: "dist/contracts/blob/dataBlobToolContracts.js",
  dataBlobProvider: "dist/blob/BlobInspector.js",
  godotContracts: "dist/contracts/godot/godotToolContracts.js",
  godotProvider: "dist/godot/GodotInspector.js",
  protocolContracts: "dist/contracts/protocol/protocolToolContracts.js",
  protocolProvider: "dist/protocol/ProtocolFieldsInspector.js",
  binaryDiffContracts: "dist/contracts/bindiff/binaryDiffToolContracts.js",
  binaryDiffProvider: "dist/bindiff/BinaryDiffInspector.js",
  libraryIdentificationContracts:
    "dist/contracts/libid/libraryIdentificationToolContracts.js",
  libraryIdentificationProvider: "dist/libid/LibraryIdentifier.js",
  evmContracts: "dist/contracts/evm/evmToolContracts.js",
  evmProvider: "dist/evm/EvmoleRelease.js",
  artifactContracts: "dist/contracts/artifactToolContracts.js",
  managedContracts: "dist/contracts/managed/managedToolContracts.js",
  firmwareContracts: "dist/contracts/firmware/firmwareToolContracts.js",
  firmwareProvider: "dist/firmware/FirmwareRelease.js",
  androidContracts: "dist/contracts/android/androidToolContracts.js",
  androidProvider: "dist/android/JadxRelease.js",
  apktoolContracts: "dist/contracts/apktool/apktoolToolContracts.js",
  apktoolProvider: "dist/apktool/ApktoolProvider.js",
  jebContracts: "dist/contracts/jeb/jebToolContracts.js",
  jebProvider: "dist/jeb/JebProvider.js",
  adbContracts: "dist/contracts/adb/adbToolContracts.js",
  adbProvider: "dist/adb/AdbProvider.js",
  managedWorkflowContracts:
    "dist/contracts/managed/managedWorkflowToolContracts.js",
  browserContracts: "dist/contracts/browserToolContracts.js",
  webRuntimeContracts: "dist/contracts/webRuntimeToolContracts.js",
  webNetworkCaptureContracts:
    "dist/contracts/webNetworkCaptureToolContracts.js",
  webNetworkCaptureProvider: "dist/browser/history/CaptureRelease.js",
  browserScenarioContracts: "dist/contracts/browserScenarioToolContracts.js",
  electronContracts: "dist/contracts/javascript/electronToolContracts.js",
  javascriptRuntimeObservationContracts:
    "dist/contracts/javascript/javascriptRuntimeObservationToolContracts.js",
  applicationContracts: "dist/contracts/applicationToolContracts.js",
  analysisViewContracts: "dist/contracts/analysisViewToolContracts.js",
  webScriptContracts: "dist/contracts/webScriptToolContracts.js",
  javascriptRecoveryContracts:
    "dist/contracts/javascript/javascriptRecoveryToolContracts.js",
  javascriptRecoveryProvider: "dist/javascript/recovery/WakaruRelease.js",
  supportedClients: "dist/application/SupportedClients.js",
  hopperProvider: "dist/hopper/HopperProviderCapabilities.js",
  ghidraProvider: "dist/ghidra/GhidraProviderCapabilities.js",
  idaProvider: "dist/ida/IdaProviderCapabilities.js",
  nativeProvider: "dist/native/NativeMacOSProviderMetadata.js",
  artifactProviders: "dist/application/InvestigationProviders.js",
  browserIdentities: "dist/browser/providerIdentities.js",
  v8InspectorProvider: "dist/inspector/providerIdentity.js",
  evidence: "dist/domain/evidence.js",
  evidenceBundle: "dist/domain/evidenceBundle.js",
  evidenceCompletion: "dist/domain/evidenceCompletionLedger.js",
  completionGeneration: "dist/domain/completionLedgerGeneration.js",
  processCapture: "dist/domain/process/processCapture.js",
  analysisSnapshot: "dist/domain/analysisSnapshot.js",
  artifactGraph: "dist/domain/artifactGraph.js",
  browserObservation: "dist/domain/browserObservation.js",
  browserScenario: "dist/domain/browserScenario.js",
  browserScenarioCapture: "dist/domain/browserScenarioCapture.js",
  browserScenarioDiff: "dist/domain/browserScenarioDiff.js",
  browserSession: "dist/domain/browserSession.js",
  electronObservation: "dist/domain/javascript/electronObservation.js",
  electronActiveObservation:
    "dist/domain/javascript/electronActiveObservation.js",
  javascriptRuntimeObservation:
    "dist/domain/javascript/javascriptRuntimeObservation.js",
  webBundleAnalysis: "dist/domain/webBundleAnalysis.js",
  webCaptureDiff: "dist/domain/webCaptureDiff.js",
  managedArtifact: "dist/domain/managed/managedArtifact.js",
  managedComparison: "dist/domain/managed/managedMemberComparison.js",
  managedNativeVerification: "dist/domain/managed/managedNativeVerification.js",
  webMcpDiscovery: "dist/domain/webMcpDiscovery.js",
  webScreenshot: "dist/domain/webScreenshot.js",
  javascriptApplicationGraph:
    "dist/domain/javascript/javascriptApplicationGraph.js",
  javascriptApplicationAnalysis:
    "dist/domain/javascript/javascriptApplicationAnalysis.js",
  javascriptSemanticGraph: "dist/domain/javascript/javascriptSemanticGraph.js",
  javascriptSemanticQuery:
    "dist/domain/javascript/javascriptSemanticQuerySchemas.js",
  javascriptSemanticTrace:
    "dist/domain/javascript/javascriptSemanticTraceSchemas.js",
  javascriptFeatureTrace:
    "dist/domain/javascript/javascriptFeatureTraceSchemas.js",
  javascriptVersionComparison:
    "dist/domain/javascript/javascriptApplicationVersionComparisonSchemas.js",
  reconstructionVerification:
    "dist/domain/reconstructionVerificationSchemas.js",
  residualUnknown: "dist/domain/residualUnknown.js",
};

/** Load every compiled source module referenced by the catalog. */
export const loadSources = async (root) =>
  Object.fromEntries(
    await Promise.all(
      Object.entries(SOURCE_PATHS).map(async ([key, path]) => [
        key,
        await load(root, path),
      ]),
    ),
  );
