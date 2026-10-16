import { WASM_TOOL_CONTRACTS } from "./wasm/wasmToolContracts.js";
import { JVM_TOOL_CONTRACTS } from "./jvm/jvmToolContracts.js";
import { IL2CPP_TOOL_CONTRACTS } from "./il2cpp/il2cppToolContracts.js";
import { COVERAGE_TOOL_CONTRACTS } from "./drcov/coverageToolContracts.js";
import { MINIDUMP_TOOL_CONTRACTS } from "./minidump/minidumpToolContracts.js";
import { LOGIC_TOOL_CONTRACTS } from "./logic/logicToolContracts.js";
import { PATTERN_TOOL_CONTRACTS } from "./patterns/patternToolContracts.js";
import { UNITY_TOOL_CONTRACTS } from "./unity/unityToolContracts.js";
import { GAME_ARCHIVE_TOOL_CONTRACTS } from "./gamearchives/gameArchiveToolContracts.js";
import { RENPY_TOOL_CONTRACTS } from "./renpy/renpyToolContracts.js";
import { RPG_MAKER_TOOL_CONTRACTS } from "./rpgmaker/rpgMakerToolContracts.js";
import { GAMEMAKER_TOOL_CONTRACTS } from "./gamemaker/gameMakerToolContracts.js";
import { X64DBG_TOOL_CONTRACTS } from "./x64dbg/x64dbgToolContracts.js";
import { WASM_MODULE_TOOL_CONTRACTS } from "./wasmmodule/wasmModuleToolContracts.js";
import { MOBSF_TOOL_CONTRACTS } from "./mobsf/mobsfToolContracts.js";
import { EVM_TOOL_CONTRACTS } from "./evm/evmToolContracts.js";
import { ANALYSIS_VIEW_TOOL_CONTRACTS } from "./analysisViewToolContracts.js";
import { BINARY_DIAGNOSTICS_TOOL_CONTRACTS } from "./native/binaryDiagnosticsToolContracts.js";
import { NATIVE_TOOL_CONTRACTS } from "./native/nativeToolContracts.js";
import { ARTIFACT_TOOL_CONTRACTS } from "./artifactToolContracts.js";
import { MANAGED_TOOL_CONTRACTS } from "./managed/managedToolContracts.js";
import { FIRMWARE_TOOL_CONTRACTS } from "./firmware/firmwareToolContracts.js";
import { ANDROID_TOOL_CONTRACTS } from "./android/androidToolContracts.js";
import { APKTOOL_TOOL_CONTRACTS } from "./apktool/apktoolToolContracts.js";
import { JEB_TOOL_CONTRACTS } from "./jeb/jebToolContracts.js";
import { ADB_TOOL_CONTRACTS } from "./adb/adbToolContracts.js";
import { MANAGED_WORKFLOW_TOOL_CONTRACTS } from "./managed/managedWorkflowToolContracts.js";
import { BROWSER_PROVIDER_TOOL_CONTRACTS } from "./browserProviderToolContracts.js";
import { ELECTRON_TOOL_CONTRACTS } from "./javascript/electronToolContracts.js";
import { JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS } from "./javascript/javascriptRuntimeObservationToolContracts.js";
import { APPLICATION_TOOL_CONTRACTS } from "./applicationToolContracts.js";
import { WEB_SCRIPT_TOOL_CONTRACTS } from "./webScriptToolContracts.js";
import { WEB_RUNTIME_TOOL_CONTRACTS } from "./webRuntimeToolContracts.js";
import { WEB_NETWORK_CAPTURE_TOOL_CONTRACTS } from "./webNetworkCaptureToolContracts.js";
import { JAVASCRIPT_RECOVERY_TOOL_CONTRACTS } from "./javascript/javascriptRecoveryToolContracts.js";
import { OFFICIAL_TOOL_CONTRACTS } from "./officialToolContracts.js";
import { ENHANCED_TOOL_CONTRACTS } from "./enhancedToolContracts.js";
import { SESSION_TOOL_CONTRACTS } from "./sessionToolContracts.js";
import { EXTERNAL_MCP_TOOL_CONTRACTS } from "./externalMcp/externalMcpToolContracts.js";
import { MOBILE_RUNTIME_TOOL_CONTRACTS } from "./mobileRuntime/mobileRuntimeToolContracts.js";

/** Complete ordered public inventory used by registration and verification. */
export const TOOL_CONTRACTS = [
  ...OFFICIAL_TOOL_CONTRACTS,
  ...ENHANCED_TOOL_CONTRACTS,
  ...NATIVE_TOOL_CONTRACTS,
  ...BINARY_DIAGNOSTICS_TOOL_CONTRACTS,
  ...ANALYSIS_VIEW_TOOL_CONTRACTS,
  ...ARTIFACT_TOOL_CONTRACTS,
  ...EVM_TOOL_CONTRACTS,
  ...WASM_TOOL_CONTRACTS,
  ...JVM_TOOL_CONTRACTS,
  ...IL2CPP_TOOL_CONTRACTS,
  ...COVERAGE_TOOL_CONTRACTS,
  ...MINIDUMP_TOOL_CONTRACTS,
  ...LOGIC_TOOL_CONTRACTS,
  ...PATTERN_TOOL_CONTRACTS,
  ...UNITY_TOOL_CONTRACTS,
  ...GAME_ARCHIVE_TOOL_CONTRACTS,
  ...RENPY_TOOL_CONTRACTS,
  ...RPG_MAKER_TOOL_CONTRACTS,
  ...GAMEMAKER_TOOL_CONTRACTS,
  ...X64DBG_TOOL_CONTRACTS,
  ...WASM_MODULE_TOOL_CONTRACTS,
  ...MOBSF_TOOL_CONTRACTS,
  ...MANAGED_TOOL_CONTRACTS,
  ...ANDROID_TOOL_CONTRACTS,
  ...APKTOOL_TOOL_CONTRACTS,
  ...JEB_TOOL_CONTRACTS,
  ...ADB_TOOL_CONTRACTS,
  ...FIRMWARE_TOOL_CONTRACTS,
  ...MANAGED_WORKFLOW_TOOL_CONTRACTS,
  ...BROWSER_PROVIDER_TOOL_CONTRACTS,
  ...ELECTRON_TOOL_CONTRACTS,
  ...JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS,
  ...APPLICATION_TOOL_CONTRACTS,
  ...WEB_SCRIPT_TOOL_CONTRACTS,
  ...WEB_RUNTIME_TOOL_CONTRACTS,
  ...WEB_NETWORK_CAPTURE_TOOL_CONTRACTS,
  ...JAVASCRIPT_RECOVERY_TOOL_CONTRACTS,
  ...SESSION_TOOL_CONTRACTS,
  ...EXTERNAL_MCP_TOOL_CONTRACTS,
  ...MOBILE_RUNTIME_TOOL_CONTRACTS,
] as const;

/** Resolve a public contract by name while retaining its exact schema types. */
export const toolContract = <
  Name extends (typeof TOOL_CONTRACTS)[number]["name"],
>(
  name: Name,
): Extract<(typeof TOOL_CONTRACTS)[number], { readonly name: Name }> => {
  const contract = TOOL_CONTRACTS.find(
    (
      candidate,
    ): candidate is Extract<
      (typeof TOOL_CONTRACTS)[number],
      { readonly name: Name }
    > => candidate.name === name,
  );
  if (contract === undefined) throw new Error(`Missing tool contract: ${name}`);
  return contract;
};
