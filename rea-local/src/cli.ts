import { registerWasmCommands } from "./cli/wasmCommands.js";
import { registerJvmCommands } from "./cli/jvmCommands.js";
import { registerIl2CppCommands } from "./cli/il2cppCommands.js";
import { registerCoverageCommands } from "./cli/coverageCommands.js";
import { registerMinidumpCommands } from "./cli/minidumpCommands.js";
import { registerLogicCommands } from "./cli/logicCommands.js";
import { registerPatternCommands } from "./cli/patternCommands.js";
import { registerUnityCommands } from "./cli/unityCommands.js";
import { registerGameArchiveCommands } from "./cli/gameArchiveCommands.js";
import { registerRenpyCommands } from "./cli/renpyCommands.js";
import { registerRpgMakerCommands } from "./cli/rpgMakerCommands.js";
import { registerGameMakerCommands } from "./cli/gameMakerCommands.js";
import { registerX64dbgCommands } from "./cli/x64dbgCommands.js";
import { registerWasmModuleCommands } from "./cli/wasmModuleCommands.js";
import { registerMobsfCommands } from "./cli/mobsfCommands.js";
import { registerLuaCommands } from "./cli/luaCommands.js";
import { registerDataBlobCommands } from "./cli/dataBlobCommands.js";
import { registerGodotCommands } from "./cli/godotCommands.js";
import { registerProtocolCommands } from "./cli/protocolCommands.js";
import { snapshotEnvironment } from "./process/snapshotEnvironment.js";
import { createDirectAnalysis } from "./composition/directAnalysis.js";
import { registerEvmCommands } from "./cli/evmCommands.js";
import { registerAnalysisViewCommands } from "./cli/analysisViewCommands.js";
import { registerBinaryDiagnosticsCommands } from "./cli/binaryDiagnosticsCommands.js";
import { Cli } from "incur";

import { createLogger, parseLogLevel } from "./logger.js";
import { PRODUCT_IDENTITY } from "./identity.js";
import { npxRegistrationCommand } from "./application/ClientRegistrationIdentity.js";
import { registerSetupCommands } from "./cli/setupCommands.js";
import { registerCoreAnalysisCommands } from "./cli/coreAnalysisCommands.js";
import { registerUtilityCommands } from "./cli/utilityCommands.js";
import { registerArtifactCommands } from "./cli/artifactCommands.js";
import { registerManagedCommands } from "./cli/managedCommands.js";
import { registerFirmwareCommands } from "./cli/firmwareCommands.js";
import { registerAndroidCommands } from "./cli/androidCommands.js";
import { registerApktoolCommands } from "./cli/apktoolCommands.js";
import { registerJebCommands } from "./cli/jebCommands.js";
import { registerAdbCommands } from "./cli/adbCommands.js";
import { registerEvidenceCommands } from "./cliEvidenceCommands.js";
import { registerProcessCommands } from "./cli/processCommands.js";
import { registerBrowserCommands } from "./cli/browserCommands.js";
import { registerWebScriptCommands } from "./cli/webScriptCommands.js";
import { registerWebModuleCommands } from "./cli/webModuleCommands.js";
import { registerWebSourceLocationCommands } from "./cli/webSourceLocationCommands.js";
import { registerWebRuntimeCommands } from "./cli/webRuntimeCommands.js";
import { registerWebNetworkCaptureCommands } from "./cli/webNetworkCaptureCommands.js";
import { registerJavaScriptRecoveryCommands } from "./cli/javascriptRecoveryCommands.js";
import { registerAdvancedBrowserCommands } from "./cli/browserAdvancedCommands.js";
import { registerBrowserScenarioCommands } from "./cliBrowserScenarioCommands.js";
import { registerElectronCommands } from "./cli/electronCommands.js";
import { registerJavaScriptRuntimeObservationCommands } from "./cliJavaScriptRuntimeCommands.js";
import { registerApplicationCommands } from "./cli/applicationCommands.js";
import { presentOmittableDefaults } from "./cli/omittableDefaults.js";
import type { CliInstance } from "./cli/types.js";
import {
  streamCliCommandResults,
  type CliResultOutput,
} from "./cli/streamedJsonOutput.js";

/**
 * Build the one-shot Incur CLI without starting Hopper at import time.
 * Analysis commands acquire and close their own sessions; bare `mcp` and
 * `--mcp` are intercepted by the executable dispatcher before this module loads.
 */
export const createCli = (
  selectedEnvironment: Readonly<
    Record<string, string | undefined>
  > = process.env,
  resultOutput?: CliResultOutput,
): CliInstance => {
  const environment = snapshotEnvironment(selectedEnvironment);
  const analysis = createDirectAnalysis(environment);
  const logger = createLogger(
    "cli",
    environment.REA_LOG_LEVEL === undefined
      ? "silent"
      : parseLogLevel(environment.REA_LOG_LEVEL),
  );
  const cli = Cli.create(PRODUCT_IDENTITY.cliBinary, {
    version: PRODUCT_IDENTITY.packageVersion,
    description: "Reverse engineer anything from your terminal or agent.",
    mcp: {
      command: npxRegistrationCommand().join(" "),
      instructions:
        "Ask what software, artifact, protocol, or behavior the user wants to understand, then choose the available investigation capabilities that can produce evidence.",
    },
    sync: false,
  });

  registerSetupCommands(cli, logger, environment);
  registerCoreAnalysisCommands(cli, logger, analysis.runDirectAnalysis);
  registerUtilityCommands(cli, logger, environment, analysis);
  registerWasmCommands(cli, logger, environment);
  registerJvmCommands(cli, logger, environment);
  registerIl2CppCommands(cli, logger, environment);
  registerCoverageCommands(cli, logger);
  registerMinidumpCommands(cli, logger);
  registerLogicCommands(cli, logger, environment);
  registerPatternCommands(cli, logger);
  registerUnityCommands(cli, logger);
  registerGameArchiveCommands(cli, logger);
  registerRenpyCommands(cli, logger);
  registerRpgMakerCommands(cli, logger);
  registerGameMakerCommands(cli, logger);
  registerX64dbgCommands(cli, logger);
  registerWasmModuleCommands(cli, logger);
  registerMobsfCommands(cli, logger);
  registerLuaCommands(cli, logger);
  registerDataBlobCommands(cli, logger);
  registerGodotCommands(cli, logger, environment);
  registerProtocolCommands(cli, logger);
  registerEvmCommands(cli, logger, environment);
  registerArtifactCommands(cli, logger, analysis.runProviderAnalysis);
  registerManagedCommands(cli, logger, analysis.runProviderAnalysis);
  registerAndroidCommands(cli, logger, environment);
  registerApktoolCommands(cli, logger, environment);
  registerJebCommands(cli, logger, environment);
  registerAdbCommands(cli, logger, environment);
  registerFirmwareCommands(cli, logger, environment);
  registerBinaryDiagnosticsCommands(cli, logger, environment);
  registerAnalysisViewCommands(cli, logger);
  registerEvidenceCommands(cli, logger);
  registerProcessCommands(cli, logger, environment);
  registerBrowserCommands(cli, logger);
  registerWebScriptCommands(cli, logger);
  registerWebModuleCommands(cli, logger, environment);
  registerWebSourceLocationCommands(cli, logger, environment);
  registerWebRuntimeCommands(cli, logger);
  registerWebNetworkCaptureCommands(cli, logger, environment);
  registerJavaScriptRecoveryCommands(cli, logger, environment);
  registerAdvancedBrowserCommands(cli, logger);
  registerBrowserScenarioCommands(cli, logger, environment);
  registerElectronCommands(cli, logger, environment);
  registerJavaScriptRuntimeObservationCommands(cli, logger);
  registerApplicationCommands(cli, logger);
  presentOmittableDefaults(cli);
  if (resultOutput !== undefined) streamCliCommandResults(cli, resultOutput);
  return cli;
};
