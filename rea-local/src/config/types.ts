import type { LogLevel } from "../logger.js";
import type { ReferenceSourcePolicy } from "../domain/referenceSourcePolicy.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";

import type { GhidraLanguageOverride } from "./ghidraLanguageOverride.js";
import type { McpInputSchemaProfile } from "./mcpInputSchemaProfile.js";
import type { Radare2AnalysisLevel } from "./radare2Settings.js";

export interface AppConfig {
  readonly mcpMaxResponseBytes?: number;
  readonly mcpInputSchemaProfile?: McpInputSchemaProfile;
  readonly analysisProvider: AnalysisProviderSelector;
  readonly idaMcpConfigPath?: string;
  readonly idaOfficialMcpConfigPath?: string;
  readonly externalMcpConfigPath?: string;
  readonly ghidraInstallDir: string | undefined;
  readonly ghidraJavaHome: string | undefined;
  readonly ghidraStartupTimeoutMs: number;
  readonly ghidraLanguageOverride?: GhidraLanguageOverride;
  readonly ghidraSeedFile?: string;
  readonly ghidraNativeAotJar?: string;
  readonly ilspyCmdPath: string | undefined;
  /** Absolute caller-supplied radare2 executable; unset leaves radare2 unconfigured. */
  readonly radare2Path?: string;
  /** Defaults to aaa when omitted by programmatic callers. */
  readonly radare2AnalysisLevel?: Radare2AnalysisLevel;
  readonly radare2AnalysisTimeoutMs?: number;
  readonly fridaPythonPath: string | undefined;
  readonly objectionCommandPath: string | undefined;
  readonly hopperLauncherPath: string;
  readonly hopperTargetPath: string | undefined;
  readonly hopperTargetKind: "executable" | "database";
  readonly hopperLoaderArgs: readonly string[];
  readonly logLevel: LogLevel;
  readonly referenceSourcePolicy: ReferenceSourcePolicy;
}
