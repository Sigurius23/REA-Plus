import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import type { AppConfig } from "../config/types.js";
import type { BinarySession } from "../application/binary/BinarySession.js";
import { HopperProvider } from "../hopper/HopperProvider.js";
import { GhidraProvider } from "../ghidra/GhidraProvider.js";
import { IdaProvider } from "../ida/IdaProvider.js";
import { OfficialIdaProvider } from "../ida/OfficialIdaProvider.js";
import { BinaryNinjaProvider } from "../binaryNinja/BinaryNinjaProvider.js";
import { Radare2Provider } from "../radare2/Radare2Provider.js";
import type { Logger } from "pino";
import { auxiliaryAnalysisProviderDeclarations } from "./auxiliaryAnalysisProviders.js";
import { AnalysisProviderRegistry } from "../application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../application/binary/BinarySessionComposition.js";
import { LazyAnalysisProvider } from "../application/binary/LazyAnalysisProvider.js";
import { ManagedStaticProvider } from "../dotnet/ManagedStaticProvider.js";

/**
 * Compose the target-switching runtime shared directly by CLI and MCP adapters.
 * This is the sole production wiring point, so both adapters share identical
 * provider selection, profile, lifecycle, and Evidence semantics.
 */
export const createBinarySession = (
  config: AppConfig,
  logger: Logger,
  selectedEnvironment: Readonly<NodeJS.ProcessEnv>,
): BinarySession => {
  const environment = snapshotEnvironment(selectedEnvironment);
  const hopper = new HopperProvider(config, logger, environment);
  const ghidra = new GhidraProvider(config, logger, environment);
  const ida = new IdaProvider(config, environment);
  const officialIda = new OfficialIdaProvider(config, environment);
  const binaryNinja = new BinaryNinjaProvider(config, environment);
  const radare2 = new Radare2Provider(config, environment);
  return composeBinarySession(
    new AnalysisProviderRegistry(
      [hopper, ghidra, ida, officialIda, binaryNinja, radare2],
      config.analysisProvider,
    ),
    auxiliaryAnalysisProviderDeclarations(environment).map(
      (declaration) => new LazyAnalysisProvider(declaration),
    ),
  );
};

/** Compose an execution-free managed session without native provider selection. */
export const createManagedBinarySession = (): BinarySession =>
  composeBinarySession(new AnalysisProviderRegistry([]), [
    new ManagedStaticProvider(),
  ]);
