import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { GameMakerDataPort } from "../application/gamemaker/GameMakerDataPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  gameMakerDataSchema,
  type InspectGameMakerDataInput,
} from "../domain/gamemaker/gameMakerData.js";
import type { Result } from "../domain/result.js";
import { GameMakerFormatError } from "./GameMakerForm.js";
import { buildGameMakerReport } from "./GameMakerReport.js";

const OPERATION = "inspect_gamemaker_data";

export const GAMEMAKER_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "gamemaker-data-reader",
  name: "REA+ GameMaker data reader",
  version: "1",
};

const LIMITATIONS = [
  "Reads GameMaker Studio 1.4 to GameMaker 2024+ data files (bytecode 13-17): data.win, game.unx, game.droid, game.ios, audiogroupN.dat, or a FORM appended to a runner. GameMaker 8 executables use a different format and are not read.",
  "GameMaker Studio 2 and later store 2.0.0.0 as their version; minimum_version is inferred from which chunks exist, as UndertaleModTool does.",
  "Resource fields are limited to those at the same offsets in every version. Bytecode is listed with sizes and arguments, not disassembled or decompiled; use UndertaleModTool for that.",
  "Sounds in audio groups other than 0 play entries from audiogroupN.dat; inspect that file for them.",
];

const SPEC = {
  operation: OPERATION,
  identity: GAMEMAKER_PROVIDER_IDENTITY,
  maxFileBytes: 2 * 1024 * 1024 * 1024,
  schema: gameMakerDataSchema,
  limitations: LIMITATIONS,
  /** The parsed report carries its own limitations onto the execution. */
  reportLimitations: true,
  formatErrors: [GameMakerFormatError, RangeError],
  notReadable: "Not a readable GameMaker data file",
} as const;

/** Read a caller-selected GameMaker data file; bytecode is listed, never run. */
export const createGameMakerInspector = (): GameMakerDataPort => {
  const inspect = inspectSingleArtifact<InspectGameMakerDataInput>(
    SPEC,
    (selected, input, limitations) =>
      buildGameMakerReport(selected.bytes, input, selected, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectGameMakerDataInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> =>
      inspect(input, options),
  };
};
