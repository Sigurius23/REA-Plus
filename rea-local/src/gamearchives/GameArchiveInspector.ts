import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { GameArchivePort } from "../application/gamearchives/GameArchivePort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  gameArchiveSchema,
  type InspectGameArchiveInput,
} from "../domain/gamearchives/gameArchive.js";
import type { Result } from "../domain/result.js";
import {
  buildGameArchiveReport,
  GameArchiveEntryNotFound,
} from "./GameArchiveReport.js";
import { GameArchiveError } from "./GameArchiveTypes.js";

const OPERATION = "inspect_game_archive";

export const GAME_ARCHIVE_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "game-archive-reader",
  name: "REA+ game archive reader",
  version: "1",
};

const LIMITATIONS = [
  "Reads Godot packs (formats 1-3, standalone or appended to an exported executable), Ren'Py RPA-2.0/3.0/3.2/4.0 archives, Valve VPK 1/2 directories, Doom IWAD/PWAD files and Unreal Engine paks (versions 1-11); Unreal IoStore (.utoc/.ucas) and other engines' archives are refused.",
  "Ren'Py indexes are Python pickles; REA+ decodes only containers, strings, bytes and integers and refuses anything that would import or call code.",
  "Encrypted Godot directories, encrypted pak indexes and encrypted entries are reported but not decrypted; Oodle-compressed pak entries and VPK data in sibling _NNN.vpk chunks are listed without preview or checksum check.",
  "Nothing is extracted, mounted or executed; previews return at most 64 KiB of one entry.",
];

const SPEC = {
  operation: OPERATION,
  identity: GAME_ARCHIVE_PROVIDER_IDENTITY,
  /** Archives (or executables embedding a pack) are read into memory up to this size. */
  maxFileBytes: 2 * 1024 * 1024 * 1024,
  schema: gameArchiveSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: GameArchiveEntryNotFound, field: "entry" }],
  formatErrors: [GameArchiveError],
  notReadable: "Not a readable game archive",
} as const;

/** Read caller-selected game archives; nothing is extracted or run. */
export const createGameArchiveInspector = (): GameArchivePort => {
  const inspect = inspectSingleArtifact<InspectGameArchiveInput>(
    SPEC,
    (selected, input, limitations) =>
      buildGameArchiveReport(selected.bytes, input, selected, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectGameArchiveInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> =>
      inspect(input, options),
  };
};
