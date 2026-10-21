import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { GodotFilePort } from "../application/godot/GodotFilePort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  godotFileSchema,
  type InspectGodotFileInput,
} from "../domain/godot/godotFile.js";
import type { Result } from "../domain/result.js";
import { GodotFormatError, GodotSelectionError } from "./GodotBytes.js";
import { buildGodotFileReport } from "./GodotReport.js";
import type { Environment } from "./GodotSelect.js";

const OPERATION = "inspect_godot_file";

export const GODOT_FILE_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "godot-file-reader",
  name: "REA+ Godot file reader",
  version: "1",
};

const LIMITATIONS = [
  "Reads Godot 3 and 4 binary resources and scenes, compiled GDScript (bytecode 12 and 13 from Godot 3, tokenizer 100 and 101 from Godot 4.3 and later), and store_var data, without loading or running them. Text resources (.tres, .tscn) and plain .gd scripts are already readable and are not parsed.",
  "Compiled GDScript keeps tokens, not comments or formatting: source is rebuilt on the original line numbers with regenerated spacing and tab indentation. Godot 3.1 and 3.2+ share bytecode 13 but not the built-in function table; 3.2+ names are used.",
  "Encrypted files (GDEC) need the game's key or password, named through key_env or password_env; REA+ does not recover keys. Encrypted pack entries and directories are not decrypted.",
  "Property values are shown as Godot's text format writes them, cut at 4000 characters; external resources are named by path, sub-resources by id.",
];

const SPEC = {
  operation: OPERATION,
  identity: GODOT_FILE_PROVIDER_IDENTITY,
  maxFileBytes: 2 * 1024 * 1024 * 1024,
  schema: godotFileSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: GodotSelectionError }],
  formatErrors: [GodotFormatError, RangeError],
  notReadable: "Not a readable Godot file",
} as const;

/** Decode a caller-selected Godot file or pack entry; nothing is loaded or run. */
export const createGodotFileInspector = (
  environment: Environment = {},
): GodotFilePort => {
  const inspect = inspectSingleArtifact<InspectGodotFileInput>(
    SPEC,
    (selected, input, limitations) =>
      buildGodotFileReport(selected, input, environment, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectGodotFileInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> =>
      inspect(input, options),
  };
};
