import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { RenpyScriptPort } from "../application/renpy/RenpyScriptPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  renpyScriptSchema,
  type InspectRenpyScriptInput,
} from "../domain/renpy/renpyScript.js";
import type { Result } from "../domain/result.js";
import { RenpyScriptError } from "./RenpyScript.js";
import { buildRenpyScriptReport } from "./RenpyScriptReport.js";

const OPERATION = "inspect_renpy_script";

export const RENPY_SCRIPT_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "renpy-script-reader",
  name: "REA+ Ren'Py script reader",
  version: "1",
};

const LIMITATIONS = [
  "Reads compiled Ren'Py scripts (.rpyc): RPC2 files from Ren'Py 6.18 to 8.x, preferring slot 2 where dialogue carries translation identifiers, and older zlib-only files.",
  "The script is a Python pickle; REA+ records renpy.* and store.* classes as inert data and never imports or runs them. Any other class is refused.",
  "Text is reported as written in the script, with text tags, {{ and %% escapes kept; screen language, ATL and Python blocks are counted and named but not decompiled to source.",
  "Archived scripts must be read out of their .rpa first (inspect_game_archive previews entries; nothing is extracted).",
];

const SPEC = {
  operation: OPERATION,
  identity: RENPY_SCRIPT_PROVIDER_IDENTITY,
  maxFileBytes: 256 * 1024 * 1024,
  schema: renpyScriptSchema,
  limitations: LIMITATIONS,
  formatErrors: [RenpyScriptError],
  notReadable: "Not a readable Ren'Py script",
} as const;

/** Read caller-selected .rpyc files; nothing is unpickled into live objects. */
export const createRenpyScriptInspector = (): RenpyScriptPort => {
  const inspect = inspectSingleArtifact<InspectRenpyScriptInput>(
    SPEC,
    (selected, input, limitations) =>
      buildRenpyScriptReport(selected.bytes, input, selected, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectRenpyScriptInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> =>
      inspect(input, options),
  };
};
