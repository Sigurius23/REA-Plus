import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { inspectSingleArtifact } from "../application/ArtifactInspection.js";
import type { MinidumpPort } from "../application/minidump/MinidumpPort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  minidumpSchema,
  type InspectMinidumpInput,
} from "../domain/minidump/minidump.js";
import type { Result } from "../domain/result.js";
import { MinidumpFormatError } from "./MinidumpFile.js";
import {
  buildMinidumpReport,
  MinidumpThreadNotFound,
} from "./MinidumpReport.js";

const OPERATION = "inspect_minidump";

export const MINIDUMP_PROVIDER_IDENTITY: ProviderIdentity = {
  id: "minidump-reader",
  name: "REA+ minidump reader",
  version: "1",
};

const LIMITATIONS = [
  "The stack scan reports stack slots that point into module images; it is the classic return-address heuristic, not unwinding, and can include stale values or data pointers.",
  "Module identities come from the dump's own records (paths, code and debug identifiers); REA+ does not fetch symbols or confirm that files on this host match them.",
  "Register sets are decoded for x86, AMD64, ARM64 and 32-bit ARM contexts; other architectures report addresses only where the dump records them outside a context.",
  "Streams REA+ does not interpret are listed with their sizes; malformed streams are reported and the rest of the dump is still decoded.",
];

const SPEC = {
  operation: OPERATION,
  identity: MINIDUMP_PROVIDER_IDENTITY,
  /** Full-memory dumps are read into memory up to this size. */
  maxFileBytes: 2 * 1024 * 1024 * 1024,
  schema: minidumpSchema,
  limitations: LIMITATIONS,
  fieldErrors: [{ error: MinidumpThreadNotFound, field: "thread_id" }],
  formatErrors: [MinidumpFormatError],
  notReadable: "Not a readable minidump",
} as const;

/** Read caller-selected minidumps; nothing is loaded, executed or symbolized. */
export const createMinidumpInspector = (): MinidumpPort => {
  const inspect = inspectSingleArtifact<InspectMinidumpInput>(
    SPEC,
    (selected, input, limitations) =>
      buildMinidumpReport(selected.bytes, input, selected, limitations),
  );
  return {
    close: () => Promise.resolve(),
    inspect: (
      input: InspectMinidumpInput,
      options?: ExecutionOptions,
    ): Promise<Result<AnalysisExecution, AnalysisError>> =>
      inspect(input, options),
  };
};
