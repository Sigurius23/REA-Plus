import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  inspectInlineReport,
} from "../InlineReportService.js";
import type { Il2CppMetadataPort } from "./Il2CppMetadataPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import {
  IL2CPP_METADATA_VIEWS,
  il2cppMetadataSchema,
  inspectIl2CppMetadataInputSchema,
  type Il2CppMetadata,
  type InspectIl2CppMetadataInput,
} from "../../domain/il2cpp/il2cppMetadata.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_il2cpp_metadata";

const VIEW_FIELDS = {
  classes: "classes",
  string_literals: "string_literals",
  interop: "interop",
  assemblies: "assemblies",
} as const;

/** The report must describe exactly the selected files and requested page. */
const matchesSelection = (
  report: Il2CppMetadata,
  input: InspectIl2CppMetadataInput,
): boolean => {
  const { page } = report;
  const returned = report[VIEW_FIELDS[input.view]].length;
  return (
    report.metadata.path === input.metadata_path &&
    (report.native_binary?.path ?? null) === (input.binary_path ?? null) &&
    page.view === input.view &&
    page.query === (input.query ?? null) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.returned === returned &&
    returned <= input.limit &&
    returned ===
      Math.max(0, Math.min(input.limit, page.total - input.offset)) &&
    IL2CPP_METADATA_VIEWS.every(
      (view) => view === input.view || report[VIEW_FIELDS[view]].length === 0,
    )
  );
};

/** Shared IL2CPP metadata validation and typed inline Evidence for CLI/MCP. */
export class Il2CppMetadataService {
  constructor(readonly provider: Il2CppMetadataPort) {}

  /** Join provider cleanup during shutdown or an explicit retry. */
  close(): Promise<void> {
    return this.provider.close();
  }

  /** Preserve both file identities and the requested page. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return inspectInlineReport(
      {
        operation: OPERATION,
        parseInput: (rawInput) =>
          parseInputWithAbsolutePaths(
            OPERATION,
            inspectIl2CppMetadataInputSchema,
            rawInput,
            (input) => [
              [["metadata_path"], input.metadata_path],
              [["binary_path"], input.binary_path],
            ],
          ),
        reportSchema: il2cppMetadataSchema,
        matchesSelection,
        inputPath: ({ metadata_path }) => metadata_path,
        reportPath: (report) => report.metadata.path,
        reportSha256: (report) => report.metadata.sha256,
        malformedMessage:
          "r2unity adapter returned malformed data, changed a selected file identity or returned a different page than requested.",
        confidence: "derived",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
