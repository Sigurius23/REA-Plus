import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  type InputPathField,
  inspectInlineReport,
} from "../InlineReportService.js";
import type { LibraryIdentificationPort } from "./LibraryIdentificationPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Evidence } from "../../domain/evidence.js";
import type { Result } from "../../domain/result.js";
import {
  identifyLibraryFunctionsInputSchema,
  libraryIdentificationSchema,
  type IdentifyLibraryFunctionsInput,
  type LibraryIdentificationReport,
} from "../../domain/libid/libraryIdentification.js";

const OPERATION = "identify_library_functions";

/** The report must describe the selected file, libraries, view and page. */
const matchesSelection = (
  report: LibraryIdentificationReport,
  input: IdentifyLibraryFunctionsInput,
): boolean => {
  const { page } = report;
  return (
    report.file.path === input.path &&
    report.libraries.map(({ path }) => path).join("\n") ===
      input.libraries.join("\n") &&
    page.view === input.view &&
    page.status === (input.status ?? null) &&
    page.query === (input.query ?? null) &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.returned === report.functions.length &&
    report.functions.length <= input.limit &&
    (input.view === "functions" || report.functions.length === 0) &&
    (input.status === undefined ||
      report.functions.every(({ status }) => status === input.status))
  );
};

/** Shared library identification validation and typed inline Evidence for CLI/MCP. */
export class LibraryIdentificationService {
  constructor(readonly provider: LibraryIdentificationPort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

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
            identifyLibraryFunctionsInputSchema,
            rawInput,
            (input) => [
              [["path"], input.path],
              ...input.libraries.map((path, index): InputPathField => [
                ["libraries", index],
                path,
              ]),
            ],
          ),
        reportSchema: libraryIdentificationSchema,
        matchesSelection,
        inputPath: ({ path }) => path,
        reportPath: (report) => report.file.path,
        reportSha256: (report) => report.file.sha256,
        malformedMessage:
          "Library identification returned malformed data, changed the selected file or libraries, or returned a different view or page than requested.",
        confidence: "inferred",
      },
      (input, invocation) => this.provider.inspect(input, invocation),
      rawInput,
      options,
    );
  }
}
