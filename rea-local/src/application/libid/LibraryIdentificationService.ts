import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parseInputWithAbsolutePaths,
  type InputPathField,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { LibraryIdentificationPort } from "./LibraryIdentificationPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
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
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parseInputWithAbsolutePaths(
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
    );
    if (!input.ok) return input;
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = libraryIdentificationSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Library identification returned malformed data, changed the selected file or libraries, or returned a different view or page than requested.",
        ),
      );
    return ok(
      inlineReportEvidence(
        OPERATION,
        execution,
        input.value,
        report.data,
        "inferred",
      ),
    );
  }
}
