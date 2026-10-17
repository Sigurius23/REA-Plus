import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { LibraryIdentificationPort } from "./LibraryIdentificationPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
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
    const input = identifyLibraryFunctionsInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const relative = [
      ...(isAbsolute(input.data.path) ? [] : [["path"]]),
      ...input.data.libraries.flatMap((path, index) =>
        isAbsolute(path) ? [] : [["libraries", index]],
      ),
    ];
    if (relative.length > 0)
      return err(
        new AnalysisInputError(
          OPERATION,
          undefined,
          relative.map((path) => ({
            path,
            reason: "invalid_format" as const,
            message: "Expected an absolute filesystem path on this host.",
          })),
        ),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = libraryIdentificationSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.file.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Library identification returned malformed data, changed the selected file or libraries, or returned a different view or page than requested.",
        ),
      );
    return ok(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: Object.fromEntries(
          Object.entries(input.data).filter(([, value]) => value !== undefined),
        ) as Readonly<Record<string, JsonValue>>,
        result: report.data,
        ...(execution.rawResult === null
          ? {}
          : { rawResult: execution.rawResult }),
        confidence: "inferred",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
    );
  }
}
