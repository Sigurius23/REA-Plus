import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { Il2CppMetadataPort } from "./Il2CppMetadataPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  IL2CPP_METADATA_VIEWS,
  il2cppMetadataSchema,
  inspectIl2CppMetadataInputSchema,
  type Il2CppMetadata,
  type InspectIl2CppMetadataInput,
} from "../../domain/il2cpp/il2cppMetadata.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import type { JsonValue } from "../../domain/jsonValue.js";
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
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectIl2CppMetadataInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const relative = (["metadata_path", "binary_path"] as const).filter(
      (field) => {
        const value = input.data[field];
        return value !== undefined && !isAbsolute(value);
      },
    );
    if (relative.length > 0)
      return err(
        new AnalysisInputError(
          OPERATION,
          undefined,
          relative.map((field) => ({
            path: [field],
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
    const report = il2cppMetadataSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.data) ||
      execution.subject?.path !== input.data.metadata_path ||
      execution.subject.sha256 !== report.data.metadata.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "r2unity adapter returned malformed data, changed a selected file identity or returned a different page than requested.",
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
        confidence: "derived",
        locations: execution.locations,
        limitations: execution.limitations,
      }),
    );
  }
}
