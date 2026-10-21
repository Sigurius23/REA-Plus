import type { ExecutionOptions } from "../AnalysisProvider.js";
import {
  parsePathInput,
  inlineReportEvidence,
} from "../InlineReportService.js";
import type { WasmModulePort } from "./WasmModulePort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import type { Evidence } from "../../domain/evidence.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  inspectWasmModuleInputSchema,
  WASM_MODULE_VIEWS,
  wasmModuleSchema,
  type InspectWasmModuleInput,
  type WasmModuleReport,
} from "../../domain/wasmmodule/wasmModule.js";

const OPERATION = "inspect_wasm_module";

/** The report must describe the selected module, view, function filter and page. */
const matchesSelection = (
  report: WasmModuleReport,
  input: InspectWasmModuleInput,
): boolean => {
  const { page } = report;
  const rows = WASM_MODULE_VIEWS.reduce(
    (sum, view) => sum + report[view].length,
    0,
  );
  const selected = input.function;
  return (
    report.module.path === input.path &&
    page.view === input.view &&
    page.offset === input.offset &&
    page.limit === input.limit &&
    page.query === (input.query ?? null) &&
    page.function === (selected ?? null) &&
    page.returned === rows &&
    rows === report[input.view].length &&
    rows <= input.limit &&
    rows <= Math.max(0, page.total - input.offset) &&
    (selected === undefined ||
      input.view !== "functions" ||
      report.functions.every((row) =>
        typeof selected === "number"
          ? row.index === selected
          : row.name === selected,
      ))
  );
};

/** Shared WebAssembly module validation and typed inline Evidence for CLI/MCP. */
export class WasmModuleService {
  constructor(readonly provider: WasmModulePort) {}

  close(): Promise<void> {
    return this.provider.close();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = parsePathInput(
      OPERATION,
      inspectWasmModuleInputSchema,
      rawInput,
    );
    if (!input.ok) return input;
    if (input.value.view === "calls" && input.value.function === undefined)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["function"],
            reason: "invalid_value",
            message: "The calls view needs a function index or name.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.value, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = wasmModuleSchema.safeParse(execution.result);
    if (
      !report.success ||
      !matchesSelection(report.data, input.value) ||
      execution.subject?.path !== input.value.path ||
      execution.subject.sha256 !== report.data.module.sha256
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "WebAssembly reader returned malformed data, changed the selected module identity or returned a different view or page than requested.",
        ),
      );
    return ok(
      inlineReportEvidence(
        OPERATION,
        execution,
        input.value,
        report.data,
        "observed",
      ),
    );
  }
}
