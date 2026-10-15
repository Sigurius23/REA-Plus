import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { JvmArtifactPort } from "./JvmArtifactPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectJvmArtifactInputSchema,
  jvmArtifactSchema,
} from "../../domain/jvm/jvmArtifact.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_jvm_artifact";

/** Shared JVM artifact validation and typed inline Evidence for CLI/MCP. */
export class JvmArtifactService {
  constructor(readonly provider: JvmArtifactPort) {}

  /** Join provider cleanup during shutdown or an explicit retry. */
  close(): Promise<void> {
    return this.provider.close();
  }

  /** Preserve the selected artifact identity and every requested class. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectJvmArtifactInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const execution = inspected.value;
    const report = jvmArtifactSchema.safeParse(execution.result);
    const requested = new Set(input.data.classes);
    if (
      !report.success ||
      report.data.artifact.path !== input.data.path ||
      execution.subject?.path !== input.data.path ||
      execution.subject.sha256 !== report.data.artifact.sha256 ||
      report.data.decompiled.some(
        ({ text, sha256 }) =>
          createHash("sha256").update(text).digest("hex") !== sha256,
      ) ||
      ![...requested].every((name) =>
        report.data.decompiled.some(({ requested: names }) =>
          names.includes(name),
        ),
      )
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "CFR adapter returned malformed data, changed the selected artifact identity or omitted a requested class.",
        ),
      );
    return ok(
      createEvidence(execution.subject, execution.provider, {
        operation: OPERATION,
        parameters: input.data,
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
