import { redactExplicitFailure } from "../domain/explicitSensitiveFailure.js";
import { excludeCaptureCoordinates } from "../domain/webNetworkCaptureCoordinates.js";
import { redactExplicitText } from "../domain/explicitSensitiveValues.js";
import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "./AnalysisProvider.js";
import type { WebNetworkCapturePort } from "./WebNetworkCapturePort.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { jsonObjectSchema } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  inspectWebNetworkCaptureInputSchema,
  webNetworkCaptureSchema,
} from "../domain/webNetworkCapture.js";

const OPERATION = "inspect_web_network_capture";

/** Shared CLI/MCP historical inspection preserves caller selection and producer record identity. */
export class WebNetworkCaptureService {
  constructor(readonly port: WebNetworkCapturePort) {}

  /** Return selected complete records inline, without inventing live browser attribution. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const declarations =
      inspectWebNetworkCaptureInputSchema.shape.sensitive_values.safeParse(
        typeof rawInput === "object" &&
          rawInput !== null &&
          "sensitive_values" in rawInput
          ? rawInput.sensitive_values
          : undefined,
      );
    const failure = (error: AnalysisError): Result<never, AnalysisError> =>
      err(
        redactExplicitFailure(
          error,
          declarations.success ? declarations.data : [],
        ),
      );
    const parsed = inspectWebNetworkCaptureInputSchema.safeParse(rawInput);
    if (!parsed.success)
      return failure(
        analysisInputErrorFromIssues(OPERATION, parsed.error.issues, rawInput, {
          cause: parsed.error,
        }),
      );
    const input = parsed.data;
    if (!isAbsolute(input.capture_path))
      return failure(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["capture_path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    if (
      input.record_ordinals !== undefined &&
      new Set(input.record_ordinals).size !== input.record_ordinals.length
    )
      return failure(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["record_ordinals"],
            reason: "invalid_format",
            message: "Each requested producer ordinal must occur once.",
          },
        ]),
      );
    const loaded = await this.port.inspect(input, options);
    if (!loaded.ok) return failure(loaded.error);
    if (options?.signal?.aborted)
      return failure(new AnalysisCancelledError(OPERATION));
    const report = webNetworkCaptureSchema.safeParse(loaded.value);
    if (!report.success)
      return failure(
        new AnalysisOutputError(
          OPERATION,
          "Capture adapter returned malformed historical evidence.",
        ),
      );
    const value = report.data;
    const artifactSha256 = value.artifact.sha256;
    if (artifactSha256 === null)
      return failure(
        new AnalysisOutputError(
          OPERATION,
          "Capture adapter omitted its observed artifact digest before explicit projection.",
        ),
      );
    if (
      value.artifact.path !== input.capture_path ||
      value.format !== input.format
    )
      return failure(
        new AnalysisOutputError(
          OPERATION,
          "Capture adapter changed the selected artifact or format.",
        ),
      );
    const requested = input.record_ordinals;
    if (requested !== undefined) {
      const unavailable = requested.find(
        (ordinal) => ordinal >= value.total_records,
      );
      if (unavailable !== undefined)
        return failure(
          new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["record_ordinals"],
              reason: "invalid_format",
              message: `Producer ordinal ${unavailable} is outside the retained capture (${value.total_records} records).`,
            },
          ]),
        );
    }
    const decoderSelectsRecords = input.format !== "mitmproxy";
    const expectedOrdinals =
      decoderSelectsRecords && requested !== undefined ? requested : undefined;
    const ordinalsMatch =
      expectedOrdinals === undefined
        ? value.total_records === value.records.length &&
          value.records.every((record, index) => record.ordinal === index)
        : value.records.length === expectedOrdinals.length &&
          value.records.every(
            (record, index) => record.ordinal === expectedOrdinals[index],
          );
    if (!ordinalsMatch)
      return failure(
        new AnalysisOutputError(
          OPERATION,
          "Capture adapter changed the original record sequence or caller selection.",
        ),
      );
    const safeValue = excludeCaptureCoordinates(value, input.sensitive_values);
    const redactText = (text: string): string =>
      redactExplicitText(text, input.sensitive_values);
    const selected =
      requested ?? safeValue.records.map(({ ordinal }) => ordinal);
    const byOrdinal = new Map(
      safeValue.records.map((record) => [record.ordinal, record] as const),
    );
    const records = [];
    for (const ordinal of selected) {
      const record = byOrdinal.get(ordinal);
      if (record === undefined)
        return failure(
          new AnalysisOutputError(
            OPERATION,
            "Capture adapter omitted a validated producer record.",
          ),
        );
      records.push({
        ...record,
        limitations: record.limitations.map(redactText),
      });
    }
    const safePath = input.sensitive_values.some((literal) =>
      input.capture_path.includes(literal),
    )
      ? ""
      : input.capture_path;
    const safeSha256 = input.sensitive_values.some((literal) =>
      artifactSha256.includes(literal),
    )
      ? null
      : artifactSha256;
    const subjectUnavailableReason = redactText(
      "The explicitly sensitive artifact digest is excluded; its cryptographic identity is unknown in this Evidence.",
    );
    const limitations = [
      ...safeValue.limitations,
      ...(safePath === ""
        ? [
            "The explicitly sensitive artifact path is excluded; its size remains available.",
          ]
        : []),
    ].map(redactText);
    const parameters = jsonObjectSchema.parse({
      capture_path: safePath,
      ...(input.sensitive_values.some((literal) =>
        input.format.includes(literal),
      )
        ? {}
        : { format: input.format }),
      record_ordinals: selected,
      sensitive_value_count: input.sensitive_values.length,
    });
    return ok(
      createEvidence(
        safeSha256 === null
          ? undefined
          : {
              path: safePath,
              sha256: safeSha256,
              format: "file",
            },
        value.decoder,
        {
          operation: OPERATION,
          parameters,
          result: {
            ...safeValue,
            artifact: { ...value.artifact, path: safePath, sha256: safeSha256 },
            records,
            limitations:
              safeSha256 === null
                ? [...limitations, subjectUnavailableReason]
                : limitations,
          },
          confidence: "observed",
          authority: "historical-reference",
          limitations,
          ...(safeSha256 === null ? { subjectUnavailableReason } : {}),
          locations:
            safePath === "" ? [] : [{ kind: "artifact-path", path: safePath }],
        },
      ),
    );
  }
}
