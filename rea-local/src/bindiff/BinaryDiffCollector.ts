import type {
  AnalysisExecution,
  AnalysisOperation,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { functionDossierSchema } from "../domain/hopperValues.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  functionFeatures,
  type AddressRanges,
  type FunctionFeatures,
} from "./BinaryDiffFeatures.js";

/** The part of a binary session the diff drives: one target, provider operations. */
export interface DiffAnalysisSession {
  open(
    path: string,
    options?: { readonly signal?: AbortSignal },
  ): Promise<Result<BinaryTarget, AnalysisError>>;
  execute(
    operation: AnalysisOperation,
    input: Readonly<Record<string, JsonValue>>,
    options?: { readonly signal?: AbortSignal },
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
  close(): Promise<Result<null, AnalysisError>>;
}

/** Every analyzed function of one build, with what could not be analyzed. */
export interface FunctionInventory {
  readonly path: string;
  readonly sha256: string;
  readonly format: BinaryTarget["format"];
  readonly provider: ProviderIdentity;
  readonly profile: AnalysisProfileCommitment | null;
  readonly listed: number;
  readonly functions: readonly FunctionFeatures[];
  readonly failed: readonly {
    readonly address: string;
    readonly name: string;
    readonly reason: string;
  }[];
  /** More functions were listed than `max_functions` allowed. */
  readonly truncated: boolean;
  readonly limitations: readonly string[];
}

const procedureRows = (value: JsonValue) =>
  Array.isArray(value)
    ? value.flatMap((row) =>
        typeof row === "object" &&
        row !== null &&
        !Array.isArray(row) &&
        typeof row.address === "string" &&
        typeof row.value === "string"
          ? [{ address: row.address, name: row.value }]
          : [],
      )
    : [];

/** Loaded segments, so numeric operands inside them read as addresses. */
const segmentRanges = (value: JsonValue): AddressRanges =>
  Array.isArray(value)
    ? value.flatMap((row) => {
        if (typeof row !== "object" || row === null || Array.isArray(row))
          return [];
        const { start, end } = row;
        if (typeof start !== "string" || typeof end !== "string") return [];
        try {
          return [{ start: BigInt(start), end: BigInt(end) }];
        } catch {
          return [];
        }
      })
    : [];

/** Open one build, analyze each listed function, and close it again. */
export const collectFunctions = async (
  session: DiffAnalysisSession,
  path: string,
  options: { readonly maxFunctions: number; readonly signal?: AbortSignal },
): Promise<Result<FunctionInventory, AnalysisError>> => {
  const { signal } = options;
  const opened = await session.open(
    path,
    signal === undefined ? {} : { signal },
  );
  if (!opened.ok) return opened;
  try {
    const call = signal === undefined ? {} : { signal };
    const procedures = await session.execute("list_procedures", {}, call);
    if (!procedures.ok) return procedures;
    const segments = await session.execute("list_segments", {}, call);
    const ranges = segments.ok ? segmentRanges(segments.value.result) : [];
    const listed = procedureRows(procedures.value.result);
    const selected = listed.slice(0, options.maxFunctions);
    const functions: FunctionFeatures[] = [];
    const failed: { address: string; name: string; reason: string }[] = [];
    let limitations: readonly string[] = [];
    for (const { address, name } of selected) {
      if (signal?.aborted === true)
        return err(new AnalysisCancelledError("diff_binaries"));
      const analyzed = await session.execute(
        "analyze_function",
        { procedure: address },
        call,
      );
      if (!analyzed.ok) {
        if (analyzed.error instanceof AnalysisCancelledError) return analyzed;
        failed.push({ address, name, reason: analyzed.error.message });
        continue;
      }
      const dossier = functionDossierSchema.safeParse(analyzed.value.result);
      if (!dossier.success) {
        failed.push({
          address,
          name,
          reason:
            "The provider's function report did not match the dossier contract.",
        });
        continue;
      }
      if (limitations.length === 0) limitations = analyzed.value.limitations;
      functions.push(functionFeatures(dossier.data, ranges));
    }
    return ok({
      path: opened.value.path,
      sha256: opened.value.sha256,
      format: opened.value.format,
      provider: procedures.value.provider,
      profile: procedures.value.analysisProfile ?? null,
      listed: listed.length,
      functions,
      failed,
      truncated: listed.length > selected.length,
      limitations: [...procedures.value.limitations, ...limitations],
    });
  } finally {
    await session.close();
  }
};
