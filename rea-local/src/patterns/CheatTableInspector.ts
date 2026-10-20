import {
  createAnalysisExecution,
  type AnalysisExecution,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { CheatTablePort } from "../application/patterns/CheatTablePort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import {
  cheatTableSchema,
  type CheatTableReport,
  type InspectCheatTableInput,
} from "../domain/patterns/cheatTable.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  CheatTableError,
  MAX_TABLE_ENTRIES,
  parseCheatTable,
  scriptDirectives,
  type CheatTable,
} from "./CheatTable.js";
import { checkAobScans, checkAsserts } from "./CheatTableCheck.js";
import { layoutRecord } from "./PatternScanner.js";
import {
  BYTE_PATTERN_LIMITATIONS,
  mapImage,
  MAX_SCAN_BYTES,
} from "./PatternScanProvider.js";

const OPERATION = "inspect_cheat_table";
const MAX_TABLE_BYTES = 64 * 1024 * 1024;

export const CHEAT_TABLE_PROVIDER_IDENTITY = {
  id: "cheat-engine-table",
  name: "REA+ Cheat Engine table reader",
  version: "1",
} as const;

const LIMITATIONS = [
  "The table is parsed, never executed: Auto Assembler and Lua scripts are summarized by their directives, and addresses that depend on runtime symbols, registered symbols or pointer reads stay unresolved.",
  "Field meanings follow Cheat Engine 7 table XML; tables were not round-tripped through Cheat Engine itself.",
  ...BYTE_PATTERN_LIMITATIONS,
];

const hex = (value: bigint) => `0x${value.toString(16)}`;

type Field = "path" | "binary_path";
class TableInputRejected extends Error {
  constructor(
    readonly field: Field,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

const failure = (cause: unknown, path: string): AnalysisError => {
  if (cause instanceof AnalysisCancelledError) return cause;
  const reason = cause instanceof Error ? cause.message : String(cause);
  if (
    (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled") ||
    (cause instanceof Error && cause.name === "AbortError")
  )
    return new AnalysisCancelledError(OPERATION, { cause });
  if (cause instanceof TableInputRejected)
    return new AnalysisInputError(OPERATION, { cause }, [
      { path: [cause.field], reason: "invalid_value", message: reason },
    ]);
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, reason, { cause });
  if (
    cause instanceof Error &&
    "code" in cause &&
    (cause.code === "EACCES" || cause.code === "EPERM")
  )
    return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
      cause,
    });
  return new AnalysisInputError(OPERATION, { cause }, [
    { path: ["path"], reason: "invalid_value", message: reason },
  ]);
};

const tableRecord = (
  table: CheatTable,
): Omit<CheatTableReport, "table" | "binary_check" | "limitations"> => {
  const scripted = table.entries.filter(({ script }) => script !== null);
  return {
    entries: table.entries.map((entry) => ({
      id: entry.id,
      path: [...entry.path],
      description: entry.description,
      type: entry.type,
      address: entry.address,
      module: entry.module,
      module_offset:
        entry.moduleOffset === null ? null : hex(entry.moduleOffset),
      offsets: [...entry.offsets],
      group: entry.group,
      hotkeys: entry.hotkeys,
      children: entry.children,
      script_lines:
        entry.script === null ? null : entry.script.split(/\r?\n/u).length,
    })),
    scripts: scripted.map((entry) => {
      const directives = scriptDirectives(entry.script ?? "");
      return {
        entry_id: entry.id,
        description: entry.description,
        aob_scans: directives.aobScans.map((scan) => ({ ...scan })),
        asserts: directives.asserts.map((assertion) => ({
          address: assertion.address,
          module: assertion.module,
          offset: assertion.offset === null ? null : hex(assertion.offset),
          bytes: assertion.bytes,
        })),
        registered_symbols: [...directives.registeredSymbols],
        allocations: directives.allocations,
      };
    }),
    symbols: table.symbols.map((symbol) => ({ ...symbol })),
    structures: table.structures.map((structure) => ({
      name: structure.name,
      elements: structure.elements.map((element) => ({ ...element })),
    })),
    lua:
      table.lua === null
        ? null
        : {
            bytes: Buffer.byteLength(table.lua),
            lines: table.lua.split(/\r?\n/u).length,
          },
  };
};

/** Read a caller-selected Cheat Engine table and optionally check it against a module. */
export class CheatTableInspector implements CheatTablePort {
  close(): Promise<void> {
    return Promise.resolve();
  }

  async inspect(
    input: InspectCheatTableInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    try {
      if (signal?.aborted === true) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        MAX_TABLE_BYTES,
        signal,
      );
      let table: CheatTable;
      try {
        table = parseCheatTable(selected.bytes.toString("utf8"));
      } catch (cause: unknown) {
        if (!(cause instanceof CheatTableError)) throw cause;
        throw new TableInputRejected(
          "path",
          `Not a Cheat Engine table: ${cause.message}`,
          { cause },
        );
      }
      const record = tableRecord(table);
      let binaryCheck: CheatTableReport["binary_check"] = null;
      if (input.binary_path !== undefined) {
        const binary = await readStableArtifact(
          input.binary_path,
          MAX_SCAN_BYTES,
          signal,
        ).catch((cause: unknown) => {
          throw new TableInputRejected(
            "binary_path",
            cause instanceof Error ? cause.message : String(cause),
            { cause },
          );
        });
        const { layout, error } = mapImage(binary.bytes);
        binaryCheck = {
          file: {
            path: input.binary_path,
            sha256: binary.sha256,
            bytes: binary.bytes.length,
            ...layoutRecord(layout),
            layout_error: error,
          },
          aob_scans: checkAobScans(
            binary.bytes,
            layout,
            input.binary_path,
            record.scripts,
          ),
          asserts: checkAsserts(
            binary.bytes,
            layout,
            input.binary_path,
            record.scripts,
          ),
        };
      }
      const report = cheatTableSchema.parse({
        table: {
          path: input.path,
          sha256: selected.sha256,
          bytes: selected.bytes.length,
          table_version: table.version,
          entries_total: table.entriesTotal,
          entries_truncated: table.entriesTotal > MAX_TABLE_ENTRIES,
        },
        ...record,
        binary_check: binaryCheck,
        limitations: LIMITATIONS,
      });
      return ok(
        createAnalysisExecution(report, CHEAT_TABLE_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [
            { kind: "artifact-path", path: input.path },
            ...(input.binary_path === undefined
              ? []
              : [{ kind: "artifact-path" as const, path: input.binary_path }]),
          ],
          limitations: LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      return err(failure(cause, input.path));
    }
  }
}
