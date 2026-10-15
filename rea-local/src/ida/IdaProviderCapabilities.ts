import type {
  AnalysisOperation,
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";

/** This version identifies REA+'s adapter, not IDA or the upstream Python package. */
export const IDA_PROVIDER_IDENTITY = Object.freeze({
  id: "ida",
  name: "IDA Pro MCP adapter",
  version: "1",
});

/** Separate profile for Hex-Rays' vendor-maintained IDA MCP server. */
export const IDA_OFFICIAL_PROVIDER_IDENTITY = Object.freeze({
  id: "ida-official",
  name: "Hex-Rays official IDA MCP adapter",
  version: "1",
});

/** Authority and observation limits specific to the official MCP surface. */
export const IDA_OFFICIAL_LIMITATIONS = Object.freeze([
  "The official server exposes execute_python, which can run arbitrary IDAPython and flushes the database after execution. REA+'s normalized provider therefore supports only headless analysis of a verified private input copy; it does not attach to, save, or close a user's GUI database.",
  "REA+ releases only the private idalib lease it opened. Any upstream persistence is confined to the private workspace, which is removed after confirmed worker shutdown.",
  "Provider version identifies the REA+ official-IDAPython adapter. IDA engine, ida-mcp, and ida-nexus versions are reported separately when observed and are not inferred from this adapter version.",
  "Analysis results describe the current IDA database and may omit facts IDA has not discovered. Image-base and input-hash checks bracket every normalized request but cannot lock the database against external GUI edits.",
  "IDA API function containment and rendered pseudocode/disassembly are provider observations, not original source. Caller/callee relationships include only instructions IDA identifies as direct call instructions; unresolved indirect calls remain unknown.",
  "Headless worker availability and IDA/idalib licensing are controlled by the caller-supplied official server; REA+ does not install, activate, or license Hex-Rays software.",
]);

/** Read-only analyst outcomes supported by both upstream compatibility profiles. */
export const IDA_OPERATIONS = Object.freeze([
  "list_procedures",
  "search_procedures",
  "list_strings",
  "search_strings",
  "procedure_address",
  "procedure_pseudo_code",
  "procedure_assembly",
  "procedure_callers",
  "procedure_callees",
  "read_function_instructions",
  "xrefs",
  "analyze_function",
] as const satisfies readonly Exclude<AnalysisOperation, "health">[]);
export type IdaOperation = (typeof IDA_OPERATIONS)[number];

/** Shared limitations of observations from an externally mutable analysis database. */
export const IDA_LIMITATIONS = Object.freeze([
  "Provider version identifies the REA+ IDA adapter. IDA engine and upstream distribution versions are unknown unless separately observed; MCP serverInfo is reported independently.",
  "Results describe the current IDA analysis database. Input identity does not prove an unmodified database; patches, annotations, analysis completeness, and database revision remain unknown.",
  "Live results are never replayed from analysis snapshots. Target checks before and after a request do not provide an atomic lock against external GUI changes.",
  "Caller cancellation drains the in-flight MCP request before cleanup; it does not prove that IDA engine work was interrupted.",
  "Headless workers are released through the upstream database lifecycle. Abrupt termination of REA+, its proxy, or the supervisor cannot prove worker cleanup; inspect upstream inventory after an interrupted process.",
  "Complete function body ranges, typed references, unresolved indirect calls, referenced data, and basic blocks are unavailable in this adapter. Empty unsupported dossier facets are unknown, not observed absence.",
]);

/**
 * Attached mode requires the legacy 1.4 profile, whose `disassemble_function`
 * jumps to the function and whose `decompile_function` opens or reuses a
 * pseudocode view whenever an IDA window is active.
 */
const ATTACHED_GUI_NAVIGATION_OPERATIONS: ReadonlySet<IdaOperation> = new Set([
  "procedure_pseudo_code",
  "procedure_assembly",
  "read_function_instructions",
  "analyze_function",
]);

/** Advertise live observations and configured lifecycle effects truthfully. */
export const idaCapabilities = (
  mode: "attached" | "headless",
  stdio: boolean,
  provider: ProviderIdentity = IDA_PROVIDER_IDENTITY,
  limitations: readonly string[] = IDA_LIMITATIONS,
  directCallersSupported: boolean = mode === "attached",
): readonly CapabilityDescriptor[] =>
  IDA_OPERATIONS.map((operation) => ({
    provider,
    operation,
    ...(!directCallersSupported && operation === "procedure_callers"
      ? ({
          available: false,
          reason:
            "The modern upstream profile reports code references without proving direct call edges.",
        } as const)
      : ({ available: true, reason: null } as const)),
    cachePolicy: "live",
    effects: {
      mutatesArtifact: false,
      launchesProcess: stdio || mode === "headless",
      mayShowUi:
        mode === "attached" &&
        ATTACHED_GUI_NAVIGATION_OPERATIONS.has(operation),
      mayAccessNetwork: true,
      mayWriteFilesystem: stdio || mode === "headless",
      changesPermissions: false,
      requiresRoot: false,
    },
    limitations,
  }));
