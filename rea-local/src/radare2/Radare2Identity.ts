import type {
  AnalysisOperation,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";

export const RADARE2_PROVIDER_IDENTITY = Object.freeze({
  id: "radare2",
  name: "radare2 pipe adapter",
  version: "1",
} as const satisfies ProviderIdentity);

/** Accepted radare2 release line; 6.2.4 is the verified engine. */
export const RADARE2_SUPPORTED_RANGE = ">=6.0.0 <7.0.0";
export const RADARE2_VERIFIED_VERSION = "6.2.4";

/** Operations normalized from radare2 commands; everything else is unavailable. */
export const RADARE2_OPERATIONS = Object.freeze([
  "address_name",
  "address_to_file_offset",
  "analyze_function",
  "list_documents",
  "list_names",
  "list_procedures",
  "list_segments",
  "list_strings",
  "procedure_address",
  "procedure_assembly",
  "procedure_callees",
  "procedure_callers",
  "procedure_info",
  "procedure_pseudo_code",
  "read_bytes",
  "resolve_containing_procedure",
  "search_procedures",
  "search_strings",
  "xrefs",
] as const satisfies readonly Exclude<AnalysisOperation, "health">[]);

export type Radare2Operation = (typeof RADARE2_OPERATIONS)[number];

export const RADARE2_LIMITATIONS = Object.freeze([
  "REA+ runs the caller-supplied radare2 executable (REA_RADARE2_PATH) in its documented -q0 pipe mode over a SHA-256-verified private copy of the admitted target, with user rc files disabled (-N) and cfg.sandbox enabled. radare2 never opens the original path, and REA+ never forwards caller text into radare2 commands.",
  "Functions, names, strings, references and call edges are observations of radare2's selected analysis level (aa, aaa or aaaa), not original source. Indirect calls and references radare2 did not resolve are absent rather than proven nonexistent.",
  "procedure_pseudo_code returns radare2's built-in pdc pseudo-code, an annotated low-level listing rather than structured decompilation. Use procedure_assembly when instruction precision matters.",
  "list_strings and search_strings cover radare2's data-section string inventory (izj); an empty result does not prove the text is absent from the artifact bytes.",
  "Procedure names keep radare2 flag prefixes such as sym., sym.imp., fcn. and entry0. Procedure arguments also accept an exact symbol name or a 0x-prefixed address.",
  "Cancelling or timing out an in-flight radare2 command stops its process. The next operation starts a fresh process and repeats the analysis.",
]);
