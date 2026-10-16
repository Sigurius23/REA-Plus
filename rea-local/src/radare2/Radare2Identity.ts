import type {
  AnalysisOperation,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";

export const RADARE2_PROVIDER_IDENTITY = Object.freeze({
  id: "radare2",
  name: "radare2 pipe adapter",
  version: "1",
} as const satisfies ProviderIdentity);

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

/** Results observed through Rizin, the radare2 fork, carry these instead. */
export const RIZIN_LIMITATIONS = Object.freeze([
  "REA+ runs the caller-supplied Rizin executable (REA_RADARE2_PATH) in its -q0 pipe mode over a SHA-256-verified private copy of the admitted target, with user rc files disabled (-N). Rizin has no command sandbox (radare2's cfg.sandbox does not exist in Rizin), so nothing inside Rizin refuses shell or file commands; REA+ sends only fixed commands and never forwards caller text into them.",
  "Functions, names, strings, references and call edges are observations of Rizin's selected analysis level (aa, aaa or aaaa), not original source. Rizin names functions by its own heuristics, such as main for the first call of an entry point. Indirect calls and references Rizin did not resolve are absent rather than proven nonexistent.",
  "Rizin has no built-in pseudo-code command, so procedure_pseudo_code is unavailable and analyze_function reports empty pseudocode. Use procedure_assembly.",
  "list_strings and search_strings cover Rizin's data-section string inventory (izj); an empty result does not prove the text is absent from the artifact bytes.",
  "Procedure names keep Rizin flag prefixes such as sym., sym.imp. and fcn. Procedure arguments also accept an exact symbol or flag name or a 0x-prefixed address.",
  "Cancelling or timing out an in-flight Rizin command stops its process. The next operation starts a fresh process and repeats the analysis.",
]);

/** Advertised before any engine is probed: the configured executable may be either engine. */
export const RADARE2_CAPABILITY_LIMITATIONS = Object.freeze([
  ...RADARE2_LIMITATIONS,
  "REA_RADARE2_PATH may instead name Rizin 0.9.x. Rizin has no command sandbox and no pdc pseudo-code; results then carry Rizin's limitations.",
]);
