import type { ProviderIdentity } from "../application/AnalysisProvider.js";
import type { AnalysisOperation } from "../application/AnalysisProvider.js";

export const BINARY_NINJA_PROVIDER_IDENTITY = Object.freeze({
  id: "binary-ninja",
  name: "Binary Ninja official MCP adapter",
  version: "1",
} as const satisfies ProviderIdentity);

export const BINARY_NINJA_OPERATIONS = Object.freeze([
  "list_procedures",
  "search_procedures",
  "list_strings",
  "search_strings",
  "procedure_address",
  "procedure_pseudo_code",
  "procedure_assembly",
] as const satisfies readonly Exclude<AnalysisOperation, "health">[]);

export const BINARY_NINJA_LIMITATIONS = Object.freeze([
  "The official Binary Ninja MCP server uses server-issued, session-scoped open-item and BinaryView handles. REA+ binds one view by its returned handle and revalidates its path and input SHA-256 around each normalized operation; image base is also revalidated when exposed by the installed overview tool.",
  "The GUI server shares its active BinaryView with the Binary Ninja UI. REA+ may select the bound view to make official active-view tools target the admitted artifact; this changes server/UI selection but does not save, close, rename, or patch the user's database.",
  "The normalized provider calls only allowlisted official read/query tools plus the open-item and view-selection tools required to bind the target. It does not invoke save, close, analysis-control, or mutation tools.",
  "Function and string inventories, pseudocode, and assembly are Binary Ninja analysis observations, not original source. The installed official tool catalog and output schemas can change; REA+ reports an actionable compatibility error when required tools or fields differ.",
  "Provider version identifies the REA+ adapter. Binary Ninja engine and MCP server versions remain the caller-supplied server's responsibility and are reported separately when available.",
]);
