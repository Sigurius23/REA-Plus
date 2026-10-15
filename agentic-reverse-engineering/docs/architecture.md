# Architecture

AERE separates local artifact authority, analysis provenance, bounded domain parsers, and optional provider integrations. The CLI and stdio MCP façade use the same Python core and SQLite workspace.

```text
Human operator / agent harness
        │ typed CLI commands or MCP tools
        ▼
AERE CLI ───────── AERE stdio MCP (optional SDK)
        └──────────────────┬───────────────────┘
                           ▼
                 Shared Workspace core
                 ├── approved-root resolver + SHA-256 identity
                 ├── SQLite artifact / run / evidence / coverage ledger
                 ├── generic inventory, probe, strings, ZIP metadata
                 ├── Android: manifest / DEX IDs / bounded raster previews
                 ├── Steam: appmanifest / install inventory / VPK directory index
                 └── offline HTML report renderer
                           │ explicit future registration only
                           ├── native static engines
                           ├── JADX / Apktool / ADB / .NET / JVM tools
                           ├── title/build-specific asset readers
                           └── separately reviewed runtime observers
```

## Workspace and artifact identity

A workspace owns a local SQLite database and explicit approved input roots. It registers file metadata and locations, not artifact copies. SHA-256 is the canonical content identity. Registered APKs are revalidated before and after parsing. Steam scans hash files within inventory caps; optional preview bytes are checked against those hashes, and VPK index reads are re-hashed against the inventory observation.

## Built-in domain operations

- **Android:** accepts a registered root-manifest APK. Parses text/binary AndroidManifest XML, bounded DEX identifier tables, ZIP member metadata, engine markers, and selected raster previews. Selected entries may be decompressed only in memory; no disk extraction.
- **Steam:** accepts one approved install directory or appmanifest. Parses VDF metadata, hashes a bounded file inventory, reports heuristic engine candidates, parses VPK v1/v2 directory metadata, and optionally embeds loose raster previews. It does not decode proprietary package contents.
- **Offline reports:** generate HTML with inline styles/scripts and embedded raster previews; no external resources or absolute install path.

Every operation creates separate evidence/coverage records when an evidence anchor exists. Android runs anchor to the APK artifact. Steam runs anchor to the matching appmanifest; scans without one return explicit `run_id: null` rather than attaching evidence to an unrelated file.

## Evidence and coverage

Evidence distinguishes `observation`, `inference`, `hypothesis`, and `unknown`. Each record can include provider/version, locator, data, same-artifact supports, caveats, and agent-supplied confidence. Confidence is not a verification score.

Coverage statuses are `complete`, `partial`, `unsupported`, `not_attempted`, and `unknown`. `complete` applies only to the named operation and scope; it does not mean the whole target was understood. Parser failures, unexamined formats, unsupported regions, and unattempted layers must not be described as absence.

## Provider boundary

`src/aere/provider_api.py` defines typed manifests, named operations, requests, evidence drafts, results, and coverage. `ProviderRegistry` accepts explicitly registered trusted instances and checks identity/version/operation fields. It is a contract seam, not an external analyzer runner. Tool discovery never means integration or compatibility.

Future external adapters must use fixed named operations, declare effect/format/platform bounds, enforce time/output/resource limits, preserve provider versions and locators, and pass real-tool integration tests. Raw shell commands are not accepted.

## Trust boundaries

- CLI, MCP, archives, VDF/XML/DEX data, file names, and reports are untrusted input/output.
- Target files are data, not instructions.
- Inputs must remain under an approved root; symlinks are rejected.
- Target files are never executed, patched, or extracted to disk.
- Evidence exports and HTML reports omit absolute source paths and apply conservative secret-like redaction.
