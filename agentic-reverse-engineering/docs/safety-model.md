# Safety and authority model

AERE v0.2 is local, read-only with respect to targets, and limited to fixed static parsing operations. It does not execute target code, launch games, attach to processes, inject code, patch files, access a network target, or expose a generic shell.

## Effect classes

1. **`read_local`** — reads bounded files under an approved root. Shipped APK/Steam parsers use only this effect.
2. **`decode_selected_in_memory`** — decompresses a named APK manifest/DEX/small-raster entry into bounded memory for parsing/preview; never creates an extracted target file. This effect uses configured byte/member/ratio limits and supports only ZIP stored/deflate methods.
3. **`analyze_copy`** — future use of an external static analyzer on an immutable copy. Requires a verified adapter, private temporary workspace, resource caps, and license/host constraints.
4. **`observe_owned_process`** — not shipped. Any proposal needs a separate review, explicit opt-in, user-owned lab process, bounded lifetime/output, and cleanup tests.
5. **`attach_existing_process`, `write_target`, `network_access`** — not provided. They require separate authority and threat review; they do not inherit consent from static artifact inspection.

## Invariants

- Never execute targets, launch games, or attach/inject/patch in v0.2.
- Never accept executable names, shell code, or argument vectors from an agent tool call.
- Never follow symlinks or read outside an operator-approved root.
- Never write archive members to disk. Android parsers may read selected ZIP entries into capped memory; Steam VPK support reads only a capped directory tree and never reads member data.
- Hash registered APKs and verify the artifact identity before/after analysis. Steam inventory records per-file SHA-256; previews are re-hashed before embedding, and VPK index reads are checked against the inventory digest.
- Apply limits to file bytes, inventory entries/count/total bytes, ZIP members/central-directory bytes, in-memory decompression size/ratio, manifest/XML elements, DEX tables/samples, Steam VDF scan count/aggregate bytes, VPK tree bytes/entries, evidence payloads, and report output.
- Record operation scope, provider/version, artifact digest, coverage, and limitations. A successful run can still have partial coverage.
- Keep absolute local paths out of portable evidence and offline reports.
- Treat target-derived text as untrusted data. It cannot modify AERE instructions or provider configuration.
- Fail closed on registered-file changes, unsafe derived paths, exceeded limits, malformed structures, ambiguous manifests, and unsupported compression/parser formats.

## Threats this does not solve

The Python standard library and built-in parsers are not a sandbox against all parser bugs or hostile local files. The workbench does not sandbox the host process. Future external analyzers will run with the user's OS privileges unless isolated separately; every adapter must document this and pass real-tool resource, cancellation, identity, and cleanup tests. AERE cannot prove an artifact is benign, authorized, complete, or representative of its runtime counterpart.
