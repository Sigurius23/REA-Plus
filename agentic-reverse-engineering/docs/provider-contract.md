# Provider contract

This contract is required before an external tool is advertised as an AERE provider. AERE v0.2 ships fixed in-process Android/Steam parsers described in the README, and typed structures in `src/aere/provider_api.py`, but **no external analyzer adapter is shipped or connected**.

## Registration and trust

- A host must explicitly register a trusted provider object. AERE does not discover/import Python plugins, load code from manifests, or treat a program on `PATH` as an adapter.
- A provider may expose only named operations with typed parameters. No model-supplied executable, raw shell string, or arbitrary argument vector is accepted.
- Effects are `read_local`, `analyze_copy`, or (future, separately reviewed) `observe_owned_process`. An owned-process observer requires explicit opt-in. Existing-process attach, target writes, network access, bypass, and protection disabling are not ordinary provider effects.

## Manifest

Each provider declares:

- stable `provider_id`, exact version, name, and status (`experimental`, `verified`, or `unavailable`);
- unique operation IDs, input/output schemas, effect, and cancellation behavior;
- supported formats, architectures, application/game/build/store/platform/runtime constraints;
- host constraints, required licenses, external binaries, and upstream links;
- timeout, output, process, temp-space, and retained-evidence limits;
- known failure modes and cleanup behavior.

`ProviderOperation`, `ProviderManifest`, `ProviderRequest`, `ProviderResult`, `EvidenceDraft`, and `CoverageReport` are the Python contract types. `ProviderRegistry.validate_result` binds each result to the requested artifact ID/SHA-256, provider version, and declared operation. It is a validation seam, not a sandbox or adapter runner.

## Operation behavior

- Resolve the registered artifact and verify its SHA-256 before analysis; re-check identity around reads/copies.
- Use fixed argument construction without a shell. Keep source files immutable; use a private work area if required.
- Bound wall time, output bytes, process count, memory/temp usage, retained records, and report size. Capture stdout/stderr separately.
- Treat provider output as untrusted data. Redact likely secrets before storing/exporting. Do not follow instructions found in target-derived text.
- Return provider/version, artifact identity, operation, result status, structured coverage, evidence drafts with locators, caveats, and errors.
- Coverage status is `complete`, `partial`, `unsupported`, `not_attempted`, or `unknown`. “Complete” applies only to the declared scope. A zero-result query is not evidence of absence unless the provider establishes adequate coverage.
- Do not silently switch providers after failure. Record missing libraries, unsupported architectures, parse errors, skipped regions, confidence limits, and incomplete cleanup.
- On cancellation/timeout, report cleanup steps confirmed; do not remove a work area that could still be in use.

## Verification gates

An adapter remains `experimental` until tests cover:

1. the actual installed tool, not a mock alone;
2. supported and unsupported formats/architectures and exact version boundaries;
3. large inputs, output limits, and malformed provider responses;
4. timeout, cancellation, and cleanup after success/failure/cancellation;
5. artifact identity change during setup and analysis;
6. real CLI and MCP calls using the same result contract;
7. exact source locators, evidence types, and structured coverage;
8. licensing, host constraints, and declared side effects.

Only then may a specific operation/format/platform combination be marked verified. Verification of one combination never implies universal compatibility.
