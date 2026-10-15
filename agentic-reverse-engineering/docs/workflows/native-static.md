# Workflow: native static investigation

## Goal

Answer a narrow question about a local native executable or library with traceable evidence.

## Steps

1. Confirm an approved input root and import the file. Record SHA-256, format candidate, architecture candidate, size, and any parse limitations.
2. Select one native provider that supports the artifact and host. If none is verified, stop at triage and report the gap.
3. Create an analysis run with exact provider version and settings. Open the artifact as read-only or an immutable private copy.
4. Start with bounded inventory: sections, imports/exports, symbols, strings, entry points, and functions.
5. Query only relevant functions/strings/references. Preserve provider locations and xrefs.
6. Record direct facts as observations. Label interpretations as inferences/hypotheses; link each to evidence IDs.
7. Re-run a targeted query if the first result is incomplete. Record non-results with search scope and coverage.
8. Export a report; include unknowns, unsupported capabilities, and unverified dynamic behavior.

## Do not

- Execute the target or attach to a process using AERE v0.2.
- Claim source recovery from pseudocode.
- Treat a decompiler's reconstructed type/name as ground truth.
- Infer “not present” from a failed provider, unsupported format, or partial search.

## Current implementation

AERE v0.2 implements bounded Android APK and Steam install analysis but no native disassembler/decompiler adapter. Native triage remains limited to hashes, format candidates, strings, and evidence/coverage. Use the provider catalog to identify external routes; do not mark an external tool as AERE-connected merely because it is installed.
