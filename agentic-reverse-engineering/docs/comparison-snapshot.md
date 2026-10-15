# Comparison snapshot: AERE v0.2 and REA

**Snapshot date:** 2026-10-11. This is a scope/gap record, not a performance benchmark or a claim that AERE is globally superior.

The latest official REA release observed for this snapshot is `rea-agents-6.4.0` (2026-10-11). Its release notes list Android ADB/device workflows, Apktool resource/manifest decoding, JEB project access, additional Ghidra analyses, and deeper evidence/large-analysis work. REA's repository README describes a broader target matrix including native binaries, Android packages/devices, JavaScript/Electron, .NET, websites, firmware, and process observation. See [REA 6.4.0](https://github.com/morluto/rea/releases/tag/rea-agents-6.4.0) and [REA README](https://github.com/morluto/rea/blob/main/README.md).

| Capability | AERE v0.2 | REA snapshot | Conclusion |
|---|---|---|---|
| Android manifest | Built-in bounded text/binary XML parse for root-manifest APKs | Release has Apktool-backed manifest/resource work | AERE has a small in-process parser; this does not establish better coverage |
| Android DEX | Header and identifier tables; no bytecode/decompilation | REA has JADX/JEB workflows and broader Android analysis | REA is substantially deeper here |
| Android runtime/device | Unsupported | REA 6.4.0 has explicit ADB device workflows | REA is substantially broader here |
| Steam install | Appmanifest VDF plus bounded file hashes | REA documents broader multi-domain workflows; a per-title comparison is not established here | AERE's scan is a narrow local inventory, not proof of superiority |
| Source VPK | Bounded VPK v1/v2 directory-tree metadata | No like-for-like real-target benchmark has been run | AERE is a concrete built-in slice; compare on an authorized sample before claiming it is better |
| Visualization | Self-contained offline HTML with capped raster previews and searchable tables | No feature-by-feature report comparison was performed | AERE's potential differentiator is an offline local asset/inventory view, not proven overall superiority |
| Evidence | Run records with per-operation coverage for the shipped parsers | REA also has a mature evidence model and tracks unknowns | Do not claim AERE invented or generally improves evidence-first analysis |

## Acceptance gate for a stronger claim

A claim that AERE is “better than REA” needs a named workflow and a reproducible, same-input evaluation: exact title/build/store/platform/runtime, artifact hashes, supported and rejected cases, outputs/locators, elapsed time/resource limits, failure behavior, and coverage. The test suite currently uses synthetic fixtures; it does **not** establish compatibility with any real game or Android application.

AERE v0.2 is a first domain-specific Android/Steam implementation slice. The next meaningful Steam enhancement requires an exact title/build and representative sample so an asset reader can be selected and tested instead of guessed from the storefront or filename.
