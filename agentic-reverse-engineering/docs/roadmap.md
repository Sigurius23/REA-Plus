# Roadmap and verification gates

AERE prioritizes implemented, testable operations over counting integrations. “Supported” must name the exact operation and bounded format/platform scope; it never means universal target coverage.

## v0.1 — safe local foundation (superseded)

- Approved roots, SHA-256 file identity, bounded inventory/probe/strings/ZIP metadata, evidence and coverage ledger, CLI/MCP, provider seam.

## v0.2 — Android/Steam first analysis slice (implemented)

- Android root-manifest APK parsing: text/binary XML metadata, bounded DEX string/type/class/method identifier tables, member index, candidate engine markers, and optional capped in-memory raster previews.
- Steam single-install analysis: VDF appmanifest metadata, approved-root hashed inventory, heuristic engine markers, VPK v1/v2 directory-tree metadata, and optional capped previews of loose raster images.
- Evidence/coverage runs and self-contained offline HTML reports.
- Does not decompile DEX, resolve Android resources, decode proprietary assets, run a target, or claim engine/title compatibility.

## Next Android slice: provider-backed semantic analysis

- Add real-tool, fixed-operation integrations for JADX and Apktool only after exact host/runtime/tool versions and licenses are established.
- Keep manifest/resources, DEX decompilation, native libraries, package signature checks, split APKs, and device/runtime evidence as separate operations.
- Verify actual CLI/MCP behavior against real APK fixtures and negative cases; report method locators, skipped classes, resource failures, cancellation, and exact coverage.

## Next Steam/game slice: one title-specific asset format

- Choose a concrete game/build/store/platform/runtime before implementing a proprietary reader.
- First candidate reader should be selected from a real sample and official/public format research; no extension-only assumptions.
- Build a read-only asset browser with bounded virtual member listing, metadata, previews where format licensing/technical constraints allow, stable offsets/hash provenance, and explicit unsupported records.
- Candidate future families: Unity serialized assets/AssetBundles, Unreal PAK/IoStore, Godot PCK, Source 2 resources, and additional Source VPK features. None is included in v0.2 unless stated in the feature table.
- Keep code decompilers, asset readers, loaders/frameworks, runtime inspectors, editors, and discovery indexes distinct.

## Later: native and managed analysis

Implement one read-only native provider with reproducible function/call/xref coverage and actual-tool tests. Keep Unity Mono/IL2CPP, .NET, JVM, and native code workflows distinct; reconstructed text is not original source.

## Separate review: runtime evidence

Any runtime provider requires separate threat/authority review, explicit user opt-in, user-owned lab process, limited lifetime/output, stop/cleanup semantics, and non-bypass use. Existing-process attachment, anti-cheat interaction, protection bypass, target writes, or network access are not routine roadmap work.

## Release gate

For every operation, publish a testable support row: provider/version, artifact family, architecture, OS, title/build/store/runtime constraints where relevant, operation, effects, coverage test, and limitations. “Available on PATH,” “works on one sample,” or a model-generated explanation is not verification.
