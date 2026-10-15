# AERE Workbench

**AERE** means **Agentic Evidence-first Reverse Engineering**. It is a local Android/Steam investigation workbench with bounded APK structure analysis, Steam install inventory, Source VPK directory indexes, offline asset previews, and an evidence/coverage ledger.

> **Status: v0.2 — a working, bounded Android/Steam analysis slice, not a universal REA replacement.** AERE now parses Android text/binary manifests and DEX identifier tables, inventories one approved Steam install, reads Steam appmanifest VDF, indexes VPK v1/v2 directory metadata, and can create self-contained HTML reports with selected raster previews. It still does not decompile methods, resolve Android resource tables, decode Unity/Unreal/Godot/Source 2 proprietary assets, or observe runtime behavior. Compatibility is not inferred from a store, extension, or engine marker.

This repository remains **separate from** `game-modding-research-index`. It does not alter that link-only catalog, copy upstream analyzer source code, or use submodules.

## What is implemented

### Android APKs

- Read-only, hash-bound inspection of a registered APK with a root-level `AndroidManifest.xml`.
- Parses text XML and Android binary XML for package/version/SDK declarations, permission names, and activity/service/receiver/provider declarations. Resource references are left unresolved.
- Parses bounded DEX header, string/type/class/method identifier tables across `classes.dex`, `classes2.dex`, and sequential DEX entries. This is **not** bytecode analysis or decompilation.
- Lists member names/sizes and candidate Unity/Unreal/Godot markers.
- Optional in-memory PNG/JPEG/GIF/WebP/BMP previews, with per-file, count, ratio, and aggregate byte limits. Files are never written out of the APK.
- Records evidence and operation-scoped coverage in SQLite.

### Steam game installs

- Inspects one approved install directory, or a matching `steamapps/appmanifest_<id>.acf` file.
- Parses bounded Steam VDF app/build/install metadata and hashes an approved-root file inventory.
- Reports Unity, Unreal, Godot, and Source/Source 2 **marker candidates**, not confirmed engines.
- Reads VPK v1/v2 header and directory-tree metadata from a small bounded sample. It reports virtual paths, sizes, preload lengths, archive indexes, and offsets; it does not read VPK member data.
- Optional in-memory previews of small loose raster images. Preview files are re-hashed against the inventory before inclusion.
- Anchors a persisted evidence run to the matching Steam appmanifest when found. If there is no manifest, the scan is returned with an explicit note and no fabricated evidence run.

### Offline visual reports

The HTML reports are self-contained: inline CSS/JavaScript, embedded raster previews, no CDN assets, no fonts or scripts from a network, and no absolute install-root path. Tables can be filtered locally. `--out` is an explicit write of the report file; the inspected target is not modified.

## Quick start

Python 3.11+ is required. Analysis uses only the Python standard library; the official MCP SDK is optional.

```bash
python -m venv .venv
# macOS/Linux
. .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install -e '.[dev,mcp]'

# Initialize a local workspace and explicitly approve the input root.
aere --home ./.aere init --allow-root ./samples

# Android APK: import once to bind it to SHA-256, then inspect/report.
aere --home ./.aere import ./samples/example.apk
aere --home ./.aere android inspect sha256:REPLACE_WITH_64_HEX_DIGEST
aere --home ./.aere android report sha256:REPLACE_WITH_64_HEX_DIGEST --out ./android.html

# Steam: pass exactly one game install directory or its appmanifest.
aere --home ./.aere steam inspect '/path/to/SteamLibrary/steamapps/common/Example Game'
aere --home ./.aere steam report '/path/to/SteamLibrary/steamapps/common/Example Game' --out ./steam.html
```

The workspace approves no roots by default. Configure authority locally before connecting an agent. The Steam install directory or appmanifest must also be inside an approved root. Reports and the SQLite evidence ledger stay local; AERE does not upload target files.

## CLI commands

Pass `--home` before the command, or set `AERE_HOME`.

```text
aere [--home DIR] init [--allow-root DIR ...]
aere [--home DIR] status
aere [--home DIR] allow-root DIR
aere [--home DIR] providers
aere [--home DIR] inventory PATH
aere [--home DIR] import FILE
aere [--home DIR] artifact ARTIFACT_ID
aere [--home DIR] probe ARTIFACT_ID
aere [--home DIR] strings ARTIFACT_ID [--min-length N] [--limit N]
aere [--home DIR] archive-list ARTIFACT_ID [--limit N]
aere [--home DIR] android inspect ARTIFACT_ID [--previews]
aere [--home DIR] android report ARTIFACT_ID --out FILE
aere [--home DIR] steam inspect GAME_DIR_OR_APP_MANIFEST [--previews]
aere [--home DIR] steam report GAME_DIR_OR_APP_MANIFEST --out FILE
aere [--home DIR] run create ARTIFACT_ID --workflow NAME [--provider ID]
aere [--home DIR] evidence list RUN_ID
aere [--home DIR] coverage list RUN_ID
aere [--home DIR] report RUN_ID [--format json|markdown] [--out FILE]
aere [--home DIR] mcp
```

`android inspect` and `steam inspect` emit JSON and create provenance-bearing runs when their required evidence anchor is available. `android report`/`steam report` create standalone HTML. `steam inspect` works on a directory without an appmanifest, but clearly reports that no evidence run was created because there is no manifest anchor.

## MCP

Install the optional extra, approve roots locally, then register AERE as a local stdio MCP server:

```json
{
  "mcpServers": {
    "aere": {
      "command": "/absolute/path/to/.venv/bin/aere",
      "args": ["--home", "/absolute/path/to/.aere", "mcp"]
    }
  }
}
```

The server exposes `inspect_android_apk` and `inspect_steam_install` in addition to the evidence/coverage and bounded triage tools. Previews are opt-in because they include small base64 image data. MCP cannot approve new roots, execute targets, or accept arbitrary shell commands.

## Hard compatibility boundaries

- **Android:** root-manifest APKs only; no AAB/APKS/split acquisition. No JADX decompilation, Apktool decoding, resource-table resolution, signing/certificate verification, device/ADB inspection, or runtime instrumentation. DEX output is identifier metadata, not source.
- **Steam:** the store is not the engine. One install at a time. Inventory and file markers are not proof of which files the game actually loads.
- **Assets:** previews cover selected loose raster images and small raster files inside APKs. VPK support is directory metadata only. There is no Unity serialized-file/AssetBundle, Unreal PAK, Godot PCK, Source 2 resource, or proprietary texture/audio/model decoder in v0.2.
- **Compatibility claims:** no claim of universal Android or Steam coverage. A game-specific compatibility statement still needs the exact title, build, store, platform, runtime, and representative artifacts.
- **Code/runtime:** no target launch, process attachment, code injection, network access, target write/patch, anti-cheat/DRM bypass, or protection-disabling feature.

## Safety and resource limits

- All inputs are under operator-approved roots; symlinks are rejected.
- APK entries are read only by named parsers. Bounded decompression may occur **in memory** for a selected manifest/DEX/thumbnail; no member is extracted to disk.
- APK parser caps include a 2 MiB manifest, 32 MiB DEX, 100,000 identifier-table entries, 24 previews, 768 KiB per preview, 8 MiB aggregate previews, ZIP member/directory limits, and a maximum 250:1 decompression ratio. Only stored/deflate members are read.
- Steam VDF scan: up to 100 manifests and 16 MiB aggregate. VPK directory trees: up to 16 MiB and 50,000 entries per parsed file, four candidate indexes, and a 64 MiB maximum per-file hash revalidation pass. Large/unsupported inputs are reported as partial, not silently treated as complete.
- Recursive inventory, per-file/total bytes, response size, and evidence payloads use configurable workspace limits.
- The HTML report embeds only validated PNG/JPEG/GIF/WebP/BMP data URIs. It uses no external network resources.

## Evidence semantics

- Observations, inferences, hypotheses, and unknowns are distinct record types.
- A candidate engine marker is an inference, not a verified fact. Agent/provider confidence is not a test result.
- Every operation records a scoped status: `complete`, `partial`, `unsupported`, `not_attempted`, or `unknown`. `complete` applies only to that operation and exact inspected scope.
- A parser error or zero matches is not evidence that a feature is absent.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — shared core, analyzers, evidence, and trust boundaries.
- [`docs/safety-model.md`](docs/safety-model.md) — authority, in-memory decoding, and resource caps.
- [`docs/workflows/android.md`](docs/workflows/android.md) and [`docs/workflows/game-analysis.md`](docs/workflows/game-analysis.md) — supported scope and limitations.
- [`docs/provider-contract.md`](docs/provider-contract.md) and [`docs/roadmap.md`](docs/roadmap.md) — integration gates and next work.
- [`docs/comparison-snapshot.md`](docs/comparison-snapshot.md) — honest version-scoped AERE/REA gap record; not a benchmark.

## Development and verification

```bash
python -m pip install -e '.[dev]'
pytest -q
python -m compileall -q src tests
```

Tests use generated synthetic APK/DEX/XML/VDF/VPK fixtures; no real apps, games, executables, decompiled code, credentials, or proprietary game assets are distributed. MCP integration tests require the optional SDK.

## License

MIT for AERE Workbench. External tools, future adapters, and target artifacts retain their own licenses and terms.
