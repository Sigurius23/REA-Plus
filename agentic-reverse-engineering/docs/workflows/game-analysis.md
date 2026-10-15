# Workflow: Steam game install and asset triage

## First principle

Steam is a distribution/library platform, not an engine. Do not choose a parser from the store alone. Identify the exact title/build, appmanifest, platform, executable/runtime, and data files before making a format-specific compatibility claim.

## Shipped in AERE v0.2

`aere steam inspect GAME_DIR_OR_APP_MANIFEST` operates on one approved game install directory or its `steamapps/appmanifest_<id>.acf` file:

1. Parses bounded appmanifest VDF fields (App ID, name, install directory, build ID, branch, and install-size/update metadata).
2. Verifies the selected install path remains in an approved root and hashes the bounded file inventory. No root path is placed in the portable evidence record.
3. Reports Unity, Unreal Engine, Godot, and Source/Source 2 file-marker **candidates**. The scan does not confirm the engine or identify the files the game actually loads.
4. For sampled VPK candidates, parses VPK v1/v2 header and directory-tree metadata, including virtual member path, size, preload byte count, archive index, offset, and range checks. It does not read or extract member contents; external VPK segments and CRC values are not verified.
5. Optionally previews selected small loose PNG/JPEG/GIF/WebP/BMP files in a self-contained HTML report. Each preview is re-hashed against the preceding inventory result.
6. When a matching appmanifest exists, records a run anchored to its SHA-256 with separate inventory, manifest, engine-marker, VPK, and preview coverage. A directory without a manifest can still be scanned, but no evidence run is fabricated.

```bash
aere --home ./.aere steam inspect '/SteamLibrary/steamapps/common/Example Game'
aere --home ./.aere steam report '/SteamLibrary/steamapps/common/Example Game' --out ./reports/steam-game.html
```

A Steam library `steamapps` root is not a single-game target; pass one install directory or its matching appmanifest. If the manifest-derived `installdir` is unsafe, absent, or outside an approved root, inspection stops.

## Compatibility boundaries

- File markers are heuristics. Extensions, app ID, store, engine names, and filenames do not establish a supported title/build/runtime.
- v0.2 does **not** parse Unreal PAK, Unity serialized files/AssetBundles, Godot PCK, Source 2 resource files, proprietary texture/audio/model formats, or package contents inside VPK/PAK/other archives.
- No loader, mod framework, editor, discovery index, runtime inspector, or asset-conversion tool is bundled or silently invoked.
- No game execution, process attachment, network access, anti-cheat/DRM interaction, patching, bypass, or protection-disabling operation is provided.

For a title-specific provider, record the exact game title/build, storefront/depot, operating system/architecture, runtime/engine version, parser/provider version, representative files, supported and rejected cases, and real-tool tests. Keep code analysis and asset parsing as separate operations.
