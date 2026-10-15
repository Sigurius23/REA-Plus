# Workflow: bounded Android APK investigation

## Shipped in AERE v0.2

`aere android inspect ARTIFACT_ID` accepts a registered APK whose central directory contains a root-level `AndroidManifest.xml`. It revalidates the registered SHA-256 and performs these bounded operations:

1. **Package inventory:** central-directory names/sizes/compression metadata; no disk extraction.
2. **Manifest:** parses text XML or Android binary XML package/version/SDK declarations, permission names, and activity/activity-alias/service/receiver/provider declarations. `@resource` values are not resolved.
3. **DEX identifiers:** reads bounded string/type/class/method identifier tables from sequential `classes*.dex` entries. This is not code-item/bytecode analysis, a call graph, or decompilation.
4. **Candidate markers:** reports Unity/Unreal/Godot member-name candidates, never a verified engine/build classification.
5. **Optional visual previews:** selected small PNG/JPEG/GIF/WebP/BMP APK members are read with strict output/ratio limits and embedded in a self-contained local HTML report. No extracted files are written to disk.
6. **Evidence:** creates a run linked to the registered APK SHA-256 and records evidence plus separate coverage for ZIP indexing, manifest parsing, DEX identifiers, engine markers, and optional previews.

Commands:

```bash
aere --home ./.aere import ./samples/app.apk
aere --home ./.aere android inspect sha256:YOUR_64_HEX_DIGEST
aere --home ./.aere android report sha256:YOUR_64_HEX_DIGEST --out ./reports/app.html
```

`android report` includes bounded image previews. `android inspect` excludes image bytes unless `--previews` is supplied.

## Bounds and unsupported layers

- Root-manifest APKs only. AAB/APKS/split packages, nested/nonstandard layouts, device acquisition, and split selection are not supported.
- Manifest input cap: 2 MiB. DEX input cap: 32 MiB per entry. DEX tables cap at 100,000 entries; samples are capped.
- At most 24 previews, 768 KiB per preview, 8 MiB aggregate; only ZIP stored/deflate compression and a maximum 250:1 declared expansion ratio are accepted for selected members.
- No JADX decompilation, Apktool/Smali/resource decoding, resource-table lookup, signature/certificate validation, ABI verification, ADB/device inspection, logs, screenshots, runtime instrumentation, or target execution.
- Native `.so` files are inventoried as files but not disassembled. A DEX class/method name does not prove implementation, reachability, or runtime behavior.

## Evidence rules

Preserve package SHA-256 and member locators. Treat manifest component/permission fields as static declarations, not proof of runtime exposure or behavior. Decompiled source-like text from a future provider must be labeled reconstructed output. Keep APK facts separate from device/runtime evidence. A complete manifest parse does not mean complete Android analysis.
