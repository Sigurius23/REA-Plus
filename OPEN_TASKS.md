# Open tasks

Open work on `main` following PR #1 and the field tests.

## Status

- **Items 1, 3, 10, 11, 12:** Done. Merged in PR #1 or committed on `main`.
- **Item 4 (radare2 DEX documentation):** Done (committed in `a27f184`); the real DEX fixture test remains.
- **Native DMG verification on localized macOS hosts:** Fixed and verified. Added locale-independent status line matching and target fallback inspection in `NativeDmgArtifactReader.ts`. All 30 tests in `nativeDmgArtifactReader.test.ts` pass.
- **jscpd duplicate lines:** Reduced from 2.88% down to 2.50% duplicated lines. Beyond the shared `InlineReportService` sweep, the concentrated hotspots were extracted: `cli/coreBinaryCommands.ts` now uses shared option constants and one parameterized procedure-selector registration; `processTrace.fixture.ts` carries the trace capture/specification shared by the domain unit test and the MCP parity test; and the `webCaptureDiff` / `interfaceBuilderBundle` test suites use extracted capture helpers. 0.1 pts of headroom under the 2.6% threshold; consider lowering the threshold (the `.jscpd.json` comment calls for it) as remaining duplication is removed.
- **Flaky boundary tests:** Done. Both `processCaptureProgress.test.ts` and `clientProfileLifecycle.test.ts` now use load-tolerant budgets (test orchestration only; the <\\_s cancellation-latency commitments themselves are untouched), and both pass under the v24.11.0 Node in isolation. The capability-skip path in `processCaptureProgress.test.ts` is mutation-backed: flipping `available: true` → `false` in `ProcessCaptureCapability.ts` flips the suite's assertions to the named-skip path as intended. A whole-suite re-run to confirm the budgets hold under full parallel load is still pending (host was busy during this pass). Runtime note: this host's default `node` is v22.17.0, which the CLI's own version gate refuses; tests that shell out to the CLI proxy fail with exit 1 unless vitest runs under the v24.11.0 Node in `/private/tmp/node-v24.11.0-darwin-arm64/bin`.
- **Environment:** Node v24.11.0 is available locally in `/private/tmp/node-v24.11.0-darwin-arm64/bin`. Reverse engineering tools installed and verified: `ghidra` 12.1.4 (with OpenJDK 27), `radare2` 6.2.4, `binwalk` 3.1.0, `jadx` 1.5.6, and `apktool` 3.0.3.
- **Ghidra DEX support:** Done on `main`. Forced `DexLoader` import with the Dalvik language selected from the DEX header version; DEX string-pool definition runs as a packaged post-analysis script (`ReaGhidraPrepareDex.java`) so Dalvik method discovery keeps working; DEX byte-read and file-offset behavior is documented honestly in `docs/ghidra-dex.md`; `npm run verify:ghidra:dex` verifies the committed `tests/fixtures/dex/` fixture end to end (green on macOS arm64/ghidra 12.1.4).
- **Flaky `ghidraLauncher.test.ts` and `processFinalization.test.ts`:** Addressed. The launcher test now matches the DEX-aware conflict message (plus a new DEX-negative case); the finalization acceptance tests give compiled-workflow startup a 15s load-tolerant budget (30s test timeout) while keeping the cancellation-latency (<8s) commitments themselves untouched. Both green in isolation; whole-suite re-run pending (host load >100 at the time).

## Branch, gate and git

1. **Gate verification (`npm run check:pr`):**
   - Green end to end as of Oct 22, 2026 (exit 0): typecheck, lint, format (`oxfmt`), knip, metadata, `docs:check`, jscpd (exactly at the 2.6% threshold; further refactors wanted for headroom), `scan:todos`, and the full test suite (897 files passed, 0 failed).
2. **Push local commits:**
   - Local `main` is ahead of `origin/main` (currently 7 commits ahead); push once gate passes.

## DEX support

3. **radare2 side:**
   - [x] Documentation: `docs/radare2-provider.md`, `docs/android-analysis.md` and skill reference updated.
   - [x] Real-radare2 fixture test on a small DEX built from Java source with `javac` and `d8` (`tests/boundary/providers/radare2/radare2Provider.dex.test.ts`; 3/3 green against radare2 6.2.4).
4. **Ghidra side** (done):
   - [x] Force Ghidra's DEX loader and choose the Dalvik language from the DEX version;
   - [x] Make `list_strings`/`search_strings` cover the DEX string pool (post-analysis pool definition, `align` markers excluded);
   - [x] Document that Ghidra's DEX memory is loader-owned: `.dex` bytes read back, but file-offset mapping is explicitly rejected;
   - [x] Add a real-Ghidra test (`npm run verify:ghidra:dex`) and docs (`docs/ghidra-dex.md`).
5. **DEX inside an APK** (implemented on `main`):
   - [x] `container#member` fragment targeting (`/path/App.apk#classes2.dex`) at the generic binary/session layer (`parseBinaryTarget` → `ContainerDexTarget.ts`): ZIP container verification, top-level `.dex` member lookup, digest-reused staging beside the container (or MCP `staging_dir` / CLI `--staging-dir`), Dalvik classification, `container_selection` provenance on the resolved target.
   - [x] Boundary tests in `tests/boundary/filesystem/binaryTarget.test.ts`; documented in `docs/android-analysis.md`, `docs/cli.md` and `docs/ghidra-dex.md`. The Android-specific `inspect_android_*` operations keep whole-APK semantics.

## REA+ gaps found in the WHOOP test

6. **`decode-android-resources`:** (done in `f5f036a`)
   - Page past the first 2,000 strings (`strings_offset`, `strings_limit`), and expose `res/xml` files such as the network security config (`include_xml_resources`).
7. **`inspect-android-class` / `inspect-android-method`:** (done in `eb83e19`)
   - Show annotation values (e.g., Retrofit API paths) and static field initial values via JADX bridge without runtime class loading.
8. **Android package formats and validation:** (done in `7795b12`)
   - XAPK: done. `.xapk` containers are admitted by all five Android
     operations (`APK_CONTAINER_FORMATS`); `AndroidXapkBundle.ts` validates the
     top-level `manifest.json` + `base.apk` shape, composes a stored-entry
     4 GiB-capped `bundle.apk` (base entries verbatim, split `*.dex` entries
     merged under `splits/<member>/<name>` colliding aliases), retires staged
     members, and records the merge scope in Evidence limitations. Round-trip
     tests: `tests/boundary/process/androidXapkBundle.test.ts`. A `.aab` and
     loose split-APK sets (directories, `.apks`) remain unsupported forms.
   - Split-APK bundles: documented-only for now. ADB `pull_adb_package` already
     pulls the complete split set digested per file; a directory/`.apks`
     admission flow would be the natural follow-up once a caller owns one.
   - APK signature verification: not implemented, deliberately. v1/v2/v3
     schemes mean real crypto (message digests, RSA/ECDSA, byte-range offsets
     over signed regions up through the APK Signing Block) whose honest home is
     a dedicated adapter with its own Evidence authority, not jadx's; today
     `inspect_android_package` reports signing as `not_performed` and the
     signature blocks stay visible to inventory/extraction. Recommend building
     it only when a caller task actually needs tamper/lift detection.
9. **Android string constants and bytecode searching:** (done in working tree)
   - `search-android-strings` / `search_android_strings`: scans string constants across decompiled method bodies (Java/smali), supporting `class_limit` (up to 8,192 classes), reporting `matches`, `scanned_classes`, `scanned_methods`, `skipped_methods`, and `coverage`.
   - Scan-inspect ordering defect resolved: method bodies and `static_inits` stay byte-identical before and after whole-APK scans.
   - Known boundaries documented:
     1. Large-APK memory behavior (>8,192 classes or memory pressure near 4 GiB heap) remains unmeasured in production.
     2. APKs exceeding 8,192 classes hit third-party JAR LRU cache eviction if rescanned.
     3. Per-class method-cap skips are reflected in partial coverage, while `skipped_methods` counts engine decompile failures.
     4. Verified on macOS arm64; Windows lifecycle verifier remains unexercised locally.
     5. Engine scan-skip counts show small non-deterministic variance (12-23 across runs) on malformed/unparseable method bodies.
10. **`inspect-jvm-artifact` duplicate entry handling:**
    - Done: Archive inventory now keeps the first record of a repeated name.

## Flaky tests and gate robustness

11. **Test timeouts under concurrent load:**
    - Done on `main`: both suites' budgets and the capability-skip path are stabilized and mutation-checked as described in the status note above. Remaining follow-up: one whole-suite `npm run check:pr` re-run under the v24.11.0 Node to confirm the budgets hold under full parallel load.

## Consensus

12. Analyze a HAR exported from your own consensus.app session with `inspect-web-network-capture` once it is available.
13. Optional: add a telemetry section to the rebuild plan, and check the tool list of the anonymous MCP tier.

## WHOOP

14. **Open field-test questions:**
    - Running the app or its traffic; reading the strap protocol itself; strap unlock and membership checks.
    - Mapping UUID families to device generations, and identifying codenames (Kenmore, Copley).
    - Update [field-tests/whoop-android-5.473.0.md](field-tests/whoop-android-5.473.0.md) to reflect that radare2 and Ghidra now admit standalone DEX files (done: "gaps still open" item 1 rewritten).

## Environment

15. **Reverse engineering tools:**
    - Installing `radare2`, `binwalk`, `apktool`, and `jadx` via Homebrew (`brew install`).
    - Verify presence of `d8` (available at `/opt/homebrew/bin/d8`) and `javac` (`/usr/bin/javac`).

## Paused

16. Function emulation.
