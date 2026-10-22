# Open tasks

Open work on `main` following PR #1 and the field tests.

## Status

- **Items 1, 3, 10, 11, 12:** Done. Merged in PR #1 or committed on `main`.
- **Item 4 (radare2 DEX documentation):** Done (committed in `a27f184`); the real DEX fixture test remains.
- **Native DMG verification on localized macOS hosts:** Fixed and verified. Added locale-independent status line matching and target fallback inspection in `NativeDmgArtifactReader.ts`. All 30 tests in `nativeDmgArtifactReader.test.ts` pass.
- **jscpd duplicate lines:** Reduced from 2.88% down to 2.75% via shared `InlineReportService` abstraction across 24 offline inspector services. Refactoring CLI commands and tool registration will bring it below the 2.6% threshold.
- **Flaky boundary tests:** `processCaptureProgress.test.ts` and `clientProfileLifecycle.test.ts` pass in isolation; timeout tolerances are sensitive under heavy whole-suite load.
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
   - [ ] Real-radare2 fixture test on a small DEX built from Java source with `javac` and `d8`.
4. **Ghidra side** (done):
   - [x] Force Ghidra's DEX loader and choose the Dalvik language from the DEX version;
   - [x] Make `list_strings`/`search_strings` cover the DEX string pool (post-analysis pool definition, `align` markers excluded);
   - [x] Document that Ghidra's DEX memory is loader-owned: `.dex` bytes read back, but file-offset mapping is explicitly rejected;
   - [x] Add a real-Ghidra test (`npm run verify:ghidra:dex`) and docs (`docs/ghidra-dex.md`).
5. **DEX inside an APK** (not started):
   - Support analyzing `classesN.dex` directly inside APK containers without manual pre-extraction.

## REA+ gaps found in the WHOOP test

6. **`decode-android-resources`:**
   - Page past the first 2,000 strings, and expose `res/xml` files such as the network security config.
7. **`inspect-android-class` / `inspect-android-method`:**
   - Show annotation values (e.g., Retrofit API paths) and static field initial values.
8. **Android package formats and validation:**
   - XAPK, split-APK bundles, and APK signature verification.
9. **Android string constants and bytecode searching:**
   - Support searching string constants and Dalvik bytecode across classes and methods.
10. **`inspect-jvm-artifact` duplicate entry handling:**
    - Done: Archive inventory now keeps the first record of a repeated name.

## Flaky tests and gate robustness

11. **Test timeouts under concurrent load:**
    - Bound and stabilize `tests/boundary/process/processCaptureProgress.test.ts` and `tests/boundary/cli/clientProfileLifecycle.test.ts` during whole-suite runs.

## Consensus

12. Analyze a HAR exported from your own consensus.app session with `inspect-web-network-capture` once it is available.
13. Optional: add a telemetry section to the rebuild plan, and check the tool list of the anonymous MCP tier.

## WHOOP

14. **Open field-test questions:**
    - Running the app or its traffic; reading the strap protocol itself; strap unlock and membership checks.
    - Mapping UUID families to device generations, and identifying codenames (Kenmore, Copley).
    - Update [field-tests/whoop-android-5.473.0.md](field-tests/whoop-android-5.473.0.md) to reflect that radare2 now admits DEX files.

## Environment

15. **Reverse engineering tools:**
    - Installing `radare2`, `binwalk`, `apktool`, and `jadx` via Homebrew (`brew install`).
    - Verify presence of `d8` (available at `/opt/homebrew/bin/d8`) and `javac` (`/usr/bin/javac`).

## Paused

16. Function emulation.
