# Open tasks

Open work on the `feature/rea-plus-extensions` branch and the field tests.

## Status

- Items 1, 10, 11 and 12 are done; the fixes are committed on `main`.
- The gate now reaches the end of `test:run`: only three real-`hdiutil` DMG
  tests fail, because this macOS host is localized to German and the reader
  matches English diagnostics. `processCaptureProgress.test.ts` is load-flaky
  and passes in isolation.
- `jscpd` fails at 2.88% duplicated lines against the 2.6% threshold. This
  predates the branch's knip fixes and needs a dedicated refactor.
- This host runs Node v22.17.0, below the repo's `>=22.19` floor. The gate was
  verified with a local Node v24.11.0; CI needs a compliant Node.

## Branch and pull request

1. **Fix the `knip` findings.** `npm run check:pr` currently fails on them:
   Done: the dead HAR helpers and type aliases were removed, the Binary Ninja
   identity constants are no longer re-exported, and one heap-enforcement flag
   remains. `turbo run knip` passes.
   - five unused exports: the `BINARY_NINJA_*` re-exports in
     `src/binaryNinja/BinaryNinjaAnalysisClient.ts`, `parseHarJson`
     (`src/browser/history/HarJson.ts`) and `createHarValidator`
     (`src/browser/history/HarSchema.ts`);
   - three unused exported types: `Radare2Info`, `MinidumpThread` and
     `Il2CppMetadataView`;
   - one value exported under two names: `HAR_CAPTURE_HEAP_ENFORCED` /
     `PCAP_CAPTURE_HEAP_ENFORCED` in `src/browser/history/CaptureRelease.ts`.
2. **Re-run `npm run check:pr`** from `rea-local/`. The full test run,
   `docs:check`, duplicate-code detection and the TODO scan have not run yet,
   because the gate stops at the first failure. Done individually: typecheck,
   lint, format, knip, metadata, `docs:check` and `scan:todos` pass; `test:run`
   and `jscpd` remain as described under Status.
3. **Open the pull request** for the branch. Merged as PR #1; later fixes are
   committed directly on `main`.

## DEX support

4. **radare2 side:**
   - a real-radare2 test on a small DEX built from Java source with `javac`
     and `d8`;
   - docs: `docs/radare2-provider.md` (supported targets; the default
     analysis level is now `aa` for DEX), `docs/android-analysis.md` and the
     skill reference.
5. **Ghidra side** (not started):
   - force Ghidra's DEX loader and choose the Dalvik language from the DEX
     version;
   - fix the bridge so string listing finds DEX strings;
   - document that Ghidra's DEX memory is not backed by the file, so file
     offsets and byte reads don't work;
   - add a real-Ghidra test and docs.
6. **DEX inside an APK** (not started). Today `classesN.dex` has to be
   extracted first.

## REA+ gaps found in the WHOOP test

7. **`decode-android-resources`:** page past the first 2,000 strings, and
   expose `res/xml` files such as the network security config.
8. **`inspect-android-class` / `inspect-android-method`:** show annotation
   values (Retrofit API paths) and static field initial values.
9. **XAPK and split-APK input, and APK signature verification:** not handled
   by the Android tools.
10. **`inspect-jvm-artifact`:** probably rejects JARs with repeated entry
    names, like the JADX bridge JAR did before its fix. Not yet checked.
    Done: it did reject them. The JAR inventory now keeps the first record of
    a repeated name; the ZIP reader still rejects collisions elsewhere.

## Smaller REA+ issues

11. The `open_binary` output schema's format list
    (`targetFormatSchema`) is missing `hap`, `hsp` and `app-pack`, which
    target resolution can produce. Done.
12. `scripts/rea.mjs` is not executable in this checkout, so the
    `piClientSetup` acceptance test fails with `EACCES`. It failed before
    this branch's changes too. Done: the script is already executable; the
    remaining setup failures were the Node version floor.
13. The `clientProfileLifecycle` boundary test hits its 30 s limit when the
    whole suite runs together; it passes on its own.

## Consensus

14. Analyze a HAR exported from your own consensus.app session with
    `inspect-web-network-capture` once it is available.
15. Optional: add a telemetry section to the rebuild plan, and check the
    tool list of the anonymous MCP tier.

## WHOOP

16. The open questions under "Not done" in
    [field-tests/whoop-android-5.473.0.md](field-tests/whoop-android-5.473.0.md).

## Environment

17. Ghidra 12.1.4 in `/opt`, plus `d8`, Apktool and the JADX bridge JAR in
    the session scratchpad, last only as long as the current container. To
    keep them, add them to the environment's setup script.

## Paused

18. Function emulation.
