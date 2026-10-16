import { basename } from "node:path";

import type { CheatTableReport } from "../domain/patterns/cheatTable.js";
import { BytePatternError, parseBytePattern } from "./BytePattern.js";
import { sectionAtAddress, type ImageLayout } from "./ImageLayout.js";
import { scanPatterns } from "./PatternScanner.js";

type Check = NonNullable<CheatTableReport["binary_check"]>;
type Script = CheatTableReport["scripts"][number];

const sameModule = (module: string | null, binary: string) =>
  module === null || module.toLowerCase() === basename(binary).toLowerCase();

/** Re-scan each aobscan pattern; module-scoped scans apply to their module only. */
export const checkAobScans = (
  bytes: Buffer,
  layout: ImageLayout,
  binaryPath: string,
  scripts: readonly Script[],
): Check["aob_scans"] =>
  scripts.flatMap((script) =>
    script.aob_scans.map((scan) => {
      const applies = sameModule(scan.module, binaryPath);
      try {
        const [result] = scanPatterns(
          bytes,
          layout,
          [{ pattern: scan.pattern }],
          {
            scope: "all",
            maxMatches: 5,
          },
        ).results;
        if (result === undefined) throw new BytePatternError("No result.");
        return {
          ...result,
          entry_id: script.entry_id,
          symbol: scan.symbol,
          applies,
          error: null,
        };
      } catch (cause: unknown) {
        if (!(cause instanceof BytePatternError)) throw cause;
        return {
          name: null,
          pattern: scan.pattern,
          length: 0,
          total_matches: 0,
          complete: true,
          matches: [],
          entry_id: script.entry_id,
          symbol: scan.symbol,
          applies,
          error: cause.message,
        };
      }
    }),
  );

/** Compare assert(module+offset, bytes) with the PE image's bytes there. */
export const checkAsserts = (
  bytes: Buffer,
  layout: ImageLayout,
  binaryPath: string,
  scripts: readonly Script[],
): Check["asserts"] =>
  scripts.flatMap((script) =>
    script.asserts.map((assertion) => {
      const base = {
        entry_id: script.entry_id,
        address: assertion.address,
        expected: assertion.bytes,
      };
      const skip = (reason: string) => ({
        ...base,
        actual: null,
        matches: null,
        reason,
      });
      if (assertion.offset === null)
        return skip(
          "The address is not module+offset; it depends on runtime symbols.",
        );
      if (!sameModule(assertion.module, binaryPath))
        return skip(
          `The assert targets ${assertion.module ?? ""}, not ${basename(binaryPath)}.`,
        );
      if (layout.format !== "pe" || layout.imageBase === null)
        return skip(
          "Assert checks map module offsets through PE section headers only.",
        );
      let pattern;
      try {
        pattern = parseBytePattern(assertion.bytes);
      } catch (cause: unknown) {
        if (!(cause instanceof BytePatternError)) throw cause;
        return skip(cause.message);
      }
      const address = layout.imageBase + BigInt(assertion.offset);
      const section = sectionAtAddress(layout, address);
      if (section === undefined)
        return skip(
          "The offset lies outside the image's file-backed sections.",
        );
      const offset = section.fileOffset + Number(address - section.address);
      const actual = bytes.subarray(offset, offset + pattern.values.length);
      return {
        ...base,
        actual: actual.toString("hex"),
        matches:
          actual.length === pattern.values.length &&
          pattern.values.every(
            (value, index) =>
              ((actual[index] ?? 0) & (pattern.masks[index] ?? 0)) === value,
          ),
        reason: null,
      };
    }),
  );
