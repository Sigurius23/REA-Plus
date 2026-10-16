import { describe, expect, it } from "vitest";

import { RADARE2_DIALECT, RIZIN_DIALECT } from "./Radare2Dialect.js";
import {
  mergeBlockRanges,
  parseRadare2Address,
  parseRadare2Json,
  parseRadare2VersionBanner,
  parseSessionVersion,
  radare2BlocksSchema,
  radare2FunctionsSchema,
  radare2Reply,
  RADARE2_INVALID_ADDRESS,
} from "./Radare2Values.js";

describe("radare2 reply values", () => {
  it("keeps 64-bit addresses and UT64_MAX sentinels exact", () => {
    // Recorded `afbj` rows: radare2 prints UT64_MAX as a bare JSON number.
    const blocks = radare2Reply(
      "procedure_info",
      "afbj",
      '[{"addr":18446744071562067968,"size":12,"opaddr":18446744073709551615,"traced":0}]',
      radare2BlocksSchema,
    );
    expect(blocks).toEqual([{ addr: 0xffff_ffff_8000_0000n, size: 12 }]);
    expect(
      parseRadare2Json("x", '{"opaddr":18446744073709551615,"ratio":1.929}'),
    ).toEqual({ opaddr: RADARE2_INVALID_ADDRESS, ratio: 1.929 });
  });

  it("names the command when a reply is empty, malformed or reshaped", () => {
    expect(() => parseRadare2Json("list_procedures", "")).toThrow(/no JSON/u);
    expect(() => parseRadare2Json("list_procedures", ":\n[")).toThrow(
      /invalid JSON/u,
    );
    expect(() =>
      radare2Reply(
        "procedure_info",
        "afbj",
        '[{"addr":"0x10"}]',
        radare2BlocksSchema,
      ),
    ).toThrow(/afbj reply does not match the supported shape/u);
  });

  it("merges adjacent and overlapping blocks into maximal inclusive ranges", () => {
    expect(
      mergeBlockRanges([
        { addr: 0x1020n, size: 4 },
        { addr: 0x1000n, size: 0x10 },
        { addr: 0x1010n, size: 8 },
        { addr: 0x1014n, size: 2 },
        { addr: 0x2000n, size: 0 },
      ]),
    ).toEqual([
      { start: 0x1000n, end: 0x1017n },
      { start: 0x1020n, end: 0x1023n },
    ]);
  });

  it("reads Rizin's offset as the row address radare2 calls addr", () => {
    // Recorded Rizin 0.9.1 `afij` row, trimmed.
    expect(
      radare2Reply(
        "procedure_info",
        "afij",
        '[{"offset":4194587,"name":"sym.helper","size":5,"nbbs":1,"signature":"sym.helper();"}]',
        radare2FunctionsSchema,
      ),
    ).toEqual([
      {
        addr: 0x40011bn,
        name: "sym.helper",
        size: 5,
        nbbs: 1,
        signature: "sym.helper();",
      },
    ]);
  });

  it("accepts only the 0x-prefixed addresses REA+ publishes", () => {
    expect(parseRadare2Address("0x40011B")).toBe(0x40011bn);
    expect(parseRadare2Address("40011b")).toBeUndefined();
    expect(parseRadare2Address("0x40011b; !id")).toBeUndefined();
    expect(parseRadare2Address(`0x${"f".repeat(17)}`)).toBeUndefined();
  });

  it("reads version and commit from the recorded 6.2.4 banner", () => {
    expect(
      parseRadare2VersionBanner(
        "radare2 6.2.4 +1 abi:152 @ linux-x86_64\nbirth: git.6.2.4 2026-10-15__22:26:21\ncommit: 485e5e205b190fc297a2a95a6f982ff5d9f54039\noptions: gpl -O? cs:5 cl:2 make\n",
      ),
    ).toEqual({
      engine: "radare2",
      version: "6.2.4",
      commit: "485e5e205b190fc297a2a95a6f982ff5d9f54039",
    });
  });

  it("reads Rizin's banner and its in-session ver reply", () => {
    expect(
      parseRadare2VersionBanner(
        "rizin 0.9.1 @ linux-x86-64\ncommit: c3a90e9226d977f58f4e9c75f78fa6b07afe13c7\n",
      ),
    ).toEqual({
      engine: "rizin",
      version: "0.9.1",
      commit: "c3a90e9226d977f58f4e9c75f78fa6b07afe13c7",
    });
    expect(
      parseSessionVersion(
        RIZIN_DIALECT,
        "0.9.1 @ linux-x86-64\ncommit: c3a90e9226d977f58f4e9c75f78fa6b07afe13c7\n",
      ),
    ).toBe("0.9.1");
    expect(
      parseSessionVersion(RADARE2_DIALECT, "rizin 0.9.1 @ linux-x86-64"),
    ).toBeUndefined();
    expect(parseRadare2VersionBanner("cutter 2.3.4")).toBeNull();
  });
});
