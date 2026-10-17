import { describe, expect, it } from "vitest";

import {
  isGeneratedName,
  normalizeInstruction,
  type FunctionFeatures,
} from "./BinaryDiffFeatures.js";
import { matchFunctions, similarity } from "./BinaryDiffMatcher.js";
import { editScript } from "./BinaryDiffEdits.js";

const ranges = [{ start: 0x400000n, end: 0x500000n }];

describe("instruction normalization", () => {
  it("abstracts jump targets, addresses and generated labels but keeps constants", () => {
    expect(normalizeInstruction("je 0x768d", ranges).text).toBe("je ADDR");
    expect(normalizeInstruction("call fcn.000074d0", ranges).text).toBe(
      "call ADDR",
    );
    expect(normalizeInstruction("call sym.imp.printf", ranges).text).toBe(
      "call sym.imp.printf",
    );
    expect(normalizeInstruction("mov rax, 0x401a30", ranges).text).toBe(
      "mov rax, ADDR",
    );
    expect(
      normalizeInstruction("cmp dword [rdi + 0x18], 0x1c4f", ranges),
    ).toEqual({
      text: "cmp dword [rdi + 0x18], 0x1c4f",
      mnemonic: "cmp",
      constants: ["0x1c4f"],
    });
    expect(normalizeInstruction("lea rdx, [FUN_00101234]", ranges).text).toBe(
      "lea rdx, [SYM]",
    );
    expect(normalizeInstruction("rep stosq", ranges).mnemonic).toBe(
      "rep stosq",
    );
    expect(normalizeInstruction("BL 0x10230", ranges).text).toBe("bl ADDR");
  });

  it("recognizes names made up from a function's own address", () => {
    expect(isGeneratedName("fcn.00007630", "0x7630")).toBe(true);
    expect(isGeneratedName("FUN_00107630", "0x107630")).toBe(true);
    expect(isGeneratedName("sub_401000", "0x401000")).toBe(true);
    expect(isGeneratedName("sym.inflate", "0x7630")).toBe(false);
    expect(isGeneratedName("main", "0x1139")).toBe(false);
  });
});

describe("edit script", () => {
  const lcs = (a: readonly string[], b: readonly string[]) => {
    const table = Array.from({ length: a.length + 1 }, () =>
      new Array<number>(b.length + 1).fill(0),
    );
    for (let i = 1; i <= a.length; i += 1)
      for (let j = 1; j <= b.length; j += 1)
        (table[i] as number[])[j] =
          a[i - 1] === b[j - 1]
            ? ((table[i - 1] as number[])[j - 1] ?? 0) + 1
            : Math.max(
                (table[i - 1] as number[])[j] ?? 0,
                (table[i] as number[])[j - 1] ?? 0,
              );
    return (table[a.length] as number[])[b.length] ?? 0;
  };

  it("finds a shortest edit script that rebuilds both sides", () => {
    let seed = 7;
    const random = () => {
      seed = (seed * 1_103_515_245 + 12_345) % 2 ** 31;
      return seed / 2 ** 31;
    };
    for (let round = 0; round < 200; round += 1) {
      const a = Array.from({ length: Math.floor(random() * 30) }, () =>
        "abcde".charAt(Math.floor(random() * 5)),
      );
      const b = Array.from({ length: Math.floor(random() * 30) }, () =>
        "abcde".charAt(Math.floor(random() * 5)),
      );
      const edits = editScript(a, b) ?? [];
      const rebuiltLeft: string[] = [];
      const rebuiltRight: string[] = [];
      let x = 0;
      let y = 0;
      for (const edit of edits) {
        if (edit !== "added") rebuiltLeft.push(a[x++] as string);
        if (edit !== "removed") rebuiltRight.push(b[y++] as string);
        if (edit === "same")
          expect(rebuiltLeft.at(-1)).toBe(rebuiltRight.at(-1));
      }
      expect([rebuiltLeft, rebuiltRight]).toEqual([a, b]);
      expect(edits.filter((edit) => edit === "same").length).toBe(lcs(a, b));
    }
  });

  it("gives up beyond the edit budget", () => {
    expect(editScript(["a", "b"], ["c", "d"], 3)).toBeNull();
    expect(editScript([], [])).toEqual([]);
  });
});

const fn = (
  address: string,
  normalized: readonly string[],
  extra: Partial<FunctionFeatures> = {},
): FunctionFeatures => ({
  address,
  name: `fcn.${address.slice(2).padStart(8, "0")}`,
  generatedName: true,
  size: normalized.length * 4,
  lines: normalized,
  lineAddresses: normalized.map(() => address),
  normalized,
  mnemonics: normalized.map((line) => line.split(" ")[0] ?? ""),
  exactHash: normalized.join("|"),
  mnemonicHash: normalized.map((line) => line.split(" ")[0]).join("|"),
  blocks: 1,
  edges: 0,
  shapeHash: "1",
  mdIndex: 0,
  callees: [],
  callSequence: [],
  callers: [],
  calleeNames: [],
  strings: [],
  constants: [],
  names: [],
  ...extra,
});

describe("function matching", () => {
  const thunk = ["endbr64", "mov edx, edx", "jmp ADDR"];
  const body = (seed: string) =>
    Array.from({ length: 8 }, (_, at) => `op${seed}${String(at)} eax`);

  it("tells identical thunks apart by the functions they jump to", () => {
    const build = (shift: number) => {
      const at = (value: number) => `0x${(value + shift).toString(16)}`;
      return [
        fn(at(0x100), body("a"), { callers: [at(0x300)] }),
        fn(at(0x200), body("b"), { callers: [at(0x400)] }),
        fn(at(0x300), thunk, { callees: [at(0x100)], callers: [at(0x500)] }),
        fn(at(0x400), thunk, { callees: [at(0x200)], callers: [at(0x500)] }),
        fn(at(0x500), body("main"), { callees: [at(0x300), at(0x400)] }),
      ];
    };
    const result = matchFunctions(build(0), build(0x40), {
      names: true,
      threshold: 0.5,
    });
    expect(
      result.matches
        .map(({ left, right }) => [left.address, right.address])
        .sort(),
    ).toEqual([
      ["0x100", "0x140"],
      ["0x200", "0x240"],
      ["0x300", "0x340"],
      ["0x400", "0x440"],
      ["0x500", "0x540"],
    ]);
    expect(
      result.matches.find(({ left }) => left.address === "0x300")?.method,
    ).toBe("call-graph");
  });

  it("pairs a function changed in place by its position in its caller's calls", () => {
    const shared = Array.from(
      { length: 12 },
      (_, at) => `shared${String(at)} eax`,
    );
    const left = [
      fn("0x100", body("a")),
      fn("0x200", [...shared, "old0 ecx", "old1 ecx"]),
      fn("0x300", body("c")),
      fn("0x400", body("main"), {
        name: "main",
        generatedName: false,
        callSequence: ["0x100", "0x200", "0x300"],
        callees: ["0x100", "0x200", "0x300"],
      }),
    ];
    const right = [
      fn("0x1100", body("a")),
      fn("0x1150", body("new")),
      // The changed function gained code another function was merged into.
      fn("0x1200", [
        ...Array.from({ length: 14 }, (_, at) => `merged${String(at)} edx`),
        ...shared,
      ]),
      fn("0x1300", body("c")),
      fn("0x1400", body("main"), {
        name: "main",
        generatedName: false,
        callSequence: ["0x1100", "0x1150", "0x1200", "0x1300"],
        callees: ["0x1100", "0x1150", "0x1200", "0x1300"],
      }),
    ];
    const result = matchFunctions(left, right, { names: true, threshold: 0.5 });
    expect(
      result.matches.find(({ left: item }) => item.address === "0x200"),
    ).toMatchObject({ right: { address: "0x1200" }, method: "call-order" });
    expect(result.added.map(({ address }) => address)).toEqual(["0x1150"]);
  });

  it("leaves dissimilar functions without matched neighbours unmatched", () => {
    const result = matchFunctions(
      [fn("0x100", body("x"))],
      [fn("0x200", body("y"))],
      { names: true, threshold: 0.5 },
    );
    expect(result.matches).toEqual([]);
    expect([result.removed.length, result.added.length]).toEqual([1, 1]);
  });

  it("matches unique non-generated names first, and only when allowed", () => {
    const left = [
      fn("0x100", body("a"), { name: "inflate", generatedName: false }),
    ];
    const right = [
      fn("0x900", body("z"), { name: "inflate", generatedName: false }),
    ];
    expect(
      matchFunctions(left, right, { names: true, threshold: 0.5 }).matches[0]
        ?.method,
    ).toBe("name");
    expect(
      matchFunctions(left, right, { names: false, threshold: 0.5 }).matches,
    ).toEqual([]);
  });

  it("scores identical instructions as 1 and shares nothing as low", () => {
    expect(similarity(fn("0x1", body("a")), fn("0x2", body("a")))).toBe(1);
    expect(similarity(fn("0x1", body("a")), fn("0x2", body("b")))).toBeLessThan(
      0.5,
    );
  });
});
