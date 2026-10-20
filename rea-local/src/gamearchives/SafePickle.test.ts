import { describe, expect, it } from "vitest";

import { GameArchiveError } from "./GameArchiveTypes.js";
import { decodeSafePickle, PickleObject } from "./SafePickle.js";

/**
 * Python 3.13 pickle.dumps of an RPA-3.0-style index at protocols 2 and 5:
 * {"script.rpy": [(0x42424242 ^ 51, 0x42424242 ^ 49, b"")],
 *  "images/bg.png": [(0x42424242 ^ 100, 0x42424242 ^ 5000, b"\x89PNG")],
 *  "big.bin": [(3000000000, 2**40, b"")]}
 * Protocol 2 spells bytes as _codecs.encode(text, "latin1") and bytes().
 */
const PROTOCOL_2 =
  "80027d710028580a0000007363726970742e72707971015d71024a714242424a73424242635f5f6275696c74696e5f5f0a62797465730a71032952710487710561580d000000696d616765732f62672e706e6771065d71074a264242424aca514242635f636f646563730a656e636f64650a71085805000000c289504e47710958060000006c6174696e31710a86710b52710c87710d6158070000006269672e62696e710e5d710f8a05005ed0b2008a06000000000001680487711061752e";
const PROTOCOL_5 =
  "8005956a000000000000007d94288c0a7363726970742e727079945d944a714242424a734242424300948794618c0d696d616765732f62672e706e67945d944a264242424aca514242430489504e47948794618c076269672e62696e945d948a05005ed0b2008a060000000000016803879461752e";
/** pickle.dumps of an object whose __reduce__ returns (os.system, ("echo pwned",)). */
const SYSTEM_CALL_2 =
  "800263706f7369780a73797374656d0a7100580a0000006563686f2070776e656471018571025271032e";
const SYSTEM_CALL_4 =
  "80049525000000000000008c05706f736978948c0673797374656d9493948c0a6563686f2070776e656494859452942e";

const expected = new Map<unknown, unknown>([
  [
    "script.rpy",
    [[BigInt(0x42424242 ^ 51), BigInt(0x42424242 ^ 49), Buffer.alloc(0)]],
  ],
  [
    "images/bg.png",
    [
      [
        BigInt(0x42424242 ^ 100),
        BigInt(0x42424242 ^ 5000),
        Buffer.from([0x89, 0x50, 0x4e, 0x47]),
      ],
    ],
  ],
  ["big.bin", [[3_000_000_000n, 2n ** 40n, Buffer.alloc(0)]]],
]);

describe("decodeSafePickle", () => {
  it.each([
    ["protocol 2", PROTOCOL_2],
    ["protocol 5", PROTOCOL_5],
  ])("decodes a %s archive index", (_name, hex) => {
    expect(decodeSafePickle(Buffer.from(hex, "hex"))).toEqual(expected);
  });

  it.each([
    ["GLOBAL os.system", SYSTEM_CALL_2, /refusing global posix\.system/u],
    ["STACK_GLOBAL os.system", SYSTEM_CALL_4, /refusing global posix\.system/u],
    ["an unknown opcode", "8002632e", /unterminated line|truncated/u],
    [
      "a truncated stream",
      PROTOCOL_5.slice(0, 80),
      /truncated|past the end|missing STOP/u,
    ],
    ["INST", "80026928", /unsupported opcode 0x69/u],
  ])("refuses %s without running it", (_name, hex, message) => {
    expect(() => decodeSafePickle(Buffer.from(hex, "hex"))).toThrow(
      GameArchiveError,
    );
    expect(() => decodeSafePickle(Buffer.from(hex, "hex"))).toThrow(message);
  });
});

/**
 * Python 3.13 pickles of ({"version": 5003000}, [Say, PyExpr]) where Say is a
 * slotted renpy.ast class (state (None, slots)) and PyExpr a str subclass
 * rebuilt through NEWOBJ, as Ren'Py's compiled scripts store them.
 */
const OBJECTS_2 =
  "80027d7100580700000076657273696f6e71014af8564c00735d7102286372656e70792e6173740a5361790a7103298171044e7d710528580300000077686f710658010000006571075804000000776861747108580500000048656c6c6f71097586710a626372656e70792e6173740a5079457870720a710b5804000000666c6167710c580f00000067616d652f7363726970742e727079710d4b0487710e81710f7d711028580800000066696c656e616d657111680d58040000006c696e6571124b047562658671132e";
const OBJECTS_5 =
  "80059598000000000000007d948c0776657273696f6e944af8564c00735d94288c0972656e70792e617374948c035361799493942981944e7d94288c0377686f948c0165948c0477686174948c0548656c6c6f947586946268038c065079457870729493948c04666c6167948c0f67616d652f7363726970742e727079944b04879481947d94288c0866696c656e616d659468108c046c696e65944b0475626586942e";

describe("decodeSafePickle with objects", () => {
  const renpy = (module: string) => module.startsWith("renpy.");

  it.each([
    ["protocol 2", OBJECTS_2],
    ["protocol 5", OBJECTS_5],
  ])("records %s instances as inert objects", (_name, hex) => {
    const value = decodeSafePickle(Buffer.from(hex, "hex"), { objects: renpy });
    expect(Array.isArray(value)).toBe(true);
    const [meta, nodes] = value as unknown[];
    expect(meta).toEqual(new Map([["version", 5003000n]]));
    const [say, expression] = nodes as PickleObject[];
    expect(say).toBeInstanceOf(PickleObject);
    expect(say?.type.qualifiedName).toBe("renpy.ast.Say");
    expect(Object.fromEntries(say?.fields ?? [])).toEqual({
      who: "e",
      what: "Hello",
    });
    expect(expression?.type.qualifiedName).toBe("renpy.ast.PyExpr");
    expect(expression?.args).toEqual(["flag", "game/script.rpy", 4n]);
    expect(Object.fromEntries(expression?.fields ?? [])).toEqual({
      filename: "game/script.rpy",
      line: 4n,
    });
  });

  it("refuses classes outside the allowed namespaces", () => {
    expect(() => decodeSafePickle(Buffer.from(OBJECTS_5, "hex"))).toThrow(
      /refusing global renpy\.ast\.Say/u,
    );
    expect(() =>
      decodeSafePickle(Buffer.from(SYSTEM_CALL_4, "hex"), { objects: renpy }),
    ).toThrow(/refusing global posix\.system/u);
  });
});
