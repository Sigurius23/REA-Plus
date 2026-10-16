import { describe, expect, it } from "vitest";

import { GameArchiveError } from "./GameArchiveTypes.js";
import { decodeSafePickle } from "./SafePickle.js";

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
