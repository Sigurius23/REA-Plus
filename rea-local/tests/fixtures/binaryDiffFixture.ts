import type { DiffAnalysisSession } from "../../src/bindiff/BinaryDiffCollector.js";
import type { BinaryTarget } from "../../src/domain/binaryTargetTypes.js";
import type { JsonValue } from "../../src/domain/jsonValue.js";
import { err, ok } from "../../src/domain/result.js";
import { AnalysisInputError } from "../../src/domain/analysisErrorCore.js";

/** One function of a fixture build: instruction text and its relations. */
export interface FixtureFunction {
  readonly address: number;
  readonly name?: string;
  readonly lines: readonly string[];
  readonly calls?: readonly number[];
  readonly strings?: readonly string[];
}

const hex = (value: number) => `0x${value.toString(16)}`;
const nameOf = (fn: FixtureFunction) =>
  fn.name ?? `fcn.${fn.address.toString(16).padStart(8, "0")}`;

const identity = (fn: FixtureFunction) => ({
  address: hex(fn.address),
  name: nameOf(fn),
  classification: null,
  body: { available: false, reason: "fixture" },
});

/** A provider-neutral function dossier, as analyze_function returns it. */
const dossier = (
  fn: FixtureFunction,
  build: readonly FixtureFunction[],
): JsonValue => {
  const at = (address: number) =>
    build.find((item) => item.address === address) as FixtureFunction;
  const callers = build.filter((item) =>
    (item.calls ?? []).includes(fn.address),
  );
  return {
    procedure: { ...identity(fn), signature: null, locals: [] },
    pseudocode: "",
    assembly: fn.lines.map(
      (line, index) => `${hex(fn.address + index * 4)}: ${line}`,
    ),
    comments: [],
    callers: callers.map(identity),
    callees: (fn.calls ?? []).map((address) => identity(at(address))),
    incoming_references: [],
    outgoing_references: [],
    unresolved_calls: [],
    referenced_strings: (fn.strings ?? []).map((value, index) => ({
      address: hex(0x9000 + index * 0x20),
      value,
      source_address: hex(fn.address),
    })),
    referenced_names: [],
    basic_blocks: [
      {
        start: hex(fn.address),
        end: hex(fn.address + fn.lines.length * 4),
        successors: [],
      },
    ],
    native_api: null,
    native_value_flow: null,
    limitations: [],
  };
};

const call = (address: number) =>
  `call fcn.${address.toString(16).padStart(8, "0")}`;

/**
 * Two builds of a small program. The newer build moves every function by
 * 0x40, changes `update` (a new constant and a call to a new function
 * instead of a removed one), and keeps two identical thunks that only the
 * call graph tells apart.
 */
export const fixtureBuilds = (): {
  readonly left: readonly FixtureFunction[];
  readonly right: readonly FixtureFunction[];
} => {
  const build = (shift: number, newer: boolean): FixtureFunction[] => {
    const a = (address: number) => address + shift;
    const extra = newer ? a(0x1a00) : 0x1900;
    return [
      {
        address: a(0x1000),
        name: "entry0",
        lines: ["endbr64", "xor ebp, ebp", call(a(0x1100)), "hlt"],
        calls: [a(0x1100)],
      },
      {
        address: a(0x1100),
        name: "main",
        lines: [
          "push rbx",
          "cmp edi, 1",
          "jle 0x1180",
          call(a(0x1200)),
          call(a(0x1300)),
          call(a(0x1400)),
          call(a(0x1500)),
          call(a(0x1600)),
          "pop rbx",
          "ret",
        ],
        calls: [a(0x1200), a(0x1300), a(0x1400), a(0x1500), a(0x1600)],
        strings: ["usage: game LEVEL"],
      },
      {
        address: a(0x1200),
        lines: [
          "push rbp",
          "mov rbp, rsp",
          "mov dword [rdi], 0x1c4f",
          "lea rsi, str.config.ini",
          "mov eax, 1",
          "pop rbp",
          "ret",
        ],
        strings: ["config.ini"],
      },
      {
        address: a(0x1300),
        lines: [
          "push rbp",
          "mov rbp, rsp",
          "mov eax, dword [rdi + 8]",
          "add eax, dword [rdi + 0xc]",
          `imul eax, eax, ${newer ? "0x2710" : "0x3e8"}`,
          "mov dword [rdi + 8], eax",
          "test eax, eax",
          "js 0x1340",
          call(extra),
          "pop rbp",
          "ret",
        ],
        calls: [extra],
      },
      {
        address: a(0x1400),
        lines: [
          "push r12",
          "mov r12, rdi",
          "movss xmm0, dword [rdi + 0x10]",
          "mulss xmm0, xmm1",
          "movss dword [rdi + 0x10], xmm0",
          "pop r12",
          "ret",
        ],
      },
      // Identical thunks to two different checksum routines.
      {
        address: a(0x1500),
        lines: [
          "endbr64",
          "mov edx, edx",
          `jmp fcn.0000${a(0x1700).toString(16)}`,
        ],
        calls: [a(0x1700)],
      },
      {
        address: a(0x1600),
        lines: [
          "endbr64",
          "mov edx, edx",
          `jmp fcn.0000${a(0x1800).toString(16)}`,
        ],
        calls: [a(0x1800)],
      },
      {
        address: a(0x1700),
        lines: [
          "mov eax, 1",
          "xor ecx, ecx",
          "movzx r8d, byte [rsi + rcx]",
          "add eax, r8d",
          "cmp eax, 0xfff1",
          "inc rcx",
          "ret",
        ],
      },
      {
        address: a(0x1800),
        lines: [
          "not edi",
          "lea r9, [rip + 0x2000]",
          "movzx eax, byte [rsi]",
          "xor eax, edi",
          "shr edi, 8",
          "xor edi, dword [r9 + rax*4]",
          "not eax",
          "ret",
        ],
      },
      newer
        ? {
            address: extra,
            lines: [
              "push rbx",
              "lea rdi, str.tamper",
              "mov esi, 0xdeadbeef",
              "rdtsc",
              "pop rbx",
              "ret",
            ],
            strings: ["tamper detected"],
          }
        : {
            address: extra,
            lines: [
              "push r13",
              "lea rdi, str.cheat",
              "mov esi, 0x5a5a",
              "cpuid",
              "pop r13",
              "ret",
            ],
            strings: ["cheat detected"],
          },
    ];
  };
  return { left: build(0, false), right: build(0x40, true) };
};

/** A session answering from one fixture build, as a provider would. */
export const fixtureSession = (
  builds: ReadonlyMap<string, readonly FixtureFunction[]>,
  sha256: (path: string) => string,
  provider = "fixture-provider",
): DiffAnalysisSession => {
  let current: { path: string; build: readonly FixtureFunction[] } | undefined;
  const execution = (result: JsonValue) =>
    ok({
      result,
      rawResult: null,
      provider: { id: provider, name: provider, version: "1" },
      limitations: ["fixture limitation"],
      locations: [],
      subject: null,
    });
  return {
    open: async (path) => {
      const build = builds.get(path);
      if (build === undefined)
        return err(new AnalysisInputError("open_binary"));
      current = { path, build };
      return ok({
        kind: "executable",
        path,
        sha256: sha256(path),
        format: "elf",
      } as unknown as BinaryTarget);
    },
    execute: async (operation, input) => {
      const build = current?.build ?? [];
      if (operation === "list_procedures")
        return execution(
          build.map((fn) => ({ address: hex(fn.address), value: nameOf(fn) })),
        );
      if (operation === "list_segments")
        return execution([{ start: "0x1000", end: "0x3000" }]);
      const fn = build.find((item) => hex(item.address) === input.procedure);
      return fn === undefined
        ? err(new AnalysisInputError(operation))
        : execution(dossier(fn, build));
    },
    close: async () => {
      current = undefined;
      return ok(null);
    },
  };
};
