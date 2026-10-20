import { isInteger, parse } from "lossless-json";
import { z } from "zod";

import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import type { Radare2Dialect } from "./Radare2Dialect.js";

/** radare2 marks absent 64-bit coordinates with UT64_MAX. */
export const RADARE2_INVALID_ADDRESS = 0xffff_ffff_ffff_ffffn;

/**
 * Parse one radare2 JSON reply without losing 64-bit precision.
 *
 * Every integer becomes a bigint because radare2 prints addresses, sizes and
 * UT64_MAX sentinels as bare JSON numbers; fractional metrics stay numbers.
 */
export const parseRadare2Json = (operation: string, text: string): unknown => {
  const trimmed = text.trim();
  if (trimmed.length === 0)
    throw new AnalysisOutputError(
      operation,
      "radare2 returned no JSON for a command that requires it",
    );
  try {
    return parse(trimmed, null, (value: string) =>
      isInteger(value) ? BigInt(value) : Number(value),
    );
  } catch (cause: unknown) {
    throw new AnalysisOutputError(operation, "radare2 returned invalid JSON", {
      cause,
    });
  }
};

/** Parse a radare2 reply against one schema, naming the producing command on failure. */
export const radare2Reply = <Schema extends z.ZodType>(
  operation: string,
  command: string,
  text: string,
  schema: Schema,
): z.output<Schema> => {
  const parsed = schema.safeParse(parseRadare2Json(operation, text));
  if (!parsed.success)
    throw new AnalysisOutputError(
      operation,
      `radare2 ${command} reply does not match the supported shape: ${parsed.error.issues
        .slice(0, 3)
        .map((issue) => `${issue.path.join(".") || "$"}: ${issue.message}`)
        .join("; ")}`,
      { cause: parsed.error },
    );
  return parsed.data;
};

const u64 = z.bigint().min(0n).max(RADARE2_INVALID_ADDRESS);
const count = z
  .bigint()
  .min(0n)
  .max(BigInt(Number.MAX_SAFE_INTEGER))
  .transform(Number);

/** Rizin names a row's address `offset` where radare2 says `addr`. */
const addressed = <Schema extends z.ZodType>(schema: Schema) =>
  z.preprocess(
    (row) =>
      typeof row === "object" &&
      row !== null &&
      !("addr" in row) &&
      "offset" in row
        ? { ...row, addr: row.offset }
        : row,
    schema,
  );

/** `ij`: identity of the file radare2 actually opened. */
export const radare2InfoSchema = z.object({
  core: z.object({
    file: z.string(),
    fd: count,
    size: count,
    format: z.string(),
  }),
  bin: z.object({
    arch: z.string(),
    bits: count,
    baddr: u64,
    endian: z.string(),
  }),
});

/** `aflj` and `afij` rows. */
export const radare2FunctionSchema = addressed(
  z.object({
    addr: u64,
    name: z.string().min(1),
    size: count,
    nbbs: count,
    signature: z.string().optional(),
  }),
);
export const radare2FunctionsSchema = z.array(radare2FunctionSchema);
export type Radare2Function = z.output<typeof radare2FunctionSchema>;

/** `afbj` basic-block rows; `jump` and `fail` are successor block starts. */
export const radare2BlocksSchema = z.array(
  z.object({
    addr: u64,
    size: count,
    jump: u64.optional(),
    fail: u64.optional(),
  }),
);

/** `pdfj`: one function's instructions with resolved branch targets. */
export const radare2DisassemblySchema = z.object({
  ops: z.array(
    addressed(
      z.object({
        addr: u64,
        type: z.string(),
        disasm: z.string().optional(),
        jump: u64.optional(),
      }),
    ),
  ),
});

const variableSchema = z.object({
  name: z.string(),
  kind: z.string(),
  type: z.string(),
  ref: z.union([
    z.string(),
    z.object({ base: z.string(), offset: z.bigint() }),
  ]),
});
/** `afvj`: register, stack-pointer and frame-pointer relative variables. */
export const radare2VariablesSchema = z.object({
  reg: z.array(variableSchema),
  sp: z.array(variableSchema),
  bp: z.array(variableSchema),
});

/** Rizin `afvlj`: variables grouped by storage kind (reg, stack and others). */
export const rizinVariablesSchema = z.record(
  z.string(),
  z.array(
    z.object({
      name: z.string(),
      arg: z.boolean(),
      type: z.string(),
      storage: z.object({
        type: z.string(),
        reg: z.string().optional(),
        stack: z.bigint().optional(),
      }),
    }),
  ),
);

/** `izj` data-section strings. */
export const radare2StringsSchema = z.array(
  z.object({
    vaddr: u64,
    paddr: u64,
    size: count,
    length: count,
    type: z.string(),
    string: z.string(),
  }),
);

/** `isj` symbols; Rizin omits `vaddr` for imports it has not placed. */
export const radare2SymbolsSchema = z.array(
  z.object({
    name: z.string(),
    realname: z.string().optional(),
    flagname: z.string().optional(),
    type: z.string(),
    vaddr: u64.default(RADARE2_INVALID_ADDRESS),
    is_imported: z.boolean(),
  }),
);

/** `iSj` sections and `iSSj` segments. */
export const radare2SectionsSchema = z.array(
  z.object({
    name: z.string(),
    vaddr: u64,
    vsize: count,
    perm: z.string(),
    type: z.string().optional(),
  }),
);

/** `omj` IO maps; `to` is inclusive and `delta` is the offset inside `fd`. */
export const radare2MapsSchema = z.array(
  z.object({
    fd: count,
    from: u64,
    to: u64,
    delta: u64,
    name: z.string(),
  }),
);
export type Radare2Map = z.output<typeof radare2MapsSchema>[number];

/** `axtj` references to one address. */
export const radare2ReferencesToSchema = z.array(
  z.object({
    from: u64,
    type: z.string(),
    fcn_addr: u64.optional(),
  }),
);

/** `axffj` references made from one function body. */
export const radare2ReferencesFromSchema = z.array(
  z.object({ type: z.string(), at: u64, ref: u64 }),
);

const rizinReferenceSchema = z.object({ from: u64, to: u64, type: z.string() });
/** Rizin `afij` references made from a body: callrefs (CALL, CODE) and datarefs (DATA, STRING). */
export const rizinFunctionReferencesSchema = z.array(
  addressed(
    z.object({
      addr: u64,
      callrefs: z.array(rizinReferenceSchema).optional(),
      datarefs: z.array(rizinReferenceSchema).optional(),
    }),
  ),
);

/** `fd.j` flags at exactly one address. */
export const radare2FlagsAtSchema = z.array(z.object({ name: z.string() }));

/** Canonical REA+ text for one default-space address. */
export const formatRadare2Address = (value: bigint): string =>
  `0x${value.toString(16)}`;

/** Accept only the 0x-prefixed hexadecimal form REA+ publishes. */
export const parseRadare2Address = (value: string): bigint | undefined =>
  /^0x[0-9a-f]{1,16}$/iu.test(value) ? BigInt(value) : undefined;

/** Compare addresses without converting through IEEE-754 numbers. */
export const compareRadare2Addresses = (left: bigint, right: bigint): number =>
  left < right ? -1 : left > right ? 1 : 0;

/** Sorted, merged inclusive ranges covering a function's basic blocks. */
export const mergeBlockRanges = (
  blocks: readonly { readonly addr: bigint; readonly size: number }[],
): { readonly start: bigint; readonly end: bigint }[] => {
  const ordered = blocks
    .filter(({ size }) => size > 0)
    .map(({ addr, size }) => ({ start: addr, end: addr + BigInt(size) - 1n }))
    .sort((left, right) => compareRadare2Addresses(left.start, right.start));
  const merged: { start: bigint; end: bigint }[] = [];
  for (const range of ordered) {
    const previous = merged.at(-1);
    if (previous !== undefined && range.start <= previous.end + 1n) {
      if (range.end > previous.end) previous.end = range.end;
    } else merged.push({ ...range });
  }
  return merged;
};

/** Parse radare2's `-r-x` style permission text; `-` and `r` are positional. */
export const parseRadare2Permissions = (
  perm: string,
): {
  readonly readable: boolean;
  readonly writable: boolean;
  readonly executable: boolean;
} => ({
  readable: perm.includes("r"),
  writable: perm.includes("w"),
  executable: perm.includes("x"),
});

/** Parse the first line of `r2 -v`, `?V` or `rizin -v` into an engine and semantic version. */
export const parseRadare2VersionBanner = (
  banner: string,
): {
  readonly engine: Radare2Dialect["engine"];
  readonly version: string;
  readonly commit: string | null;
} | null => {
  const first = /^(radare2|rizin) (\d+\.\d+\.\d+)(?:[ -].*)?$/mu.exec(banner);
  if (first?.[1] === undefined || first[2] === undefined) return null;
  const commit = /^commit: ([0-9a-f]{7,64})$/mu.exec(banner)?.[1] ?? null;
  return {
    engine: first[1] === "rizin" ? "rizin" : "radare2",
    version: first[2],
    commit,
  };
};

/** The version a running session reports: radare2's `?V` banner, or Rizin's `ver` (its banner without the engine name). */
export const parseSessionVersion = (
  dialect: Radare2Dialect,
  reply: string,
): string | undefined => {
  if (dialect.engine === "rizin")
    return /^(\d+\.\d+\.\d+) @ /mu.exec(reply)?.[1];
  const banner = parseRadare2VersionBanner(reply);
  return banner?.engine === "radare2" ? banner.version : undefined;
};
