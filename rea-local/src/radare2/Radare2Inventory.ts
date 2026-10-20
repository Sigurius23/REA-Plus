import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import type { Radare2Dialect } from "./Radare2Dialect.js";
import {
  compareRadare2Addresses,
  formatRadare2Address,
  mergeBlockRanges,
  parseRadare2Address,
  radare2BlocksSchema,
  radare2FunctionsSchema,
  radare2MapsSchema,
  radare2ReferencesFromSchema,
  radare2ReferencesToSchema,
  radare2Reply,
  radare2SectionsSchema,
  radare2StringsSchema,
  radare2SymbolsSchema,
  RADARE2_INVALID_ADDRESS,
  rizinFunctionReferencesSchema,
  type Radare2Function,
  type Radare2Map,
} from "./Radare2Values.js";

/** Command execution seam; production is one owned `-q0` process. */
export interface Radare2CommandPort {
  run(command: string, signal?: AbortSignal): Promise<string>;
}

/** Facts established when the session opened its private target copy. */
export interface Radare2Binding {
  /** Document identity callers may pass; the admitted target's file name. */
  readonly documentName: string;
  /** Original admitted path, reported as the verified mapping source. */
  readonly sourcePath: string;
  /** Private SHA-256-verified copy radare2 actually opened. */
  readonly snapshotPath: string;
  /** Command dialect of the running engine (radare2 or Rizin). */
  readonly dialect: Radare2Dialect;
  /** radare2 IO descriptor of that copy, from `ij`. */
  readonly fileDescriptor: number;
  /** Load base reported by radare2, from `ij`. */
  readonly baseAddress: bigint;
}

/** One loaded section, or segment when a format has no sections; `end` is exclusive. */
export interface Radare2LoadedRegion {
  readonly command: "iSj" | "iSSj";
  readonly name: string;
  readonly start: bigint;
  readonly end: bigint;
  readonly perm: string;
}

/** One reference to an address; `fcn_addr` is the function containing its source. */
export type Radare2ReferenceTo = ReturnType<
  typeof radare2ReferencesToSchema.parse
>[number];

/** A function together with its merged inclusive basic-block ranges. */
export interface Radare2FunctionBody {
  readonly fn: Radare2Function;
  readonly ranges: readonly { readonly start: bigint; readonly end: bigint }[];
}

/**
 * Session-scoped radare2 inventories. Analysis runs once before the first
 * operation and REA+ issues no mutating command, so each inventory is read at
 * most once and reused. Every executed command is recorded for provenance.
 */
export class Radare2Inventory {
  #functions: Radare2Function[] | undefined;
  #symbols: ReturnType<typeof radare2SymbolsSchema.parse> | undefined;
  #maps: Radare2Map[] | undefined;
  #regions: Radare2LoadedRegion[] | undefined;
  #strings: { readonly address: bigint; readonly value: string }[] | undefined;
  readonly #bodies = new Map<bigint, Radare2FunctionBody["ranges"]>();
  #commands: string[] = [];

  constructor(
    private readonly port: Radare2CommandPort,
    readonly binding: Radare2Binding,
  ) {}

  /** Start recording the commands of one operation. */
  beginOperation(): void {
    this.#commands = [];
  }

  /** Commands executed since the current operation began. */
  commands(): readonly string[] {
    return [...this.#commands];
  }

  async command(command: string, signal?: AbortSignal): Promise<string> {
    this.#commands.push(command);
    return this.port.run(command, signal);
  }

  async functions(
    operation: string,
    signal?: AbortSignal,
  ): Promise<Radare2Function[]> {
    if (this.#functions !== undefined) return this.#functions;
    const functions = radare2Reply(
      operation,
      "aflj",
      await this.command("aflj", signal),
      radare2FunctionsSchema,
    );
    functions.sort(
      (left, right) =>
        compareRadare2Addresses(left.addr, right.addr) ||
        left.name.localeCompare(right.name),
    );
    this.#functions = functions;
    return functions;
  }

  async symbols(operation: string, signal?: AbortSignal) {
    this.#symbols ??= radare2Reply(
      operation,
      "isj",
      await this.command("isj", signal),
      radare2SymbolsSchema,
    );
    return this.#symbols;
  }

  /** Data-section strings (`izj`) at mapped addresses, in address order. */
  async strings(operation: string, signal?: AbortSignal) {
    this.#strings ??= radare2Reply(
      operation,
      "izj",
      await this.command("izj", signal),
      radare2StringsSchema,
    )
      .filter(({ vaddr }) => vaddr !== RADARE2_INVALID_ADDRESS)
      .sort((left, right) => compareRadare2Addresses(left.vaddr, right.vaddr))
      .map((item) => ({ address: item.vaddr, value: item.string }));
    return this.#strings;
  }

  /** IO maps, top-most first with inclusive ends as radare2 lists them. */
  async maps(operation: string, signal?: AbortSignal): Promise<Radare2Map[]> {
    if (this.#maps !== undefined) return this.#maps;
    const command = this.binding.dialect.mapsCommand;
    const maps = radare2Reply(
      operation,
      command,
      await this.command(command, signal),
      radare2MapsSchema,
    );
    // Rizin's omlj lists maps bottom-most first and ends them exclusively.
    this.#maps =
      command === "omlj"
        ? maps
            .filter(({ from, to }) => to > from)
            .map((map) => ({ ...map, to: map.to - 1n }))
            .reverse()
        : maps;
    return this.#maps;
  }

  /** References to one address (`axtj`). */
  async referencesTo(
    operation: string,
    address: bigint,
    signal?: AbortSignal,
  ): Promise<Radare2ReferenceTo[]> {
    return radare2Reply(
      operation,
      "axtj",
      await this.command(`axtj @ ${formatRadare2Address(address)}`, signal),
      radare2ReferencesToSchema,
    );
  }

  /**
   * References to one address with the function containing each source.
   * Rizin's axtj does not name it, so each source is resolved as
   * resolve_containing_procedure would.
   */
  async referencesToWithFunctions(
    operation: string,
    address: bigint,
    signal?: AbortSignal,
  ): Promise<Radare2ReferenceTo[]> {
    const references = await this.referencesTo(operation, address, signal);
    if (this.binding.dialect.referencesNameFunctions) return references;
    const named: Radare2ReferenceTo[] = [];
    for (const reference of references) {
      const containing = await this.functionContaining(
        operation,
        reference.from,
        signal,
      );
      named.push(
        containing === undefined
          ? reference
          : { ...reference, fcn_addr: containing.fn.addr },
      );
    }
    return named;
  }

  /** References made from a function body, in source address order. */
  async referencesFrom(
    operation: string,
    fn: Radare2Function,
    signal?: AbortSignal,
  ): Promise<ReturnType<typeof radare2ReferencesFromSchema.parse>> {
    const at = entryAddress(fn);
    if (this.binding.dialect.referencesFromCommand === "axffj")
      return radare2Reply(
        operation,
        "axffj",
        await this.command(`axffj @ ${at}`, signal),
        radare2ReferencesFromSchema,
      );
    const info = radare2Reply(
      operation,
      "afij",
      await this.command(`afij @ ${at}`, signal),
      rizinFunctionReferencesSchema,
    ).find(({ addr }) => addr === fn.addr);
    if (info === undefined)
      throw new AnalysisOutputError(
        operation,
        `Rizin afij did not describe the function at ${at}`,
      );
    return [...(info.callrefs ?? []), ...(info.datarefs ?? [])]
      .map(({ from, to, type }) => ({ type, at: from, ref: to }))
      .sort(
        (left, right) =>
          compareRadare2Addresses(left.at, right.at) ||
          compareRadare2Addresses(left.ref, right.ref),
      );
  }

  /** Loaded sections, or segments for formats without section headers. */
  async regions(
    operation: string,
    signal?: AbortSignal,
  ): Promise<Radare2LoadedRegion[]> {
    if (this.#regions !== undefined) return this.#regions;
    let regions = loadedRegions(
      "iSj",
      radare2Reply(
        operation,
        "iSj",
        await this.command("iSj", signal),
        radare2SectionsSchema,
      ),
    );
    if (regions.length === 0)
      regions = loadedRegions(
        "iSSj",
        radare2Reply(
          operation,
          "iSSj",
          await this.command("iSSj", signal),
          radare2SectionsSchema,
        ),
      );
    this.#regions = regions;
    return regions;
  }

  /**
   * Resolve a procedure argument without forwarding it to radare2: an exact
   * function name, then an exact symbol or flag name at a function entry,
   * then an explicit address at or inside a function.
   */
  async procedure(
    operation: string,
    value: JsonValue | undefined,
    signal?: AbortSignal,
  ): Promise<Radare2Function> {
    if (typeof value !== "string" || value.length === 0)
      throw missingArgument(operation, "procedure");
    const functions = await this.functions(operation, signal);
    const address = parseRadare2Address(value);
    if (address === undefined) {
      let matches = functions.filter(({ name }) => name === value);
      if (matches.length === 0) {
        const entries = new Set(
          (await this.symbols(operation, signal))
            .filter(
              ({ name, realname, flagname }) =>
                name === value || realname === value || flagname === value,
            )
            .map(({ vaddr }) => vaddr),
        );
        matches = functions.filter(({ addr }) => entries.has(addr));
      }
      if (matches.length > 1)
        throw invalidArgument(
          operation,
          "procedure",
          `radare2 procedure name is ambiguous: ${value}; select an exact entry address from ${matches.map(entryAddress).join(", ")}.`,
        );
      const [match] = matches;
      if (match !== undefined) return match;
      throw invalidArgument(
        operation,
        "procedure",
        `Unknown radare2 procedure name or address: ${value}`,
      );
    }
    const exact = functions.find(({ addr }) => addr === address);
    if (exact !== undefined) return exact;
    const containing = await this.functionContaining(
      operation,
      address,
      signal,
    );
    if (containing !== undefined) return containing.fn;
    throw invalidArgument(
      operation,
      "procedure",
      `No radare2 procedure exists at the requested address: ${value}`,
    );
  }

  /** The function whose observed basic blocks contain an address, if any. */
  async functionContaining(
    operation: string,
    address: bigint,
    signal?: AbortSignal,
  ): Promise<Radare2FunctionBody | undefined> {
    const [fn] = radare2Reply(
      operation,
      "afij",
      await this.command(`afij @ ${formatRadare2Address(address)}`, signal),
      radare2FunctionsSchema,
    );
    if (fn === undefined) return undefined;
    const ranges = await this.bodyRanges(operation, fn.addr, signal);
    return ranges.some(({ start, end }) => address >= start && address <= end)
      ? { fn, ranges }
      : undefined;
  }

  /** Merged inclusive basic-block ranges of the function at an entry. */
  async bodyRanges(
    operation: string,
    entry: bigint,
    signal?: AbortSignal,
  ): Promise<Radare2FunctionBody["ranges"]> {
    const cached = this.#bodies.get(entry);
    if (cached !== undefined) return cached;
    const ranges = mergeBlockRanges(
      await this.blocks(operation, entry, signal),
    );
    this.#bodies.set(entry, ranges);
    return ranges;
  }

  /** Raw `afbj` blocks, including their jump and fail successors. */
  async blocks(operation: string, entry: bigint, signal?: AbortSignal) {
    return radare2Reply(
      operation,
      "afbj",
      await this.command(`afbj @ ${formatRadare2Address(entry)}`, signal),
      radare2BlocksSchema,
    );
  }

  /** Read exactly `length` bytes radare2 maps at an address, as lowercase hex. */
  async hexBytes(
    operation: string,
    address: bigint,
    length: bigint,
    signal?: AbortSignal,
  ): Promise<string> {
    const text = (
      await this.command(
        `p8 ${length.toString(10)} @ ${formatRadare2Address(address)}`,
        signal,
      )
    ).trim();
    if (
      !/^(?:[0-9a-f]{2})*$/u.test(text) ||
      BigInt(text.length) !== length * 2n
    )
      throw new AnalysisOutputError(
        operation,
        "radare2 p8 returned an unexpected byte payload",
      );
    return text;
  }
}

const loadedRegions = (
  command: "iSj" | "iSSj",
  reply: ReturnType<typeof radare2SectionsSchema.parse>,
): Radare2LoadedRegion[] =>
  reply
    .filter(
      ({ name, vsize, perm, vaddr }) =>
        name.length > 0 &&
        vsize > 0 &&
        vaddr !== RADARE2_INVALID_ADDRESS &&
        /[rwx]/u.test(perm),
    )
    .sort((left, right) => compareRadare2Addresses(left.vaddr, right.vaddr))
    .map((item) => ({
      command,
      name: item.name,
      start: item.vaddr,
      end: item.vaddr + BigInt(item.vsize),
      perm: item.perm,
    }));

export const entryAddress = (fn: { readonly addr: bigint }): string =>
  formatRadare2Address(fn.addr);

/** Function body evidence in the provider-neutral inclusive-range shape. */
export const functionBody = ({ fn, ranges }: Radare2FunctionBody) => {
  const first = ranges[0];
  const last = ranges.at(-1);
  if (first === undefined || last === undefined)
    return {
      available: false as const,
      reason: "radare2 reported no basic blocks for this function",
    };
  const total = ranges.reduce(
    (sum, { start, end }) => sum + (end - start + 1n),
    0n,
  );
  return {
    available: true as const,
    provenance: "radare2-afbj",
    ranges: ranges.map(({ start, end }) => ({
      start: formatRadare2Address(start),
      end: formatRadare2Address(end),
    })),
    total_bytes: Number(total),
    span_bytes: Number(last.end - first.start + 1n),
    non_contiguous: ranges.length > 1,
    contains_entry: ranges.some(
      ({ start, end }) => fn.addr >= start && fn.addr <= end,
    ),
  };
};

/** Parse a required caller address in the 0x-prefixed form REA+ publishes. */
export const requiredAddress = (
  operation: string,
  value: JsonValue | undefined,
): bigint => {
  if (value === undefined) throw missingArgument(operation, "address");
  const address =
    typeof value === "string" ? parseRadare2Address(value) : undefined;
  if (address === undefined)
    throw new AnalysisInputError(operation, undefined, [
      {
        path: ["address"],
        reason: "invalid_format",
        message:
          "radare2 addresses use 0x-prefixed hexadecimal, such as 0x1189.",
      },
    ]);
  return address;
};

const missingArgument = (operation: string, field: string) =>
  new AnalysisInputError(operation, undefined, [
    {
      path: [field],
      reason: "missing_argument",
      message: `radare2 headless sessions have no cursor; pass ${field} explicitly.`,
    },
  ]);

export const invalidArgument = (
  operation: string,
  field: string,
  message: string,
) =>
  new AnalysisInputError(operation, undefined, [
    { path: [field], reason: "invalid_value", message },
  ]);
