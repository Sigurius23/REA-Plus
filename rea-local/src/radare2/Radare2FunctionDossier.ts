import type { JsonValue } from "../domain/jsonValue.js";
import {
  entryAddress,
  functionBody,
  type Radare2Inventory,
} from "./Radare2Inventory.js";
import { procedureLocals } from "./Radare2Locals.js";
import {
  compareRadare2Addresses,
  formatRadare2Address,
  radare2DisassemblySchema,
  radare2ReferencesFromSchema,
  radare2ReferencesToSchema,
  radare2Reply,
  type Radare2Function,
} from "./Radare2Values.js";

const DOSSIER_LIMITATIONS = [
  "Pseudocode is radare2's built-in pdc listing and assembly is pdfj disassembly; neither is original source nor equivalent to another provider's text.",
  "Reference kinds keep only radare2's coarse reference type (CALL, CODE, DATA, STRN); operand index, read/write access and flow details are unavailable.",
  "Outgoing references are limited to targets inside loaded sections, because radare2 also records numeric immediates as DATA references.",
  "Incoming references cover references to the function's basic-block starts from outside its body.",
  "radare2 analysis comments, native API boundaries and value flow are not reported.",
];

/** Call types radare2 can leave without a resolved target. */
const CALL_TYPES = new Set(["call", "ucall", "rcall", "icall", "ircall"]);

type ProcedureIdentity = {
  readonly address: string;
  readonly name: string;
  readonly classification: null;
  readonly body: ReturnType<typeof functionBody>;
};

interface Reference {
  readonly source: bigint;
  readonly target: bigint;
  readonly type: string;
  readonly sourceFunction: Radare2Function | undefined;
  readonly targetFunction: Radare2Function | undefined;
}

interface DossierScope {
  readonly inventory: Radare2Inventory;
  readonly operation: string;
  readonly signal: AbortSignal | undefined;
  readonly fn: Radare2Function;
  readonly ranges: readonly { readonly start: bigint; readonly end: bigint }[];
  readonly byEntry: ReadonlyMap<bigint, Radare2Function>;
}

/** Shared lookups for one dossier; identities are built once per function. */
class DossierContext {
  readonly #identities = new Map<bigint, Promise<ProcedureIdentity>>();

  constructor(readonly scope: DossierScope) {}

  inBody(address: bigint): boolean {
    return this.scope.ranges.some(
      ({ start, end }) => address >= start && address <= end,
    );
  }

  identity(target: Radare2Function): Promise<ProcedureIdentity> {
    let identity = this.#identities.get(target.addr);
    if (identity === undefined) {
      identity = this.#buildIdentity(target);
      this.#identities.set(target.addr, identity);
    }
    return identity;
  }

  async #buildIdentity(target: Radare2Function): Promise<ProcedureIdentity> {
    const { inventory, operation, signal, fn } = this.scope;
    const ranges =
      target.addr === fn.addr
        ? this.scope.ranges
        : await inventory.bodyRanges(operation, target.addr, signal);
    return {
      address: entryAddress(target),
      name: target.name,
      classification: null,
      body: functionBody({ fn: target, ranges }),
    };
  }

  async sortedIdentities(values: Iterable<Radare2Function>) {
    return Promise.all(
      [...values]
        .sort((left, right) => compareRadare2Addresses(left.addr, right.addr))
        .map((value) => this.identity(value)),
    );
  }

  async edge(reference: Reference) {
    const { source, target, type, sourceFunction, targetFunction } = reference;
    return {
      source_address: formatRadare2Address(source),
      target_address: formatRadare2Address(target),
      source_procedure:
        sourceFunction === undefined
          ? null
          : await this.identity(sourceFunction),
      target_procedure:
        targetFunction === undefined
          ? null
          : await this.identity(targetFunction),
      kind: {
        available: false,
        reason: `radare2 reference type ${type}; operand-level access and flow classification are unavailable.`,
      },
    };
  }
}

/** Build the provider-neutral function dossier from radare2 observations. */
export const analyzeRadare2Function = async (
  inventory: Radare2Inventory,
  operation: string,
  procedure: JsonValue | undefined,
  signal?: AbortSignal,
): Promise<JsonValue> => {
  const fn = await inventory.procedure(operation, procedure, signal);
  const at = entryAddress(fn);
  const functions = await inventory.functions(operation, signal);
  const context = new DossierContext({
    inventory,
    operation,
    signal,
    fn,
    ranges: await inventory.bodyRanges(operation, fn.addr, signal),
    byEntry: new Map(functions.map((item) => [item.addr, item])),
  });
  const blocks = await inventory.blocks(operation, fn.addr, signal);
  const ops = radare2Reply(
    operation,
    "pdfj",
    await inventory.command(`pdfj @ ${at}`, signal),
    radare2DisassemblySchema,
  ).ops.sort((left, right) => compareRadare2Addresses(left.addr, right.addr));
  const incoming = await incomingReferences(context, blocks);
  const outgoing = await outgoingReferences(context);
  return {
    procedure: {
      ...(await context.identity(fn)),
      signature: fn.signature ?? null,
      locals: await procedureLocals(inventory, operation, fn, signal),
    },
    pseudocode: await inventory.command(`pdc @ ${at}`, signal),
    assembly: ops.map(
      ({ addr, disasm, type }) =>
        `${formatRadare2Address(addr)}: ${disasm ?? `(${type})`}`,
    ),
    comments: [],
    callers: await context.sortedIdentities(callers(incoming)),
    callees: await context.sortedIdentities(callees(context, outgoing)),
    incoming_references: await Promise.all(
      incoming.map((reference) => context.edge(reference)),
    ),
    outgoing_references: await Promise.all(
      outgoing.map((reference) => context.edge(reference)),
    ),
    unresolved_calls: ops
      .filter(({ type, jump }) => CALL_TYPES.has(type) && jump === undefined)
      .map(({ addr, type }) => ({
        address: formatRadare2Address(addr),
        reason: `radare2 ${type} instruction without a resolved target`,
      })),
    ...(await referencedValues(context, outgoing)),
    basic_blocks: basicBlocks(blocks),
    native_api: null,
    native_value_flow: null,
    limitations: DOSSIER_LIMITATIONS,
  };
};

/** References to each block start whose source lies outside the body. */
const incomingReferences = async (
  context: DossierContext,
  blocks: readonly { readonly addr: bigint }[],
): Promise<Reference[]> => {
  const { inventory, operation, signal, fn, byEntry } = context.scope;
  const starts = [...new Set(blocks.map(({ addr }) => addr))].sort(
    compareRadare2Addresses,
  );
  const references: Reference[] = [];
  for (const start of starts) {
    const replies = radare2Reply(
      operation,
      "axtj",
      await inventory.command(`axtj @ ${formatRadare2Address(start)}`, signal),
      radare2ReferencesToSchema,
    );
    for (const { from, type, fcn_addr: caller } of replies)
      if (!context.inBody(from))
        references.push({
          source: from,
          target: start,
          type,
          sourceFunction:
            caller === undefined ? undefined : byEntry.get(caller),
          targetFunction: fn,
        });
  }
  return references;
};

/** References made from the body to targets inside loaded sections. */
const outgoingReferences = async (
  context: DossierContext,
): Promise<Reference[]> => {
  const { inventory, operation, signal, fn, byEntry } = context.scope;
  const regions = await inventory.regions(operation, signal);
  const replies = radare2Reply(
    operation,
    "axffj",
    await inventory.command(`axffj @ ${entryAddress(fn)}`, signal),
    radare2ReferencesFromSchema,
  );
  return replies
    .filter(({ ref }) =>
      regions.some(({ start, end }) => ref >= start && ref < end),
    )
    .map(({ at, ref, type }) => ({
      source: at,
      target: ref,
      type,
      sourceFunction: fn,
      targetFunction:
        byEntry.get(ref) ?? (context.inBody(ref) ? fn : undefined),
    }));
};

const callers = (incoming: readonly Reference[]) => {
  const result = new Map<bigint, Radare2Function>();
  for (const { sourceFunction, type } of incoming)
    if (sourceFunction !== undefined && (type === "CALL" || type === "CODE"))
      result.set(sourceFunction.addr, sourceFunction);
  return result.values();
};

/** Direct calls, and jumps to another function's entry. */
const callees = (context: DossierContext, outgoing: readonly Reference[]) => {
  const { byEntry, fn } = context.scope;
  const result = new Map<bigint, Radare2Function>();
  for (const { target, type } of outgoing) {
    const callee = byEntry.get(target);
    if (
      callee !== undefined &&
      (type === "CALL" || (type === "CODE" && callee.addr !== fn.addr))
    )
      result.set(callee.addr, callee);
  }
  return result.values();
};

/** Strings and exact function or symbol names at outgoing targets. */
const referencedValues = async (
  context: DossierContext,
  outgoing: readonly Reference[],
) => {
  const { inventory, operation, signal, byEntry } = context.scope;
  const symbolNames = new Map<bigint, string>();
  for (const { vaddr, name, type } of await inventory.symbols(
    operation,
    signal,
  ))
    if (name.length > 0 && type !== "FILE" && type !== "SECTION")
      symbolNames.set(vaddr, symbolNames.get(vaddr) ?? name);
  const strings = new Map(
    (await inventory.strings(operation, signal)).map(({ address, value }) => [
      address,
      value,
    ]),
  );
  const at = (
    values: (target: bigint) => string | undefined,
  ): { address: string; value: string; source_address: string }[] =>
    outgoing.flatMap(({ source, target }) => {
      const value = values(target);
      return value === undefined
        ? []
        : [
            {
              address: formatRadare2Address(target),
              value,
              source_address: formatRadare2Address(source),
            },
          ];
    });
  return {
    referenced_strings: at((target) => strings.get(target)),
    referenced_names: at(
      (target) => byEntry.get(target)?.name ?? symbolNames.get(target),
    ),
  };
};

/** Blocks with exclusive ends and their intra-function jump/fail successors. */
const basicBlocks = (
  blocks: readonly {
    readonly addr: bigint;
    readonly size: number;
    readonly jump?: bigint | undefined;
    readonly fail?: bigint | undefined;
  }[],
) => {
  const starts = new Set(blocks.map(({ addr }) => addr));
  return [...blocks]
    .sort((left, right) => compareRadare2Addresses(left.addr, right.addr))
    .map(({ addr, size, jump, fail }) => ({
      start: formatRadare2Address(addr),
      end: formatRadare2Address(addr + BigInt(size)),
      successors: [
        ...new Set(
          [jump, fail].filter(
            (next): next is bigint => next !== undefined && starts.has(next),
          ),
        ),
      ]
        .sort(compareRadare2Addresses)
        .map(formatRadare2Address),
    }));
};
