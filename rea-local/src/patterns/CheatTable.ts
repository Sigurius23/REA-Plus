import { DOMParser, onWarningStopParsing, type Element } from "@xmldom/xmldom";

/** A file that is not a Cheat Engine table. */
export class CheatTableError extends Error {}

export const MAX_TABLE_ENTRIES = 5000;

export interface TableEntry {
  readonly id: string | null;
  readonly path: readonly string[];
  readonly description: string;
  readonly type: string | null;
  readonly address: string | null;
  readonly module: string | null;
  readonly moduleOffset: bigint | null;
  readonly offsets: readonly string[];
  readonly group: boolean;
  readonly hotkeys: number;
  readonly children: number;
  readonly script: string | null;
}

export interface ScriptDirectives {
  readonly aobScans: readonly {
    readonly kind: string;
    readonly symbol: string;
    readonly module: string | null;
    readonly pattern: string;
  }[];
  readonly asserts: readonly {
    readonly address: string;
    readonly module: string | null;
    readonly offset: bigint | null;
    readonly bytes: string;
  }[];
  readonly registeredSymbols: readonly string[];
  readonly allocations: number;
  readonly lines: number;
}

export interface CheatTable {
  readonly version: number | null;
  readonly entries: readonly TableEntry[];
  readonly entriesTotal: number;
  readonly symbols: readonly {
    readonly name: string;
    readonly address: string;
  }[];
  readonly structures: readonly {
    readonly name: string;
    readonly elements: readonly {
      readonly offset: number;
      readonly type: string | null;
      readonly size: number | null;
      readonly description: string;
    }[];
  }[];
  readonly lua: string | null;
}

const children = (element: Element, name: string): Element[] =>
  Array.from(element.childNodes).filter(
    (node): node is Element => node.nodeType === 1 && node.nodeName === name,
  );

const child = (element: Element, name: string): Element | undefined =>
  children(element, name)[0];

const text = (element: Element | undefined): string | null =>
  element === undefined ? null : (element.textContent ?? "");

/** CE quotes descriptions: `"Player health"`. */
const unquote = (value: string): string =>
  value.length >= 2 && value.startsWith('"') && value.endsWith('"')
    ? value.slice(1, -1)
    : value;

/** `GameAssembly.dll+1A2B3C0` or `"game.exe"+123` as module and offset. */
export const moduleAddress = (
  address: string,
): { readonly module: string; readonly offset: bigint } | null => {
  const match = /^"?([^"+]+?)"?\s*\+\s*(?:0x)?([0-9A-Fa-f]{1,16})$/u.exec(
    address.trim(),
  );
  return match === null || !/\.[A-Za-z0-9]{2,5}$/u.test(match[1] ?? "")
    ? null
    : { module: match[1] ?? "", offset: BigInt(`0x${match[2] ?? "0"}`) };
};

const ARGUMENTS = /^\s*([a-z]+)\s*\((.*)\)\s*(?:\/\/.*)?$/iu;

type MutableDirectives = {
  aobScans: ScriptDirectives["aobScans"][number][];
  asserts: ScriptDirectives["asserts"][number][];
  registeredSymbols: string[];
  allocations: number;
};

/** aobscan variants: (symbol, pattern), (symbol, module, pattern), (symbol, start, stop, pattern). */
const aobScan =
  (kind: string, patternAt: number, moduleAt: number | null) =>
  (args: readonly string[], into: MutableDirectives) => {
    if (args.length <= patternAt) return;
    into.aobScans.push({
      kind,
      symbol: args[0] ?? "",
      module: moduleAt === null ? null : (args[moduleAt] ?? null),
      pattern: args.slice(patternAt).join(" "),
    });
  };

const DIRECTIVES: Readonly<
  Record<string, (args: readonly string[], into: MutableDirectives) => void>
> = {
  aobscan: aobScan("aobscan", 1, null),
  aobscanmodule: aobScan("aobscanmodule", 2, 1),
  aobscanregion: aobScan("aobscanregion", 3, null),
  assert: (args, into) => {
    if (args.length < 2) return;
    const address = args[0] ?? "";
    const located = moduleAddress(address);
    into.asserts.push({
      address,
      module: located?.module ?? null,
      offset: located?.offset ?? null,
      bytes: args.slice(1).join(" "),
    });
  },
  registersymbol: (args, into) => {
    into.registeredSymbols.push(...args.filter((name) => name.length > 0));
  },
  alloc: (_args, into) => {
    into.allocations += 1;
  },
  globalalloc: (_args, into) => {
    into.allocations += 1;
  },
};

/** Auto Assembler directives that identify code a script depends on. */
export const scriptDirectives = (script: string): ScriptDirectives => {
  const directives: MutableDirectives = {
    aobScans: [],
    asserts: [],
    registeredSymbols: [],
    allocations: 0,
  };
  const lines = script.split(/\r?\n/u);
  for (const line of lines) {
    const match = ARGUMENTS.exec(line);
    const handle = DIRECTIVES[(match?.[1] ?? "").toLowerCase()];
    if (match === null || handle === undefined) continue;
    handle(
      (match[2] ?? "").split(",").map((part) => part.trim()),
      directives,
    );
  }
  return { ...directives, lines: lines.length };
};

const readEntries = (
  container: Element | undefined,
  path: readonly string[],
  entries: TableEntry[],
  counter: { total: number },
): void => {
  if (container === undefined) return;
  for (const entry of children(container, "CheatEntry")) {
    counter.total += 1;
    const description = unquote(text(child(entry, "Description")) ?? "");
    const address = text(child(entry, "Address"));
    const located = address === null ? null : moduleAddress(address);
    const nested = child(entry, "CheatEntries");
    const hotkeys = child(entry, "Hotkeys");
    if (entries.length < MAX_TABLE_ENTRIES)
      entries.push({
        id: text(child(entry, "ID")),
        path: [...path, description],
        description,
        type: text(child(entry, "VariableType")),
        address,
        module: located?.module ?? null,
        moduleOffset: located?.offset ?? null,
        offsets: (() => {
          const list = child(entry, "Offsets");
          return list === undefined
            ? []
            : children(list, "Offset").map((offset) => text(offset) ?? "");
        })(),
        group: text(child(entry, "GroupHeader")) === "1",
        hotkeys: hotkeys === undefined ? 0 : children(hotkeys, "Hotkey").length,
        children:
          nested === undefined ? 0 : children(nested, "CheatEntry").length,
        script: text(child(entry, "AssemblerScript")),
      });
    readEntries(nested, [...path, description], entries, counter);
  }
};

/** Parse a Cheat Engine table (.CT) without evaluating scripts. */
export const parseCheatTable = (xml: string): CheatTable => {
  let root: Element | null;
  try {
    root = new DOMParser({ onError: onWarningStopParsing }).parseFromString(
      xml,
      "text/xml",
    ).documentElement;
  } catch (cause: unknown) {
    throw new CheatTableError(
      `Not well-formed XML: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
  if (root?.nodeName !== "CheatTable")
    throw new CheatTableError("The XML root is not <CheatTable>.");
  const entries: TableEntry[] = [];
  const counter = { total: 0 };
  readEntries(child(root, "CheatEntries"), [], entries, counter);
  const symbols = child(root, "UserdefinedSymbols");
  const structures = child(root, "Structures");
  const version = Number(root.getAttribute("CheatEngineTableVersion"));
  return {
    version: Number.isInteger(version) && version > 0 ? version : null,
    entries,
    entriesTotal: counter.total,
    symbols:
      symbols === undefined
        ? []
        : children(symbols, "SymbolEntry").map((symbol) => ({
            name: text(child(symbol, "Name")) ?? "",
            address: text(child(symbol, "Address")) ?? "",
          })),
    structures:
      structures === undefined
        ? []
        : children(structures, "Structure").map((structure) => {
            const elements = child(structure, "Elements");
            return {
              name: structure.getAttribute("Name") ?? "",
              elements: (elements === undefined
                ? []
                : children(elements, "Element")
              ).map((element) => {
                const size = Number(element.getAttribute("Bytesize"));
                return {
                  offset: Number(element.getAttribute("Offset") ?? "0"),
                  type: element.getAttribute("Vartype"),
                  size: Number.isInteger(size) ? size : null,
                  description: element.getAttribute("Description") ?? "",
                };
              }),
            };
          }),
    lua: text(child(root, "LuaScript")),
  };
};
