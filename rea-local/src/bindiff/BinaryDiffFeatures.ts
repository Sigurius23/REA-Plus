import { createHash } from "node:crypto";

import type { FunctionDossier } from "../domain/hopperValues.js";

/**
 * What a function looks like independent of where it was linked: its
 * instructions with addresses and generated labels abstracted, its control
 * flow shape, the named functions it calls, and the strings and constants it
 * uses. Two builds of the same source keep these even when every address
 * moves.
 */
export interface FunctionFeatures {
  readonly address: string;
  readonly name: string;
  /** The provider made the name up from the address (fcn.*, FUN_*, sub_*). */
  readonly generatedName: boolean;
  readonly size: number;
  /** Instruction text as the provider printed it, after the address. */
  readonly lines: readonly string[];
  readonly lineAddresses: readonly string[];
  /** Instructions with addresses, generated labels and jump targets abstracted. */
  readonly normalized: readonly string[];
  readonly mnemonics: readonly string[];
  /** Same normalized instructions in the same order. */
  readonly exactHash: string;
  /** Same mnemonics in the same order. */
  readonly mnemonicHash: string;
  readonly blocks: number;
  readonly edges: number;
  /** Same block degrees and depths, whatever the addresses. */
  readonly shapeHash: string;
  /** BinDiff's MD-index over the control-flow edges. */
  readonly mdIndex: number;
  readonly callees: readonly string[];
  /** Called functions in call-site order, repeats kept. */
  readonly callSequence: readonly string[];
  readonly callers: readonly string[];
  /** Names of called functions that are not generated (imports, symbols). */
  readonly calleeNames: readonly string[];
  readonly strings: readonly string[];
  /** Immediate operands that are not addresses and not tiny. */
  readonly constants: readonly string[];
  /** Referenced names that are not generated, such as imported data. */
  readonly names: readonly string[];
}

/** Segment ranges, start inclusive and end exclusive. */
export type AddressRanges = readonly {
  readonly start: bigint;
  readonly end: bigint;
}[];

const hash = (parts: readonly string[]): string =>
  createHash("sha256").update(parts.join("\n")).digest("hex").slice(0, 32);

const unique = (values: Iterable<string>): string[] =>
  [...new Set(values)].sort();

/** Instruction prefixes that belong to the mnemonic. */
const PREFIXES = new Set([
  "rep",
  "repe",
  "repz",
  "repne",
  "repnz",
  "lock",
  "bnd",
  "notrack",
  "data16",
  "addr32",
]);

/** Branches and calls across x86, ARM, AArch64 and MIPS: their numeric operands are targets. */
const BRANCH =
  /^(?:j\w*|call\w*|loop\w*|b|bl|blx|bx|br|blr|b\.\w+|b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)(?:\.[wn])?|cbn?z|tbn?z|beqz|bnez|bgez\w*|bgtz|blez|bltz\w*)$/u;

const NUMBER = /^[-+]?(?:0x[0-9a-f]+|\d+)$/u;
/** An identifier holding a run of hex digits: an address-derived label. */
const GENERATED_LABEL =
  /^[a-z_.$@?][\w.$@?]*?[_.$@]?(?:0x)?[0-9a-f]{4,}(?:[_.]\w*)?$/u;
const TOKEN = /0x[0-9a-f]+|[a-z_.$@?][\w.$@?]*|\d+|[^\s\w]/gu;

const parseNumber = (token: string): bigint | undefined => {
  try {
    return BigInt(token.replace(/^\+/u, ""));
  } catch {
    return undefined;
  }
};

/** Whether a name was made up from its own address, like fcn.00007630 or FUN_00107630. */
export const isGeneratedName = (name: string, address: string): boolean => {
  const digits = address.replace(/^0x0*/u, "").toLowerCase();
  return (
    digits.length > 0 &&
    new RegExp(`(?:^|[^0-9a-f])0*${digits}(?:$|[^0-9a-f])`, "u").test(
      name.toLowerCase(),
    )
  );
};

const inRanges = (value: bigint, ranges: AddressRanges): boolean =>
  ranges.some(({ start, end }) => value >= start && value < end);

interface NormalizedInstruction {
  readonly text: string;
  readonly mnemonic: string;
  readonly constants: readonly string[];
}

/** Split `mnemonic operands`, abstracting addresses and generated labels. */
export const normalizeInstruction = (
  line: string,
  ranges: AddressRanges,
): NormalizedInstruction => {
  const words = line.trim().toLowerCase().split(/\s+/u);
  let index = 0;
  while (index < words.length - 1 && PREFIXES.has(words[index] ?? ""))
    index += 1;
  const mnemonic = words.slice(0, index + 1).join(" ");
  const operands = words.slice(index + 1).join(" ");
  const branch = BRANCH.test(words[index] ?? "");
  const constants: string[] = [];
  let depth = 0;
  const text = (operands.match(TOKEN) ?? [])
    .map((token) => {
      if (token === "[") depth += 1;
      if (token === "]") depth = Math.max(0, depth - 1);
      if (NUMBER.test(token)) {
        const value = parseNumber(token);
        if (value === undefined) return token;
        if (branch || (value >= 0x10000n && inRanges(value, ranges)))
          return "ADDR";
        const magnitude = value < 0n ? -value : value;
        if (depth === 0 && magnitude >= 0x100n)
          constants.push(`0x${value.toString(16)}`);
        return token;
      }
      if (GENERATED_LABEL.test(token)) return branch ? "ADDR" : "SYM";
      return token;
    })
    .join(" ")
    .replace(/ (?=[,\]])|(?<=\[) /gu, "");
  return {
    text: text.length === 0 ? mnemonic : `${mnemonic} ${text}`,
    mnemonic,
    constants,
  };
};

const ADDRESSED_LINE = /^(0x[0-9a-f]+):\s*(.*)$/iu;

/** Block degrees and BFS depth from the entry: the shape BinDiff's MD-index measures. */
const controlFlow = (dossier: FunctionDossier) => {
  const blocks = dossier.basic_blocks;
  const starts = new Set(blocks.map(({ start }) => start.toLowerCase()));
  const successors = new Map(
    blocks.map(({ start, successors: next }) => [
      start.toLowerCase(),
      next.map((item) => item.toLowerCase()).filter((item) => starts.has(item)),
    ]),
  );
  const incoming = new Map<string, number>();
  for (const next of successors.values())
    for (const target of next)
      incoming.set(target, (incoming.get(target) ?? 0) + 1);
  const entry = dossier.procedure.address.toLowerCase();
  const first = starts.has(entry) ? entry : blocks[0]?.start.toLowerCase();
  const depth = new Map<string, number>();
  const queue = first === undefined ? [] : [first];
  if (first !== undefined) depth.set(first, 0);
  for (let at = 0; at < queue.length; at += 1) {
    const block = queue[at] as string;
    for (const next of successors.get(block) ?? [])
      if (!depth.has(next)) {
        depth.set(next, (depth.get(block) ?? 0) + 1);
        queue.push(next);
      }
  }
  const degree = (block: string) => ({
    level: depth.get(block) ?? -1,
    in: incoming.get(block) ?? 0,
    out: successors.get(block)?.length ?? 0,
  });
  let mdIndex = 0;
  let edges = 0;
  for (const [block, next] of successors)
    for (const target of next) {
      edges += 1;
      const from = degree(block);
      const to = degree(target);
      mdIndex +=
        1 /
        Math.sqrt(
          Math.max(0, from.level) +
            Math.SQRT2 * from.in +
            Math.sqrt(3) * from.out +
            Math.sqrt(5) * to.in +
            Math.sqrt(7) * to.out,
        );
    }
  const shape = [...successors.keys()]
    .map((block) => {
      const { level, in: inDegree, out } = degree(block);
      return `${String(level)}:${String(inDegree)}:${String(out)}`;
    })
    .sort();
  return {
    blocks: blocks.length,
    edges,
    shapeHash: hash(shape),
    mdIndex: Number.isFinite(mdIndex) ? mdIndex : 0,
  };
};

/** Callees in the order the body calls them, from its outgoing references. */
const callSequence = (dossier: FunctionDossier): string[] => {
  const callees = new Set(
    dossier.callees.map(({ address }) => address.toLowerCase()),
  );
  const order = (address: string) => {
    try {
      return BigInt(address);
    } catch {
      return 0n;
    }
  };
  return dossier.outgoing_references
    .map(({ source_address: source, target_address: target }) => ({
      source: order(source),
      target: target.toLowerCase(),
    }))
    .filter(({ target }) => callees.has(target))
    .sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0))
    .map(({ target }) => target);
};

/** Features of one analyzed function. */
export const functionFeatures = (
  dossier: FunctionDossier,
  ranges: AddressRanges,
): FunctionFeatures => {
  const { procedure } = dossier;
  const lines: string[] = [];
  const lineAddresses: string[] = [];
  for (const entry of dossier.assembly) {
    const match = ADDRESSED_LINE.exec(entry);
    lineAddresses.push(match?.[1]?.toLowerCase() ?? "");
    lines.push(match?.[2] ?? entry);
  }
  const instructions = lines.map((line) => normalizeInstruction(line, ranges));
  const normalized = instructions.map(({ text }) => text);
  const mnemonics = instructions.map(({ mnemonic }) => mnemonic);
  const named = (items: readonly { address: string; name: string }[]) =>
    unique(
      items
        .filter(({ name, address }) => !isGeneratedName(name, address))
        .map(({ name }) => name),
    );
  return {
    address: procedure.address.toLowerCase(),
    name: procedure.name,
    generatedName: isGeneratedName(procedure.name, procedure.address),
    size: procedure.body.available ? procedure.body.total_bytes : lines.length,
    lines,
    lineAddresses,
    normalized,
    mnemonics,
    exactHash: hash(normalized),
    mnemonicHash: hash(mnemonics),
    ...controlFlow(dossier),
    callSequence: callSequence(dossier),
    callees: unique(
      dossier.callees.map(({ address }) => address.toLowerCase()),
    ),
    callers: unique(
      dossier.callers.map(({ address }) => address.toLowerCase()),
    ),
    calleeNames: named(dossier.callees),
    strings: unique(dossier.referenced_strings.map(({ value }) => value)),
    constants: unique(instructions.flatMap(({ constants }) => constants)),
    names: unique(
      dossier.referenced_names
        .filter(({ value, address }) => !isGeneratedName(value, address))
        .map(({ value }) => value),
    ),
  };
};
