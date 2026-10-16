import type { Message } from "./ProtocolMessages.js";

/**
 * Messages of one capture often mix formats told apart by a type byte or
 * word near the start. Each candidate key (offset 0-7, one or two bytes) is
 * scored by how many byte positions it makes constant within its groups;
 * the best key beats keeping all messages together only when it explains
 * more structure than the groups it adds.
 */

export interface MessageCluster {
  readonly id: number;
  /** The type bytes this format has; for text, the first word. */
  readonly key: {
    readonly offset: number;
    readonly width: number;
    readonly value: string;
  } | null;
  /** Set when requests and responses (the two directions) are told apart. */
  readonly direction: "a-to-b" | "b-to-a" | null;
  /** Indexes into the message list, in capture order. */
  readonly members: readonly number[];
}

const MAX_CLUSTERS = 32;
const WINDOW = 64;

/** Fraction of byte positions (after the key) that hold one value across the group. */
const constancy = (
  messages: readonly Message[],
  skip: ReadonlySet<number>,
): number => {
  if (messages.length < 2) return 0;
  const length = Math.min(WINDOW, ...messages.map(({ data }) => data.length));
  let constant = 0;
  let counted = 0;
  for (let at = 0; at < length; at += 1) {
    if (skip.has(at)) continue;
    counted += 1;
    const first = messages[0]?.data[at];
    if (messages.every(({ data }) => data[at] === first)) constant += 1;
  }
  return counted === 0 ? 0 : constant / counted;
};

/** Share of the group's messages that have its most common length: a type field fixes the layout after it. */
const consistency = (messages: readonly Message[]): number => {
  const counts = new Map<number, number>();
  for (const { data } of messages)
    counts.set(data.length, (counts.get(data.length) ?? 0) + 1);
  return Math.max(...counts.values()) / messages.length;
};

const score = (
  groups: readonly (readonly Message[])[],
  skip: ReadonlySet<number>,
): number =>
  groups.reduce(
    (total, group) =>
      total + group.length * (constancy(group, skip) + consistency(group)),
    0,
  ) - groups.length;

/** A key whose every value comes from one flow separates senders, not message types. */
const followsFlows = (groups: readonly (readonly Message[])[]): boolean =>
  new Set(groups.flat().map(({ flow }) => flow)).size > 1 &&
  groups.every((group) => new Set(group.map(({ flow }) => flow)).size === 1);

interface Partition {
  readonly score: number;
  readonly key: { readonly offset: number; readonly width: number } | null;
  readonly byDirection: boolean;
  readonly groups: number[][];
}

const partition = (
  messages: readonly Message[],
  label: (message: Message) => string,
): number[][] => {
  const groups = new Map<string, number[]>();
  messages.forEach((message, index) => {
    const value = label(message);
    groups.set(value, [...(groups.get(value) ?? []), index]);
  });
  return [...groups.values()];
};

/** The first word of a text message: up to a space, colon or line end. */
const firstWord = (data: Buffer): string => {
  const end = data.findIndex(
    (byte) => byte === 0x20 || byte === 0x3a || byte === 0x0d || byte === 0x0a,
  );
  return data.subarray(0, end < 0 ? data.length : end).toString("latin1");
};

const directionOf = (message: Message): string => message.direction ?? "";

/**
 * Split messages by the type key that best explains their structure, and by
 * direction when requests and responses differ. Offsets in `exclude` (a
 * framing or length field) are never keys; text messages split by their
 * first word.
 */
/**
 * A one-byte key next to a byte that is always zero is the low byte of a
 * two-byte type: the byte before it in big-endian captures, after it in
 * little-endian ones.
 */
const widened = (
  messages: readonly Message[],
  key: { readonly offset: number; readonly width: number },
  order: "le" | "be",
  exclude: ReadonlySet<number>,
): { readonly offset: number; readonly width: number } => {
  if (key.width !== 1) return key;
  const zero = (at: number) =>
    at >= 0 &&
    !exclude.has(at) &&
    messages.every(({ data }) => data.length > at && data[at] === 0);
  if (order === "be" && zero(key.offset - 1))
    return { offset: key.offset - 1, width: 2 };
  if (order === "le" && zero(key.offset + 1))
    return { offset: key.offset, width: 2 };
  return key;
};

interface Candidate {
  readonly key: Partition["key"];
  readonly byDirection: boolean;
  readonly groups: number[][];
  readonly skip: ReadonlySet<number>;
}

/** Partitions to try: by first word for text; else by direction and by each key, with and without direction. */
const candidates = (
  messages: readonly Message[],
  exclude: ReadonlySet<number>,
  text: boolean,
): Candidate[] => {
  const directions =
    new Set(messages.map(directionOf)).size > 1 ? [false, true] : [false];
  const by = (byDirection: boolean, label: (message: Message) => string) =>
    partition(
      messages,
      (message) =>
        `${byDirection ? directionOf(message) : ""}|${label(message)}`,
    );
  if (text)
    return directions.map((byDirection) => ({
      key: { offset: 0, width: 0 },
      byDirection,
      groups: by(byDirection, ({ data }) => firstWord(data)),
      skip: new Set(),
    }));
  const found: Candidate[] = directions.includes(true)
    ? [
        {
          key: null,
          byDirection: true,
          groups: by(true, () => ""),
          skip: new Set(),
        },
      ]
    : [];
  const shortest = Math.min(...messages.map(({ data }) => data.length));
  for (let offset = 0; offset < Math.min(8, shortest); offset += 1)
    for (const width of [1, 2] as const) {
      const skip = new Set(
        Array.from({ length: width }, (_, at) => offset + at),
      );
      if (offset + width > shortest || [...skip].some((at) => exclude.has(at)))
        continue;
      for (const byDirection of directions)
        found.push({
          key: { offset, width },
          byDirection,
          skip,
          groups: by(byDirection, ({ data }) =>
            data.subarray(offset, offset + width).toString("hex"),
          ),
        });
    }
  return found;
};

export const clusterMessages = (
  messages: readonly Message[],
  exclude: ReadonlySet<number>,
  text: boolean,
  order: "le" | "be",
): MessageCluster[] => {
  const members = (groups: number[][]) =>
    groups.map((list) => list.map((index) => messages[index] as Message));
  const everything = [messages.map((_, index) => index)];
  let best: Partition = {
    score: score(members(everything), new Set()),
    key: null,
    byDirection: false,
    groups: everything,
  };
  // A type field has few values for many messages; an id or counter byte has nearly one per message.
  const most = Math.min(
    MAX_CLUSTERS,
    Math.max(4, Math.floor(Math.sqrt(messages.length))),
  );
  for (const candidate of candidates(messages, exclude, text)) {
    const groups = members(candidate.groups);
    if (
      candidate.groups.length < 2 ||
      candidate.groups.length > most ||
      followsFlows(groups)
    )
      continue;
    const value = score(groups, candidate.skip);
    if (value > best.score)
      best = {
        score: value,
        key: candidate.key,
        byDirection: candidate.byDirection,
        groups: candidate.groups,
      };
  }
  return best.groups
    .sort((left, right) => (left[0] ?? 0) - (right[0] ?? 0))
    .map((list, id) => {
      const first = messages[list[0] ?? 0];
      const data = first?.data ?? Buffer.alloc(0);
      const key =
        best.key === null || best.key.width === 0
          ? best.key
          : widened(messages, best.key, order, exclude);
      return {
        id,
        key:
          key === null
            ? null
            : key.width === 0
              ? {
                  offset: 0,
                  width: firstWord(data).length,
                  value: firstWord(data),
                }
              : {
                  offset: key.offset,
                  width: key.width,
                  value: data
                    .subarray(key.offset, key.offset + key.width)
                    .toString("hex"),
                },
        direction: best.byDirection ? (first?.direction ?? null) : null,
        members: list,
      };
    });
};
