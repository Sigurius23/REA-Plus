import type { Message, TcpStream } from "./ProtocolMessages.js";

/**
 * How a TCP byte stream divides into messages: a length prefix that tiles
 * every stream exactly, a line or NUL delimiter, or failing both, the
 * segments the sender wrote.
 */

export type Framing =
  | { readonly kind: "datagrams" | "lines" | "segments" }
  | {
      readonly kind: "length_prefix";
      readonly offset: number;
      readonly width: 1 | 2 | 4;
      readonly endian: "little" | "big";
      /** Message length = field value + adjust. */
      readonly adjust: number;
    }
  | { readonly kind: "delimiter"; readonly delimiter: string };

type Prefix = Extract<Framing, { kind: "length_prefix" }>;

const read = (data: Buffer, at: number, prefix: Prefix): number => {
  if (prefix.width === 1) return data[at] ?? 0;
  if (prefix.width === 2)
    return prefix.endian === "little"
      ? data.readUInt16LE(at)
      : data.readUInt16BE(at);
  return prefix.endian === "little"
    ? data.readUInt32LE(at)
    : data.readUInt32BE(at);
};

/** Message boundaries the prefix gives, or null unless it ends exactly at the end of the piece. */
const tile = (data: Buffer, prefix: Prefix): number[] | null => {
  const starts: number[] = [];
  let at = 0;
  while (at < data.length) {
    if (at + prefix.offset + prefix.width > data.length) return null;
    const total = read(data, at + prefix.offset, prefix) + prefix.adjust;
    if (
      total < Math.max(1, prefix.offset + prefix.width) ||
      at + total > data.length
    )
      return null;
    starts.push(at);
    at += total;
  }
  return starts;
};

const PREFIXES: readonly Prefix[] = [0, 1, 2, 3, 4].flatMap((offset) =>
  ([1, 2, 4] as const).flatMap((width) =>
    (width === 1
      ? (["little"] as const)
      : (["little", "big"] as const)
    ).flatMap((endian) =>
      Array.from({ length: 41 }, (_, step) => ({
        kind: "length_prefix" as const,
        offset,
        width,
        endian,
        adjust: step - 8,
      })),
    ),
  ),
);

/**
 * Among prefixes giving the same boundaries: the field counts the rest of
 * the message (or all of it), sits at its natural alignment, and is as
 * wide as its zero bytes allow.
 */
const preference = (prefix: Prefix): number =>
  (prefix.adjust === prefix.offset + prefix.width
    ? 0
    : prefix.adjust === 0
      ? 1
      : 2) *
    1000 +
  (prefix.offset % prefix.width === 0 ? 0 : 100) +
  prefix.offset * 10 -
  prefix.width;

interface Piece {
  readonly data: Buffer;
  readonly segments: readonly number[];
}

/** Share of segment starts a framing puts at a message start; senders write whole messages. */
const alignment = (
  pieces: readonly Piece[],
  starts: readonly number[][],
): number => {
  let aligned = 0;
  let total = 0;
  pieces.forEach((piece, index) => {
    const boundaries = new Set(starts[index]);
    for (const segment of piece.segments) {
      total += 1;
      if (boundaries.has(segment)) aligned += 1;
    }
  });
  return total === 0 ? 1 : aligned / total;
};

/**
 * The prefix that tiles every piece exactly, puts the most segment starts at
 * message starts, and gives the fewest messages: a shifted reading can also
 * tile a stream by splitting each message in two.
 */
const lengthPrefix = (
  pieces: readonly Piece[],
): { prefix: Prefix; starts: number[][] } | null => {
  let best: {
    prefix: Prefix;
    starts: number[][];
    count: number;
    aligned: number;
  } | null = null;
  const minimum = Math.max(4, pieces.length * 2);
  for (const prefix of PREFIXES) {
    const starts: number[][] = [];
    for (const piece of pieces) {
      const found = tile(piece.data, prefix);
      if (found === null) break;
      starts.push(found);
    }
    if (starts.length !== pieces.length) continue;
    const count = starts.reduce((sum, list) => sum + list.length, 0);
    // A prefix that leaves most pieces as one message is likely coincidence.
    if (count < minimum) continue;
    const aligned = alignment(pieces, starts);
    const better =
      best === null ||
      aligned > best.aligned + 1e-9 ||
      (Math.abs(aligned - best.aligned) <= 1e-9 &&
        (count < best.count ||
          (count === best.count &&
            preference(prefix) < preference(best.prefix))));
    if (better) best = { prefix, starts, count, aligned };
  }
  return best !== null && best.aligned >= 0.5 ? best : null;
};

const printable = (data: Buffer): boolean =>
  data.every(
    (byte) =>
      byte === 9 ||
      byte === 10 ||
      byte === 13 ||
      (byte >= 0x20 && byte < 0x7f) ||
      byte >= 0x80,
  );

/** Line-delimited text: printable throughout, each piece ending in a line break. */
const lines = (pieces: readonly Buffer[]): string | null => {
  const all = Buffer.concat([...pieces]);
  if (
    all.length === 0 ||
    !printable(all) ||
    !pieces.every((piece) => piece.at(-1) === 10)
  )
    return null;
  return all.includes("\r\n") ? "\r\n" : "\n";
};

/** NUL-terminated strings: printable apart from the NULs, each piece ending in one. */
const nulTerminated = (pieces: readonly Buffer[]): string | null => {
  const all = Buffer.concat([...pieces]);
  const text = Buffer.from(all.filter((byte) => byte !== 0));
  const nuls = all.length - text.length;
  return all.length > 0 &&
    pieces.every((piece) => piece.at(-1) === 0) &&
    nuls >= pieces.length * 2 &&
    printable(text)
    ? "\0"
    : null;
};

const split = (data: Buffer, delimiter: string): Buffer[] => {
  const parts: Buffer[] = [];
  let at = 0;
  for (
    let next = data.indexOf(delimiter, at);
    next >= 0;
    next = data.indexOf(delimiter, at)
  ) {
    parts.push(data.subarray(at, next + delimiter.length));
    at = next + delimiter.length;
  }
  if (at < data.length) parts.push(data.subarray(at));
  return parts;
};

export const frameStreams = (
  streams: readonly TcpStream[],
): { readonly framing: Framing; readonly messages: Message[] } => {
  const pieces = streams.flatMap((stream) =>
    stream.pieces.map((piece) => ({ stream, piece })),
  );
  const message = (
    stream: TcpStream,
    time: number | null,
    data: Buffer,
  ): Message => ({
    data,
    time,
    flow: stream.flow,
    direction: stream.direction,
    transport: "tcp",
  });
  const delimitedBy = (delimiter: string) => ({
    framing: { kind: "delimiter" as const, delimiter },
    messages: pieces.flatMap(({ stream, piece }) =>
      split(piece.data, delimiter).map((data) =>
        message(stream, piece.time, data),
      ),
    ),
  });
  const data = pieces.map(({ piece }) => piece.data);
  const line = lines(data);
  if (line !== null) return delimitedBy(line);
  const prefixed = lengthPrefix(pieces.map(({ piece }) => piece));
  if (prefixed !== null)
    return {
      framing: prefixed.prefix,
      messages: pieces.flatMap(({ stream, piece }, index) =>
        (prefixed.starts[index] ?? []).map((start, at, all) =>
          message(
            stream,
            piece.time,
            piece.data.subarray(start, all[at + 1] ?? piece.data.length),
          ),
        ),
      ),
    };
  const nul = nulTerminated(data);
  if (nul !== null) return delimitedBy(nul);
  return {
    framing: { kind: "segments" },
    messages: pieces.flatMap(({ stream, piece }) =>
      piece.segments.map((start, at) =>
        message(
          stream,
          piece.time,
          piece.data.subarray(
            start,
            piece.segments[at + 1] ?? piece.data.length,
          ),
        ),
      ),
    ),
  };
};
