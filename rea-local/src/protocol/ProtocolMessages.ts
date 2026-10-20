import { decodeFrame } from "../browser/history/PcapFrameDecoder.js";
import { ProtocolFormatError, type CaptureFrame } from "./CaptureFrames.js";

/**
 * Application messages: UDP datagrams, TCP streams (reassembled by sequence
 * number, split where data is missing), or lines of hex.
 */

export type Direction = "a-to-b" | "b-to-a";

export interface Message {
  readonly data: Buffer;
  readonly time: number | null;
  readonly flow: string;
  readonly direction: Direction | null;
  readonly transport: "udp" | "tcp" | "hex";
}

/** One direction of a TCP connection: contiguous runs of bytes, and where its segments started. */
export interface TcpStream {
  readonly flow: string;
  readonly direction: Direction;
  readonly pieces: readonly {
    readonly data: Buffer;
    readonly time: number | null;
    readonly segments: readonly number[];
  }[];
}

export interface CaptureSelection {
  readonly transport: "auto" | "udp" | "tcp";
  readonly port?: number;
  readonly flow?: string;
}

interface Segment {
  readonly seq: number;
  readonly data: Buffer;
  readonly time: number | null;
}

const fields = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : {};

/** Datagrams and TCP segments of the selected flows, in capture order. */
const segmentsOf = (
  frames: readonly CaptureFrame[],
  selection: CaptureSelection,
) => {
  const udp: Message[] = [];
  const tcp = new Map<
    string,
    { flow: string; direction: Direction; segments: Segment[] }
  >();
  for (const frame of frames) {
    const decoded = decodeFrame(frame.data, frame.linkType);
    const transport = fields(decoded.transport);
    const flow = fields(decoded.flow);
    if (
      decoded.payload === undefined ||
      decoded.payload.length === 0 ||
      typeof flow["key"] !== "string"
    )
      continue;
    const protocol = transport["protocol"];
    if (protocol !== "udp" && protocol !== "tcp") continue;
    if (selection.transport !== "auto" && selection.transport !== protocol)
      continue;
    if (
      selection.port !== undefined &&
      transport["source_port"] !== selection.port &&
      transport["destination_port"] !== selection.port
    )
      continue;
    if (selection.flow !== undefined && !flow["key"].includes(selection.flow))
      continue;
    const data = Buffer.from(
      frame.data.subarray(
        decoded.payload.offset,
        decoded.payload.offset + decoded.payload.length,
      ),
    );
    const direction = flow["direction"] === "b-to-a" ? "b-to-a" : "a-to-b";
    if (protocol === "udp") {
      udp.push({
        data,
        time: frame.time,
        flow: flow["key"],
        direction,
        transport: "udp",
      });
      continue;
    }
    const key = `${flow["key"]}|${direction}`;
    const stream = tcp.get(key) ?? {
      flow: flow["key"],
      direction,
      segments: [],
    };
    stream.segments.push({
      seq: Number(transport["sequence"] ?? 0),
      data,
      time: frame.time,
    });
    tcp.set(key, stream);
  }
  return { udp, tcp: [...tcp.values()] };
};

/** Order segments by sequence number (relative to the first, modulo 2^32), dropping repeats and splitting at gaps. */
const reassemble = (segments: readonly Segment[]): TcpStream["pieces"] => {
  const base = segments[0]?.seq ?? 0;
  const ordered = segments
    .map((segment, order) => ({
      ...segment,
      at: (segment.seq - base + 2 ** 32) % 2 ** 32,
      order,
    }))
    .sort((left, right) => left.at - right.at || left.order - right.order);
  const pieces: {
    data: Buffer[];
    time: number | null;
    start: number;
    end: number;
    segments: number[];
  }[] = [];
  for (const segment of ordered) {
    const last = pieces.at(-1);
    const end = segment.at + segment.data.length;
    if (last !== undefined && segment.at <= last.end) {
      if (end <= last.end) continue;
      const fresh = segment.data.subarray(last.end - segment.at);
      last.segments.push(last.end - last.start);
      last.data.push(fresh);
      last.end = end;
    } else
      pieces.push({
        data: [segment.data],
        time: segment.time,
        start: segment.at,
        end,
        segments: [0],
      });
  }
  return pieces.map((piece) => ({
    data: Buffer.concat(piece.data),
    time: piece.time,
    segments: piece.segments,
  }));
};

export const captureMessages = (
  frames: readonly CaptureFrame[],
  selection: CaptureSelection,
): { readonly udp: readonly Message[]; readonly tcp: readonly TcpStream[] } => {
  const { udp, tcp } = segmentsOf(frames, selection);
  return {
    udp,
    tcp: tcp.map((stream) => ({
      flow: stream.flow,
      direction: stream.direction,
      pieces: reassemble(stream.segments),
    })),
  };
};

/** One message per line of hex; spaces, colons and # comments are ignored. */
export const hexMessages = (text: string): Message[] | null => {
  const lines = text
    .split(/\r?\n/u)
    .map((line) => line.replace(/#.*$/u, "").replace(/[\s:]/gu, ""))
    .filter((line) => line !== "");
  if (
    lines.length === 0 ||
    !lines.every((line) => /^(?:[0-9a-fA-F]{2})+$/u.test(line))
  )
    return null;
  return lines.map((line) => ({
    data: Buffer.from(line, "hex"),
    time: null,
    flow: "hex",
    direction: null,
    transport: "hex",
  }));
};

export const requireMessages = (count: number): void => {
  if (count === 0)
    throw new ProtocolFormatError(
      "The selection holds no application payloads.",
    );
};
