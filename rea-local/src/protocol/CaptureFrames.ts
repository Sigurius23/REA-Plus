/** A capture or message file that cannot be read. */
export class ProtocolFormatError extends Error {}

/** A selection (flow, port, cluster) that does not fit the capture. */
export class ProtocolSelectionError extends Error {
  constructor(
    message: string,
    readonly field: "port" | "flow" | "format" | "transport" | "view",
  ) {
    super(message);
  }
}

export interface CaptureFrame {
  /** Seconds since the epoch, when the capture records it. */
  readonly time: number | null;
  readonly linkType: number;
  readonly data: Buffer;
}

export interface CaptureFrames {
  readonly format: "pcap" | "pcapng";
  readonly frames: readonly CaptureFrame[];
}

const CLASSIC: Readonly<Record<number, readonly [boolean, number]>> = {
  0xa1b2c3d4: [false, 6],
  0xa1b23c4d: [false, 9],
  0xd4c3b2a1: [true, 6],
  0x4d3cb2a1: [true, 9],
};

const need = (bytes: Buffer, at: number, length: number, what: string) => {
  if (at < 0 || length < 0 || at + length > bytes.length)
    throw new ProtocolFormatError(
      `The ${what} at ${String(at)} runs past the end of the capture.`,
    );
};

const classic = (bytes: Buffer): CaptureFrames | null => {
  const shape = CLASSIC[bytes.readUInt32BE(0)];
  if (shape === undefined) return null;
  const [little, digits] = shape;
  const u32 = (at: number) =>
    little ? bytes.readUInt32LE(at) : bytes.readUInt32BE(at);
  need(bytes, 0, 24, "header");
  const linkType = u32(20) & 0x0fffffff;
  const frames: CaptureFrame[] = [];
  for (let at = 24; at < bytes.length;) {
    need(bytes, at, 16, "packet header");
    const length = u32(at + 8);
    need(bytes, at + 16, length, "packet");
    frames.push({
      time: u32(at) + u32(at + 4) / 10 ** digits,
      linkType,
      data: bytes.subarray(at + 16, at + 16 + length),
    });
    at += 16 + length;
  }
  return { format: "pcap", frames };
};

interface Interface {
  readonly linkType: number;
  /** Ticks per second. */
  readonly resolution: number;
}

/** if_tsresol: a power of ten, or of two when the high bit is set. */
const resolution = (body: Buffer, little: boolean): number => {
  for (let at = 8; at + 4 <= body.length;) {
    const code = little ? body.readUInt16LE(at) : body.readUInt16BE(at);
    const length = little
      ? body.readUInt16LE(at + 2)
      : body.readUInt16BE(at + 2);
    if (code === 0) break;
    if (code === 9 && length >= 1) {
      const value = body[at + 4] ?? 6;
      return (value & 0x80) === 0 ? 10 ** value : 2 ** (value & 0x7f);
    }
    at += 4 + length + ((4 - (length % 4)) % 4);
  }
  return 1e6;
};

const pcapng = (bytes: Buffer): CaptureFrames | null => {
  if (bytes.readUInt32BE(0) !== 0x0a0d0d0a) return null;
  let little = true;
  let interfaces: Interface[] = [];
  const frames: CaptureFrame[] = [];
  for (let at = 0; at + 12 <= bytes.length;) {
    if (bytes.readUInt32BE(at) === 0x0a0d0d0a) {
      little = bytes.readUInt32LE(at + 8) === 0x1a2b3c4d;
      interfaces = [];
    }
    const u32 = (offset: number) =>
      little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
    const type = u32(at);
    const total = u32(at + 4);
    if (total < 12 || total % 4 !== 0)
      throw new ProtocolFormatError(
        `A PCAPNG block at ${String(at)} has length ${String(total)}.`,
      );
    need(bytes, at, total, "block");
    const body = bytes.subarray(at + 8, at + total - 4);
    if (type === 1)
      interfaces.push({
        linkType: little ? body.readUInt16LE(0) : body.readUInt16BE(0),
        resolution: resolution(body, little),
      });
    else if (type === 6 || type === 3) {
      const enhanced = type === 6;
      const port = interfaces[enhanced ? u32(at + 8) : 0];
      if (port === undefined)
        throw new ProtocolFormatError(
          `A packet at ${String(at)} names an interface that was not described.`,
        );
      const start = at + (enhanced ? 28 : 12);
      const length = Math.min(
        enhanced ? u32(at + 20) : u32(at + 8),
        at + total - 4 - start,
      );
      const ticks = enhanced ? u32(at + 12) * 2 ** 32 + u32(at + 16) : null;
      frames.push({
        time: ticks === null ? null : ticks / port.resolution,
        linkType: port.linkType,
        data: bytes.subarray(start, start + length),
      });
    }
    at += total;
  }
  return { format: "pcapng", frames };
};

/** Classic PCAP (micro- or nanosecond, either byte order) or PCAPNG. */
export const readCaptureFrames = (bytes: Buffer): CaptureFrames | null =>
  bytes.length < 24 ? null : (classic(bytes) ?? pcapng(bytes));
