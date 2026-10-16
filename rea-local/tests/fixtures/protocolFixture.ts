/**
 * Captures written byte by byte: classic PCAP and PCAPNG files of Ethernet,
 * IPv4, UDP and TCP frames, carrying a small game protocol with a known
 * layout and a length-prefixed TCP stream.
 */
import { crc32 } from "node:zlib";

const u16be = (value: number) =>
  Buffer.from([(value >> 8) & 0xff, value & 0xff]);
const u32be = (value: number) => {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value >>> 0);
  return out;
};
const u32le = (value: number) => {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value >>> 0);
  return out;
};

export interface FixturePacket {
  readonly time: number;
  readonly src: readonly [number, number, number, number];
  readonly dst: readonly [number, number, number, number];
  readonly sport: number;
  readonly dport: number;
  readonly payload: Buffer;
  /** TCP sequence number; UDP when absent. */
  readonly seq?: number;
}

const ipv4 = (packet: FixturePacket, transport: Buffer, protocol: number) =>
  Buffer.concat([
    Buffer.from([0x45, 0]),
    u16be(20 + transport.length),
    Buffer.from([0, 0, 0x40, 0, 64, protocol, 0, 0]),
    Buffer.from(packet.src),
    Buffer.from(packet.dst),
    transport,
  ]);

/** An Ethernet frame holding IPv4 and UDP, or TCP when the packet has a sequence number. */
export const frame = (packet: FixturePacket): Buffer => {
  const ports = Buffer.concat([u16be(packet.sport), u16be(packet.dport)]);
  const transport =
    packet.seq === undefined
      ? Buffer.concat([
          ports,
          u16be(8 + packet.payload.length),
          u16be(0),
          packet.payload,
        ])
      : Buffer.concat([
          ports,
          u32be(packet.seq),
          u32be(0),
          Buffer.from([0x50, 0x18]),
          u16be(0xffff),
          u16be(0),
          u16be(0),
          packet.payload,
        ]);
  const ip = ipv4(packet, transport, packet.seq === undefined ? 17 : 6);
  const ethernet = Buffer.concat([Buffer.alloc(12, 0x11), u16be(0x0800), ip]);
  // Short frames are padded to Ethernet's 60-byte minimum, after the payload.
  return ethernet.length < 60
    ? Buffer.concat([ethernet, Buffer.alloc(60 - ethernet.length)])
    : ethernet;
};

/** Classic little-endian microsecond PCAP. */
export const pcap = (packets: readonly FixturePacket[]): Buffer =>
  Buffer.concat([
    Buffer.from("d4c3b2a1020004000000000000000000ffff000001000000", "hex"),
    ...packets.flatMap((packet) => {
      const data = frame(packet);
      const seconds = Math.floor(packet.time);
      return [
        u32le(seconds),
        u32le(Math.round((packet.time - seconds) * 1e6)),
        u32le(data.length),
        u32le(data.length),
        data,
      ];
    }),
  ]);

const block = (type: number, body: Buffer) => {
  const padded = Buffer.concat([
    body,
    Buffer.alloc((4 - (body.length % 4)) % 4),
  ]);
  return Buffer.concat([
    u32le(type),
    u32le(padded.length + 12),
    padded,
    u32le(padded.length + 12),
  ]);
};

/** PCAPNG with nanosecond timestamps (if_tsresol 9) and enhanced packet blocks. */
export const pcapng = (packets: readonly FixturePacket[]): Buffer =>
  Buffer.concat([
    block(
      0x0a0d0d0a,
      Buffer.concat([
        u32le(0x1a2b3c4d),
        Buffer.from([1, 0, 0, 0]),
        Buffer.alloc(8, 0xff),
      ]),
    ),
    block(
      1,
      Buffer.concat([
        Buffer.from([1, 0, 0, 0]),
        u32le(0xffff),
        Buffer.from([9, 0, 1, 0, 9, 0, 0, 0]),
        Buffer.alloc(4),
      ]),
    ),
    ...packets.map((packet) => {
      const data = frame(packet);
      const ticks = BigInt(Math.round(packet.time * 1e9));
      return block(
        6,
        Buffer.concat([
          u32le(0),
          u32le(Number(ticks >> 32n)),
          u32le(Number(ticks & 0xffffffffn)),
          u32le(data.length),
          u32le(data.length),
          data,
        ]),
      );
    }),
  ]);

/** A deterministic generator, so the captures are the same every run. */
export const random = (seed: number) => {
  let state = seed >>> 0 || 1;
  return (bound: number): number => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) % bound;
  };
};

export const GAME_START = 1_760_000_000;

/**
 * "GAME", type u8 (1 move, 2 chat, 3 ping), sequence u32le per client,
 * payload length u16le, CRC-32 of the payload u32le, time u32le seconds,
 * then: move = three f32le and a u8; chat = text; ping = a u64 nonce.
 */
export const gamePackets = (count = 240): FixturePacket[] => {
  const next = random(7);
  const sequence = [100, 5000];
  const chats = ["hello there", "gg", "anyone want to trade?", "lag!!"];
  return Array.from({ length: count }, (_, index) => {
    const client = index % 2;
    const kind = [1, 1, 2, 3][next(4)] ?? 1;
    let payload: Buffer;
    if (kind === 1) {
      payload = Buffer.alloc(13);
      payload.writeFloatLE((next(100_000) - 50_000) / 97);
      payload.writeFloatLE(next(6400) / 101, 4);
      payload.writeFloatLE((next(100_000) - 50_000) / 89, 8);
      payload[12] = next(4);
    } else if (kind === 2)
      payload = Buffer.from(chats[next(chats.length)] ?? "gg");
    else payload = Buffer.from(Array.from({ length: 8 }, () => next(256)));
    sequence[client] = (sequence[client] ?? 0) + 1;
    const time = GAME_START + index * 0.05;
    const header = Buffer.alloc(19);
    header.write("GAME");
    header[4] = kind;
    header.writeUInt32LE(sequence[client] ?? 0, 5);
    header.writeUInt16LE(payload.length, 9);
    header.writeUInt32LE(crc32(payload) >>> 0, 11);
    header.writeUInt32LE(Math.floor(time), 15);
    return {
      time,
      src: [10, 0, 0, 1 + client],
      dst: [10, 0, 0, 9],
      sport: 40001 + client,
      dport: 7777,
      payload: Buffer.concat([header, payload]),
    };
  });
};

/**
 * One TCP direction of messages with a u32le total length then a u16le
 * opcode and JSON text: some segments carry two messages, one message is
 * split over two segments, one segment is sent twice, and two arrive out
 * of order.
 */
export const lengthPrefixedStream = (): {
  packets: FixturePacket[];
  messages: Buffer[];
} => {
  const next = random(11);
  const messages = Array.from({ length: 40 }, (_, index) => {
    const body = Buffer.from(
      JSON.stringify({
        op: ["move", "say", "buy"][next(3)],
        id: index,
        x: next(1000),
      }),
    );
    const head = Buffer.alloc(6);
    head.writeUInt32LE(6 + body.length);
    head.writeUInt16LE(1 + next(3), 4);
    return Buffer.concat([head, body]);
  });
  const stream = Buffer.concat(messages);
  const cuts = [0];
  for (const message of messages)
    cuts.push((cuts.at(-1) ?? 0) + message.length);
  // Segment starts: every message start, except that some pairs share a segment, plus one cut mid-message.
  const starts = cuts.filter(
    (cut, index) => index % 5 !== 3 && cut < stream.length,
  );
  starts.splice(7, 0, (cuts[7] ?? 0) + 5);
  const segments = starts.map((start, index) => ({
    start,
    data: stream.subarray(start, starts[index + 1] ?? stream.length),
  }));
  const ordered = [...segments];
  [ordered[3], ordered[4]] = [
    ordered[4] ?? segments[4],
    ordered[3] ?? segments[3],
  ] as [(typeof segments)[number], (typeof segments)[number]];
  ordered.splice(
    10,
    0,
    segments[9] ?? (segments[0] as (typeof segments)[number]),
  );
  const packets = ordered.map((segment, index) => ({
    time: GAME_START + index * 0.01,
    src: [10, 0, 3, 2] as const,
    dst: [10, 0, 3, 3] as const,
    sport: 45000,
    dport: 9000,
    seq: 1000 + segment.start,
    payload: segment.data,
  }));
  return { packets, messages };
};
