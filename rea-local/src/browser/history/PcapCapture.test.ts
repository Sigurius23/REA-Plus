import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { decodePcapCapture } from "./PcapCapture.js";
import { classicPcap, ethernetIpv4Frame } from "./PcapCapture.fixture.js";

const ethernetIpv6UdpFrame = (payload = Buffer.from("payload")): Buffer => {
  const frame = Buffer.alloc(14 + 40 + 8 + payload.length);
  Buffer.from("00112233445566778899aabb86dd", "hex").copy(frame, 0);
  const ipOffset = 14;
  frame[ipOffset] = 0x60;
  frame.writeUInt16BE(8 + payload.length, ipOffset + 4);
  frame[ipOffset + 6] = 17;
  frame[ipOffset + 7] = 64;
  Buffer.from("20010db8000000000000000000000001", "hex").copy(
    frame,
    ipOffset + 8,
  );
  Buffer.from("20010db8000000000000000000000002", "hex").copy(
    frame,
    ipOffset + 24,
  );
  const transportOffset = ipOffset + 40;
  frame.writeUInt16BE(53_000, transportOffset);
  frame.writeUInt16BE(443, transportOffset + 2);
  frame.writeUInt16BE(8 + payload.length, transportOffset + 4);
  frame.writeUInt16BE(0, transportOffset + 6);
  payload.copy(frame, transportOffset + 8);
  return frame;
};

const ethernetIpv6NonInitialFragment = (): Buffer => {
  const payload = Buffer.from("fragment-data");
  const frame = Buffer.alloc(14 + 40 + 8 + payload.length);
  Buffer.from("00112233445566778899aabb86dd", "hex").copy(frame, 0);
  const ipOffset = 14;
  frame[ipOffset] = 0x60;
  frame.writeUInt16BE(8 + payload.length, ipOffset + 4);
  frame[ipOffset + 6] = 44;
  frame[ipOffset + 7] = 64;
  Buffer.from("20010db8000000000000000000000001", "hex").copy(
    frame,
    ipOffset + 8,
  );
  Buffer.from("20010db8000000000000000000000002", "hex").copy(
    frame,
    ipOffset + 24,
  );
  const fragmentOffset = ipOffset + 40;
  frame[fragmentOffset] = 17;
  frame.writeUInt16BE(8, fragmentOffset + 2);
  frame.writeUInt32BE(0x12345678, fragmentOffset + 4);
  payload.copy(frame, fragmentOffset + 8);
  return frame;
};

const pcapNgBlock = (
  type: number,
  body: Buffer,
  endian: "little" | "big" = "little",
): Buffer => {
  const block = Buffer.alloc(8 + body.length + 4);
  if (type === 0x0a0d0d0a) Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]).copy(block, 0);
  else if (endian === "little") block.writeUInt32LE(type, 0);
  else block.writeUInt32BE(type, 0);
  const writeU32 = (value: number, offset: number): void => {
    if (endian === "little") block.writeUInt32LE(value, offset);
    else block.writeUInt32BE(value, offset);
  };
  writeU32(block.length, 4);
  body.copy(block, 8);
  writeU32(block.length, block.length - 4);
  return block;
};

const pcapNg = (
  frame: Buffer,
  endian: "little" | "big" = "little",
  packetType: 2 | 3 | 6 = 6,
): Buffer => {
  const section = Buffer.alloc(16);
  const writeU16 = (value: number, offset: number): void => {
    if (endian === "little") section.writeUInt16LE(value, offset);
    else section.writeUInt16BE(value, offset);
  };
  if (endian === "little") {
    section.writeUInt32LE(0x1a2b3c4d, 0);
    section.writeBigInt64LE(-1n, 8);
  } else {
    section.writeUInt32BE(0x1a2b3c4d, 0);
    section.writeBigInt64BE(-1n, 8);
  }
  writeU16(1, 4);
  writeU16(0, 6);

  const interfaceBody = Buffer.alloc(8);
  if (endian === "little") {
    interfaceBody.writeUInt16LE(1, 0);
    interfaceBody.writeUInt32LE(65_535, 4);
  } else {
    interfaceBody.writeUInt16BE(1, 0);
    interfaceBody.writeUInt32BE(65_535, 4);
  }

  const padded = (frame.length + 3) & ~3;
  const packetBody = Buffer.alloc((packetType === 3 ? 4 : 20) + padded);
  const writePacketU32 = (value: number, offset: number): void => {
    if (endian === "little") packetBody.writeUInt32LE(value, offset);
    else packetBody.writeUInt32BE(value, offset);
  };
  if (packetType === 3) {
    writePacketU32(frame.length, 0);
    frame.copy(packetBody, 4);
  } else {
    writePacketU32(0, 0);
    writePacketU32(0, 4);
    writePacketU32(123, 8);
    writePacketU32(frame.length, 12);
    writePacketU32(frame.length, 16);
    frame.copy(packetBody, 20);
  }

  return Buffer.concat([
    pcapNgBlock(0x0a0d0d0a, section, endian),
    pcapNgBlock(1, interfaceBody, endian),
    pcapNgBlock(packetType, packetBody, endian),
  ]);
};

it("preserves classic PCAP frame bytes, packet offsets and normalized TCP flow provenance", () => {
  const frame = ethernetIpv4Frame("tcp");
  const input = classicPcap([frame]);
  const result = decodePcapCapture(input, "pcap", []);
  const record = result.records[0];
  expect(result.total_records).toBe(1);
  expect(record).toMatchObject({
    ordinal: 0,
    location: { kind: "byte-range", offset: 24, bytes: 16 + frame.length },
  });
  expect(record?.reported).toMatchObject({
    frame: {
      record_kind: "classic-packet-record",
      packet_data_offset: 40,
      captured_bytes: frame.length,
      original_bytes: frame.length,
      timestamp: {
        seconds: 1_700_000_000,
        fraction: 123_456,
        unix_seconds: "1700000000.123456",
      },
    },
    link: {
      kind: "ethernet",
      source: "66:77:88:99:aa:bb",
      destination: "00:11:22:33:44:55",
    },
    network: {
      version: 4,
      source_address: "192.0.2.1",
      destination_address: "198.51.100.2",
      protocol: "tcp",
    },
    transport: {
      protocol: "tcp",
      source_port: 12_345,
      destination_port: 443,
      sequence: 77,
      acknowledgment: 88,
    },
    flow: {
      kind: "transport-5-tuple",
      key: "tcp|192.0.2.1:12345|198.51.100.2:443",
      direction: "a-to-b",
      reassembled: false,
    },
  });
  expect(record?.binary_fields[0]).toMatchObject({
    pointer: "/frame/data",
    representation: "producer-bytes",
    state: "retained",
    content_base64: frame.toString("base64"),
    bytes: frame.length,
    sha256: createHash("sha256").update(frame).digest("hex"),
  });
  expect(result.container.records_pointer).toBeNull();
});

it("parses IPv6/UDP addresses and normalized flow provenance", () => {
  const frame = ethernetIpv6UdpFrame(Buffer.from("dns"));
  const result = decodePcapCapture(classicPcap([frame]), "pcap", []);
  expect(result.records[0]?.reported).toMatchObject({
    network: {
      version: 6,
      source_address: "2001:db8::1",
      destination_address: "2001:db8::2",
      protocol: "udp",
    },
    transport: {
      protocol: "udp",
      source_port: 53_000,
      destination_port: 443,
    },
    flow: {
      kind: "transport-5-tuple",
      key: "udp|[2001:db8::1]:53000|[2001:db8::2]:443",
      direction: "a-to-b",
    },
  });
});

it("does not interpret non-initial IPv4 fragment payload as a transport header", () => {
  const frame = ethernetIpv4Frame("udp", Buffer.from("fragment"));
  frame.writeUInt16BE(1, 14 + 6);
  const result = decodePcapCapture(classicPcap([frame]), "pcap", []);
  expect(result.records[0]?.reported).toMatchObject({
    network: {
      fragmented: true,
      fragment_offset_bytes: 8,
      protocol: "udp",
    },
    transport: null,
    flow: null,
  });
});

it("does not parse non-initial IPv6 fragment payload as a transport header", () => {
  const result = decodePcapCapture(
    classicPcap([ethernetIpv6NonInitialFragment()]),
    "pcap",
    [],
  );
  expect(result.records[0]?.reported).toMatchObject({
    network: {
      version: 6,
      fragmented: true,
      fragment_offset_bytes: 8,
      protocol: "udp",
    },
    transport: null,
    flow: null,
  });
});

it("decodes big-endian nanosecond classic PCAP timestamps exactly", () => {
  const frame = ethernetIpv4Frame("udp");
  const result = decodePcapCapture(
    classicPcap([frame], "big", true),
    "pcap",
    [],
  );
  expect(result.container.reported).toMatchObject({
    byte_order: "big-endian",
    timestamp_precision: "nanoseconds",
  });
  expect(result.records[0]?.reported).toMatchObject({
    frame: {
      timestamp: {
        unix_seconds: "1700000000.000000123",
      },
    },
  });
});

it("retains only selected PCAP records in caller order while counting every frame", () => {
  const input = classicPcap([
    ethernetIpv4Frame("udp", Buffer.from("first")),
    ethernetIpv4Frame("udp", Buffer.from("second")),
  ]);
  const result = decodePcapCapture(input, "pcap", [], [1, 0]);
  expect(result.total_records).toBe(2);
  expect(result.records.map(({ ordinal }) => ordinal)).toEqual([1, 0]);
});

it("redacts explicitly sensitive packet bytes but preserves the observed frame boundary", () => {
  const frame = ethernetIpv4Frame("udp", Buffer.from("secret-payload"));
  const result = decodePcapCapture(classicPcap([frame]), "pcap", ["secret"]);
  expect(result.records[0]?.binary_fields[0]).toMatchObject({
    state: "redacted",
    content_base64: null,
    bytes: null,
    sha256: null,
  });
  expect(result.records[0]?.redactions).toContainEqual({
    pointer: "/frame/data",
    reason: "explicit-sensitive-value",
  });
});

it("validates later unselected packet boundaries instead of returning selected partial success", () => {
  const valid = classicPcap([ethernetIpv4Frame("udp")]);
  const malformedHeader = Buffer.alloc(16);
  malformedHeader.writeUInt32LE(1_700_000_010, 0);
  malformedHeader.writeUInt32LE(0, 4);
  malformedHeader.writeUInt32LE(100, 8);
  malformedHeader.writeUInt32LE(100, 12);
  const input = Buffer.concat([valid, malformedHeader, Buffer.from([1, 2, 3])]);
  expect(() => decodePcapCapture(input, "pcap", [], [0])).toThrow(
    "PCAP packet data is truncated",
  );
});

it.each(["little", "big"] as const)(
  "parses %s-endian PCAPNG and preserves enhanced-packet frame provenance",
  (endian) => {
    const frame = ethernetIpv4Frame("udp", Buffer.from("dns"));
    const result = decodePcapCapture(pcapNg(frame, endian), "pcapng", []);
    expect(result.total_records).toBe(1);
    expect(result.container.reported).toMatchObject({
      format: "pcapng",
      byte_order: endian === "little" ? "little-endian" : "big-endian",
      section_version: "1.0",
      sections: 1,
      interfaces: 1,
      packets: 1,
    });
    expect(result.records[0]).toMatchObject({
      ordinal: 0,
      location: {
        kind: "byte-range",
        offset: 48,
        bytes: 32 + ((frame.length + 3) & ~3),
      },
    });
    expect(result.records[0]?.reported).toMatchObject({
      frame: {
        record_kind: "enhanced-packet-block",
        packet_data_offset: 76,
        section_index: 0,
        interface_index: 0,
        timestamp: {
          ticks: 123,
          unix_seconds: "0.000123",
        },
      },
      transport: {
        protocol: "udp",
        source_port: 53_000,
        destination_port: 53,
      },
    });
  },
);

it.each([
  { packetType: 2, recordKind: "packet-block", dataOffset: 76 },
  { packetType: 3, recordKind: "simple-packet-block", dataOffset: 60 },
] as const)(
  "preserves PCAPNG packet-block provenance for block type $packetType",
  ({ packetType, recordKind, dataOffset }) => {
    const frame = ethernetIpv4Frame("udp", Buffer.from("dns"));
    const result = decodePcapCapture(
      pcapNg(frame, "little", packetType),
      "pcapng",
      [],
    );
    expect(result.records[0]?.reported).toMatchObject({
      frame: {
        record_kind: recordKind,
        packet_data_offset: dataOffset,
        section_index: 0,
        interface_index: 0,
      },
    });
    expect(result.records[0]?.binary_fields[0]).toMatchObject({
      state: "retained",
      content_base64: frame.toString("base64"),
    });
  },
);

it("decodes mixed-endian PCAPNG sections with independent interface tables", () => {
  const littleFrame = ethernetIpv4Frame("udp", Buffer.from("first"));
  const bigFrame = ethernetIpv4Frame("udp", Buffer.from("second"));
  const result = decodePcapCapture(
    Buffer.concat([pcapNg(littleFrame, "little"), pcapNg(bigFrame, "big")]),
    "pcapng",
    [],
  );
  expect(result.container.reported).toMatchObject({
    byte_order: "mixed-endian-sections",
    sections: 2,
    interfaces: 2,
    packets: 2,
  });
  expect(result.records.map(({ ordinal }) => ordinal)).toEqual([0, 1]);
  expect(result.records[0]?.reported).toMatchObject({
    frame: { section_index: 0 },
  });
  expect(result.records[1]?.reported).toMatchObject({
    frame: { section_index: 1 },
  });
});

it("rejects mismatched formats and inconsistent PCAPNG block trailers", () => {
  const classic = classicPcap([ethernetIpv4Frame("udp")]);
  expect(() => decodePcapCapture(classic, "pcapng", [])).toThrow("not PCAPNG");

  const invalid = pcapNg(ethernetIpv4Frame("udp"));
  invalid.writeUInt32LE(4, invalid.length - 4);
  expect(() => decodePcapCapture(invalid, "pcapng", [])).toThrow(
    "block lengths disagree",
  );
});
