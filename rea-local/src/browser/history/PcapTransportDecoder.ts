import type { UnknownObject } from "./PcapCaptureTypes.js";

interface TransportInput {
  readonly frame: Buffer;
  readonly offset: number;
  readonly length: number;
  readonly protocolNumber: number;
  readonly fragmentOffsetBytes: number;
}

interface TransportDecode {
  readonly reported: UnknownObject;
  readonly protocol: string;
  readonly sourcePort?: number;
  readonly destinationPort?: number;
  readonly status?: string;
  /** Captured transport payload within the frame, when its header decoded. */
  readonly payload?: { readonly offset: number; readonly length: number };
}

interface FlowInput {
  readonly sourceAddress: string;
  readonly destinationAddress: string;
  readonly sourcePort: number;
  readonly destinationPort: number;
  readonly protocol: string;
}

interface TcpMetadataInput {
  readonly frame: Buffer;
  readonly offset: number;
  readonly length: number;
  readonly headerBytes: number;
  readonly protocol: string;
  readonly sourcePort: number;
  readonly destinationPort: number;
}

export const decodeTransport = (
  input: TransportInput,
): TransportDecode | undefined => {
  if (input.fragmentOffsetBytes !== 0) return undefined;
  const protocol = ipProtocolName(input.protocolNumber);
  if (input.protocolNumber === 6) return decodeTcp(input, protocol);
  if (input.protocolNumber === 17) return decodeUdp(input, protocol);
  if (input.protocolNumber === 1 || input.protocolNumber === 58)
    return decodeIcmp(input, protocol);
  return undefined;
};

const decodeUdp = (
  { frame, offset, length }: TransportInput,
  protocol: string,
): TransportDecode => {
  if (length < 4 || frame.length - offset < 4)
    return {
      reported: { protocol, decode_status: "truncated-transport-ports" },
      protocol,
      status: "truncated-transport-header",
    };
  const sourcePort = frame.readUInt16BE(offset);
  const destinationPort = frame.readUInt16BE(offset + 2);
  if (length < 8 || frame.length - offset < 8)
    return {
      reported: {
        protocol,
        source_port: sourcePort,
        destination_port: destinationPort,
        decode_status: "truncated-udp-header",
      },
      protocol,
      sourcePort,
      destinationPort,
      status: "truncated-transport-header",
    };
  const declaredBytes = frame.readUInt16BE(offset + 4);
  const checksum = frame.readUInt16BE(offset + 6);
  if (declaredBytes < 8)
    return {
      reported: {
        protocol,
        source_port: sourcePort,
        destination_port: destinationPort,
        declared_bytes: declaredBytes,
        checksum,
        decode_status: "malformed-udp-length",
      },
      protocol,
      sourcePort,
      destinationPort,
      status: "malformed-transport-header",
    };
  const capturedPayloadBytes = Math.max(
    0,
    Math.min(length, declaredBytes, frame.length - offset) - 8,
  );
  return {
    reported: {
      protocol,
      source_port: sourcePort,
      destination_port: destinationPort,
      declared_bytes: declaredBytes,
      checksum,
      captured_payload_bytes: Math.max(0, Math.min(length, declaredBytes) - 8),
      truncated: declaredBytes > length,
    },
    protocol,
    sourcePort,
    destinationPort,
    payload: { offset: offset + 8, length: capturedPayloadBytes },
    ...(declaredBytes > length ? { status: "truncated-udp-packet" } : {}),
  };
};

const decodeTcp = (
  { frame, offset, length }: TransportInput,
  protocol: string,
): TransportDecode => {
  if (length < 4 || frame.length - offset < 4)
    return {
      reported: { protocol, decode_status: "truncated-transport-ports" },
      protocol,
      status: "truncated-transport-header",
    };
  const sourcePort = frame.readUInt16BE(offset);
  const destinationPort = frame.readUInt16BE(offset + 2);
  if (length < 20 || frame.length - offset < 20)
    return {
      reported: {
        protocol,
        source_port: sourcePort,
        destination_port: destinationPort,
        decode_status: "truncated-tcp-header",
      },
      protocol,
      sourcePort,
      destinationPort,
      status: "truncated-transport-header",
    };
  const headerBytes = ((frame[offset + 12] ?? 0) >> 4) * 4;
  if (headerBytes < 20)
    return {
      reported: {
        protocol,
        source_port: sourcePort,
        destination_port: destinationPort,
        header_bytes: headerBytes,
        decode_status: "malformed-tcp-header",
      },
      protocol,
      sourcePort,
      destinationPort,
      status: "malformed-transport-header",
    };
  if (length < headerBytes || frame.length - offset < headerBytes)
    return {
      reported: {
        protocol,
        source_port: sourcePort,
        destination_port: destinationPort,
        header_bytes: headerBytes,
        decode_status: "truncated-tcp-options",
      },
      protocol,
      sourcePort,
      destinationPort,
      status: "truncated-transport-header",
    };
  return tcpMetadata({
    frame,
    offset,
    length,
    headerBytes,
    protocol,
    sourcePort,
    destinationPort,
  });
};

const tcpMetadata = ({
  frame,
  offset,
  length,
  headerBytes,
  protocol,
  sourcePort,
  destinationPort,
}: TcpMetadataInput): TransportDecode => {
  const flagsByte = frame[offset + 13] ?? 0;
  const flags = [
    [0x01, "FIN"],
    [0x02, "SYN"],
    [0x04, "RST"],
    [0x08, "PSH"],
    [0x10, "ACK"],
    [0x20, "URG"],
    [0x40, "ECE"],
    [0x80, "CWR"],
  ]
    .filter(([mask]) => (flagsByte & Number(mask)) !== 0)
    .map(([, name]) => name);
  return {
    reported: {
      protocol,
      source_port: sourcePort,
      destination_port: destinationPort,
      sequence: frame.readUInt32BE(offset + 4),
      acknowledgment: frame.readUInt32BE(offset + 8),
      header_bytes: headerBytes,
      flags,
      flags_byte: flagsByte,
      window: frame.readUInt16BE(offset + 14),
      checksum: frame.readUInt16BE(offset + 16),
      urgent_pointer: frame.readUInt16BE(offset + 18),
      captured_payload_bytes: Math.max(0, length - headerBytes),
    },
    protocol,
    sourcePort,
    destinationPort,
    payload: {
      offset: offset + headerBytes,
      length: Math.max(
        0,
        Math.min(length, frame.length - offset) - headerBytes,
      ),
    },
  };
};

const decodeIcmp = (
  { frame, offset, length }: TransportInput,
  protocol: string,
): TransportDecode => {
  if (length < 2 || frame.length - offset < 2)
    return {
      reported: { protocol, decode_status: "truncated-icmp-header" },
      protocol,
      status: "truncated-transport-header",
    };
  return {
    reported: {
      protocol,
      type: frame[offset] ?? 0,
      code: frame[offset + 1] ?? 0,
      ...(length >= 4 && frame.length - offset >= 4
        ? { checksum: frame.readUInt16BE(offset + 2) }
        : {}),
    },
    protocol,
  };
};

export const createFlow = ({
  sourceAddress,
  destinationAddress,
  sourcePort,
  destinationPort,
  protocol,
}: FlowInput): UnknownObject => {
  const source = endpoint(sourceAddress, sourcePort);
  const destination = endpoint(destinationAddress, destinationPort);
  const [first, second] = [source, destination].sort();
  return {
    kind: "transport-5-tuple",
    key: `${protocol}|${first}|${second}`,
    direction:
      source === destination
        ? "same-endpoint"
        : source === first
          ? "a-to-b"
          : "b-to-a",
    reassembled: false,
  };
};

const endpoint = (address: string, port: number): string =>
  address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;

export const isIpv6Extension = (protocol: number): boolean =>
  protocol === 0 ||
  protocol === 43 ||
  protocol === 44 ||
  protocol === 51 ||
  protocol === 60;

export const ipProtocolName = (protocol: number): string =>
  protocol === 1
    ? "icmp"
    : protocol === 6
      ? "tcp"
      : protocol === 17
        ? "udp"
        : protocol === 41
          ? "ipv6-encapsulation"
          : protocol === 47
            ? "gre"
            : protocol === 50
              ? "esp"
              : protocol === 58
                ? "icmpv6"
                : protocol === 132
                  ? "sctp"
                  : `ip-${protocol}`;
