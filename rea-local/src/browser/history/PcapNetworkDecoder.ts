import { MAX_IPV6_EXTENSION_HEADERS } from "./PcapCaptureLimits.js";
import { ipv4Address, ipv6Address } from "./PcapCaptureBinary.js";
import { ipProtocolName, isIpv6Extension } from "./PcapTransportDecoder.js";
import type { UnknownObject } from "./PcapCaptureTypes.js";

export interface NetworkDecode {
  readonly reported: UnknownObject;
  readonly transportOffset: number;
  readonly transportLength: number;
  readonly protocolNumber: number;
  readonly sourceAddress?: string;
  readonly destinationAddress?: string;
  readonly fragmentOffsetBytes: number;
  readonly status?: string;
}

export const decodeIpv4 = (frame: Buffer, offset: number): NetworkDecode => {
  if (frame.length - offset < 20)
    return {
      reported: { version: 4, decode_status: "truncated-ipv4-header" },
      transportOffset: frame.length,
      transportLength: 0,
      protocolNumber: -1,
      fragmentOffsetBytes: 0,
      status: "truncated-network-header",
    };
  const first = frame[offset] ?? 0;
  const version = first >> 4;
  const headerLength = (first & 0x0f) * 4;
  if (version !== 4 || headerLength < 20)
    return {
      reported: {
        version,
        header_bytes: headerLength,
        decode_status: "malformed-ipv4-header",
      },
      transportOffset: frame.length,
      transportLength: 0,
      protocolNumber: -1,
      fragmentOffsetBytes: 0,
      status: "malformed-network-header",
    };
  if (frame.length - offset < headerLength)
    return {
      reported: {
        version: 4,
        header_bytes: headerLength,
        decode_status: "truncated-ipv4-options",
      },
      transportOffset: frame.length,
      transportLength: 0,
      protocolNumber: -1,
      fragmentOffsetBytes: 0,
      status: "truncated-network-header",
    };
  const totalBytes = frame.readUInt16BE(offset + 2);
  if (totalBytes < headerLength)
    return {
      reported: {
        version: 4,
        header_bytes: headerLength,
        total_bytes: totalBytes,
        decode_status: "malformed-ipv4-length",
      },
      transportOffset: frame.length,
      transportLength: 0,
      protocolNumber: -1,
      fragmentOffsetBytes: 0,
      status: "malformed-network-header",
    };
  const fragmentField = frame.readUInt16BE(offset + 6);
  const fragmentOffsetBytes = (fragmentField & 0x1fff) * 8;
  const moreFragments = (fragmentField & 0x2000) !== 0;
  const protocolNumber = frame[offset + 9] ?? 0;
  const sourceAddress = ipv4Address(frame, offset + 12);
  const destinationAddress = ipv4Address(frame, offset + 16);
  const capturedPayloadLength = Math.max(
    0,
    Math.min(frame.length - (offset + headerLength), totalBytes - headerLength),
  );
  const networkTruncated = frame.length - offset < totalBytes;
  const reported: UnknownObject = {
    version,
    header_bytes: headerLength,
    total_bytes: totalBytes,
    identification: frame.readUInt16BE(offset + 4),
    ttl: frame[offset + 8] ?? 0,
    protocol_number: protocolNumber,
    protocol: ipProtocolName(protocolNumber),
    source_address: sourceAddress,
    destination_address: destinationAddress,
    fragmented: fragmentOffsetBytes !== 0 || moreFragments,
    fragment_offset_bytes: fragmentOffsetBytes,
    more_fragments: moreFragments,
    captured_payload_bytes: capturedPayloadLength,
    truncated: networkTruncated,
  };
  return {
    reported,
    transportOffset: offset + headerLength,
    transportLength: fragmentOffsetBytes === 0 ? capturedPayloadLength : 0,
    protocolNumber,
    sourceAddress,
    destinationAddress,
    fragmentOffsetBytes,
    ...(networkTruncated ? { status: "truncated-ipv4-packet" } : {}),
  };
};

export const decodeIpv6 = (frame: Buffer, offset: number): NetworkDecode => {
  if (frame.length - offset < 40)
    return {
      reported: { version: 6, decode_status: "truncated-ipv6-header" },
      transportOffset: frame.length,
      transportLength: 0,
      protocolNumber: -1,
      fragmentOffsetBytes: 0,
      status: "truncated-network-header",
    };
  const version = (frame[offset] ?? 0) >> 4;
  if (version !== 6)
    return {
      reported: { version, decode_status: "malformed-ipv6-version" },
      transportOffset: frame.length,
      transportLength: 0,
      protocolNumber: -1,
      fragmentOffsetBytes: 0,
      status: "malformed-network-header",
    };
  const payloadBytes = frame.readUInt16BE(offset + 4);
  const sourceAddress = ipv6Address(frame, offset + 8);
  const destinationAddress = ipv6Address(frame, offset + 24);
  const extension = walkIpv6Extensions(
    frame,
    offset + 40,
    payloadBytes,
    frame[offset + 6] ?? 0,
  );
  const capturedPayloadLength = Math.max(
    0,
    Math.min(frame.length - extension.cursor, extension.remaining),
  );
  const truncated = payloadBytes > frame.length - (offset + 40);
  const reported: UnknownObject = {
    version,
    header_bytes: extension.cursor - offset,
    payload_bytes: payloadBytes,
    protocol_number: extension.protocolNumber,
    protocol: ipProtocolName(extension.protocolNumber),
    source_address: sourceAddress,
    destination_address: destinationAddress,
    fragmented: extension.fragmented,
    fragment_offset_bytes: extension.fragmentOffsetBytes,
    extension_headers: extension.extensionCount,
    captured_payload_bytes: capturedPayloadLength,
    truncated,
    ...(payloadBytes === 0 ? { zero_payload_length: true } : {}),
    ...(extension.failure === undefined
      ? {}
      : { decode_status: extension.failure }),
  };
  return {
    reported,
    transportOffset: extension.cursor,
    transportLength:
      extension.fragmentOffsetBytes === 0 ? capturedPayloadLength : 0,
    protocolNumber: extension.protocolNumber,
    sourceAddress,
    destinationAddress,
    fragmentOffsetBytes: extension.fragmentOffsetBytes,
    ...(extension.failure !== undefined
      ? { status: extension.failure }
      : truncated
        ? { status: "truncated-ipv6-packet" }
        : {}),
  };
};

interface Ipv6ExtensionWalk {
  readonly cursor: number;
  readonly remaining: number;
  readonly protocolNumber: number;
  readonly fragmentOffsetBytes: number;
  readonly fragmented: boolean;
  readonly extensionCount: number;
  readonly failure?: string;
}

const walkIpv6Extensions = (
  frame: Buffer,
  start: number,
  payloadBytes: number,
  firstProtocol: number,
): Ipv6ExtensionWalk => {
  let cursor = start;
  let remaining = payloadBytes;
  let protocolNumber = firstProtocol;
  let fragmentOffsetBytes = 0;
  let fragmented = false;
  let extensionCount = 0;
  let failure: string | undefined;
  while (isIpv6Extension(protocolNumber)) {
    extensionCount++;
    if (extensionCount > MAX_IPV6_EXTENSION_HEADERS) {
      failure = "ipv6-extension-limit";
      break;
    }
    const header = readIpv6Extension(frame, cursor, remaining, protocolNumber);
    if (header === undefined) {
      failure =
        protocolNumber === 44
          ? "truncated-ipv6-fragment-header"
          : "truncated-ipv6-extension-header";
      break;
    }
    protocolNumber = header.followingProtocol;
    cursor += header.bytes;
    remaining -= header.bytes;
    if (header.fragmentOffsetBytes !== undefined) {
      fragmentOffsetBytes = header.fragmentOffsetBytes;
      fragmented = header.fragmented ?? false;
      if (fragmentOffsetBytes !== 0) break;
    }
  }
  return {
    cursor,
    remaining,
    protocolNumber,
    fragmentOffsetBytes,
    fragmented,
    extensionCount,
    ...(failure === undefined ? {} : { failure }),
  };
};

interface Ipv6ExtensionHeader {
  readonly followingProtocol: number;
  readonly bytes: number;
  readonly fragmentOffsetBytes?: number;
  readonly fragmented?: boolean;
}

const readIpv6Extension = (
  frame: Buffer,
  cursor: number,
  remaining: number,
  protocolNumber: number,
): Ipv6ExtensionHeader | undefined => {
  if (protocolNumber === 44) {
    if (remaining < 8 || frame.length - cursor < 8) return undefined;
    const fragment = frame.readUInt16BE(cursor + 2);
    return {
      followingProtocol: frame[cursor] ?? 0,
      bytes: 8,
      fragmentOffsetBytes: ((fragment >> 3) & 0x1fff) * 8,
      fragmented: ((fragment >> 3) & 0x1fff) !== 0 || (fragment & 1) !== 0,
    };
  }
  if (remaining < 2 || frame.length - cursor < 2) return undefined;
  const followingProtocol = frame[cursor] ?? 0;
  const length =
    protocolNumber === 51
      ? ((frame[cursor + 1] ?? 0) + 2) * 4
      : ((frame[cursor + 1] ?? 0) + 1) * 8;
  if (length < 8 || length > remaining || frame.length - cursor < length)
    return undefined;
  return { followingProtocol, bytes: length };
};
