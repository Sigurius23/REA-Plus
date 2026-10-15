import { macAddress } from "./PcapCaptureBinary.js";
import {
  decodeIpv4,
  decodeIpv6,
  type NetworkDecode,
} from "./PcapNetworkDecoder.js";
import { decodeApplication } from "./PcapApplicationDecoder.js";
import { createFlow, decodeTransport } from "./PcapTransportDecoder.js";
import type { PacketDecode, UnknownObject } from "./PcapCaptureTypes.js";

interface LinkDecode {
  readonly link: UnknownObject;
  readonly protocolType?: number;
  readonly payloadOffset?: number;
  readonly status: string;
}

/** Decode only supported link and network headers; captured bytes remain authoritative. */
export const decodeFrame = (frame: Buffer, linkType: number): PacketDecode => {
  const layer = decodeLinkLayer(frame, linkType);
  if (layer.payloadOffset === undefined || layer.protocolType === undefined)
    return emptyNetworkResult(layer);
  const networkResult = decodeNetwork(
    frame,
    layer.payloadOffset,
    layer.protocolType,
  );
  if (networkResult === undefined)
    return {
      link: layer.link,
      network: null,
      transport: null,
      flow: null,
      application: null,
      credentialPointers: [],
      status:
        layer.protocolType === 0
          ? "unknown-raw-network-version"
          : "unsupported-network-protocol",
    };
  return completeNetworkDecode(frame, layer.link, networkResult);
};

const decodeLinkLayer = (frame: Buffer, linkType: number): LinkDecode => {
  if (linkType === 1) return decodeEthernet(frame);
  if (linkType === 101 || linkType === 228 || linkType === 229)
    return decodeRawIp(frame, linkType);
  if (linkType === 113) return decodeLinuxCookedV1(frame);
  if (linkType === 276) return decodeLinuxCookedV2(frame);
  return {
    link: {
      kind: "unknown",
      link_type: linkType,
      captured_bytes: frame.length,
    },
    status: "unsupported-link-type",
  };
};

const decodeEthernet = (frame: Buffer): LinkDecode => {
  if (frame.length < 14)
    return {
      link: { kind: "ethernet", captured_bytes: frame.length },
      status: "truncated-link-header",
    };
  let protocolType = frame.readUInt16BE(12);
  let payloadOffset = 14;
  const tags: UnknownObject[] = [];
  while (isVlanType(protocolType)) {
    if (frame.length - payloadOffset < 4)
      return {
        link: {
          kind: "ethernet",
          destination: macAddress(frame, 0),
          source: macAddress(frame, 6),
          ether_type: protocolType,
          vlan_tags: tags,
        },
        status: "truncated-vlan-header",
      };
    const tag = frame.readUInt16BE(payloadOffset);
    tags.push({
      priority: (tag >> 13) & 0x7,
      drop_eligible: ((tag >> 12) & 1) === 1,
      vlan_id: tag & 0x0fff,
      tag_type: protocolType,
    });
    protocolType = frame.readUInt16BE(payloadOffset + 2);
    payloadOffset += 4;
  }
  return {
    link: {
      kind: "ethernet",
      destination: macAddress(frame, 0),
      source: macAddress(frame, 6),
      ether_type: protocolType,
      vlan_tags: tags,
    },
    protocolType,
    payloadOffset,
    status: "decoded-link-layer",
  };
};

const decodeRawIp = (frame: Buffer, linkType: number): LinkDecode => {
  const version = frame.length === 0 ? 0 : (frame[0] ?? 0) >> 4;
  const protocolType =
    linkType === 228
      ? 0x0800
      : linkType === 229
        ? 0x86dd
        : version === 4
          ? 0x0800
          : version === 6
            ? 0x86dd
            : 0;
  return {
    link: { kind: "raw-ip", link_type: linkType },
    protocolType,
    payloadOffset: 0,
    status: "decoded-link-layer",
  };
};

const decodeLinuxCookedV1 = (frame: Buffer): LinkDecode => {
  if (frame.length < 16)
    return {
      link: { kind: "linux-cooked-v1", captured_bytes: frame.length },
      status: "truncated-link-header",
    };
  const protocolType = frame.readUInt16BE(14);
  const addressLength = Math.min(frame.readUInt16BE(4), 8);
  return {
    link: {
      kind: "linux-cooked-v1",
      packet_type: frame.readUInt16BE(0),
      hardware_type: frame.readUInt16BE(2),
      address_length: frame.readUInt16BE(4),
      source_address: frame.subarray(6, 6 + addressLength).toString("hex"),
      protocol_type: protocolType,
    },
    protocolType,
    payloadOffset: 16,
    status: "decoded-link-layer",
  };
};

const decodeLinuxCookedV2 = (frame: Buffer): LinkDecode => {
  if (frame.length < 20)
    return {
      link: { kind: "linux-cooked-v2", captured_bytes: frame.length },
      status: "truncated-link-header",
    };
  const protocolType = frame.readUInt16BE(0);
  const addressLength = Math.min(frame[11] ?? 0, 8);
  return {
    link: {
      kind: "linux-cooked-v2",
      protocol_type: protocolType,
      interface_index: frame.readUInt32BE(4),
      hardware_type: frame.readUInt16BE(8),
      packet_type: frame[10] ?? 0,
      address_length: frame[11] ?? 0,
      source_address: frame.subarray(12, 12 + addressLength).toString("hex"),
    },
    protocolType,
    payloadOffset: 20,
    status: "decoded-link-layer",
  };
};

const decodeNetwork = (
  frame: Buffer,
  payloadOffset: number,
  protocolType: number,
): NetworkDecode | undefined => {
  if (protocolType === 0x0800) return decodeIpv4(frame, payloadOffset);
  if (protocolType === 0x86dd) return decodeIpv6(frame, payloadOffset);
  return undefined;
};

const emptyNetworkResult = (layer: LinkDecode): PacketDecode => ({
  link: layer.link,
  network: null,
  transport: null,
  flow: null,
  application: null,
  credentialPointers: [],
  status: layer.status,
});

const completeNetworkDecode = (
  frame: Buffer,
  link: UnknownObject,
  network: NetworkDecode,
): PacketDecode => {
  const transport = decodeTransport({
    frame,
    offset: network.transportOffset,
    length: network.transportLength,
    protocolNumber: network.protocolNumber,
    fragmentOffsetBytes: network.fragmentOffsetBytes,
  });
  const flow =
    network.sourceAddress !== undefined &&
    network.destinationAddress !== undefined &&
    transport?.sourcePort !== undefined &&
    transport.destinationPort !== undefined &&
    network.fragmentOffsetBytes === 0
      ? createFlow({
          sourceAddress: network.sourceAddress,
          destinationAddress: network.destinationAddress,
          sourcePort: transport.sourcePort,
          destinationPort: transport.destinationPort,
          protocol: transport.protocol,
        })
      : null;
  const application =
    transport?.payload === undefined ||
    transport.sourcePort === undefined ||
    transport.destinationPort === undefined
      ? null
      : decodeApplication({
          payload: frame.subarray(
            transport.payload.offset,
            transport.payload.offset + transport.payload.length,
          ),
          protocol: transport.protocol,
          sourcePort: transport.sourcePort,
          destinationPort: transport.destinationPort,
        });
  return {
    link,
    network: network.reported,
    transport: transport?.reported ?? null,
    flow,
    application: application?.reported ?? null,
    credentialPointers: application?.credentialPointers ?? [],
    status: network.status ?? transport?.status ?? "decoded-network-layer",
  };
};

const isVlanType = (type: number): boolean =>
  type === 0x8100 || type === 0x88a8 || type === 0x9100;
