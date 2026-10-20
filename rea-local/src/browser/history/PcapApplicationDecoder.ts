import type { UnknownObject } from "./PcapCaptureTypes.js";
import { decodeDnsMessage } from "./PcapDnsDecoder.js";
import { decodeHttp1Head, isHttp1Start } from "./PcapHttpDecoder.js";
import { decodeTlsHello, isTlsHandshake } from "./PcapTlsDecoder.js";

/** Application metadata observed in one segment, with removed credential pointers. */
export interface ApplicationDecode {
  readonly reported: UnknownObject;
  readonly credentialPointers: readonly string[];
}

const DNS_PORTS = new Set([53, 5353]);

/**
 * Decode application metadata that begins in this one segment or datagram.
 * TLS and HTTP/1.x are recognized from their leading bytes; DNS from the
 * well-known DNS and mDNS ports. Nothing is reassembled across packets.
 */
export const decodeApplication = (input: {
  readonly payload: Buffer;
  readonly protocol: string;
  readonly sourcePort: number;
  readonly destinationPort: number;
}): ApplicationDecode | null => {
  const { payload, protocol } = input;
  if (payload.length === 0) return null;
  const dns =
    DNS_PORTS.has(input.sourcePort) || DNS_PORTS.has(input.destinationPort);
  if (protocol === "udp")
    return dns
      ? { reported: decodeDnsMessage(payload, "udp"), credentialPointers: [] }
      : null;
  if (protocol !== "tcp") return null;
  if (isTlsHandshake(payload))
    return { reported: decodeTlsHello(payload), credentialPointers: [] };
  if (isHttp1Start(payload)) return decodeHttp1Head(payload, "/application");
  return dns
    ? { reported: decodeDnsMessage(payload, "tcp"), credentialPointers: [] }
    : null;
};
