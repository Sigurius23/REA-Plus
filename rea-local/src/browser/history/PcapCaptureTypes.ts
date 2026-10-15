import type { WebNetworkCaptureRecord } from "../../domain/webNetworkCapture.js";

type PcapFormat = "pcap" | "pcapng";
type Endian = "little" | "big";
type Projection = Pick<
  WebNetworkCaptureRecord,
  "reported" | "numeric_literals" | "binary_fields" | "redactions"
>;
type UnknownObject = Record<string, unknown>;

interface TimestampDescription {
  readonly reported: UnknownObject;
  readonly exactTicks?: bigint;
}

interface InterfaceDescription {
  readonly linkType: number;
  readonly snapLength: number;
  readonly resolutionBase: 2 | 10;
  readonly resolutionExponent: number;
  readonly offsetSeconds: bigint;
  readonly fcsLength: number | null;
}

interface PacketDescription {
  readonly ordinal: number;
  readonly recordKind: string;
  readonly recordOffset: number;
  readonly recordBytes: number;
  readonly dataOffset: number;
  readonly capturedBytes: number;
  readonly originalBytes: number;
  readonly linkType: number;
  readonly timestamp?: TimestampDescription;
  readonly sectionIndex?: number;
  readonly interfaceIndex?: number;
  readonly fcsLength?: number | null;
}

interface PacketDecode {
  readonly link: UnknownObject;
  readonly network: UnknownObject | null;
  readonly transport: UnknownObject | null;
  readonly flow: UnknownObject | null;
  readonly status: string;
}

interface PacketCollector {
  readonly bytes: Buffer;
  readonly requested?: ReadonlySet<number>;
  readonly sensitiveValues: readonly string[];
  readonly recordsByOrdinal: Map<number, WebNetworkCaptureRecord>;
  packetCount: number;
  estimatedReplyBytes: number;
  outputLimitReached: boolean;
}

export type {
  Endian,
  InterfaceDescription,
  PacketCollector,
  PacketDecode,
  PacketDescription,
  PcapFormat,
  Projection,
  TimestampDescription,
  UnknownObject,
};
