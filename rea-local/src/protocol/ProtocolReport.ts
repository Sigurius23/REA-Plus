import type {
  InferProtocolFieldsInput,
  ProtocolFieldsReport,
} from "../domain/protocol/protocolFields.js";
import {
  ProtocolFormatError,
  ProtocolSelectionError,
  readCaptureFrames,
} from "./CaptureFrames.js";
import { frameStreams, type Framing } from "./ProtocolFraming.js";
import { inferProtocol, type Inference } from "./ProtocolInference.js";
import {
  captureMessages,
  hexMessages,
  requireMessages,
  type Message,
} from "./ProtocolMessages.js";

const MAX_ANALYSED = 5000;

type Report = ProtocolFieldsReport;

interface Source {
  readonly format: Report["source"]["format"];
  readonly frames: number;
  readonly messages: readonly Message[];
  readonly framing: Framing;
}

const source = (bytes: Buffer, input: InferProtocolFieldsInput): Source => {
  const capture = readCaptureFrames(bytes);
  if (capture === null) {
    const lines = hexMessages(bytes.toString("utf8"));
    if (lines === null)
      throw new ProtocolFormatError(
        "Not a PCAP or PCAPNG capture, or a file of hex messages one per line.",
      );
    return {
      format: "hex_lines",
      frames: 0,
      messages: lines,
      framing: { kind: "lines" },
    };
  }
  const { udp, tcp } = captureMessages(capture.frames, {
    transport: input.transport,
    ...(input.port === undefined ? {} : { port: input.port }),
    ...(input.flow === undefined ? {} : { flow: input.flow }),
  });
  if (udp.length > 0 && tcp.length > 0)
    throw new ProtocolSelectionError(
      `The selection holds ${String(udp.length)} UDP datagrams and ${String(tcp.length)} TCP streams, likely different protocols. Choose transport udp or tcp, or a port.`,
      "transport",
    );
  if (tcp.length === 0)
    return {
      format: capture.format,
      frames: capture.frames.length,
      messages: udp,
      framing: { kind: "datagrams" },
    };
  const framed = frameStreams(tcp);
  return {
    format: capture.format,
    frames: capture.frames.length,
    messages: framed.messages,
    framing: framed.framing,
  };
};

const framingRow = (framing: Framing): Report["framing"] => ({
  kind: framing.kind,
  offset: framing.kind === "length_prefix" ? framing.offset : null,
  width: framing.kind === "length_prefix" ? framing.width : null,
  endian: framing.kind === "length_prefix" ? framing.endian : null,
  adjust: framing.kind === "length_prefix" ? framing.adjust : null,
  delimiter: framing.kind === "delimiter" ? framing.delimiter : null,
});

const rows = (
  messages: readonly Message[],
  inference: Inference,
  all: readonly Message[],
) => {
  const formatOf = new Map<number, number>();
  for (const { cluster } of inference.formats)
    for (const index of cluster.members) formatOf.set(index, cluster.id);
  const formats: Report["formats"] = inference.formats.map(
    ({ cluster, fields }) => {
      const lengths = cluster.members.map(
        (index) => messages[index]?.data.length ?? 0,
      );
      return {
        id: cluster.id,
        key: cluster.key?.value ?? null,
        key_offset: cluster.key?.offset ?? null,
        key_width: cluster.key?.width ?? null,
        direction: cluster.direction,
        messages: cluster.members.length,
        min_length: Math.min(...lengths),
        max_length: Math.max(...lengths),
        fields: fields.length,
      };
    },
  );
  const fields: Report["fields"] = inference.formats.flatMap(
    ({ cluster, fields: list }) =>
      list.map((field) => ({
        format: cluster.id,
        offset: field.offset,
        from: field.from,
        length: field.length,
        kind: field.kind,
        encoding: field.encoding,
        detail: field.detail,
        distinct: field.distinct,
        samples: [...field.samples],
      })),
  );
  const listed: Report["messages"] = messages.map((message, index) => ({
    index,
    format: formatOf.get(index) ?? 0,
    flow: message.flow,
    direction: message.direction,
    time: message.time,
    length: message.data.length,
    hex: message.data.subarray(0, 64).toString("hex"),
  }));
  const byFlow = new Map<string, Report["flows"][number]>();
  for (const message of all) {
    const flow = byFlow.get(message.flow) ?? {
      flow: message.flow,
      transport: message.transport,
      messages: 0,
      bytes: 0,
    };
    byFlow.set(message.flow, {
      ...flow,
      messages: flow.messages + 1,
      bytes: flow.bytes + message.data.length,
    });
  }
  return { formats, fields, messages: listed, flows: [...byFlow.values()] };
};

export const buildProtocolReport = (
  file: { readonly bytes: Buffer; readonly sha256: string },
  input: InferProtocolFieldsInput,
  limitations: readonly string[],
): Report => {
  const selected = source(file.bytes, input);
  requireMessages(selected.messages.length);
  const analysed = selected.messages.slice(0, MAX_ANALYSED);
  const inference = inferProtocol(analysed, selected.framing);
  const all = rows(analysed, inference, selected.messages);
  if (
    input.format !== undefined &&
    !all.formats.some(({ id }) => id === input.format)
  )
    throw new ProtocolSelectionError(
      `There is no format ${String(input.format)}; the capture has ${String(all.formats.length)}.`,
      "format",
    );
  const view = input.view;
  const chosen = (all[view] as readonly object[]).filter((row) => {
    if (input.format === undefined || view === "flows") return true;
    const record = row as { id?: number; format?: number };
    return (view === "formats" ? record.id : record.format) === input.format;
  });
  const query = input.query?.toLowerCase();
  const matching = chosen.filter(
    (row) =>
      query === undefined || JSON.stringify(row).toLowerCase().includes(query),
  );
  const page = matching.slice(input.offset, input.offset + input.limit);
  return {
    file: { path: input.path, sha256: file.sha256, bytes: file.bytes.length },
    source: {
      format: selected.format,
      frames: selected.frames,
      analysed: analysed.length,
    },
    framing: framingRow(selected.framing),
    inference: {
      text: inference.text,
      byte_order: inference.context.order === "le" ? "little" : "big",
    },
    summary: {
      messages: selected.messages.length,
      formats: all.formats.length,
      fields: all.fields.length,
      flows: all.flows.length,
    },
    page: {
      view,
      format: input.format ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: matching.length,
      returned: page.length,
    },
    formats: [],
    fields: [],
    messages: [],
    flows: [],
    [view]: page,
    limitations: [...limitations],
  } as Report;
};
