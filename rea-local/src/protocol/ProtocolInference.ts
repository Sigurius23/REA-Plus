import { clusterMessages, type MessageCluster } from "./ProtocolClusters.js";
import type { InferredField } from "./ProtocolFields.js";
import type { Framing } from "./ProtocolFraming.js";
import {
  captureContext,
  inferLayout,
  textLayout,
  type CaptureContext,
} from "./ProtocolLayout.js";
import type { Message } from "./ProtocolMessages.js";

/** Messages split into formats, each with its inferred fields. */

export interface InferredFormat {
  readonly cluster: MessageCluster;
  readonly fields: readonly InferredField[];
}

export interface Inference {
  readonly text: boolean;
  readonly context: CaptureContext;
  readonly formats: readonly InferredFormat[];
}

/**
 * Messages of text: nearly all printable, and spaced or broken into lines
 * like text. Audio or random bytes can be mostly printable too, but are
 * rarely spaces.
 */
const isText = (messages: readonly Message[]): boolean => {
  const bytes = Buffer.concat(messages.map(({ data }) => data));
  const printable = bytes.filter(
    (byte) =>
      byte === 9 || byte === 10 || byte === 13 || (byte >= 0x20 && byte < 0x7f),
  ).length;
  const spacing = bytes.filter((byte) => byte === 0x20 || byte === 10).length;
  // A binary header carrying text (a file in chunks) is still a binary protocol.
  const textStarts = messages.filter(({ data }) =>
    data.subarray(0, 4).every((byte) => byte >= 0x20 && byte < 0x7f),
  ).length;
  return (
    bytes.length > 0 &&
    printable >= bytes.length * 0.97 &&
    spacing >= bytes.length * 0.05 &&
    textStarts >= messages.length * 0.9
  );
};

export const inferProtocol = (
  messages: readonly Message[],
  framing: Framing,
): Inference => {
  const text = isText(messages);
  const context = captureContext(messages, framing);
  const exclude = new Set<number>();
  const mark = (offset: number, length: number) => {
    for (let at = offset; at < offset + length; at += 1) exclude.add(at);
  };
  if (framing.kind === "length_prefix") mark(framing.offset, framing.width);
  // Lengths and counters vary by message, not by format; they are never type keys.
  for (const field of [...context.lengths, ...context.counters])
    mark(field.offset, field.length ?? 0);
  const formats = clusterMessages(messages, exclude, text, context.order).map(
    (cluster) => {
      const members = cluster.members.map(
        (index) => messages[index] as Message,
      );
      return {
        cluster,
        fields: text
          ? textLayout(members, cluster.key)
          : inferLayout(members, context, cluster.key),
      };
    },
  );
  return { text, context, formats };
};
