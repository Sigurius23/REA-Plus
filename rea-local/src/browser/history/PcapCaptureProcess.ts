import { readFile, writeFile } from "node:fs/promises";
import { z } from "zod";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import { WEB_NETWORK_CAPTURE_LIMITS } from "../../domain/webNetworkCapture.js";
import { CaptureFormatError } from "./CaptureFormatError.js";
import { decodePcapCapture } from "./PcapCapture.js";

const requestSchema = z.strictObject({
  snapshot_path: z.string(),
  reply_path: z.string(),
  sensitive_values: z.array(z.string().min(1)),
  record_ordinals: z.array(z.number().int().nonnegative()).optional(),
});
const formatSchema = z.enum(["pcap", "pcapng"]);

/** Decode untrusted packet captures in an owned, bounded process without network access. */
const main = async (): Promise<void> => {
  const request = requestSchema.parse(
    JSON.parse(await readFile(process.argv[2] ?? "", "utf8")),
  );
  const format = formatSchema.parse(process.argv[3]);
  let reply: unknown;
  try {
    const snapshot = await readStableArtifact(
      request.snapshot_path,
      WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
    );
    reply = {
      ok: true,
      value: decodePcapCapture(
        snapshot.bytes,
        format,
        request.sensitive_values,
        request.record_ordinals,
      ),
    };
  } catch (cause: unknown) {
    reply =
      cause instanceof CaptureFormatError
        ? {
            ok: false,
            reason: cause.reason,
            message: cause.message,
            pointer: cause.pointer,
            limit: cause.limit,
          }
        : {
            ok: false,
            reason: "decoder",
            message: `Packet-capture decoder failed unexpectedly (${cause instanceof Error ? cause.name : "unknown exception"}).`,
            pointer: "",
          };
  }
  let text = JSON.stringify(reply);
  if (Buffer.byteLength(text) > WEB_NETWORK_CAPTURE_LIMITS.outputBytes)
    text = JSON.stringify({
      ok: false,
      reason: "limit",
      message:
        "Packet-capture reply exceeds the complete-evidence output budget.",
      pointer: "",
    });
  await writeFile(request.reply_path, text, { flag: "wx", mode: 0o600 });
};
await main();
