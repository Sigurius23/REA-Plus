import { execFile } from "node:child_process";
import { promisify } from "node:util";

/**
 * Where tshark's dissectors put field boundaries in each UDP payload: the
 * start of every field Wireshark decodes, relative to the payload, per
 * packet in capture order (packets with an empty payload are skipped).
 */
export const tsharkFieldStarts = async (
  tshark: string,
  capture: string,
  filter: string,
): Promise<ReadonlySet<number>[]> => {
  const { stdout } = await promisify(execFile)(
    tshark,
    ["-r", capture, "-Y", filter, "-T", "pdml"],
    { maxBuffer: 512 * 1024 * 1024 },
  );
  return stdout
    .split("<packet>")
    .slice(1)
    .flatMap((packet) => {
      const udp =
        /<proto name="udp"[^>]*?(?:size="(\d+)"[^>]*?pos="(\d+)"|pos="(\d+)"[^>]*?size="(\d+)")/u.exec(
          packet,
        );
      if (udp === null) return [];
      const size = Number(udp[1] ?? udp[4]);
      const start = Number(udp[2] ?? udp[3]) + size;
      const length =
        Number(
          /<field name="udp\.length"[^>]*show="(\d+)"/u.exec(packet)?.[1] ?? 8,
        ) - 8;
      if (length <= 0) return [];
      const starts = new Set<number>();
      for (const field of packet.matchAll(/<field [^>]*?pos="(\d+)"/gu)) {
        const at = Number(field[1]) - start;
        if (at >= 0 && at < length) starts.add(at);
      }
      return [starts];
    });
};
