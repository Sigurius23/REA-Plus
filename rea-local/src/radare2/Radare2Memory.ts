import { open } from "node:fs/promises";

import {
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import {
  invalidArgument,
  requiredAddress,
  type Radare2Inventory,
} from "./Radare2Inventory.js";
import { formatRadare2Address, type Radare2Map } from "./Radare2Values.js";

/** Largest read_bytes request; its hexadecimal reply stays within the pipe budget. */
export const RADARE2_MAX_READ_BYTES = 16 * 1024 * 1024;
const FILE_OFFSET_PROBE_BYTES = 16n;

/**
 * Read only bytes whose top-most radare2 IO map is the admitted file. radare2
 * itself returns 0xff for unmapped addresses and zero-fills uninitialized
 * segments, so neither is reported as target bytes.
 */
export const readRadare2Bytes = async (
  inventory: Radare2Inventory,
  operation: string,
  input: Readonly<Record<string, JsonValue>>,
  signal?: AbortSignal,
) => {
  const address = requiredAddress(operation, input.address);
  const length = input.length ?? 256;
  if (
    typeof length !== "number" ||
    !Number.isSafeInteger(length) ||
    length < 1 ||
    length > RADARE2_MAX_READ_BYTES
  )
    throw new AnalysisInputError(operation, undefined, [
      {
        path: ["length"],
        reason: "out_of_range",
        minimum: 1,
        maximum: RADARE2_MAX_READ_BYTES,
      },
    ]);
  const maps = await inventory.maps(operation, signal);
  const fd = inventory.binding.fileDescriptor;
  const end = address + BigInt(length);
  let cursor = address;
  while (cursor < end) {
    const map = topMap(maps, cursor);
    if (map?.fd !== fd) break;
    cursor = min(end, map.to + 1n);
  }
  const covered = cursor - address;
  const at = formatRadare2Address(address);
  return {
    result: {
      address: at,
      requested_bytes: length,
      returned_bytes: Number(covered),
      bytes_hex:
        covered === 0n
          ? ""
          : await inventory.hexBytes(operation, address, covered, signal),
      complete: covered === BigInt(length),
    },
    address: at,
  };
};

/** Map an address through its file-backed IO map and verify the bytes there. */
export const mapRadare2FileOffset = async (
  inventory: Radare2Inventory,
  operation: string,
  value: JsonValue | undefined,
  signal?: AbortSignal,
) => {
  const address = requiredAddress(operation, value);
  const at = formatRadare2Address(address);
  const { binding } = inventory;
  const map = topMap(await inventory.maps(operation, signal), address);
  if (map?.fd !== binding.fileDescriptor)
    throw invalidArgument(
      operation,
      "address",
      `${at} is not backed by bytes of the admitted file in radare2's IO maps.`,
    );
  const offset = map.delta + (address - map.from);
  if (offset > BigInt(Number.MAX_SAFE_INTEGER))
    throw new AnalysisOutputError(
      operation,
      "radare2 mapped the address beyond a representable file offset",
    );
  const probe = min(FILE_OFFSET_PROBE_BYTES, map.to - address + 1n);
  const mapped = await inventory.hexBytes(operation, address, probe, signal);
  const original = await readFileHex(
    binding.snapshotPath,
    Number(offset),
    Number(probe),
  );
  if (original !== mapped)
    throw new AnalysisProtocolError(
      `radare2 file mapping for ${at} disagrees with the admitted target bytes at offset ${offset.toString(10)}.`,
    );
  return {
    result: {
      address: at,
      file_offset: Number(offset),
      provider_file_offset: Number(offset),
      image_base_file_offset: 0,
      source_path: binding.sourcePath,
    },
    address: at,
  };
};

const min = (left: bigint, right: bigint): bigint =>
  left < right ? left : right;

/** radare2 lists maps top-most first; the first containing map serves reads. */
const topMap = (
  maps: readonly Radare2Map[],
  address: bigint,
): Radare2Map | undefined =>
  maps.find(({ from, to }) => address >= from && address <= to);

const readFileHex = async (
  path: string,
  offset: number,
  length: number,
): Promise<string> => {
  const handle = await open(path, "r");
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, offset);
    return buffer.subarray(0, bytesRead).toString("hex");
  } finally {
    await handle.close();
  }
};
