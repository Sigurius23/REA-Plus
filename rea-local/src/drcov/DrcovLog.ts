/** A drcov log that does not follow the module or block table layout. */
export class DrcovFormatError extends Error {}

/** One module-table row; drcov 3+ logs list each mapped segment separately. */
export interface DrcovSegment {
  readonly id: number;
  /** Row of the module's first segment; equal to `id` before table version 3. */
  readonly containingId: number;
  readonly start: bigint;
  readonly end: bigint;
  readonly fileOffset: bigint | null;
  readonly preferredBase: bigint | null;
  readonly path: string;
}

export interface DrcovLog {
  readonly version: number;
  readonly flavor: string;
  readonly moduleTableVersion: number;
  readonly blockTable: "binary" | "text";
  readonly segments: readonly DrcovSegment[];
  /** Block start offsets relative to their segment's start. */
  readonly blockStarts: Uint32Array;
  readonly blockSizes: Uint16Array;
  readonly blockSegments: Uint16Array;
}

const BLOCK_TABLE = /^BB Table: (\d+) bbs$/u;
const TEXT_HEADER = "module id, start, size:";
const TEXT_ROW = /^module\[ *(\d+)\]: 0x([0-9a-f]{1,16}), *(\d+)$/iu;
const DECIMAL_COLUMNS = new Set(["id", "containing_id"]);
const KNOWN_COLUMNS = new Set([
  "id",
  "containing_id",
  "base",
  "start",
  "end",
  "entry",
  "offset",
  "preferred_base",
  "checksum",
  "timestamp",
  "path",
]);

const fail = (message: string): never => {
  throw new DrcovFormatError(message);
};

/** Header lines are UTF-8 text up to the block table header. */
const readHeaderLines = (bytes: Buffer) => {
  const marker = bytes.indexOf("\nBB Table: ");
  if (marker < 0) fail("The log has no BB Table header.");
  const tableEnd = bytes.indexOf("\n", marker + 1);
  if (tableEnd < 0) fail("The BB Table header is not terminated.");
  const lines = bytes
    .subarray(0, marker)
    .toString("utf8")
    .replace(/\r$/gmu, "")
    .split("\n");
  const table = bytes
    .subarray(marker + 1, tableEnd)
    .toString("latin1")
    .replace(/\r$/u, "");
  return { lines, table, body: bytes.subarray(tableEnd + 1) };
};

const parseNumber = (column: string, raw: string): bigint => {
  const value = raw.trim();
  if (DECIMAL_COLUMNS.has(column)) {
    if (!/^\d{1,9}$/u.test(value))
      fail(`Column ${column} is not decimal: ${value}`);
    return BigInt(value);
  }
  const digits = value.replace(/^0x/iu, "");
  if (!/^[0-9a-f]{1,16}$/iu.test(digits))
    fail(`Column ${column} is not hexadecimal: ${value}`);
  return BigInt(`0x${digits}`);
};

/** Columns before `path` are comma-separated; the path keeps any commas. */
const parseSegment = (
  line: string,
  columns: readonly string[],
  position: number,
): DrcovSegment => {
  const fields: string[] = [];
  let rest = line;
  for (let index = 0; index < columns.length - 1; index += 1) {
    const comma = rest.indexOf(",");
    if (comma < 0) fail(`Module row ${String(position)} has too few columns.`);
    fields.push(rest.slice(0, comma));
    rest = rest.slice(comma + 1);
  }
  const path = rest.replace(/^\s+/u, "");
  const value = new Map<string, bigint>();
  columns
    .slice(0, -1)
    .forEach((column, index) =>
      value.set(column, parseNumber(column, fields[index] ?? "")),
    );
  const id = Number(value.get("id"));
  const start = value.get("start") ?? value.get("base") ?? 0n;
  const end = value.get("end") ?? 0n;
  if (id !== position)
    fail(`Module row ${String(position)} has id ${String(id)}.`);
  if (end < start) fail(`Module ${String(id)} ends before it starts.`);
  return {
    id,
    containingId: Number(value.get("containing_id") ?? BigInt(id)),
    start,
    end,
    fileOffset: value.get("offset") ?? null,
    preferredBase: value.get("preferred_base") ?? null,
    path,
  };
};

/** Column names in order; the path column must come last. */
const parseColumns = (line: string | undefined): string[] => {
  const columns = /^Columns: (.*)$/u
    .exec(line ?? "")?.[1]
    ?.split(",")
    .map((column) => column.trim());
  const valid =
    columns !== undefined &&
    columns[0] === "id" &&
    columns.at(-1) === "path" &&
    columns.includes("end") &&
    (columns.includes("start") || columns.includes("base")) &&
    columns.every((column) => KNOWN_COLUMNS.has(column)) &&
    new Set(columns).size === columns.length;
  return valid
    ? columns
    : fail(`Unsupported module table columns: ${line ?? "(missing)"}`);
};

const parseTableHeader = (line: string | undefined) => {
  const table = /^Module Table: version (\d+), count (\d+)$/u.exec(line ?? "");
  if (table !== null)
    return { version: Number(table[1]), count: Number(table[2]) };
  return fail(
    /^Module Table: \d+$/u.test(line ?? "")
      ? "Module table version 1 (DynamoRIO before 6.1) is not supported."
      : "Expected a 'Module Table: version N, count M' header.",
  );
};

const parseModuleTable = (lines: readonly string[]) => {
  const [versionLine, flavorLine, tableLine, columnsLine, ...rows] = lines;
  const version = /^DRCOV VERSION: (\d+)$/u.exec(versionLine ?? "")?.[1];
  const flavor = /^DRCOV FLAVOR: (.*)$/u.exec(flavorLine ?? "")?.[1];
  if (version === undefined || flavor === undefined)
    return fail("Expected DRCOV VERSION and DRCOV FLAVOR header lines.");
  const table = parseTableHeader(tableLine);
  const columns = parseColumns(columnsLine);
  if (rows.length !== table.count)
    fail(
      `Module table declares ${String(table.count)} rows but has ${String(rows.length)}.`,
    );
  const segments = rows.map((row, index) => parseSegment(row, columns, index));
  for (const segment of segments)
    if (segments[segment.containingId]?.containingId !== segment.containingId)
      fail(`Module ${String(segment.id)} names an invalid containing module.`);
  return {
    version: Number(version),
    flavor,
    moduleTableVersion: table.version,
    segments,
  };
};

const parseBlocks = (body: Buffer, count: number, segments: number) => {
  const starts = new Uint32Array(count);
  const sizes = new Uint16Array(count);
  const owners = new Uint16Array(count);
  const check = (index: number) => {
    if ((owners[index] ?? 0) >= segments)
      fail(
        `Block ${String(index)} names module ${String(owners[index])}, outside the module table.`,
      );
  };
  if (body.length === count * 8) {
    for (let index = 0; index < count; index += 1) {
      starts[index] = body.readUInt32LE(index * 8);
      sizes[index] = body.readUInt16LE(index * 8 + 4);
      owners[index] = body.readUInt16LE(index * 8 + 6);
      check(index);
    }
    return { table: "binary" as const, starts, sizes, owners };
  }
  const lines = body.toString("latin1").replace(/\r/gu, "").split("\n");
  if (lines[0] !== TEXT_HEADER)
    fail(
      `The block table holds ${String(body.length)} bytes, not ${String(count)} 8-byte entries or a text table.`,
    );
  const rows = lines.slice(1).filter((line) => line.length > 0);
  if (rows.length !== count)
    fail(
      `The text block table has ${String(rows.length)} rows, not ${String(count)}.`,
    );
  rows.forEach((row, index) => {
    const match = TEXT_ROW.exec(row);
    if (match === null) fail(`Text block row ${String(index)} is malformed.`);
    const start = BigInt(`0x${match?.[2] ?? "0"}`);
    const size = Number(match?.[3]);
    if (start > 0xffff_ffffn || size > 0xffff)
      fail(`Text block row ${String(index)} exceeds drcov's entry widths.`);
    starts[index] = Number(start);
    sizes[index] = size;
    owners[index] = Number(match?.[1]);
    check(index);
  });
  return { table: "text" as const, starts, sizes, owners };
};

/** Parse a drcov 2 or 3 log with a version 2-5 module table. */
export const parseDrcovLog = (bytes: Buffer): DrcovLog => {
  const { lines, table, body } = readHeaderLines(bytes);
  const modules = parseModuleTable(lines);
  const count = BLOCK_TABLE.exec(table)?.[1];
  if (count === undefined) fail(`Malformed block table header: ${table}`);
  const blocks = parseBlocks(body, Number(count), modules.segments.length);
  return {
    ...modules,
    blockTable: blocks.table,
    blockStarts: blocks.starts,
    blockSizes: blocks.sizes,
    blockSegments: blocks.owners,
  };
};
