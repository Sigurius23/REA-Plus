/**
 * Members of a Unix `ar` archive, the container of static libraries on
 * Linux (`.a`) and of import and static libraries on Windows (`.lib`). GNU,
 * BSD and Microsoft long-name schemes are read; the symbol-index members
 * (`/`, `/SYM64/`, `__.SYMDEF`) are skipped. A file that is not an archive is
 * one member: a single object file.
 */
export interface ArchiveMember {
  readonly name: string;
  readonly data: Buffer;
}

const MAGIC = "!<arch>\n";
const HEADER = 60;

export const isArchive = (data: Buffer): boolean =>
  data.toString("latin1", 0, MAGIC.length) === MAGIC;

export const archiveMembers = (
  data: Buffer,
  fallbackName: string,
): ArchiveMember[] => {
  if (!isArchive(data)) return [{ name: fallbackName, data }];
  const members: ArchiveMember[] = [];
  let longNames: Buffer | undefined;
  for (let at = MAGIC.length; at + HEADER <= data.length; ) {
    const header = data.toString("latin1", at, at + HEADER);
    const size = Number.parseInt(header.slice(48, 58).trim(), 10);
    if (!Number.isSafeInteger(size) || size < 0) break;
    let start = at + HEADER;
    let length = size;
    let name = header.slice(0, 16).trimEnd();
    if (name === "//") longNames = data.subarray(start, start + size);
    else if (/^\/\d+$/u.test(name) && longNames !== undefined) {
      const offset = Number(name.slice(1));
      const end = longNames.indexOf("\n", offset);
      name = longNames
        .toString("latin1", offset, end < 0 ? longNames.length : end)
        .replace(/\/$/u, "");
    } else if (name.startsWith("#1/")) {
      // BSD: the name follows the header and counts towards the size.
      const nameLength = Number(name.slice(3));
      name = data
        .toString("latin1", start, start + nameLength)
        .replace(/\0+$/u, "");
      start += nameLength;
      length -= nameLength;
    } else name = name.replace(/\/$/u, "");
    const special =
      name === "" ||
      name === "/" ||
      name === "//" ||
      name === "/SYM64" ||
      name === "/SYM64/" ||
      name.startsWith("__.SYMDEF");
    if (!special)
      members.push({ name, data: data.subarray(start, start + length) });
    at += HEADER + size + (size % 2);
  }
  return members;
};
