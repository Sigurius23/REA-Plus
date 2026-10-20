import { describe, expect, it } from "vitest";

import { archiveMembers } from "./ArchiveMembers.js";

const header = (name: string, size: number) =>
  Buffer.from(
    `${name.padEnd(16)}${"0".padEnd(12)}${"0".padEnd(6)}${"0".padEnd(6)}${"644".padEnd(8)}${String(size).padEnd(10)}\`\n`,
    "latin1",
  );

describe("ar archive members", () => {
  it("reads BSD names stored after the header and skips the symbol index", () => {
    const name = "a_long_bsd_member_name.o";
    const body = Buffer.from("OBJ!");
    const archive = Buffer.concat([
      Buffer.from("!<arch>\n", "latin1"),
      header("__.SYMDEF SORTED", 4),
      Buffer.alloc(4),
      header(`#1/${String(name.length)}`, name.length + body.length),
      Buffer.from(name, "latin1"),
      body,
    ]);
    expect(
      archiveMembers(archive, "lib.a").map((member) => [
        member.name,
        member.data.toString("latin1"),
      ]),
    ).toEqual([[name, "OBJ!"]]);
  });

  it("treats any other file as one object", () => {
    const object = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
    expect(archiveMembers(object, "single.o")).toEqual([
      { name: "single.o", data: object },
    ]);
  });
});
