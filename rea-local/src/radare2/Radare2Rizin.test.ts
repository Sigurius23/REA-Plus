import { describe, expect, it } from "vitest";

import { RIZIN_DIALECT } from "./Radare2Dialect.js";
import { Radare2Inventory } from "./Radare2Inventory.js";
import { procedureLocals } from "./Radare2Locals.js";

/** An inventory answering from recorded Rizin 0.9.1 replies. */
const inventory = (replies: Readonly<Record<string, string>>) =>
  new Radare2Inventory(
    {
      run: (command) => {
        const reply = replies[command];
        if (reply === undefined)
          throw new Error(`unrecorded command: ${command}`);
        return Promise.resolve(reply);
      },
    },
    {
      documentName: "prog",
      sourcePath: "/work/prog",
      snapshotPath: "/runtime/prog",
      dialect: RIZIN_DIALECT,
      fileDescriptor: 3,
      baseAddress: 0n,
    },
  );

describe("Rizin dialect replies", () => {
  it("orders omlj maps top-most first with inclusive ends", async () => {
    // Recorded after `om 3 0x400000 0x10 0x200` laid a map over fmap.LOAD0;
    // Rizin then served 0x400000 from file offset 0x200.
    const maps = await inventory({
      omlj: '[{"map":1,"fd":3,"delta":0,"from":4194304,"to":4195336,"perm":"r-x","name":"fmap.LOAD0"},{"map":2,"fd":4,"delta":0,"from":5242880,"to":5242944,"perm":"rw-","name":"mmap.LOAD1"},{"map":3,"fd":3,"delta":512,"from":4194304,"to":4194320,"perm":"r-x","name":""}]',
    }).maps("read_bytes");
    expect(maps).toEqual([
      { fd: 3, delta: 512n, from: 0x400000n, to: 0x40000fn, name: "" },
      { fd: 4, delta: 0n, from: 0x500000n, to: 0x50003fn, name: "mmap.LOAD1" },
      { fd: 3, delta: 0n, from: 0x400000n, to: 0x400407n, name: "fmap.LOAD0" },
    ]);
  });

  it("reports non-argument variables with entry-relative stack displacements", async () => {
    // Recorded `afvlj` for a gcc -O0 function with a stack buffer, trimmed.
    const locals = await procedureLocals(
      inventory({
        "afvlj @ 0x11a9":
          '{"stack":[{"name":"src","arg":false,"type":"const char *","storage":{"type":"stack","stack":-80}},{"name":"canary","arg":false,"type":"int64_t","storage":{"type":"stack","stack":-16}}],"reg":[{"name":"arg1","arg":true,"type":"const char *","storage":{"type":"reg","reg":"rdi"}}]}',
      }),
      "procedure_info",
      { addr: 0x11a9n, name: "sym.checksum", size: 148, nbbs: 6 },
    );
    expect(locals).toEqual([
      {
        description: "const char * src @ stack-0x50",
        provenance: "rizin-afvlj",
        name: "src",
        stack_displacement: "-80",
      },
      {
        description: "int64_t canary @ stack-0x10",
        provenance: "rizin-afvlj",
        name: "canary",
        stack_displacement: "-16",
      },
    ]);
  });

  it("reads a body's references from afij callrefs and datarefs in address order", async () => {
    // Recorded `afij` for that program's main, trimmed to the used fields.
    const references = await inventory({
      "afij @ 0x123d":
        '[{"offset":4669,"name":"main","size":106,"nbbs":4,"callrefs":[{"from":4704,"to":4240,"type":"CALL"},{"from":4714,"to":4773,"type":"CODE"},{"from":4730,"to":4521,"type":"CALL"},{"from":4758,"to":4272,"type":"CALL"}],"datarefs":[{"from":4694,"to":8196,"type":"DATA"},{"from":4743,"to":8212,"type":"DATA"}]}]',
    }).referencesFrom("procedure_callees", {
      addr: 0x123dn,
      name: "main",
      size: 106,
      nbbs: 4,
    });
    expect(
      references.map(({ at, ref, type }) => [at, ref, type] as const),
    ).toEqual([
      [0x1256n, 0x2004n, "DATA"],
      [0x1260n, 0x1090n, "CALL"],
      [0x126an, 0x12a5n, "CODE"],
      [0x127an, 0x11a9n, "CALL"],
      [0x1287n, 0x2014n, "DATA"],
      [0x1296n, 0x10b0n, "CALL"],
    ]);
  });
});
