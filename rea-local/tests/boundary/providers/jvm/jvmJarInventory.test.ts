import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it } from "vitest";

import {
  renameZipMember,
  writeZipMembers,
} from "../../../fixtures/artifactEntryOrder.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { listJarClasses } from "../../../../src/jvm/JvmJarInventory.js";

/** A minimal class file carrying only the constant pool this_class needs. */
const classFile = (internalName: string): Buffer => {
  const name = Buffer.from(internalName, "utf8");
  const declaration = Buffer.alloc(10);
  declaration.writeUInt32BE(0xca_feba_be, 0);
  declaration.writeUInt16BE(0, 4);
  declaration.writeUInt16BE(52, 6);
  declaration.writeUInt16BE(3, 8);
  const constantPool = Buffer.concat([
    Buffer.from([1, name.length >> 8, name.length & 0xff]),
    name,
    Buffer.from([7, 0, 1]),
  ]);
  const trailer = Buffer.alloc(8);
  trailer.writeUInt16BE(0x00_21, 0);
  trailer.writeUInt16BE(2, 2);
  return Buffer.concat([declaration, constantPool, trailer]);
};

it("lists a classpath JAR whose shaded entries repeat names", async () => {
  const root = await createTestTempDirectory("rea-jvm-duplicate-entries-");
  const path = join(root, "shaded.jar");
  const first = classFile("com/example/A");
  await writeZipMembers(path, [
    { name: "com/example/A.class", content: first },
    { name: "com/example/B.class", content: classFile("com/example/B") },
    { name: "license1.txt", content: "license\n" },
    { name: "license2.txt", content: "license\n" },
  ]);
  let bytes: Buffer = await readFile(path);
  bytes = renameZipMember(bytes, "com/example/B.class", "com/example/A.class");
  bytes = renameZipMember(bytes, "license2.txt", "license1.txt");
  await writeFile(path, bytes);

  const inventory = await listJarClasses(path);
  try {
    expect(inventory.classes).toEqual([
      {
        name: "com.example.A",
        entry: "com/example/A.class",
        bytes: first.length,
      },
    ]);
    const observation = await inventory.read("com/example/A.class");
    expect(observation.header).toEqual({
      name: "com.example.A",
      major: 52,
      minor: 0,
    });
  } finally {
    await inventory.close();
  }
});
