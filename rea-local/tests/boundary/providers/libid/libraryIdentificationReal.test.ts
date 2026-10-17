import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createLibraryIdentificationService } from "../../../../src/composition/libraryIdentification.js";
import type { LibraryIdentificationReport } from "../../../../src/domain/libid/libraryIdentification.js";
import { librarySignatures } from "../../../../src/libid/LibrarySignatures.js";
import { elfFunctionSymbols } from "../../../support/bindiff/elfSymbols.js";
import { peFunctionSymbols } from "../../../support/libid/peSymbols.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

/**
 * Real-tool lanes. REA_VERIFY_LIBID_ZLIB is a zlib source checkout; it is
 * built into a static library and linked into minigzip by
 * REA_VERIFY_LIBID_CC (ELF) and REA_VERIFY_LIBID_MINGW (PE, COFF objects),
 * once stripped for identification and once unstripped as the answer key.
 * REA_VERIFY_LIBID_LIBC is a libc.a for a fully static build.
 */
const setting = (name: string) => {
  const value = process.env[name];
  return value === undefined || value.length === 0 ? undefined : value;
};
const ZLIB = setting("REA_VERIFY_LIBID_ZLIB");
const CC = setting("REA_VERIFY_LIBID_CC");
const MINGW = setting("REA_VERIFY_LIBID_MINGW");
const LIBC = setting("REA_VERIFY_LIBID_LIBC");
const run = promisify(execFile);
const SOURCES = [
  "adler32",
  "crc32",
  "deflate",
  "infback",
  "inffast",
  "inflate",
  "inftrees",
  "trees",
  "zutil",
  "compress",
  "uncompr",
  "gzclose",
  "gzlib",
  "gzread",
  "gzwrite",
];

const service = createLibraryIdentificationService();
let root = "";
beforeAll(async () => {
  root = (await createTestWorkspace("rea-libid-real-")).root;
});
afterAll(async () => {
  await service.close();
  await removeTestWorkspace(root);
});

/** Build zlib with one toolchain into an archive, and minigzip against it. */
const build = async (
  compiler: string,
  tag: string,
  options: { readonly extra?: readonly string[]; readonly exe?: boolean } = {},
) => {
  const archiver = (await run(compiler, ["-print-prog-name=ar"])).stdout.trim();
  const objects = await Promise.all(
    SOURCES.map(async (source) => {
      const object = join(root, `${tag}-${source}.o`);
      await run(
        compiler,
        ["-O2", "-c", join(ZLIB ?? "", `${source}.c`), "-o", object],
        {
          cwd: ZLIB ?? "",
        },
      );
      return object;
    }),
  );
  const archive = join(root, `libz-${tag}.a`);
  await run(archiver, ["rcs", archive, ...objects]);
  // MinGW names its outputs .exe.
  const suffix = options.exe === true ? ".exe" : "";
  const program = join(root, `minigzip-${tag}${suffix}`);
  const stripped = join(root, `minigzip-${tag}-stripped${suffix}`);
  for (const [output, strip] of [
    [program, []],
    [stripped, ["-s"]],
  ] as const)
    await run(compiler, [
      "-O2",
      "-I",
      ZLIB ?? "",
      "-o",
      output,
      join(ZLIB ?? "", "test", "minigzip.c"),
      archive,
      ...(options.extra ?? []),
      ...strip,
    ]);
  return { archive, program, stripped };
};

/** Identify in the stripped build and score against the unstripped one's symbols. */
const score = async (
  built: { readonly program: string; readonly stripped: string },
  libraries: readonly string[],
  symbols: (path: string) => Promise<Map<string, string>>,
) => {
  const result = await service.inspect({
    path: built.stripped,
    libraries,
    view: "functions",
    limit: 1000,
  });
  if (!result.ok) throw result.error;
  const report = result.value.normalized_result as LibraryIdentificationReport;
  const truth = await symbols(built.program);
  const signed = new Set(
    (
      await Promise.all(
        libraries.map(async (path) =>
          librarySignatures(path, await readFile(path), {
            minBytes: 16,
            includeLocal: true,
          }),
        ),
      )
    ).flatMap(({ signatures }) => signatures.map(({ name }) => name)),
  );
  const wrong = report.functions
    .filter(({ status }) => status !== "ambiguous")
    .filter(({ address, names }) => !names.includes(truth.get(address) ?? ""))
    .map(
      ({ address, names }) =>
        `${address} ${names.join("|")} is ${truth.get(address) ?? "nothing"}`,
    );
  const found = new Set(
    report.functions
      .filter(({ status }) => status !== "ambiguous")
      .map(({ address }) => address),
  );
  const present = [...truth].filter(([, name]) => signed.has(name));
  const recall =
    present.filter(([address]) => found.has(address)).length / present.length;
  return { report, wrong, recall, total: report.page.total };
};

describe.skipIf(ZLIB === undefined)(
  "identify_library_functions with real toolchains",
  () => {
    it.skipIf(CC === undefined)(
      "names zlib in a stripped ELF build",
      async () => {
        const built = await build(CC ?? "", "elf");
        const result = await score(built, [built.archive], elfFunctionSymbols);
        expect(result.wrong).toEqual([]);
        expect(result.recall).toBe(1);
      },
      300_000,
    );

    it.skipIf(CC === undefined || LIBC === undefined)(
      "names zlib and glibc in a fully static ELF build",
      async () => {
        const built = await build(CC ?? "", "static", { extra: ["-static"] });
        const result = await score(
          built,
          [built.archive, LIBC ?? ""],
          elfFunctionSymbols,
        );
        expect(result.wrong).toEqual([]);
        expect(result.recall).toBeGreaterThanOrEqual(0.95);
        // The dynamically linked build holds no libc code to find.
        const dynamic = await score(
          await build(CC ?? "", "dynamic"),
          [LIBC ?? ""],
          elfFunctionSymbols,
        );
        expect(dynamic.total).toBe(0);
      },
      600_000,
    );

    it.skipIf(MINGW === undefined)(
      "names zlib in a stripped PE build from COFF objects",
      async () => {
        const built = await build(MINGW ?? "", "pe", { exe: true });
        const result = await score(built, [built.archive], peFunctionSymbols);
        expect(result.wrong).toEqual([]);
        expect(result.recall).toBe(1);
      },
      300_000,
    );
  },
);
