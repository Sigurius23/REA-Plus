import { execFile } from "node:child_process";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { promisify } from "node:util";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createGodotFileService } from "../../../../src/composition/godot.js";
import type { GodotFileReport } from "../../../../src/domain/godot/godotFile.js";
import { readGodotPack } from "../../../../src/gamearchives/GodotPck.js";
import { scriptSource } from "../../../../src/godot/GdscriptSource.js";
import {
  readCompiledScript,
  type CompiledScript,
} from "../../../../src/godot/GdscriptTokens.js";
import {
  decompressGodot,
  decryptGodot,
  passwordKey,
} from "../../../../src/godot/GodotContainers.js";
import { readGodotResource } from "../../../../src/godot/GodotResource.js";
import { readScene } from "../../../../src/godot/GodotScene.js";
import { variantStream } from "../../../../src/godot/MarshalledVariant.js";
import {
  lexGdscript,
  type LexedToken,
} from "../../../support/godot/gdscriptLexer.js";
import { GODOT3_GENERATOR } from "../../../support/godot/godot3Generator.js";
import {
  entryProblems,
  type ReferenceEntry,
} from "../../../support/godot/godot3Reference.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

/**
 * Real-tool lanes. REA_VERIFY_GODOT3_BIN is a Godot 3 editor binary (it needs
 * a display; run the tests under xvfb-run on a headless machine), and
 * REA_VERIFY_GODOT3_SCRIPTS a folder of .gd files it compiles.
 * REA_VERIFY_GODOT_PCK_DIR holds released games' .pck files.
 * REA_VERIFY_GODOT4_PCK and REA_VERIFY_GODOT4_SOURCES are a Godot 4 game's
 * pack and the source tree it was exported from.
 */
const GODOT3 = process.env["REA_VERIFY_GODOT3_BIN"];
const GODOT3_SCRIPTS = process.env["REA_VERIFY_GODOT3_SCRIPTS"];
const PCK_DIR = process.env["REA_VERIFY_GODOT_PCK_DIR"];
const GODOT4_PCK = process.env["REA_VERIFY_GODOT4_PCK"];
const GODOT4_SOURCES = process.env["REA_VERIFY_GODOT4_SOURCES"];

const MAX = 1 << 30;
let root = "";
beforeAll(async () => {
  root = (await createTestWorkspace("rea-godot-real-")).root;
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const PROJECT = 'config_version=4\n\n[application]\nconfig/name="REA+"\n';
const presets = (mode: number, key: string) =>
  `[preset.0]\n\nname="Linux"\nplatform="Linux/X11"\nrunnable=true\ncustom_features=""\nexport_filter="all_resources"\ninclude_filter=""\nexclude_filter=""\nexport_path=""\nscript_export_mode=${String(mode)}\nscript_encryption_key="${key}"\n\n[preset.0.options]\n`;

const godot3 = (args: string[], timeout = 600_000) =>
  promisify(execFile)(GODOT3 ?? "", ["--no-window", ...args], {
    cwd: root,
    timeout,
    maxBuffer: 64 * 1024 * 1024,
  });

const codeTokens = (script: CompiledScript): LexedToken[] =>
  script.tokens
    .filter(
      ({ role }) => !["newline", "indent", "dedent", "eof"].includes(role),
    )
    .map(({ text, line }) => ({ text, line: line ?? 0 }));

/** Index of the first token that differs in text or line, or -1. */
const firstDifference = (
  left: readonly LexedToken[],
  right: readonly LexedToken[],
): number => {
  const index = left.findIndex(
    (token, at) =>
      token.text !== right[at]?.text || token.line !== right[at]?.line,
  );
  return index === -1 && left.length !== right.length
    ? Math.min(left.length, right.length)
    : index;
};

/** The rebuilt source, padded so every row keeps its line number. */
const rebuilt = (script: CompiledScript): string => {
  const lines: string[] = [];
  for (const row of scriptSource(script.tokens)) {
    while (lines.length < row.line - 1) lines.push("");
    lines.push(row.text);
  }
  return lines.join("\n");
};

const packEntries = (bytes: Buffer) =>
  readGodotPack(bytes).entries.flatMap((entry) => {
    const part = entry.parts[0];
    return part?.kind === "file" && !entry.encrypted
      ? [
          {
            path: entry.path,
            data: bytes.subarray(part.offset, part.offset + part.length),
          },
        ]
      : [];
  });

const filesUnder = async (folder: string, pattern: RegExp): Promise<string[]> =>
  (await readdir(folder, { recursive: true, withFileTypes: true }))
    .filter((entry) => entry.isFile() && pattern.test(entry.name))
    .map((entry) => join(entry.parentPath, entry.name));

describe.skipIf(GODOT3 === undefined)("files Godot 3 writes", () => {
  it("reads resources, scenes and saves as Godot reads them back", async () => {
    const project = join(root, "generated");
    await mkdir(project, { recursive: true });
    await writeFile(join(project, "project.godot"), PROJECT);
    await writeFile(join(project, "gen.gd"), GODOT3_GENERATOR);
    await godot3(["--path", project, "-s", "res://gen.gd"]);
    const out = join(project, "out");
    const reference = JSON.parse(
      await readFile(join(out, "reference.json"), "utf8"),
    ) as Record<string, ReferenceEntry>;
    const password =
      Object.values(reference).find((entry) => entry.password !== undefined)
        ?.password ?? "";
    const key =
      Object.values(reference).find((entry) => entry.key !== undefined)?.key ??
      "";
    const service = createGodotFileService({
      GODOT3_PASSWORD: password,
      GODOT3_KEY: key,
    });
    const inspect = async (input: Record<string, unknown>) => {
      const result = await service.inspect(input);
      if (!result.ok) throw result.error;
      return result.value.normalized_result as GodotFileReport;
    };
    let checked = 0;
    const problems: string[] = [];
    for (const [name, entry] of Object.entries(reference)) {
      const result = await entryProblems(inspect, join(out, name), name, entry);
      checked += result.checked;
      problems.push(...result.problems);
    }
    expect(problems).toEqual([]);
    expect(Object.keys(reference).length).toBeGreaterThan(30);
    expect(checked).toBeGreaterThan(150);
    // Every compressed and encrypted save holds exactly the plain save's bytes.
    const plain = await readFile(join(out, "save_plain.dat"));
    for (const mode of ["fastlz", "deflate", "zstd", "gzip"])
      expect(
        decompressGodot(
          await readFile(join(out, `save_${mode}.dat`)),
          MAX,
        ).data.equals(plain),
        mode,
      ).toBe(true);
    expect(
      decryptGodot(
        await readFile(join(out, "save_password.dat")),
        passwordKey(password),
      )?.data.equals(plain),
    ).toBe(true);
    expect(
      decryptGodot(
        await readFile(join(out, "save_key.dat")),
        Buffer.from(key, "hex"),
      )?.data.equals(plain),
    ).toBe(true);
  }, 900_000);

  it.skipIf(GODOT3_SCRIPTS === undefined)(
    "compiles scripts whose tokens are their source's, plain and encrypted",
    async () => {
      const project = join(root, "scripts");
      const sources = await filesUnder(GODOT3_SCRIPTS ?? "", /\.gd$/u);
      for (const source of sources) {
        const target = join(project, relative(GODOT3_SCRIPTS ?? "", source));
        await mkdir(dirname(target), { recursive: true });
        await writeFile(target, await readFile(source));
      }
      await writeFile(join(project, "project.godot"), PROJECT);
      const key =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
      await writeFile(join(project, "export_presets.cfg"), presets(1, ""));
      await godot3([
        "--path",
        project,
        "--export-pack",
        "Linux",
        join(root, "compiled.pck"),
      ]);
      await writeFile(join(project, "export_presets.cfg"), presets(2, key));
      await godot3([
        "--path",
        project,
        "--export-pack",
        "Linux",
        join(root, "encrypted.pck"),
      ]);
      const compiled = packEntries(
        await readFile(join(root, "compiled.pck")),
      ).filter(({ path }) => path.endsWith(".gdc"));
      const encrypted = new Map(
        packEntries(await readFile(join(root, "encrypted.pck"))).map(
          ({ path, data }) => [path, data],
        ),
      );
      const differences: string[] = [];
      for (const { path, data } of compiled) {
        const script = readCompiledScript(data, MAX);
        const source = await readFile(
          join(project, path.replace(/\.gdc$/u, ".gd")),
          "utf8",
        );
        const at = firstDifference(codeTokens(script), lexGdscript(source, 3));
        if (at !== -1) differences.push(`${path} at token ${String(at)}`);
        const decrypted = decryptGodot(
          encrypted.get(path.replace(/\.gdc$/u, ".gde")) ?? Buffer.alloc(0),
          Buffer.from(key, "hex"),
        );
        // Godot 3 orders constants by hash, so the two exports can differ in bytes but not in tokens.
        if (
          decrypted === null ||
          firstDifference(
            codeTokens(readCompiledScript(decrypted.data, MAX)),
            codeTokens(script),
          ) !== -1
        )
          differences.push(
            `${path}: the .gde does not decrypt to the .gdc's tokens`,
          );
      }
      expect(differences).toEqual([]);
      expect(compiled.length).toBeGreaterThan(sources.length * 0.9);
    },
    900_000,
  );
});

/** Problems reading one pack entry, or null when the entry is not a kind this lane reads. */
const packEntryProblems = (
  where: string,
  path: string,
  data: Buffer,
  major: 3 | 4,
): string[] | null => {
  const magic = data.subarray(0, 4).toString("latin1");
  if (path.endsWith(".gdc")) {
    const script = readCompiledScript(data, MAX);
    const lexed = lexGdscript(rebuilt(script), script.version >= 100 ? 4 : 3);
    return firstDifference(codeTokens(script), lexed) === -1
      ? []
      : [`${where}: the rebuilt source does not lex back to its tokens`];
  }
  if (magic === "RSRC" || magic === "RSCC") {
    const resource = readGodotResource(data, MAX);
    const ordered = [...resource.resources].sort((a, b) => a.offset - b.offset);
    const problems = ordered.flatMap((entry, index) => {
      const next = ordered[index + 1]?.offset;
      return entry.error !== null || (next !== undefined && entry.end !== next)
        ? [
            `${where} ${entry.id}: ${entry.error ?? "ends before the next resource"}`,
          ]
        : [];
    });
    if (!resource.trailer) problems.push(`${where}: no RSRC trailer`);
    const bundled = resource.resources
      .at(-1)
      ?.properties.find(({ name }) => name === "_bundled");
    if (bundled !== undefined && !readScene(bundled.value).exact)
      problems.push(`${where}: scene arrays not used exactly`);
    return problems;
  }
  if (path !== "project.binary") return null;
  variantStream(data, major);
  return [];
};

describe.skipIf(PCK_DIR === undefined)("packs of released Godot games", () => {
  it("reads every compiled script, binary resource, scene and project.binary", async () => {
    const problems: string[] = [];
    let read = 0;
    for (const pack of await filesUnder(PCK_DIR ?? "", /\.pck$/u)) {
      const bytes = await readFile(pack);
      const major =
        readGodotPack(bytes).engineVersion?.startsWith("3") === true ? 3 : 4;
      for (const { path, data } of packEntries(bytes)) {
        const where = `${relative(PCK_DIR ?? "", pack)}:${path}`;
        try {
          const found = packEntryProblems(where, path, data, major);
          if (found === null) continue;
          problems.push(...found);
          read += 1;
        } catch (cause) {
          problems.push(
            `${where}: ${cause instanceof Error ? cause.message : String(cause)}`,
          );
        }
      }
    }
    expect(problems).toEqual([]);
    expect(read).toBeGreaterThan(0);
  }, 900_000);
});

describe.skipIf(GODOT4_PCK === undefined || GODOT4_SOURCES === undefined)(
  "a Godot 4 game and its sources",
  () => {
    it("compiled the tokens its source holds", async () => {
      const scripts = packEntries(await readFile(GODOT4_PCK ?? "")).filter(
        ({ path }) => path.endsWith(".gdc"),
      );
      let exact = 0;
      const shapes: string[] = [];
      for (const { path, data } of scripts) {
        const decoded = codeTokens(readCompiledScript(data, MAX));
        const lexed = lexGdscript(
          await readFile(
            join(GODOT4_SOURCES ?? "", path.replace(/\.gdc$/u, ".gd")),
            "utf8",
          ),
          4,
        );
        if (firstDifference(decoded, lexed) === -1) exact += 1;
        // A build step may rewrite a literal (a version string); nothing else may differ.
        else if (
          decoded.length !== lexed.length ||
          decoded.some(
            (token, at) =>
              token.line !== lexed[at]?.line ||
              (!token.text.startsWith('"') && token.text !== lexed[at]?.text),
          )
        )
          shapes.push(path);
      }
      expect(shapes).toEqual([]);
      expect(exact).toBeGreaterThanOrEqual(Math.ceil(scripts.length * 0.99));
    }, 600_000);
  },
);
