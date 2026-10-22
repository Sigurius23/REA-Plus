import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, onTestFinished, test } from "vitest";

import { ApktoolProvider } from "./ApktoolProvider.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { apktoolRequestSchema } from "../domain/apktool/apktoolResourceAnalysis.js";
import type { ApktoolRequest } from "../domain/apktool/apktoolResourceAnalysis.js";

/** A decode request with the schema's defaulted paging inputs applied. */
const decodeRequest = (input: {
  path: string;
  include_strings?: boolean;
  locale?: string;
  strings_offset?: number;
  strings_limit?: number;
  include_xml_resources?: boolean;
}): ApktoolRequest =>
  apktoolRequestSchema.parse({
    operation: "decode_android_resources",
    input,
  }) as ApktoolRequest;

const it = test.skipIf(process.platform === "win32");

const VERSION_BLOCK = "printf '2.7.0-stub\\n'";

const REAL_YML = [
  "!!brut.androlib.meta.MetaInfo",
  "sdkInfo:",
  "  minSdkVersion: '24'",
  "  targetSdkVersion: '34'",
  "versionInfo:",
  "  versionCode: '7'",
  "  versionName: 1.2.3",
  "",
].join("\n");

const REAL_MANIFEST = [
  '<?xml version="1.0" encoding="utf-8" standalone="no"?>',
  '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.rea.apktool.probe">',
  '    <application android:label="@string/app_name" android:debuggable="true"/>',
  "</manifest>",
  "",
].join("\n");

const REAL_STRINGS = [
  '<?xml version="1.0" encoding="utf-8"?>',
  "<resources>",
  '    <string name="api_endpoint">https://api.example.com/v1</string>',
  '    <string name="app_name">ApktoolProbe</string>',
  "</resources>",
  "",
].join("\n");

const DE_STRINGS = [
  '<?xml version="1.0" encoding="utf-8"?>',
  "<resources>",
  '    <string name="app_name">ApktoolProbe DE</string>',
  "</resources>",
  "",
].join("\n");

const writeApktoolStub = async (
  body: (root: string) => string,
): Promise<{ readonly command: string; readonly root: string }> => {
  const root = await mkdtemp(join("/tmp", "rea-apktool-stub-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const command = join(root, "apktool");
  await writeFile(command, `#!/bin/sh\n${body(root)}\n`, { mode: 0o755 });
  await chmod(command, 0o755);
  return { command, root };
};

const providerOver = (command: string): ApktoolProvider =>
  new ApktoolProvider({
    environment: { REA_APKTOOL_COMMAND: command },
  });

const evidenceResult = async (
  provider: ApktoolProvider,
  request: ApktoolRequest,
): Promise<Record<string, unknown>> => {
  const result = await provider.execute(request);
  if (!result.ok) throw new Error(result.error.message);
  return result.value.result as Record<string, unknown>;
};

const refusedBy = async (
  provider: ApktoolProvider,
  request: ApktoolRequest,
): Promise<ReturnType<typeof projectAnalysisError>> => {
  const result = await provider.execute(request);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("expected a refusal");
  return projectAnalysisError(result.error);
};

/** Stub writing a real-shaped decoded workspace into the -o directory. */
const decodeStub = (
  options: {
    readonly withStrings?: boolean;
    readonly withGerman?: boolean;
    readonly failDecode?: boolean;
  } = {},
): ((root: string) => string) => {
  const withStrings = options.withStrings ?? true;
  const withGerman = options.withGerman ?? true;
  return () => `if [ "$1" = "--version" ]; then ${VERSION_BLOCK}; exit 0; fi
if [ "$1" = "d" ]; then
  ${
    options.failDecode === true
      ? `printf 'Exception in thread "main" brut.androlib.AndrolibException: Could not decode the APK\\n' >&2; exit 1;`
      : `printf '%s\\n' '${REAL_YML.replace(/'/gu, "'\\''")}' > "$5/apktool.yml"
  printf '%s\\n' '${REAL_MANIFEST.replace(/'/gu, "'\\''")}' > "$5/AndroidManifest.xml"
  mkdir -p "$5/res/values"${withGerman ? ' "$5/res/values-de"' : ""}
  ${withStrings ? `printf '%s\\n' '${REAL_STRINGS.replace(/'/gu, "'\\''")}' > "$5/res/values/strings.xml"` : ""}
  ${withGerman ? `printf '%s\\n' '${DE_STRINGS.replace(/'/gu, "'\\''")}' > "$5/res/values-de/strings.xml"` : ""}
  printf 'I: Using Apktool on stub\\n'
  exit 0`
  }
fi
printf 'unexpected arguments: %s\\n' "$@"
exit 1`;
};

const apkFixture = async (
  root: string,
): Promise<{
  readonly path: string;
  readonly bytes: number;
  readonly sha256: string;
}> => {
  const path = join(root, "probe.apk");
  const bytes = "apk-bytes-for-apktool";
  await writeFile(path, bytes);
  return {
    path,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
};

it("inspects the apktool launcher", async () => {
  const { command } = await writeApktoolStub(
    () => `if [ "$1" = "--version" ]; then ${VERSION_BLOCK}; exit 0; fi`,
  );
  const result = await evidenceResult(providerOver(command), {
    operation: "inspect_apktool_client",
    input: {},
  });
  expect(result.client).toEqual({
    command,
    command_source: "environment",
    apktool_version: "2.7.0-stub",
  });
});

it("decodes resources with target identity, metadata, and strings", async () => {
  const { command, root } = await writeApktoolStub(decodeStub());
  const apk = await apkFixture(root);
  const result = await evidenceResult(
    providerOver(command),
    decodeRequest({ path: apk.path, include_strings: true }),
  );
  expect(result.target).toEqual({
    path: apk.path,
    bytes: apk.bytes,
    sha256: apk.sha256,
  });
  expect(result.metadata).toEqual({
    version_name: "1.2.3",
    version_code: "7",
    min_sdk_version: "24",
    target_sdk_version: "34",
    package_name: "com.rea.apktool.probe",
  });
  expect(result.manifest).toContain('package="com.rea.apktool.probe"');
  expect(result.strings).toEqual([
    { name: "api_endpoint", value: "https://api.example.com/v1" },
    { name: "app_name", value: "ApktoolProbe" },
  ]);
  expect(result.locales).toEqual(["de"]);
  expect(result.locale).toBeNull();
  expect(result.decoded_file_count).toBeGreaterThan(2);
  expect(result.coverage).toBe("complete");
});

it("projects one locale's strings on request", async () => {
  const { command, root } = await writeApktoolStub(decodeStub());
  const apk = await apkFixture(root);
  const result = await evidenceResult(
    providerOver(command),
    decodeRequest({ path: apk.path, include_strings: true, locale: "de" }),
  );
  expect(result.locale).toBe("de");
  expect(result.strings).toEqual([
    { name: "app_name", value: "ApktoolProbe DE" },
  ]);
});

it("notes a missing locale table instead of failing", async () => {
  const { command, root } = await writeApktoolStub(decodeStub());
  const apk = await apkFixture(root);
  const result = await evidenceResult(
    providerOver(command),
    decodeRequest({ path: apk.path, include_strings: true, locale: "fr" }),
  );
  expect(result.strings).toEqual([]);
});

it("notes a missing default strings table without strings", async () => {
  const { command, root } = await writeApktoolStub(
    decodeStub({ withStrings: false }),
  );
  const apk = await apkFixture(root);
  const result = await evidenceResult(
    providerOver(command),
    decodeRequest({ path: apk.path, include_strings: true }),
  );
  expect(result.strings).toEqual([]);
});

it("reports apktool's own refusal for undecodable targets", async () => {
  const { command, root } = await writeApktoolStub(
    decodeStub({ failDecode: true }),
  );
  const apk = await apkFixture(root);
  const projected = await refusedBy(
    providerOver(command),
    decodeRequest({
      path: apk.path,
      include_strings: true,
    }),
  );
  expect(projected).toMatchObject({ code: "unsupported_target" });
  expect(projected.message).toContain("Could not decode");
});

it("reports a missing launcher as a capability gap with recovery", async () => {
  const provider = new ApktoolProvider({
    environment: { REA_APKTOOL_COMMAND: "/nonexistent/apktool" },
  });
  const availability = await provider.inspectAvailability();
  expect(availability).toMatchObject({
    status: "unavailable",
    code: "executable_missing",
  });
  const projected = await refusedBy(provider, {
    operation: "inspect_apktool_client",
    input: {},
  });
  expect(projected).toMatchObject({ code: "capability_unavailable" });
  expect(projected.details).toMatchObject({
    provider_id: "apktool",
    reason: expect.stringContaining("REA_APKTOOL_COMMAND") as unknown,
  });
});

it("rejects a target that is not a readable file", async () => {
  const { command, root } = await writeApktoolStub(decodeStub());
  const projected = await refusedBy(
    providerOver(command),
    decodeRequest({
      path: join(root, "absent.apk"),
      include_strings: true,
    }),
  );
  expect(projected).toMatchObject({ code: "invalid_request" });
});

it("cancels before spawning anything", async () => {
  const { command, root } = await writeApktoolStub(
    (root) => `: > ${join(root, "spawned")}
if [ "$1" = "--version" ]; then ${VERSION_BLOCK}; exit 0; fi`,
  );
  const controller = new AbortController();
  controller.abort();
  const result = await providerOver(command).execute(
    decodeRequest({ path: "/targets/x.apk", include_strings: true }),
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error)).toMatchObject({
    code: "cancelled",
  });
  expect(
    await readFile(join(root, "spawned")).then(
      () => true,
      () => false,
    ),
  ).toBe(false);
});

it("uses an owned APK snapshot and framework cache and resolves regional locales", async () => {
  const { command, root } = await writeApktoolStub((root) =>
    decodeStub()(root).replace(
      'if [ "$1" = "d" ]; then',
      `if [ "$1" = "d" ]; then
    [ "$6" = "--frame-path" ] || exit 7
    [ -d "$7" ] || exit 8
    printf 'changed original' > "${join(root, "probe.apk")}"
    cat "$8" > "${join(root, "snapshot-bytes")}"
    mkdir -p "$5/res/values-pt-rBR"
    printf '<resources><string name="greeting">Olá</string></resources>' > "$5/res/values-pt-rBR/strings.xml"`,
    ),
  );
  const apk = await apkFixture(root);
  const result = await evidenceResult(
    providerOver(command),
    decodeRequest({ path: apk.path, include_strings: true, locale: "pt-BR" }),
  );
  expect(result.target).toMatchObject({
    sha256: apk.sha256,
    bytes: apk.bytes,
    path: apk.path,
  });
  expect(await readFile(join(root, "snapshot-bytes"), "utf8")).toBe(
    "apk-bytes-for-apktool",
  );
  expect(result.strings).toEqual([{ name: "greeting", value: "Olá" }]);
});

it("marks an oversized strings document partial without claiming it is missing", async () => {
  const { command, root } = await writeApktoolStub((root) =>
    decodeStub()(root).replace(
      "  printf 'I: Using Apktool on stub",
      '  dd if=/dev/zero of="$5/res/values/strings.xml" bs=1048576 count=9 2>/dev/null\n  printf \'I: Using Apktool on stub',
    ),
  );
  const apk = await apkFixture(root);
  const result = await providerOver(command).execute(
    decodeRequest({ path: apk.path, include_strings: true }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.result).toMatchObject({
    coverage: "partial",
    strings: [],
  });
  expect(result.value.limitations.join(" ")).toContain("exceeds");
  expect(result.value.limitations.join(" ")).not.toContain("No default");
});

it("retains failed workspace cleanup and retries it on close", async () => {
  const { command, root } = await writeApktoolStub(
    decodeStub({ failDecode: true }),
  );
  const apk = await apkFixture(root);
  let attempts = 0;
  let owned: string | undefined;
  const provider = new ApktoolProvider({
    environment: { REA_APKTOOL_COMMAND: command },
    removeWorkspace: async (path) => {
      owned = path;
      if (++attempts === 1) throw new Error("busy");
      await rm(path, { recursive: true, force: true });
    },
  });
  const result = await provider.execute(
    decodeRequest({ path: apk.path, include_strings: true }),
  );
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error.cleanup?.resources).toContain(owned);
  await provider.close();
  expect(attempts).toBe(2);
});

it("accepts a BCP47 resource qualifier through the public request schema", async () => {
  const { command, root } = await writeApktoolStub((root) =>
    decodeStub()(root).replace(
      "  printf 'I: Using Apktool on stub",
      '  mkdir -p "$5/res/values-b+zh+Hans+CN"\n  printf \'<resources><string name="greeting">你好</string></resources>\' > "$5/res/values-b+zh+Hans+CN/strings.xml"\n  printf \'I: Using Apktool on stub',
    ),
  );
  const apk = await apkFixture(root);
  const request = apktoolRequestSchema.parse({
    operation: "decode_android_resources",
    input: { path: apk.path, locale: "b+zh+Hans+CN" },
  });
  const result = await evidenceResult(providerOver(command), request);
  expect(result.strings).toEqual([{ name: "greeting", value: "你好" }]);
});

/** Base decode stub with a caller-provided additional `res` setup. */
const resStub =
  (extra: string): ((root: string) => string) =>
  () =>
    `if [ "$1" = "--version" ]; then ${VERSION_BLOCK}; exit 0; fi
if [ "$1" = "d" ]; then
  printf '%s\\n' '${REAL_YML.replace(/'/gu, "'\\''")}' > "$5/apktool.yml"
  printf '%s\\n' '${REAL_MANIFEST.replace(/'/gu, "'\\''")}' > "$5/AndroidManifest.xml"
  mkdir -p "$5/res/values"
  printf '%s\\n' '${REAL_STRINGS.replace(/'/gu, "'\\''")}' > "$5/res/values/strings.xml"
  ${extra}
  printf 'I: Using Apktool on stub\\n'
  exit 0
fi
printf 'unexpected arguments: %s\\n' "$@"
exit 1`;

const THREE_STRINGS_SETUP = `  {
    printf '<resources>\\n'
    printf '    <string name="entry_1">one</string>\\n'
    printf '    <string name="entry_2">two</string>\\n'
    printf '    <string name="entry_3">three</string>\\n'
    printf '</resources>\\n'
  } > "$5/res/values/strings.xml"`;

it("pages string entries with strings_page and partial coverage", async () => {
  const { command, root } = await writeApktoolStub(
    resStub(THREE_STRINGS_SETUP),
  );
  const apk = await apkFixture(root);
  const firstPage = await evidenceResult(
    providerOver(command),
    decodeRequest({ path: apk.path, include_strings: true, strings_limit: 2 }),
  );
  expect(firstPage.strings).toEqual([
    { name: "entry_1", value: "one" },
    { name: "entry_2", value: "two" },
  ]);
  expect(firstPage.strings_page).toEqual({
    offset: 0,
    limit: 2,
    total: 3,
    returned: 2,
  });
  expect(firstPage.coverage).toBe("partial");
  const lastPage = await evidenceResult(
    providerOver(command),
    decodeRequest({
      path: apk.path,
      include_strings: true,
      strings_offset: 2,
      strings_limit: 2,
    }),
  );
  expect(lastPage.strings).toEqual([{ name: "entry_3", value: "three" }]);
  expect(lastPage.strings_page).toEqual({
    offset: 2,
    limit: 2,
    total: 3,
    returned: 1,
  });
  // A page is partial whenever this response omits parsed entries on
  // either side of the window; only entries 2 exists here.
  expect(lastPage.coverage).toBe("partial");
});

it("projects decoded res/xml contents under the per-file budget", async () => {
  const { command, root } = await writeApktoolStub(
    resStub(
      `mkdir -p "$5/res/xml"
  printf '<?xml version="1.0" encoding="utf-8"?>\\n<network-security-config>\\n  <domain-config cleartextTrafficPermitted="false"/>\\n</network-security-config>\\n' > "$5/res/xml/network_security_config.xml"
  dd if=/dev/zero of="$5/res/xml/oversized.xml" bs=1024 count=513 2>/dev/null`,
    ),
  );
  const apk = await apkFixture(root);
  const result = await evidenceResult(
    providerOver(command),
    decodeRequest({
      path: apk.path,
      include_strings: true,
      include_xml_resources: true,
    }),
  );
  const xmlResources = result.xml_resources as
    | Array<{
        path: string;
        bytes: number;
        truncated: boolean;
        content: string | null;
      }>
    | undefined;
  expect(xmlResources?.map((resource) => resource.path)).toEqual([
    "res/xml/network_security_config.xml",
    "res/xml/oversized.xml",
  ]);
  const [networkConfig, oversized] = xmlResources ?? [];
  expect(networkConfig?.truncated).toBe(false);
  expect(networkConfig?.content).toContain("network-security-config");
  expect(oversized).toEqual({
    path: "res/xml/oversized.xml",
    bytes: 525_312,
    truncated: true,
    content: null,
  });
  expect(result.coverage).toBe("partial");
});

it("names skipped res/xml exposure instead of contents", async () => {
  const { command, root } = await writeApktoolStub(
    resStub(
      `mkdir -p "$5/res/xml"
  printf '<network-security-config/>' > "$5/res/xml/network_security_config.xml"`,
    ),
  );
  const apk = await apkFixture(root);
  const result = await providerOver(command).execute(
    decodeRequest({ path: apk.path, include_strings: true }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(
    (result.value.result as Record<string, unknown>).xml_resources,
  ).toEqual([]);
  expect(result.value.limitations.join(" ")).toContain(
    "were not projected; enable include_xml_resources",
  );
  expect(result.value.limitations.join(" ")).not.toContain(
    "network_security_config",
  );
  expect(result.value.result).toMatchObject({ coverage: "complete" });
});
