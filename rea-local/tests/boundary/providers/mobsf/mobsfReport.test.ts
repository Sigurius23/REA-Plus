import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createMobsfReportService } from "../../../../src/composition/mobsf.js";
import type { MobsfReport } from "../../../../src/domain/mobsf/mobsfReport.js";
import {
  androidReport,
  APK_BYTES,
  APK_SHA256,
  iosReport,
  legacyAndroidReport,
  MOBSFSCAN_OUTPUT,
} from "../../../fixtures/mobsfFixture.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";

const service = createMobsfReportService();
let root = "";
const paths = { android: "", ios: "", legacy: "", apk: "", other: "" };

beforeAll(async () => {
  root = (await createTestWorkspace("rea-mobsf-")).root;
  paths.android = join(root, "game.apk.json");
  paths.ios = join(root, "game.ipa.json");
  paths.legacy = join(root, "old.apk.json");
  paths.apk = join(root, "game.apk");
  paths.other = join(root, "other.apk");
  await writeFile(paths.android, JSON.stringify(androidReport()));
  await writeFile(paths.ios, JSON.stringify(iosReport()));
  await writeFile(paths.legacy, JSON.stringify(legacyAndroidReport()));
  await writeFile(paths.apk, APK_BYTES);
  await writeFile(paths.other, "another build");
});
afterAll(async () => {
  await removeTestWorkspace(root);
});

const inspect = async (input: Record<string, unknown>) => {
  const result = await service.inspect(input);
  if (!result.ok) throw result.error;
  return result.value.normalized_result as MobsfReport;
};

describe("MobSF Android reports", () => {
  it("reports the app, the score and counts", async () => {
    const report = await inspect({ path: paths.android });
    expect(report.report).toMatchObject({
      mobsf_version: "v4.0.7",
      layout: "current",
      unread: [],
    });
    expect(report.app).toMatchObject({
      platform: "android",
      identifier: "com.game.spaceminer",
      version: "1.4.2",
      build: "142",
      min_sdk: "22",
      target_sdk: "34",
      main_activity: "com.unity3d.player.UnityPlayerActivity",
      sha256: APK_SHA256,
    });
    expect(report.app.certificate).toContain("CN=Space Miner Studio");
    expect(report.summary).toEqual({
      security_score: 47,
      average_cvss: null,
      findings: { high: 3, warning: 5, info: 3, secure: 1 },
      permissions: 2,
      dangerous_permissions: 1,
      components: 6,
      exported_components: 2,
      binaries: 2,
      weak_binaries: 2,
      api_categories: 1,
      endpoints: 3,
      domains: 2,
      flagged_domains: 1,
      secrets: 1,
      trackers: 1,
      total_trackers: 432,
      protections: 2,
      files: 3,
    });
  });
});

describe("MobSF Android report findings", () => {
  it("lists findings from every section with MobSF's metadata", async () => {
    const report = await inspect({ path: paths.android, limit: 1000 });
    expect(
      report.findings.map(({ section, rule, title, severity }) => [
        section,
        rule,
        title,
        severity,
      ]),
    ).toEqual([
      [
        "manifest",
        "clear_text_traffic",
        "Clear text traffic is Enabled For App",
        "high",
      ],
      [
        "manifest",
        "exported_protected_permission_not_defined",
        "Activity (com.game.spaceminer.DeepLinkActivity) is not Protected.",
        "warning",
      ],
      [
        "manifest",
        "app_is_debuggable",
        "Launch Mode of activity is not standard.",
        "info",
      ],
      [
        "network",
        null,
        "Base config is insecurely configured to permit clear text traffic to all domains",
        "high",
      ],
      ["certificate", null, "Signed Application", "info"],
      [
        "certificate",
        null,
        "Application vulnerable to Janus Vulnerability",
        "warning",
      ],
      [
        "code",
        "android_hardcoded",
        "Files may contain hardcoded sensitive information like usernames, passwords, keys etc.",
        "warning",
      ],
      [
        "code",
        "android_logging",
        "The App logs information. Sensitive information should never be logged.",
        "info",
      ],
      [
        "code",
        "android_root_detection",
        "This App may have root detection capabilities.",
        "secure",
      ],
      [
        "hardening",
        "fortify",
        "The binary does not have any fortified functions",
        "warning",
      ],
      ["hardening", "nx", "The binary does not have NX bit set", "high"],
      [
        "hardening",
        "fortify",
        "The binary does not have any fortified functions",
        "warning",
      ],
    ]);
    expect(report.findings[1]).toMatchObject({
      description:
        "[android:exported=true]\nAn Activity is found to be shared with other apps on the device.",
      components: ["Activity", "com.game.spaceminer.DeepLinkActivity"],
    });
    expect(report.findings[3]?.components).toEqual(["*"]);
    expect(report.findings[6]).toMatchObject({
      cwe: "CWE-312: Cleartext Storage of Sensitive Information",
      owasp_mobile: "M9: Reverse Engineering",
      masvs: "MSTG-STORAGE-14",
      cvss: 7.4,
      reference: "https://github.com/MobSF/owasp-mstg/",
      locations: [{ path: "com/game/net/ApiClient.java", lines: [14, 88] }],
    });
    expect(report.findings[7]).toMatchObject({
      owasp_mobile: null,
      location_count: 250,
    });
    expect(report.findings[7]?.locations).toHaveLength(200);
    expect(report.findings[8]).toMatchObject({
      severity: "secure",
      mobsf_severity: "good",
    });
    expect(report.findings[10]?.components).toEqual([
      "lib/armeabi-v7a/libgame.so",
    ]);
  });
});

describe("MobSF Android report filters", () => {
  it("filters findings and pages through every location", async () => {
    const high = await inspect({ path: paths.android, severity: "high" });
    expect(high.page).toMatchObject({ severity: "high", total: 3 });
    const code = await inspect({
      path: paths.android,
      section: "code",
      query: "LOGS",
    });
    expect(code.findings.map(({ rule }) => rule)).toEqual(["android_logging"]);
    const locations = await inspect({
      path: paths.android,
      view: "locations",
      section: "code",
      query: "android_logging",
      offset: 240,
      limit: 50,
    });
    expect(locations.page).toMatchObject({ total: 250, returned: 10 });
    expect(locations.locations.at(-1)).toEqual({
      source: "finding",
      section: "code",
      rule: "android_logging",
      path: "com/game/gen/G249.java",
      lines: [250],
    });
    const apis = await inspect({
      path: paths.android,
      view: "locations",
      section: "api",
    });
    expect(apis.locations).toEqual([
      {
        source: "api",
        section: "api",
        rule: "api_crypto",
        path: "com/game/save/SaveCrypto.java",
        lines: [4, 12],
      },
    ]);
  });
});

describe("MobSF Android report views", () => {
  it("lists permissions, components and native libraries", async () => {
    const permissions = await inspect({
      path: paths.android,
      view: "permissions",
    });
    expect(
      permissions.permissions.map(({ name, status, malware_top }) => [
        name,
        status,
        malware_top,
      ]),
    ).toEqual([
      ["android.permission.INTERNET", "normal", false],
      ["android.permission.READ_PHONE_STATE", "dangerous", true],
    ]);
    const components = await inspect({
      path: paths.android,
      view: "components",
    });
    expect(
      components.components.map(({ kind, name, main, exported }) => [
        kind,
        name,
        main,
        exported,
      ]),
    ).toEqual([
      ["activity", "com.unity3d.player.UnityPlayerActivity", true, true],
      ["activity", "com.game.spaceminer.DeepLinkActivity", false, true],
      ["activity", "com.game.spaceminer.SettingsActivity", false, false],
      [
        "service",
        "com.google.firebase.messaging.FirebaseMessagingService",
        false,
        null,
      ],
      ["receiver", "com.game.spaceminer.BootReceiver", false, null],
      ["provider", "androidx.startup.InitializationProvider", false, null],
    ]);
    expect(components.components[1]).toMatchObject({
      schemes: ["spaceminer://", "https://"],
      hosts: ["play.spaceminer.example"],
      paths: ["/invite", "/gift/"],
    });
    const binaries = await inspect({
      path: paths.android,
      view: "binaries",
      query: "il2cpp",
    });
    expect(binaries.binaries).toHaveLength(1);
    expect(binaries.binaries[0]).toMatchObject({
      name: "lib/arm64-v8a/libil2cpp.so",
      kind: "library",
      weak: 1,
    });
    expect(
      binaries.binaries[0]?.checks.map(({ check, value, severity }) => [
        check,
        value,
        severity,
      ]),
    ).toEqual([
      ["nx", true, "info"],
      ["stack_canary", true, "info"],
      ["relocation_readonly", "Full RELRO", "info"],
      ["rpath", null, "info"],
      ["fortify", false, "warning"],
    ]);
  });

  it("lists APIs, endpoints, domains, secrets, trackers, protections and files", async () => {
    const view = async (name: string) =>
      inspect({ path: paths.android, view: name });
    expect((await view("apis")).apis).toEqual([
      {
        id: "api_crypto",
        description: "Crypto",
        severity: "info",
        file_count: 1,
        files: [{ path: "com/game/save/SaveCrypto.java", lines: [4, 12] }],
      },
    ]);
    expect((await view("endpoints")).endpoints).toEqual([
      {
        kind: "url",
        value: "https://api.spaceminer.example/v2/save",
        path: "com/game/net/ApiClient.java",
        open: null,
      },
      {
        kind: "email",
        value: "support@spaceminer.example",
        path: "com/game/ui/About.java",
        open: null,
      },
      {
        kind: "firebase",
        value: "https://spaceminer-default-rtdb.firebaseio.com",
        path: null,
        open: true,
      },
    ]);
    expect((await view("domains")).domains).toEqual([
      {
        domain: "api.spaceminer.example",
        bad: false,
        ofac: false,
        ip: "192.0.2.10",
        country: "Germany",
        region: "Hessen",
        city: "Frankfurt am Main",
      },
      {
        domain: "ads.bad.example",
        bad: true,
        ofac: null,
        ip: null,
        country: null,
        region: null,
        city: null,
      },
    ]);
    expect((await view("secrets")).secrets).toEqual([
      { text: '"google_api_key" : "fixture-not-a-key"' },
    ]);
    expect((await view("trackers")).trackers).toEqual([
      {
        name: "Unity3d Ads",
        categories: ["Advertisement", "Analytics"],
        url: "https://reports.exodus-privacy.eu.org/trackers/121",
      },
    ]);
    expect((await view("protections")).protections).toEqual([
      {
        file: "classes.dex",
        category: "anti_vm",
        value: "Build.FINGERPRINT check",
      },
      { file: "classes.dex", category: "compiler", value: "r8" },
    ]);
    expect((await view("files")).files.map(({ path }) => path)).toContain(
      "lib/arm64-v8a/libil2cpp.so",
    );
  });
});

describe("MobSF reports and app files", () => {
  it("checks the report against the app file", async () => {
    const same = await inspect({
      path: paths.android,
      app_path: paths.apk,
      limit: 1,
    });
    expect(same.app_file).toEqual({
      path: paths.apk,
      sha256: APK_SHA256,
      matches_report: true,
    });
    const other = await inspect({
      path: paths.android,
      app_path: paths.other,
      limit: 1,
    });
    expect(other.app_file?.matches_report).toBe(false);
  });
});

describe("MobSF iOS reports", () => {
  it("reads iOS permissions, URL schemes, ATS, binary and Mach-O findings", async () => {
    const report = await inspect({ path: paths.ios });
    expect(report.app).toMatchObject({
      platform: "ios",
      identifier: "com.game.spaceminer",
      version: "1.4.2",
      build: "88",
      min_sdk: "13.0",
      target_sdk: "iphoneos17.0",
    });
    expect(
      report.findings.map(({ section, title, severity }) => [
        section,
        title,
        severity,
      ]),
    ).toEqual([
      [
        "network",
        "App Transport Security AllowsArbitraryLoads is allowed",
        "high",
      ],
      ["binary", "Binary makes use of insecure API(s)", "high"],
      ["macho", "The binary has Runpath Search Path (@rpath) set", "warning"],
      [
        "hardening",
        "The binary has Runpath Search Path (@rpath) set",
        "warning",
      ],
      ["files", "Plist Files", "info"],
    ]);
    expect(report.findings[1]?.description).toBe(
      "The binary may contain the following insecure API(s) _memcpy, _strlen",
    );
    expect(report.findings[4]).toMatchObject({
      mobsf_severity: "",
      locations: [{ path: "Game.app/Info.plist", lines: [] }],
    });
    const components = await inspect({ path: paths.ios, view: "components" });
    expect(components.components).toEqual([
      {
        kind: "url-scheme",
        name: "com.game.spaceminer",
        main: false,
        exported: true,
        schemes: ["spaceminer", "fb1234"],
        hosts: [],
        paths: [],
        mime_types: [],
      },
    ]);
    const binaries = await inspect({ path: paths.ios, view: "binaries" });
    expect(
      binaries.binaries.map(({ name, kind, weak }) => [name, kind, weak]),
    ).toEqual([
      ["Game", "executable", 1],
      [
        "Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework",
        "framework",
        1,
      ],
    ]);
    const permissions = await inspect({ path: paths.ios, view: "permissions" });
    expect(permissions.permissions).toEqual([
      {
        name: "NSCameraUsageDescription",
        status: "dangerous",
        info: "Access the Camera.",
        description: "Scan friend codes.",
        malware_top: null,
      },
    ]);
  });
});

describe("MobSF legacy reports", () => {
  it("reads the MobSF 3.1 layout", async () => {
    const report = await inspect({ path: paths.legacy });
    expect(report.report).toMatchObject({ layout: "legacy", unread: [] });
    expect(report.summary).toMatchObject({
      security_score: 30,
      average_cvss: 6,
    });
    expect(
      report.findings.map(
        ({ section, rule, title, severity, mobsf_severity }) => [
          section,
          rule,
          title,
          severity,
          mobsf_severity,
        ],
      ),
    ).toEqual([
      ["manifest", null, "Debug Enabled For App", "warning", "medium"],
      [
        "code",
        "android_insecure_random",
        "The App uses an insecure Random Number Generator.",
        "high",
        "high",
      ],
      [
        "files",
        null,
        "Certificate/Key files hardcoded inside the app.",
        "info",
        "",
      ],
    ]);
    expect(report.findings[0]?.description).toMatch(
      /^\[android:debuggable=true\]\nDebugging was enabled/u,
    );
    const legacyIos = join(root, "legacy-ios.json");
    await writeFile(
      legacyIos,
      JSON.stringify({
        ...iosReport(),
        version: "v3.1.6 Beta",
        appsec: undefined,
        permissions: [
          {
            name: "NSCameraUsageDescription",
            description: "Access the Camera.",
            status: "dangerous",
            reason: "Scan friend codes.",
          },
        ],
        ats_analysis: [
          {
            issue: "NSExceptionDomains",
            status: "insecure",
            description: "game.example",
          },
        ],
      }),
    );
    const ios = await inspect({ path: legacyIos, view: "permissions" });
    expect(ios.report.layout).toBe("legacy");
    expect(ios.permissions[0]).toMatchObject({
      info: "Access the Camera.",
      description: "Scan friend codes.",
    });
  });

  it("records sections in an unknown shape as unread", async () => {
    const odd = join(root, "odd.json");
    await writeFile(
      odd,
      JSON.stringify({
        ...androidReport(),
        code_analysis: "pending",
        permissions: 3,
      }),
    );
    const report = await inspect({ path: odd });
    expect(report.report.unread).toEqual(["code_analysis", "permissions"]);
    expect(report.summary.permissions).toBe(0);
  });
});

describe("MobSF report refusals", () => {
  it("refuses files that are not MobSF reports", async () => {
    const files = {
      "text.json": "not json",
      "list.json": JSON.stringify([{ category: "x" }]),
      "mobsfscan.json": JSON.stringify(MOBSFSCAN_OUTPUT),
      "other.json": JSON.stringify({ version: "1", results: [] }),
    };
    for (const [name, content] of Object.entries(files)) {
      const path = join(root, name);
      await writeFile(path, content);
      expect(await service.inspect({ path })).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisInputError",
          issues: [
            {
              path: ["path"],
              message: expect.stringContaining("Not a readable MobSF report"),
            },
          ],
        },
      });
    }
    expect(
      JSON.stringify(
        await service.inspect({ path: join(root, "mobsfscan.json") }),
      ),
    ).toContain("mobsfscan");
  });

  it("refuses relative and unreadable app files", async () => {
    expect(
      await service.inspect({ path: paths.android, app_path: "game.apk" }),
    ).toMatchObject({
      ok: false,
      error: { issues: [{ path: ["app_path"] }] },
    });
    expect(
      await service.inspect({
        path: paths.android,
        app_path: join(root, "missing.apk"),
      }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError", issues: [{ path: ["app_path"] }] },
    });
  });
});

/** A folder of MobSF reports; each is checked against the scorecard MobSF itself wrote into it. */
const REAL = process.env["REA_VERIFY_MOBSF_DIR"];
/** MobSF's scorecard keeps only these six Mach-O checks. */
const SCORECARD_MACHO = new Set([
  "nx",
  "pie",
  "stack_canary",
  "arc",
  "rpath",
  "symbol",
]);

const scorecardKey = (section: string, severity: string, title: string) =>
  section === "macho"
    ? `macho|${severity}`
    : `${section}|${severity}|${title.trim()}`;

/** What MobSF's appsec scorecard should list, per section, severity and title. */
const fromScorecard = (
  appsec: Record<string, { section: string; title: string }[]>,
) => {
  const counts = new Map<string, number>();
  for (const severity of ["high", "warning", "info", "secure"])
    for (const { section, title } of appsec[severity] ?? [])
      if (
        [
          "manifest",
          "network",
          "certificate",
          "code",
          "binary",
          "macho",
        ].includes(section)
      ) {
        const key = scorecardKey(section, severity, title);
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
  return counts;
};

/** The same projection of REA+ findings: the scorecard skips info manifest and certificate entries. */
const fromFindings = (findings: MobsfReport["findings"]) => {
  const counts = new Map<string, number>();
  for (const { section, severity, title, rule } of findings) {
    if (section === "files" || section === "hardening") continue;
    if (
      (section === "manifest" || section === "certificate") &&
      severity === "info"
    )
      continue;
    if (section === "macho" && !SCORECARD_MACHO.has(rule ?? "")) continue;
    const key = scorecardKey(section, severity, title);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
};

describe.skipIf(REAL === undefined)("real MobSF reports", () => {
  it("reads every report and agrees with MobSF's own scorecard", async () => {
    const names = (await readdir(REAL ?? ""))
      .filter((name) => name.endsWith(".json"))
      .sort();
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      const path = join(REAL ?? "", name);
      const raw = JSON.parse(await readFile(path, "utf8")) as Record<
        string,
        unknown
      >;
      const report = await inspect({ path, limit: 1000 });
      expect(report.report.unread, name).toEqual([]);
      expect(report.summary.permissions, name).toBe(
        Array.isArray(raw["permissions"])
          ? raw["permissions"].length
          : Object.keys(raw["permissions"] ?? {}).length,
      );
      expect(report.summary.domains, name).toBe(
        Object.keys(raw["domains"] ?? {}).length,
      );
      expect(report.summary.secrets, name).toBe(
        (raw["secrets"] as unknown[] | undefined)?.length ?? 0,
      );
      expect(report.summary.files, name).toBe(
        (raw["files"] as unknown[] | undefined)?.length ?? 0,
      );
      const appsec = raw["appsec"] as
        | Record<string, { section: string; title: string }[]>
        | undefined;
      if (appsec !== undefined)
        expect(Object.fromEntries(fromFindings(report.findings)), name).toEqual(
          Object.fromEntries(fromScorecard(appsec)),
        );
    }
  }, 300_000);
});
