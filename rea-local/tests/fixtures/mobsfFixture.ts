/**
 * MobSF static-analysis reports in the layouts MobSF writes: the 4.x Android
 * and iOS layouts (also used by 3.6 and 3.7) and the 3.1 Android layout.
 * Field names, nesting and value formats follow reports written by MobSF
 * 3.1.6, 3.1.9, 3.6.7, 3.7.9 and 4.0.7 and MobSF's own report builders.
 */

import { createHash } from "node:crypto";

export const APK_BYTES = Buffer.from("PK\u0003\u0004 fixture apk");
export const APK_SHA256 = createHash("sha256").update(APK_BYTES).digest("hex");

const code = (
  id: string,
  metadata: Readonly<Record<string, unknown>> & {
    readonly severity: string;
    readonly description: string;
  },
  files: Readonly<Record<string, string>>,
) => ({
  [id]: {
    files,
    metadata: {
      id,
      type: "Regex",
      cvss: 7.4,
      cwe: "CWE-312: Cleartext Storage of Sensitive Information",
      "owasp-mobile": "M9: Reverse Engineering",
      masvs: "MSTG-STORAGE-14",
      ref: "https://github.com/MobSF/owasp-mstg/",
      ...metadata,
    },
  },
});

const hardening = (name: string, nx: boolean) => ({
  name,
  nx: {
    is_nx: nx,
    severity: nx ? "info" : "high",
    description: nx
      ? "The binary has NX bit set. This marks a memory page non-executable."
      : "The binary does not have NX bit set. NX bit offer protection against exploitation.",
  },
  stack_canary: {
    has_canary: true,
    severity: "info",
    description: "This binary has a stack canary value added to the stack.",
  },
  relocation_readonly: {
    relro: "Full RELRO",
    severity: "info",
    description: "This shared object has full RELRO enabled.",
  },
  rpath: {
    rpath: null,
    severity: "info",
    description: "The binary does not have run-time search path or RPATH set.",
  },
  fortify: {
    is_fortified: false,
    severity: "warning",
    description:
      "The binary does not have any fortified functions. Fortified functions provides buffer overflow checks.",
  },
});

/** Many files under one rule exercise the per-row location cap. */
const manyFiles = Object.fromEntries(
  Array.from({ length: 250 }, (_, index) => [
    `com/game/gen/G${String(index)}.java`,
    String(index + 1),
  ]),
);

const androidManifest = () => ({
  manifest_findings: [
    {
      rule: "clear_text_traffic",
      title:
        "Clear text traffic is Enabled For App<br>[android:usesCleartextTraffic=true]",
      severity: "high",
      description: "The app intends to use cleartext network traffic.",
      name: "Clear text traffic is Enabled For App [android:usesCleartextTraffic=true]",
      component: [],
    },
    {
      rule: "exported_protected_permission_not_defined",
      title:
        "<strong>Activity</strong> (com.game.spaceminer.DeepLinkActivity) is not Protected.<br>[android:exported=true]",
      severity: "warning",
      description:
        "An Activity is found to be shared with other apps on the device.",
      name: "Activity (com.game.spaceminer.DeepLinkActivity) is not Protected. [android:exported=true]",
      component: ["Activity", "com.game.spaceminer.DeepLinkActivity"],
    },
    {
      rule: "app_is_debuggable",
      title: "Launch Mode of activity is not standard.",
      severity: "info",
      description:
        "An Activity should not be having the launch mode attribute set.",
      name: "Launch Mode of activity is not standard.",
      component: [],
    },
  ],
  manifest_summary: { high: 1, warning: 1, info: 1, suppressed: 0 },
});

const androidCertificate = () => ({
  certificate_info:
    "Binary is signed\nv1 signature: False\nv2 signature: True\nX.509 Subject: CN=Space Miner Studio",
  certificate_findings: [
    [
      "info",
      "Application is signed with a code signing certificate",
      "Signed Application",
    ],
    [
      "warning",
      "Application is signed with v1 signature scheme, making it vulnerable to Janus vulnerability on Android 5.0-8.0.",
      "Application vulnerable to Janus Vulnerability",
    ],
  ],
  certificate_summary: { high: 0, warning: 1, info: 1 },
});

const androidCode = () => ({
  findings: {
    ...code(
      "android_hardcoded",
      {
        severity: "warning",
        description:
          "Files may contain hardcoded sensitive information like usernames, passwords, keys etc.",
      },
      {
        "com/game/net/ApiClient.java": "88,14,14",
      },
    ),
    ...code(
      "android_logging",
      {
        severity: "info",
        description:
          "The App logs information. Sensitive information should never be logged.",
        cwe: "CWE-532: Insertion of Sensitive Information into Log File",
        "owasp-mobile": "",
      },
      manyFiles,
    ),
    ...code(
      "android_root_detection",
      {
        severity: "good",
        description: "This App may have root detection capabilities.",
      },
      {
        "com/game/guard/Root.java": "40",
      },
    ),
  },
  summary: { high: 0, warning: 1, info: 1, secure: 1, suppressed: 0 },
});

const androidDomains = () => ({
  "api.spaceminer.example": {
    bad: "no",
    geolocation: {
      ip: "192.0.2.10",
      country_short: "DE",
      country_long: "Germany",
      region: "Hessen",
      city: "Frankfurt am Main",
      latitude: "50.11",
      longitude: "8.68",
    },
    ofac: false,
  },
  "ads.bad.example": { bad: "yes", geolocation: null },
});

const androidDeepLinks = () => ({
  "com.game.spaceminer.DeepLinkActivity": {
    schemes: ["spaceminer://", "https://"],
    mime_types: [],
    hosts: ["play.spaceminer.example"],
    ports: [],
    paths: ["/invite"],
    path_prefixs: ["/gift/"],
    path_patterns: [],
    browsable: true,
    well_known: {},
  },
});

/** A MobSF 4.x report of an Android game. */
export const androidReport = (sha256 = APK_SHA256) => ({
  version: "v4.0.7",
  title: "Static Analysis",
  file_name: "game.apk",
  app_name: "Space Miner",
  app_type: "apk",
  size: "48.2MB",
  md5: "0123456789abcdef0123456789abcdef",
  sha1: "0123456789abcdef0123456789abcdef01234567",
  sha256,
  package_name: "com.game.spaceminer",
  main_activity: "com.unity3d.player.UnityPlayerActivity",
  exported_activities:
    "['com.unity3d.player.UnityPlayerActivity', 'com.game.spaceminer.DeepLinkActivity']",
  browsable_activities: androidDeepLinks(),
  activities: [
    "com.unity3d.player.UnityPlayerActivity",
    "com.game.spaceminer.DeepLinkActivity",
    "com.game.spaceminer.SettingsActivity",
  ],
  receivers: ["com.game.spaceminer.BootReceiver"],
  providers: ["androidx.startup.InitializationProvider"],
  services: ["com.google.firebase.messaging.FirebaseMessagingService"],
  libraries: [],
  target_sdk: "34",
  max_sdk: "",
  min_sdk: "22",
  version_name: "1.4.2",
  version_code: "142",
  permissions: {
    "android.permission.INTERNET": {
      status: "normal",
      info: "full Internet access",
      description: "Allows an application to create network sockets.",
    },
    "android.permission.READ_PHONE_STATE": {
      status: "dangerous",
      info: "read phone state and identity",
      description:
        "Allows the application to access the phone features of the device.",
    },
  },
  malware_permissions: {
    top_malware_permissions: ["android.permission.READ_PHONE_STATE"],
    other_abused_permissions: [],
    total_malware_permissions: 25,
    total_other_permissions: 44,
  },
  certificate_analysis: androidCertificate(),
  manifest_analysis: androidManifest(),
  network_security: {
    network_findings: [
      {
        scope: ["*"],
        description:
          "Base config is insecurely configured to permit clear text traffic to all domains.",
        severity: "high",
      },
    ],
    network_summary: { high: 1, warning: 0, info: 0, secure: 0 },
  },
  binary_analysis: [
    hardening("lib/arm64-v8a/libil2cpp.so", true),
    hardening("lib/armeabi-v7a/libgame.so", false),
  ],
  file_analysis: [],
  android_api: {
    api_crypto: {
      files: { "com/game/save/SaveCrypto.java": "12,4" },
      metadata: { description: "Crypto", severity: "info" },
    },
  },
  code_analysis: androidCode(),
  niap_analysis: {},
  urls: [
    {
      urls: ["https://api.spaceminer.example/v2/save"],
      path: "com/game/net/ApiClient.java",
    },
  ],
  domains: androidDomains(),
  emails: [
    { emails: ["support@spaceminer.example"], path: "com/game/ui/About.java" },
  ],
  strings: { strings_apk_res: [], strings_so: [], strings_code: [] },
  firebase_urls: [
    { url: "https://spaceminer-default-rtdb.firebaseio.com", open: true },
  ],
  files: ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libil2cpp.so"],
  exported_count: {
    exported_activities: 2,
    exported_services: 0,
    exported_receivers: 0,
    exported_providers: 0,
  },
  apkid: {
    "classes.dex": {
      anti_vm: ["Build.FINGERPRINT check"],
      compiler: ["r8"],
    },
  },
  trackers: {
    detected_trackers: 1,
    total_trackers: 432,
    trackers: [
      {
        name: "Unity3d Ads",
        categories: "Advertisement, Analytics",
        url: "https://reports.exodus-privacy.eu.org/trackers/121",
      },
    ],
  },
  secrets: ['"google_api_key" : "fixture-not-a-key"'],
  average_cvss: null,
  appsec: { security_score: 47 },
  timestamp: "2026-10-01T12:00:00.000Z",
});

const machoCheck = (
  key: string,
  value: boolean,
  severity: string,
  description: string,
) => ({
  [key]: { [`has_${key}`]: value, severity, description },
});

/** A MobSF 4.x report of an iOS game. */
export const iosReport = () => ({
  version: "v4.0.7",
  title: "Static Analysis",
  file_name: "Game.ipa",
  app_name: "Space Miner",
  app_type: "Swift",
  size: "61.0MB",
  md5: "fedcba9876543210fedcba9876543210",
  sha1: "fedcba9876543210fedcba9876543210fedcba98",
  sha256: "a".repeat(64),
  build: "88",
  app_version: "1.4.2",
  sdk_name: "iphoneos17.0",
  platform: "17.0",
  min_os_version: "13.0",
  bundle_id: "com.game.spaceminer",
  bundle_url_types: [
    {
      CFBundleURLName: "com.game.spaceminer",
      CFBundleURLSchemes: ["spaceminer", "fb1234"],
    },
  ],
  permissions: {
    NSCameraUsageDescription: {
      info: "Access the Camera.",
      status: "dangerous",
      description: "Scan friend codes.",
    },
  },
  ats_analysis: {
    ats_findings: [
      {
        issue: "App Transport Security AllowsArbitraryLoads is allowed",
        severity: "high",
        description:
          "App Transport Security restrictions are disabled for all network connections.",
      },
    ],
    ats_summary: { high: 1, warning: 0, info: 0, secure: 0 },
  },
  binary_analysis: {
    findings: {
      "Binary makes use of insecure API(s)": {
        detailed_desc:
          "The binary may contain the following insecure API(s) _memcpy\n, _strlen\n",
        severity: "high",
        cvss: 6,
        cwe: "CWE-676: Use of Potentially Dangerous Function",
        "owasp-mobile": "M7: Client Code Quality",
        masvs: "MSTG-CODE-8",
      },
    },
    summary: { high: 1, warning: 0, info: 0, secure: 0 },
  },
  macho_analysis: {
    name: "Game",
    ...machoCheck("nx", true, "info", "The binary has NX bit set."),
    ...machoCheck("pie", true, "info", "The binary is build with -fPIC flag."),
    ...machoCheck(
      "rpath",
      true,
      "warning",
      "The binary has Runpath Search Path (@rpath) set. In certain cases an attacker can abuse this feature.",
    ),
  },
  dylib_analysis: [],
  framework_analysis: [
    {
      name: "Payload/Game.app/Frameworks/UnityFramework.framework/UnityFramework",
      ...machoCheck(
        "rpath",
        true,
        "warning",
        "The binary has Runpath Search Path (@rpath) set. In certain cases an attacker can abuse this feature.",
      ),
    },
  ],
  ios_api: {},
  code_analysis: { findings: {}, summary: {} },
  file_analysis: [
    {
      issue: "Plist Files",
      files: [
        {
          file_path: "Game.app/Info.plist",
          type: "ipa",
          hash: "fedcba9876543210fedcba9876543210",
        },
      ],
    },
  ],
  libraries: ["/usr/lib/libc++.1.dylib (compatibility version 1.0.0)"],
  files: ["Game.app/Info.plist", "Game.app/Data/data.unity3d"],
  urls: [],
  domains: {},
  emails: [],
  strings: [],
  firebase_urls: [],
  secrets: [],
  trackers: { detected_trackers: 0, total_trackers: 432, trackers: [] },
  appsec: { security_score: 52 },
  average_cvss: null,
});

/** A MobSF 3.1 report: bare manifest list with stat/desc, flat code rules, security_score. */
export const legacyAndroidReport = () => ({
  version: "v3.1.6 Beta",
  title: "Static Analysis",
  file_name: "old.apk",
  app_name: "Old Game",
  app_type: "apk",
  size: "12.0MB",
  md5: "00112233445566778899aabbccddeeff",
  sha1: "00112233445566778899aabbccddeeff00112233",
  sha256: "b".repeat(64),
  package_name: "com.old.game",
  main_activity: "com.old.game.Main",
  exported_activities: "[]",
  browsable_activities: {},
  activities: ["com.old.game.Main"],
  receivers: [],
  providers: [],
  services: [],
  target_sdk: "28",
  min_sdk: "16",
  version_name: "0.9",
  version_code: "9",
  permissions: {
    "android.permission.INTERNET": {
      status: "normal",
      info: "full Internet access",
      description: "Allows network sockets.",
    },
  },
  certificate_analysis: {
    certificate_info: "APK is signed\nv1 signature: True",
  },
  manifest_analysis: [
    {
      title:
        "<strong>Debug Enabled For App</strong><br>[android:debuggable=true]",
      stat: "medium",
      desc: "Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it.",
      name: "Debug Enabled For App [android:debuggable=true]",
      component: [],
    },
  ],
  network_security: [],
  binary_analysis: [],
  file_analysis: [
    {
      finding: "Certificate/Key files hardcoded inside the app.",
      files: ["assets/server.crt"],
    },
  ],
  android_api: {},
  code_analysis: {
    ...code(
      "android_insecure_random",
      {
        severity: "high",
        description: "The App uses an insecure Random Number Generator.",
      },
      {
        "com/old/game/Dice.java": "7",
      },
    ),
  },
  urls: [],
  domains: {},
  emails: [],
  firebase_urls: [],
  files: ["AndroidManifest.xml"],
  apkid: {},
  trackers: { detected_trackers: 0, total_trackers: 323, trackers: [] },
  secrets: [],
  average_cvss: 6,
  security_score: 30,
});

/** What mobsfscan (MobSF's source-code scanner) writes; not a MobSF report. */
export const MOBSFSCAN_OUTPUT = {
  errors: [],
  mobsfscan_version: "0.3.0",
  results: {},
};
