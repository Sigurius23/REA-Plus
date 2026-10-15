/** Exact CFR release whose output this adapter admits. */
export const CFR_PROVIDER_IDENTITY = {
  id: "cfr-jvm-decompiler",
  name: "REA+ CFR JVM decompiler adapter",
  version: "cfr@0.152",
} as const;

export const CFR_RELEASE = "0.152";

export const CFR_LIMITS = {
  /** Largest selected .class or JAR read into the private snapshot. */
  inputBytes: 512 * 1024 * 1024,
  /** Combined size of decompiled sources returned inline. */
  outputBytes: 32 * 1024 * 1024,
  /** Retained Java stdout/stderr diagnostics per process. */
  diagnosticBytes: 4 * 1024 * 1024,
  /** Deadline for each Java process, including decompilation. */
  timeoutMs: 300_000,
} as const;
