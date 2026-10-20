/** r2unity releases whose CLI output this adapter admits. */
export const R2UNITY_PROVIDER_IDENTITY = {
  id: "r2unity-il2cpp-metadata",
  name: "REA+ r2unity IL2CPP metadata adapter",
  version: "r2unity@1.2",
} as const;

/** Release whose JSON and literal listings the tests were recorded from. */
export const R2UNITY_VERIFIED_VERSION = "1.2.8";

/** Admit 1.2.x from the verified patch on; output schemas reject drift. */
export const isSupportedR2UnityVersion = (version: string): boolean => {
  const match = /^1\.2\.(\d{1,4})$/u.exec(version);
  return match?.[1] !== undefined && Number(match[1]) >= 8;
};

export const R2UNITY_LIMITS = {
  /** Largest global-metadata.dat admitted. */
  metadataBytes: 512 * 1024 * 1024,
  /** Largest native IL2CPP binary admitted. */
  binaryBytes: 2 * 1024 * 1024 * 1024,
  /** Complete stdout/stderr retained per r2unity process. */
  outputBytes: 256 * 1024 * 1024,
  /** Serialized size of one returned page. */
  pageBytes: 16 * 1024 * 1024,
  /** Deadline for each r2unity process, including pointer recovery. */
  timeoutMs: 600_000,
} as const;
