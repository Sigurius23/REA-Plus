/** Provider-neutral CPU families detected from supported executable headers. */
export const BINARY_ARCHITECTURES = [
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "mips",
  "dalvik",
] as const;
export type BinaryArchitecture = (typeof BINARY_ARCHITECTURES)[number];

/** Facts from an Android DEX header. */
export interface DexMetadata {
  /** The three-digit format version from the magic, such as `"039"`. */
  readonly version: string;
}

/** Raw ELF facts; family recognition does not establish ISA or ABI support. */
export interface MipsElfMetadata {
  readonly elfClass: 32 | 64;
  readonly byteOrder: "little" | "big";
  readonly type: number;
  readonly flags: number;
  /** Undefined until inspected; null means no ABI record was observed. */
  readonly abiFlags?: MipsAbiFlags | null;
  /** Unavailable declaration sources; missing records there remain unknown. */
  readonly limitations?: readonly string[];
}

/** Declared fields of the 24-byte MIPS ABI flags record, not inferred semantics. */
export interface MipsAbiFlags {
  readonly version: number;
  readonly isaLevel: number;
  readonly isaRevision: number;
  readonly gprSize: number;
  readonly cpr1Size: number;
  readonly cpr2Size: number;
  readonly fpAbi: number;
  readonly isaExtension: number;
  readonly ases: number;
  readonly flags1: number;
  readonly flags2: number;
}

interface BinaryTargetIdentity {
  readonly path: string;
  readonly sourcePath?: string;
  /** Info.plist of the app bundle the target was resolved from. */
  readonly bundleInfoPlist?: string;
  readonly sha256: string;
}

type NonExecutableMetadata = {
  readonly architecture?: never;
  readonly availableArchitectures?: never;
  readonly executableRole?: never;
  readonly managed?: never;
};

type ExecutableTarget = BinaryTargetIdentity & {
  readonly kind: "executable";
  readonly architecture: Exclude<BinaryArchitecture, "mips" | "dalvik">;
  readonly availableArchitectures: readonly Exclude<
    BinaryArchitecture,
    "mips" | "dalvik"
  >[];
};

/**
 * Canonical local target identity and provider-neutral file classification.
 * Each variant carries only metadata established for that exact file kind.
 */
export type BinaryTarget =
  | (BinaryTargetIdentity & {
      readonly kind: "executable";
      readonly format: "elf";
      readonly architecture: "mips";
      readonly availableArchitectures: readonly "mips"[];
      readonly mips: MipsElfMetadata;
      readonly executableRole?: never;
      readonly managed?: never;
    })
  | (BinaryTargetIdentity & {
      readonly kind: "executable";
      readonly format: "dex";
      readonly architecture: "dalvik";
      readonly availableArchitectures: readonly "dalvik"[];
      readonly dex: DexMetadata;
      /** Provenance of a DEX resolved from inside a ZIP-based container. */
      readonly containerSelection?: {
        /** Canonical container path the member was extracted from. */
        readonly path: string;
        /** SHA-256 of the whole container bytes at resolution time. */
        readonly sha256: string;
        /** Exact archive entry name of the selected member. */
        readonly member: string;
      };
      readonly executableRole?: never;
      readonly managed?: never;
    })
  | (ExecutableTarget & {
      readonly format: "mach-o" | "elf" | "dos-mz" | "dos-com";
      readonly executableRole?: never;
      readonly managed?: never;
    })
  | (ExecutableTarget & {
      readonly format: "pe";
      /** Provider-neutral PE image role observed from COFF characteristics. */
      readonly executableRole:
        | "application"
        | "shared-library"
        | "non-executable";
      /** Whether the PE declares a non-empty CLI header data-directory entry. */
      readonly managed: boolean;
    })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "database";
        readonly format: "analysis-database";
      })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "archive";
        readonly format:
          | "zip"
          | "ipa"
          | "apk"
          | "xapk"
          | "msix"
          | "appx"
          | "hap"
          | "hsp"
          | "app-pack"
          | "asar"
          | "dmg"
          | "pkg";
      })
  | (BinaryTargetIdentity &
      NonExecutableMetadata & {
        readonly kind: "artifact";
        readonly format: "plist" | "javascript" | "source-map";
      });
