import type { DexMetadata } from "../domain/binaryTargetTypes.js";

/** Ghidra's DEX loader class, forced instead of auto-detection. */
export const GHIDRA_DEX_LOADER = "DexLoader";

/** Compiler spec every Dalvik language ships with. */
export const DALVIK_COMPILER_SPEC_ID = "default";

/**
 * Ghidra's Dalvik language variants carry Android-era instruction sets,
 * not one-per-DEX-diff entries; a newer revision's bytes decode under the
 * closest older variant with later opcodes marked as errors.
 */
const DALVIK_BY_DEX_VERSION: Readonly<Record<string, string>> = {
  "035": "Dalvik:LE:32:DEX_KitKat",
  "037": "Dalvik:LE:32:DEX_Lollipop",
  "038": "Dalvik:LE:32:DEX_Nougat",
  "039": "Dalvik:LE:32:DEX_Pie",
  "040": "Dalvik:LE:32:DEX_Android10",
  "041": "Dalvik:LE:32:DEX_Android11",
  "042": "Dalvik:LE:32:DEX_Android12",
};

/** Newest language shipped when a future DEX revision appears. */
const DALVIK_NEWEST = "Dalvik:LE:32:DEX_Android13";

/** Pre-035 revisions use the base variant. */
const DALVIK_BASE = "Dalvik:LE:32:DEX_Base";

/**
 * The Dalvik language matching one DEX header version, in the smallest
 * variant covering it. Versions after the newest table entry use the
 * newest language; unknowns fall back to the base variant.
 */
export const dalvikLanguageForDex = (dex: DexMetadata): string => {
  const fromTable = DALVIK_BY_DEX_VERSION[dex.version];
  if (fromTable !== undefined) return fromTable;
  const revision = Number.parseInt(dex.version, 10);
  if (Number.isNaN(revision)) return DALVIK_BASE;
  return revision > 42 ? DALVIK_NEWEST : DALVIK_BASE;
};
