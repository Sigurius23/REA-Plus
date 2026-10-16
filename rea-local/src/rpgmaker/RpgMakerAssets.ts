import { createHash } from "node:crypto";
import { join } from "node:path";

import type { RpgMakerProjectReport } from "../domain/rpgmaker/rpgMakerProject.js";
import {
  decryptAsset,
  decryptedName,
  hasEncryptionHeader,
  pngSize,
  recoverKeyFromPng,
  signatureOf,
} from "./RpgMakerCrypto.js";
import { relativeName, type ProjectReader } from "./RpgMakerFiles.js";

type Asset = RpgMakerProjectReport["assets"][number];

const FOLDERS = [
  ["img", "image"],
  ["audio", "audio"],
  ["movies", "video"],
] as const;
const MAX_SELECTED_ASSET_BYTES = 512 * 1024 * 1024;

export interface AssetScan {
  readonly assets: readonly Asset[];
  readonly recoveredKey: string | null;
  readonly truncated: boolean;
}

const describe = async (
  reader: ProjectReader,
  file: { path: string; bytes: number },
  kind: Asset["kind"],
  key: Buffer | null,
): Promise<{ asset: Asset; head: Buffer | null }> => {
  const path = relativeName(reader.location, file.path);
  const plain = decryptedName(path);
  const base = {
    path,
    kind,
    encrypted: plain !== null,
    decrypted_path: plain,
    bytes: file.bytes,
    sha256: null,
    image: null,
  };
  if (plain === null) {
    const head = await reader.head(file.path, 16);
    return { asset: { ...base, header: null, signature: signatureOf(head) }, head: null };
  }
  const head = await reader.head(file.path, 32);
  const valid = hasEncryptionHeader(head);
  return {
    asset: {
      ...base,
      header: valid ? "valid" : "invalid",
      signature:
        valid && key !== null
          ? signatureOf(decryptAsset(head, key))
          : "unknown",
    },
    head,
  };
};

/** List images, audio and movies, checking each encrypted file's header against the key. */
export const scanAssets = async (
  reader: ProjectReader,
  key: Buffer | null,
): Promise<AssetScan> => {
  const assets: Asset[] = [];
  let recoveredKey: string | null = null;
  let truncated = false;
  for (const [folder, kind] of FOLDERS) {
    const walked = await reader.walk(join(reader.location.base, folder));
    truncated ||= walked.truncated;
    for (const file of walked.files) {
      const { asset, head } = await describe(reader, file, kind, key);
      assets.push(asset);
      if (recoveredKey === null && head !== null && asset.decrypted_path?.toLowerCase().endsWith(".png"))
        recoveredKey = recoverKeyFromPng(head);
    }
  }
  return { assets, recoveredKey, truncated };
};

/** Fully decrypt one selected asset for its digest and image size. */
export const inspectAsset = async (
  reader: ProjectReader,
  asset: Asset,
  key: Buffer | null,
): Promise<Asset> => {
  const file = await reader.readWhole(
    join(reader.location.root, asset.path),
    MAX_SELECTED_ASSET_BYTES,
  );
  if (!asset.encrypted)
    return { ...asset, sha256: file.sha256, image: pngSize(file.bytes) };
  if (asset.header !== "valid" || key === null) return asset;
  const plain = decryptAsset(file.bytes, key);
  return {
    ...asset,
    sha256: createHash("sha256").update(plain).digest("hex"),
    image: pngSize(plain),
  };
};
