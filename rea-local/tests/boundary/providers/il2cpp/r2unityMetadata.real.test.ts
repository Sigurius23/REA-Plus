import { mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect } from "vitest";

import { Il2CppMetadataService } from "../../../../src/application/il2cpp/Il2CppMetadataService.js";
import { R2UnityMetadataProvider } from "../../../../src/il2cpp/R2UnityMetadataProvider.js";
import { PrivateRuntimeRoot } from "../../../../src/process/PrivateRuntimeRoot.js";
import {
  createTestWorkspace,
  removeTestWorkspace,
} from "../../../support/workspace/workspaceFixture.js";
import {
  describeIl2CppViews,
  writeIl2CppFixtures,
  type Il2CppLaneFiles,
} from "./il2cppLane.js";

const configured = process.env.REA_VERIFY_R2UNITY_PATH;
const R2UNITY =
  configured === undefined || configured.length === 0 ? undefined : configured;

describe.skipIf(R2UNITY === undefined)(
  "real r2unity 1.2 lane (set REA_VERIFY_R2UNITY_PATH)",
  () => {
    let root = "";
    let runtimeParent = "";
    let files: Il2CppLaneFiles;
    let service: Il2CppMetadataService;
    beforeAll(async () => {
      root = (await createTestWorkspace("rea-r2unity-real-")).root;
      runtimeParent = join(root, "runtime");
      await mkdir(runtimeParent);
      files = await writeIl2CppFixtures(root);
      service = new Il2CppMetadataService(
        new R2UnityMetadataProvider(
          { ...process.env, REA_R2UNITY_PATH: R2UNITY },
          undefined,
          () => PrivateRuntimeRoot.create({ parent: runtimeParent }),
        ),
      );
    });
    afterAll(async () => {
      await service.close();
      await expect(readdir(runtimeParent)).resolves.toEqual([]);
      await removeTestWorkspace(root);
    });

    describeIl2CppViews(() => ({ service, files }));
  },
);
