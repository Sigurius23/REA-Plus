import type {
  UnityContainerEntry,
  UnityObject,
  UnityScript,
} from "../domain/unity/unityAssets.js";
import {
  classNameOf,
  listValue,
  pointerValue,
  recordValue,
  textField,
  type LoadedFile,
  type ObjectRecord,
  type Pointer,
} from "./UnityObjects.js";

export const basename = (path: string): string =>
  path.slice(Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\")) + 1);

/** Objects across the loaded files, addressable by file and path ID. */
export class ObjectIndex {
  private readonly byFile = new Map<string, Map<bigint, ObjectRecord>>();

  constructor(private readonly files: readonly LoadedFile[]) {
    for (const file of files)
      this.byFile.set(
        file.name,
        new Map(file.records.map((record) => [record.object.pathId, record])),
      );
  }

  /** The loaded file an external path names, matched on its last segment. */
  private external(
    file: LoadedFile,
    fileId: number,
  ): {
    readonly path: string;
    readonly loaded: string | null;
  } | null {
    const external = file.file?.externals[fileId - 1];
    if (external === undefined) return null;
    const name = basename(external.path).toLowerCase();
    const loaded = this.files.find(
      (candidate) => basename(candidate.name).toLowerCase() === name,
    );
    return { path: external.path, loaded: loaded?.name ?? null };
  }

  resolve(
    file: LoadedFile,
    pointer: Pointer,
  ): {
    readonly record: ObjectRecord | null;
    readonly targetFile: string | null;
  } {
    if (pointer.fileId === 0)
      return {
        record: this.byFile.get(file.name)?.get(pointer.pathId) ?? null,
        targetFile: null,
      };
    const external = this.external(file, pointer.fileId);
    if (external === null) return { record: null, targetFile: null };
    return {
      record:
        external.loaded === null
          ? null
          : (this.byFile.get(external.loaded)?.get(pointer.pathId) ?? null),
      targetFile: external.path,
    };
  }
}

const scriptOf = (
  index: ObjectIndex,
  file: LoadedFile,
  record: ObjectRecord,
): UnityObject["script"] => {
  const pointer = pointerValue(record.fields.get("m_Script"));
  if (pointer === null) return null;
  const { record: target, targetFile } = index.resolve(file, pointer);
  const fields = target?.object.classId === 115 ? target.fields : new Map();
  return {
    file_id: pointer.fileId,
    path_id: pointer.pathId.toString(),
    file: targetFile,
    class_name: textField(fields, "m_ClassName"),
    namespace: textField(fields, "m_Namespace"),
    assembly: textField(fields, "m_AssemblyName"),
  };
};

export const objectsOf = (
  index: ObjectIndex,
  files: readonly LoadedFile[],
): UnityObject[] =>
  files.flatMap((file) =>
    file.records.map((record) => {
      const owner = pointerValue(record.fields.get("m_GameObject"));
      const ownerRecord =
        owner === null || owner.fileId !== 0
          ? null
          : index.resolve(file, owner).record;
      return {
        file: file.name,
        path_id: record.object.pathId.toString(),
        class_id: record.object.classId,
        class_name: record.className,
        byte_start: record.object.byteStart,
        byte_size: record.object.byteSize,
        name: textField(record.fields, "m_Name"),
        game_object:
          owner === null || ownerRecord?.object.classId !== 1
            ? null
            : {
                path_id: owner.pathId.toString(),
                name: textField(ownerRecord.fields, "m_Name"),
              },
        script: scriptOf(index, file, record),
      };
    }),
  );

export const containerOf = (
  index: ObjectIndex,
  files: readonly LoadedFile[],
): UnityContainerEntry[] =>
  files.flatMap((file) =>
    file.records.flatMap((record) => {
      const source =
        record.object.classId === 142
          ? ("asset_bundle" as const)
          : record.object.classId === 147
            ? ("resource_manager" as const)
            : null;
      if (source === null) return [];
      return listValue(record.fields.get("m_Container")).flatMap((entry) => {
        const pair = recordValue(entry);
        const assetPath = pair?.["first"];
        const second = recordValue(pair?.["second"]);
        const info = source === "asset_bundle" ? second : null;
        const pointer = pointerValue(
          source === "asset_bundle" ? info?.["asset"] : pair?.["second"],
        );
        if (typeof assetPath !== "string" || pointer === null) return [];
        const { record: target, targetFile } = index.resolve(file, pointer);
        const preloadIndex = info?.["preloadIndex"];
        const preloadSize = info?.["preloadSize"];
        return [
          {
            source,
            file: file.name,
            asset_path: assetPath,
            file_id: pointer.fileId,
            path_id: pointer.pathId.toString(),
            target_file: targetFile,
            class_name: target === null ? null : classNameOf(target.object),
            name: target === null ? null : textField(target.fields, "m_Name"),
            preload_index:
              typeof preloadIndex === "number" ? preloadIndex : null,
            preload_size: typeof preloadSize === "number" ? preloadSize : null,
          },
        ];
      });
    }),
  );

/** Local MonoScripts plus external scripts MonoBehaviours point at. */
export const scriptsOf = (
  objects: readonly UnityObject[],
  files: readonly LoadedFile[],
): UnityScript[] => {
  const scripts = new Map<string, UnityScript & { behaviours: number }>();
  const localKey = (file: string, pathId: string) =>
    `local\0${file}\0${pathId}`;
  for (const file of files)
    for (const record of file.records)
      if (record.object.classId === 115) {
        const pathId = record.object.pathId.toString();
        scripts.set(localKey(file.name, pathId), {
          file: file.name,
          path_id: pathId,
          local: true,
          class_name: textField(record.fields, "m_ClassName"),
          namespace: textField(record.fields, "m_Namespace"),
          assembly: textField(record.fields, "m_AssemblyName"),
          behaviours: 0,
        });
      }
  for (const object of objects) {
    const script = object.script;
    if (script === null) continue;
    const key =
      script.file === null
        ? localKey(object.file, script.path_id)
        : `external\0${script.file}\0${script.path_id}`;
    const resolved =
      scripts.get(key) ??
      [...scripts.values()].find(
        (candidate) =>
          candidate.local &&
          script.file !== null &&
          candidate.path_id === script.path_id &&
          basename(candidate.file).toLowerCase() ===
            basename(script.file).toLowerCase(),
      );
    if (resolved !== undefined) {
      resolved.behaviours += 1;
      continue;
    }
    scripts.set(key, {
      file: script.file ?? object.file,
      path_id: script.path_id,
      local: false,
      class_name: null,
      namespace: null,
      assembly: null,
      behaviours: 1,
    });
  }
  return [...scripts.values()];
};
