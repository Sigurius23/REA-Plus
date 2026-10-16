import type { Il2CppClass } from "../domain/il2cpp/il2cppMetadata.js";

/** One page of matching entries and the number of matches overall. */
export interface Il2CppPage<T> {
  readonly total: number;
  readonly entries: readonly T[];
}

const contains = (query: string) => {
  const needle = query.toLowerCase();
  return (value: string | null | undefined): boolean =>
    value !== null &&
    value !== undefined &&
    value.toLowerCase().includes(needle);
};

/** Page entries in r2unity order; `fields` select the searchable text. */
export const pageEntries = <T>(
  items: readonly T[],
  {
    query,
    fields,
    offset,
    limit,
  }: {
    readonly query: string | undefined;
    readonly fields: (item: T) => readonly (string | null)[];
    readonly offset: number;
    readonly limit: number;
  },
): Il2CppPage<T> => {
  if (query === undefined)
    return {
      total: items.length,
      entries: items.slice(offset, offset + limit),
    };
  const has = contains(query);
  const matches = items.filter((item) => fields(item).some(has));
  return {
    total: matches.length,
    entries: matches.slice(offset, offset + limit),
  };
};

/**
 * A class matches by its qualified name, keeping every member, or through
 * member names, keeping only the matching fields and methods.
 */
export const pageClasses = (
  classes: readonly Il2CppClass[],
  query: string | undefined,
  offset: number,
  limit: number,
): Il2CppPage<Il2CppClass> => {
  if (query === undefined)
    return pageEntries(classes, {
      query: undefined,
      fields: () => [],
      offset,
      limit,
    });
  const has = contains(query);
  const matches: Il2CppClass[] = [];
  for (const type of classes) {
    if (has(type.name)) {
      matches.push(type);
      continue;
    }
    const fields = type.fields.filter(({ name }) => has(name));
    const methods = type.methods.filter(({ name }) => has(name));
    if (fields.length > 0 || methods.length > 0)
      matches.push({ ...type, member_scope: "matching", fields, methods });
  }
  return {
    total: matches.length,
    entries: matches.slice(offset, offset + limit),
  };
};
