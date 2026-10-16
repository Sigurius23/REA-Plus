/** Narrow accessors for untrusted RPG Maker JSON; nothing is evaluated. */

export type JsonRecord = Readonly<Record<string, unknown>>;

export const recordOf = (value: unknown): JsonRecord | null =>
  typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonRecord)
    : null;

export const arrayOf = (value: unknown): readonly unknown[] =>
  Array.isArray(value) ? value : [];

export const stringOf = (value: unknown): string | null =>
  typeof value === "string" ? value : null;

/** A non-empty string, else null. */
export const textOf = (value: unknown): string | null =>
  typeof value === "string" && value.length > 0 ? value : null;

export const intOf = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) ? value : null;

export const numberOf = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

/** A non-negative integer id, else null. */
export const idOf = (value: unknown): number | null => {
  const id = intOf(value);
  return id !== null && id >= 0 ? id : null;
};

/** RPG Maker database arrays start with null; keep the records with an id. */
export const entriesOf = (value: unknown): JsonRecord[] =>
  arrayOf(value)
    .map(recordOf)
    .filter(
      (entry): entry is JsonRecord => entry !== null && idOf(entry["id"]) !== null,
    );
