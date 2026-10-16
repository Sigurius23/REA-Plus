import type {
  InspectRenpyScriptInput,
  RenpyScriptReport,
} from "../domain/renpy/renpyScript.js";
import { readRenpyScript, type RenpyScript } from "./RenpyScript.js";

const MAX_KINDS = 100;
const MAX_SPEAKERS = 50;

const matches = (needle: string | undefined, ...values: (string | null)[]) =>
  needle === undefined ||
  values.some((value) => value?.toLowerCase().includes(needle) === true);

type Rows = Pick<
  RenpyScriptReport,
  "labels" | "dialogue" | "menus" | "definitions" | "translations"
>;

/** Rows of the selected view that pass the label and query filters. */
const viewRows = (
  script: RenpyScript,
  input: InspectRenpyScriptInput,
): Rows => {
  const needle = input.query?.toLowerCase();
  const inLabel = (label: string | null) =>
    input.label === undefined || label === input.label;
  const empty: Rows = {
    labels: [],
    dialogue: [],
    menus: [],
    definitions: [],
    translations: [],
  };
  switch (input.view) {
    case "labels":
      return {
        ...empty,
        labels: script.labels
          .filter((label) => matches(needle, label.name))
          .map((label) => ({
            ...label,
            jumps: [...label.jumps],
            calls: [...label.calls],
          })),
      };
    case "dialogue":
      return {
        ...empty,
        dialogue: script.dialogue.filter(
          (say) => inLabel(say.label) && matches(needle, say.what, say.who),
        ),
      };
    case "menus":
      return {
        ...empty,
        menus: script.menus
          .filter(
            (menu) =>
              inLabel(menu.label) &&
              matches(
                needle,
                menu.caption,
                ...menu.choices.map((choice) => choice.text),
              ),
          )
          .map((menu) => ({
            ...menu,
            choices: menu.choices.map((choice) => ({
              ...choice,
              jumps: [...choice.jumps],
              calls: [...choice.calls],
            })),
          })),
      };
    case "definitions":
      return {
        ...empty,
        definitions: script.definitions.filter((definition) =>
          matches(needle, definition.name, definition.value),
        ),
      };
    default:
      return {
        ...empty,
        translations: script.translations.filter((translation) =>
          matches(
            needle,
            translation.old,
            translation.new,
            translation.identifier,
          ),
        ),
      };
  }
};

const speakers = (script: RenpyScript) => {
  const lines = new Map<string | null, number>();
  for (const say of script.dialogue)
    if (say.language === null)
      lines.set(say.who, (lines.get(say.who) ?? 0) + 1);
  return [...lines]
    .map(([who, count]) => ({ who, lines: count }))
    .sort((left, right) => right.lines - left.lines)
    .slice(0, MAX_SPEAKERS);
};

/** Read one .rpyc and page the selected view. */
export const buildRenpyScriptReport = (
  bytes: Buffer,
  input: InspectRenpyScriptInput,
  identity: { readonly sha256: string },
  limitations: readonly string[],
): RenpyScriptReport => {
  const script = readRenpyScript(bytes);
  const rows = viewRows(script, input);
  const page = <T>(items: readonly T[]) =>
    items.slice(input.offset, input.offset + input.limit);
  const total =
    rows.labels.length +
    rows.dialogue.length +
    rows.menus.length +
    rows.definitions.length +
    rows.translations.length;
  const paged: Rows = {
    labels: page(rows.labels),
    dialogue: page(rows.dialogue),
    menus: page(rows.menus),
    definitions: page(rows.definitions),
    translations: page(rows.translations),
  };
  const kinds = [...script.kinds]
    .map(([kind, count]) => ({ kind, count }))
    .sort(
      (left, right) =>
        right.count - left.count || left.kind.localeCompare(right.kind),
    );
  return {
    script: {
      path: input.path,
      sha256: identity.sha256,
      bytes: bytes.length,
      format: script.container.format,
      slot: script.container.slot,
      script_version: script.scriptVersion,
      source_files: [...script.files],
      statements: kinds.reduce((sum, { count }) => sum + count, 0),
      statement_kinds: kinds.slice(0, MAX_KINDS),
    },
    summary: {
      labels: script.labels.length,
      dialogue: script.dialogue.length,
      menus: script.menus.length,
      definitions: script.definitions.length,
      translations: script.translations.length,
      languages: [
        ...new Set(
          [...script.translations, ...script.dialogue]
            .map((entry) => entry.language)
            .filter((language): language is string => language !== null),
        ),
      ].sort(),
      speakers: speakers(script),
    },
    page: {
      view: input.view,
      label: input.label ?? null,
      query: input.query ?? null,
      offset: input.offset,
      limit: input.limit,
      total,
      returned:
        paged.labels.length +
        paged.dialogue.length +
        paged.menus.length +
        paged.definitions.length +
        paged.translations.length,
    },
    ...paged,
    limitations: [...limitations],
  };
};
