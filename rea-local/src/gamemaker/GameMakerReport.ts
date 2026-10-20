import {
  GAMEMAKER_RESOURCE_KINDS,
  type GameMakerDataReport,
  type InspectGameMakerDataInput,
} from "../domain/gamemaker/gameMakerData.js";
import { Form, locateForm } from "./GameMakerForm.js";
import { readGeneral } from "./GameMakerGeneral.js";
import {
  lookupOf,
  readAudio,
  readCode,
  readResources,
  readStrings,
  readSymbols,
  readTextures,
} from "./GameMakerResources.js";

type Report = GameMakerDataReport;
type View = InspectGameMakerDataInput["view"];
type Rows = Pick<Report, View>;

const LIST_CHUNKS = new Set([
  "EXTN",
  "SOND",
  "AGRP",
  "SPRT",
  "BGND",
  "PATH",
  "SCPT",
  "SHDR",
  "FONT",
  "TMLN",
  "OBJT",
  "ROOM",
  "TPAG",
  "CODE",
  "STRG",
  "TXTR",
  "AUDO",
  "UILR",
]);
const VERSIONED_LIST_CHUNKS = new Set([
  "TGIN",
  "ACRV",
  "SEQN",
  "PSYS",
  "PSEM",
  "FEDS",
]);

const matches = (
  query: string | undefined,
  ...values: (string | null)[]
): boolean =>
  query === undefined ||
  values.some(
    (value) => value?.toLowerCase().includes(query.toLowerCase()) === true,
  );

const chunkRows = (form: Form): Report["chunks"] =>
  form.chunks.map((chunk) => {
    const listed =
      LIST_CHUNKS.has(chunk.name) || VERSIONED_LIST_CHUNKS.has(chunk.name);
    const skip = VERSIONED_LIST_CHUNKS.has(chunk.name) ? 4 : 0;
    return {
      name: chunk.name,
      offset: chunk.offset,
      size: chunk.size,
      entries:
        listed && chunk.size >= skip + 4 ? form.u32(chunk.data + skip) : null,
    };
  });

/** Parse a data file into the summary and one paged view. */
export const buildGameMakerReport = (
  bytes: Buffer,
  input: InspectGameMakerDataInput,
  file: { readonly sha256: string },
  limitations: readonly string[],
): Report => {
  const form = new Form(bytes, locateForm(bytes));
  const code = form.chunk("CODE");
  const bytecode = form.hasGeneral
    ? form.u8((form.chunk("GEN8")?.data ?? 0) + 1)
    : 17;
  const general = form.hasGeneral
    ? readGeneral(form, code === undefined || code.size === 0 ? "yyc" : "vm")
    : null;
  const lookup = lookupOf(form, bytecode);
  const resources = readResources(form, lookup);
  const all: Rows = {
    chunks: chunkRows(form),
    resources,
    code: readCode(form, bytecode),
    strings: readStrings(form),
    symbols: readSymbols(form, bytecode),
    textures: readTextures(form),
    audio: readAudio(form, resources),
  };
  const { view, query, kind } = input;
  const filtered: readonly unknown[] = {
    chunks: () => all.chunks.filter((row) => matches(query, row.name)),
    resources: () =>
      all.resources.filter(
        (row) =>
          (kind === undefined || row.kind === kind) && matches(query, row.name),
      ),
    code: () => all.code.filter((row) => matches(query, row.name)),
    strings: () => all.strings.filter((row) => matches(query, row.text)),
    symbols: () => all.symbols.filter((row) => matches(query, row.name)),
    textures: () => all.textures,
    audio: () => all.audio.filter((row) => matches(query, ...row.sounds)),
  }[view]();
  const page = filtered.slice(input.offset, input.offset + input.limit);
  const rows: Rows = {
    chunks: [],
    resources: [],
    code: [],
    strings: [],
    symbols: [],
    textures: [],
    audio: [],
    [view]: page,
  };
  return {
    file: {
      path: input.path,
      sha256: file.sha256,
      bytes: bytes.length,
      form_offset: form.start,
      form_size: form.size,
    },
    general,
    summary: {
      chunks: form.chunks.length,
      resources: GAMEMAKER_RESOURCE_KINDS.map((resource) => ({
        kind: resource,
        count: resources.filter((row) => row.kind === resource).length,
      })).filter(({ count }) => count > 0),
      code: all.code.length,
      strings: all.strings.length,
      functions: all.symbols.filter((row) => row.kind === "function").length,
      variables: all.symbols.filter((row) => row.kind === "variable").length,
      textures: all.textures.length,
      audio: all.audio.length,
    },
    page: {
      view,
      kind: kind ?? null,
      query: query ?? null,
      offset: input.offset,
      limit: input.limit,
      total: filtered.length,
      returned: page.length,
    },
    ...rows,
    limitations: [
      ...limitations,
      ...(general?.compiled === "yyc"
        ? [
            "Compiled with YYC: game logic is native code in the executable, not bytecode in this file.",
          ]
        : []),
      ...(bytecode < 13 || bytecode > 17
        ? [
            `Bytecode version ${String(bytecode)} is outside 13-17; resource fields may be misread.`,
          ]
        : []),
    ],
  };
};
