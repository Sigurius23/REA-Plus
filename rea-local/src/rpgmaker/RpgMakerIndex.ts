import type { RpgMakerProjectReport } from "../domain/rpgmaker/rpgMakerProject.js";
import {
  emptyCounts,
  EventIndex,
  type ListCounts,
  type ListSource,
  type SiteKind,
} from "./RpgMakerEvents.js";
import {
  arrayOf,
  entriesOf,
  idOf,
  intOf,
  recordOf,
  stringOf,
  textOf,
} from "./RpgMakerJson.js";
import type { LoadedProject, MapEntry } from "./RpgMakerProject.js";

type MapRow = RpgMakerProjectReport["maps"][number];
type SwitchRow = RpgMakerProjectReport["switches"][number];

const MAX_SITES = 20;

export interface ProjectIndex {
  readonly events: EventIndex;
  readonly maps: readonly MapRow[];
  readonly eventCount: number;
}

const mapRow = (
  map: MapEntry,
  index: EventIndex,
): { row: MapRow; events: number } => {
  const counts: ListCounts = emptyCounts();
  const data = map.data;
  const events = entriesOf(data?.["events"]);
  let pages = 0;
  for (const event of events) {
    arrayOf(event["pages"]).forEach((value, page) => {
      const record = recordOf(value);
      pages += 1;
      const at: ListSource = {
        source: "map",
        source_id: map.id,
        source_name: stringOf(map.info["name"]),
        event_id: idOf(event["id"]),
        event_name: stringOf(event["name"]),
        page: page + 1,
      };
      index.walk(record?.["list"], at, counts);
      index.pageConditions(record?.["conditions"], at);
    });
  }
  const parent = idOf(map.info["parentId"]);
  return {
    events: events.length,
    row: {
      id: map.id,
      name: stringOf(map.info["name"]),
      display_name: textOf(data?.["displayName"]),
      parent_id: parent === null || parent === 0 ? null : parent,
      order: intOf(map.info["order"]),
      present: data !== null,
      width: idOf(data?.["width"]),
      height: idOf(data?.["height"]),
      tileset_id: idOf(data?.["tilesetId"]),
      bgm: textOf(recordOf(data?.["bgm"])?.["name"]),
      events: events.length,
      pages,
      commands: counts.commands,
      messages: counts.messages,
      choices: counts.choices,
      transfers: [...counts.transfers].sort((a, b) => a - b),
      common_events: [...counts.commonEvents].sort((a, b) => a - b),
    },
  };
};

/** Walk every map event page, common event and troop page once. */
export const indexProject = (project: LoadedProject): ProjectIndex => {
  const events = new EventIndex();
  let eventCount = 0;
  const maps = project.maps.map((map) => {
    const { row, events: count } = mapRow(map, events);
    eventCount += count;
    return row;
  });
  for (const common of project.tables.common_events) {
    const at: ListSource = {
      source: "common_event",
      source_id: idOf(common["id"]) ?? 0,
      source_name: stringOf(common["name"]),
      event_id: null,
      event_name: null,
      page: null,
    };
    events.walk(common["list"], at, emptyCounts());
    if (common["trigger"] === 1 || common["trigger"] === 2)
      events.site("switch", idOf(common["switchId"]), "read", {
        ...at,
        index: 0,
        command: null,
      });
  }
  for (const troop of project.tables.troops)
    arrayOf(troop["pages"]).forEach((value, page) => {
      const record = recordOf(value);
      const at: ListSource = {
        source: "troop",
        source_id: idOf(troop["id"]) ?? 0,
        source_name: stringOf(troop["name"]),
        event_id: null,
        event_name: null,
        page: page + 1,
      };
      events.walk(record?.["list"], at, emptyCounts());
      events.pageConditions(record?.["conditions"], at);
    });
  return { events, maps, eventCount };
};

const namesOf = (value: unknown): string[] =>
  arrayOf(value).map((name) => stringOf(name) ?? "");

/** Named or referenced switches and variables, with read and write sites. */
export const switchRows = (
  project: LoadedProject,
  index: EventIndex,
  map: number | undefined,
): SwitchRow[] => {
  const rows: SwitchRow[] = [];
  for (const kind of [
    "switch",
    "variable",
  ] as const satisfies readonly SiteKind[]) {
    const names = namesOf(
      project.system[kind === "switch" ? "switches" : "variables"],
    );
    const ids = new Set<number>();
    names.forEach((name, id) => {
      if (id > 0 && name.length > 0) ids.add(id);
    });
    for (const key of index.sites.keys())
      if (key.startsWith(`${kind}:`))
        ids.add(Number(key.slice(kind.length + 1)));
    for (const id of [...ids].sort((a, b) => a - b)) {
      const sites = (index.sites.get(`${kind}:${String(id)}`) ?? []).filter(
        (site) =>
          map === undefined ||
          (site.source === "map" && site.source_id === map),
      );
      if (map !== undefined && sites.length === 0) continue;
      rows.push({
        kind,
        id,
        name: names[id] ?? "",
        reads: sites.filter(({ access }) => access === "read").length,
        writes: sites.filter(({ access }) => access === "write").length,
        sites: sites.slice(0, MAX_SITES),
      });
    }
  }
  return rows;
};
