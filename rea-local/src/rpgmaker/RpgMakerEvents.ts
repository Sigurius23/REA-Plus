import type { RpgMakerProjectReport } from "../domain/rpgmaker/rpgMakerProject.js";
import {
  arrayOf,
  idOf,
  intOf,
  recordOf,
  stringOf,
  textOf,
  type JsonRecord,
} from "./RpgMakerJson.js";

type Dialogue = RpgMakerProjectReport["dialogue"][number];
type Site = RpgMakerProjectReport["switches"][number]["sites"][number];

/** Where a command list lives: a map event page, a common event or a troop page. */
export interface ListSource {
  readonly source: Site["source"];
  readonly source_id: number;
  readonly source_name: string | null;
  readonly event_id: number | null;
  readonly event_name: string | null;
  readonly page: number | null;
}

interface Command {
  readonly code: number;
  readonly parameters: readonly unknown[];
}

const commandsOf = (list: unknown): Command[] =>
  arrayOf(list).flatMap((value) => {
    const command = recordOf(value);
    const code = intOf(command?.["code"]);
    return code === null
      ? []
      : [{ code, parameters: arrayOf(command?.["parameters"]) }];
  });

/** Totals per command list, rolled up per map. */
export interface ListCounts {
  commands: number;
  messages: number;
  choices: number;
  readonly transfers: Set<number>;
  readonly commonEvents: Set<number>;
}

export const emptyCounts = (): ListCounts => ({
  commands: 0,
  messages: 0,
  choices: 0,
  transfers: new Set(),
  commonEvents: new Set(),
});

type Access = Site["access"];
export type SiteKind = "switch" | "variable";
/** A command (or page condition, command null) inside one list. */
type At = ListSource & {
  readonly index: number;
  readonly command: number | null;
};

/** Collects dialogue, flow and switch/variable sites from command lists. */
export class EventIndex {
  readonly dialogue: Dialogue[] = [];
  readonly sites = new Map<string, Site[]>();

  site(kind: SiteKind, id: number | null, access: Access, at: At): void {
    if (id === null || id <= 0) return;
    const key = `${kind}:${String(id)}`;
    const sites = this.sites.get(key) ?? [];
    sites.push({ ...at, access });
    this.sites.set(key, sites);
  }

  private range(kind: SiteKind, first: unknown, last: unknown, at: At): void {
    const start = idOf(first);
    const end = idOf(last) ?? start;
    if (start === null || end === null) return;
    for (let id = start; id <= Math.min(end, start + 5000); id += 1)
      this.site(kind, id, "write", at);
  }

  /** Text continuation lines (401, 405, 408) following a header command. */
  private static lines(
    commands: readonly Command[],
    start: number,
    code: number,
  ): { lines: string[]; next: number } {
    const lines: string[] = [];
    let next = start;
    while (commands[next]?.code === code) {
      lines.push(stringOf(commands[next]?.parameters[0]) ?? "");
      next += 1;
    }
    return { lines, next };
  }

  private text(
    commands: readonly Command[],
    index: number,
    at: ListSource,
    counts: ListCounts,
  ): number {
    const command = commands[index];
    if (command === undefined) return index + 1;
    const { parameters } = command;
    const kinds: Readonly<Record<number, readonly [Dialogue["kind"], number]>> =
      { 101: ["message", 401], 105: ["scrolling", 405], 108: ["comment", 408] };
    const [kind, continuation] = kinds[command.code] ?? ["message", 401];
    const { lines, next } = EventIndex.lines(commands, index + 1, continuation);
    const face = textOf(parameters[0]);
    if (kind === "comment") lines.unshift(stringOf(parameters[0]) ?? "");
    if (kind === "message") counts.messages += 1;
    this.dialogue.push({
      ...at,
      index,
      kind,
      speaker: kind === "message" ? textOf(parameters[4]) : null,
      face:
        kind === "message" && face !== null
          ? `${face}:${String(intOf(parameters[1]) ?? 0)}`
          : null,
      lines,
    });
    return next;
  }

  private flow(
    command: Command,
    where: ListSource & { index: number },
    counts: ListCounts,
  ): void {
    const p = command.parameters;
    const at: At = { ...where, command: command.code };
    switch (command.code) {
      case 102:
        counts.choices += 1;
        this.dialogue.push({
          ...where,
          kind: "choice",
          speaker: null,
          face: null,
          lines: arrayOf(p[0]).map((choice) => stringOf(choice) ?? ""),
        });
        return;
      case 117: {
        const id = idOf(p[0]);
        if (id !== null && id > 0) counts.commonEvents.add(id);
        return;
      }
      case 201: {
        const target = idOf(p[1]);
        if (p[0] === 0 && target !== null && target > 0)
          counts.transfers.add(target);
        if (p[0] === 1)
          for (const id of [p[1], p[2], p[3]])
            this.site("variable", idOf(id), "read", at);
        return;
      }
      default:
        this.variables(command, at);
    }
  }

  private variables(command: Command, at: At): void {
    const p = command.parameters;
    switch (command.code) {
      case 121:
        this.range("switch", p[0], p[1], at);
        return;
      case 122:
        this.range("variable", p[0], p[1], at);
        if (p[3] === 1) this.site("variable", idOf(p[4]), "read", at);
        return;
      case 111:
        if (p[0] === 0) this.site("switch", idOf(p[1]), "read", at);
        if (p[0] === 1) {
          this.site("variable", idOf(p[1]), "read", at);
          if (p[2] !== 0) this.site("variable", idOf(p[3]), "read", at);
        }
        return;
      case 103:
      case 104:
      case 285:
        this.site("variable", idOf(p[0]), "write", at);
        return;
      default:
    }
  }

  /** Walk one command list; returns its counts for the owning map. */
  walk(list: unknown, at: ListSource, counts: ListCounts): void {
    const commands = commandsOf(list);
    counts.commands += commands.filter(({ code }) => code !== 0).length;
    let index = 0;
    while (index < commands.length) {
      const command = commands[index];
      if (command === undefined) break;
      if ([101, 105, 108].includes(command.code)) {
        index = this.text(commands, index, at, counts);
        continue;
      }
      this.flow(command, { ...at, index }, counts);
      index += 1;
    }
  }

  /** Map event page conditions read switches and a variable. */
  pageConditions(conditions: unknown, at: ListSource): void {
    const c: JsonRecord = recordOf(conditions) ?? {};
    const where: At = { ...at, index: 0, command: null };
    if (c["switch1Valid"] === true || c["switchValid"] === true)
      this.site("switch", idOf(c["switch1Id"] ?? c["switchId"]), "read", where);
    if (c["switch2Valid"] === true)
      this.site("switch", idOf(c["switch2Id"]), "read", where);
    if (c["variableValid"] === true)
      this.site("variable", idOf(c["variableId"]), "read", where);
  }
}
