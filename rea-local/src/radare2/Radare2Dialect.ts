/**
 * radare2 6.x and Rizin 0.9.x (a radare2 fork) share the `-q0` pipe protocol
 * and most commands. A dialect names what differs; the `-v` banner selects
 * it, and the analysis profile commits it.
 */
export interface Radare2Dialect {
  readonly engine: "radare2" | "rizin";
  /** Accepted release line and the release the lanes verified. */
  readonly supportedRange: string;
  readonly verifiedVersion: string;
  /** Fixed process arguments before the target file name. */
  readonly processArguments: readonly string[];
  /** Prints the running engine's version inside a session. */
  readonly versionCommand: "?V" | "ver";
  /** radare2 lists IO maps top-most first with inclusive ends; Rizin's omlj lists them bottom-most first with exclusive ends. */
  readonly mapsCommand: "omj" | "omlj";
  /** radare2 groups variables by base register (afvj); Rizin by storage (afvlj). */
  readonly variablesCommand: "afvj" | "afvlj";
  /** Built-in pseudo-code; Rizin has none. */
  readonly pseudoCodeCommand: "pdc" | null;
  /** radare2's axffj lists a body's references; Rizin's afij reports them as callrefs and datarefs. */
  readonly referencesFromCommand: "axffj" | "afij";
  /** radare2's axtj names the function containing each source (fcn_addr); Rizin's does not. */
  readonly referencesNameFunctions: boolean;
}

/**
 * radare2: no user rc (-N), NUL-framed pipe replies (-q0), deterministic
 * plain-text output and a sandbox that refuses shell, network and
 * absolute-path file access from radare2 commands.
 */
export const RADARE2_DIALECT: Radare2Dialect = Object.freeze({
  engine: "radare2",
  supportedRange: ">=6.0.0 <7.0.0",
  verifiedVersion: "6.2.4",
  processArguments: Object.freeze([
    "-N",
    "-q0",
    "-e",
    "scr.color=0",
    "-e",
    "scr.utf8=false",
    "-e",
    "scr.interactive=false",
    "-e",
    "cfg.json.num=none",
    "-e",
    "cfg.sandbox.grain=all",
    "-e",
    "cfg.sandbox=true",
  ]),
  versionCommand: "?V",
  mapsCommand: "omj",
  variablesCommand: "afvj",
  pseudoCodeCommand: "pdc",
  referencesFromCommand: "axffj",
  referencesNameFunctions: true,
});

/**
 * Rizin: the same pipe and output settings. Rizin has no cfg.sandbox or
 * cfg.json.num (its `-e` silently creates unknown keys), so neither is passed.
 */
export const RIZIN_DIALECT: Radare2Dialect = Object.freeze({
  engine: "rizin",
  supportedRange: ">=0.9.0 <0.10.0",
  verifiedVersion: "0.9.1",
  processArguments: Object.freeze([
    "-N",
    "-q0",
    "-e",
    "scr.color=0",
    "-e",
    "scr.utf8=false",
    "-e",
    "scr.interactive=false",
  ]),
  versionCommand: "ver",
  mapsCommand: "omlj",
  variablesCommand: "afvlj",
  pseudoCodeCommand: null,
  referencesFromCommand: "afij",
  referencesNameFunctions: false,
});

export const radare2Dialect = (engine: Radare2Dialect["engine"]) =>
  engine === "rizin" ? RIZIN_DIALECT : RADARE2_DIALECT;
