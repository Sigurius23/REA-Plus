import { entryAddress, type Radare2Inventory } from "./Radare2Inventory.js";
import {
  radare2Reply,
  radare2VariablesSchema,
  rizinVariablesSchema,
  type Radare2Function,
} from "./Radare2Values.js";

/** Signed displacement text such as `-0x50`. */
const displacement = (offset: bigint) =>
  `${offset < 0n ? "-" : "+"}0x${(offset < 0n ? -offset : offset).toString(16)}`;

/**
 * Stack and register locals from `afvj` (radare2) or `afvlj` (Rizin).
 * Register and stack arguments are parameters, so only radare2 `var`
 * entries and Rizin non-argument variables are reported.
 */
export const procedureLocals = async (
  inventory: Radare2Inventory,
  operation: string,
  fn: Radare2Function,
  signal?: AbortSignal,
) => {
  if (inventory.binding.dialect.variablesCommand === "afvlj")
    return rizinLocals(inventory, operation, fn, signal);
  const variables = radare2Reply(
    operation,
    "afvj",
    await inventory.command(`afvj @ ${entryAddress(fn)}`, signal),
    radare2VariablesSchema,
  );
  return [...variables.bp, ...variables.sp, ...variables.reg]
    .filter(({ kind }) => kind === "var")
    .map(({ name, type, ref }) =>
      typeof ref === "string"
        ? {
            description: `${type} ${name} (${ref})`,
            provenance: "radare2-afvj",
            name,
          }
        : {
            description: `${type} ${name} @ ${ref.base}${displacement(ref.offset)}`,
            provenance: "radare2-afvj",
            name,
            stack_displacement: ref.offset.toString(10),
          },
    );
};

/** Rizin stack offsets are relative to the stack pointer at function entry. */
const rizinLocals = async (
  inventory: Radare2Inventory,
  operation: string,
  fn: Radare2Function,
  signal?: AbortSignal,
) => {
  const variables = radare2Reply(
    operation,
    "afvlj",
    await inventory.command(`afvlj @ ${entryAddress(fn)}`, signal),
    rizinVariablesSchema,
  );
  return Object.values(variables)
    .flat()
    .filter(({ arg }) => !arg)
    .map(({ name, type, storage }) =>
      storage.stack === undefined
        ? {
            description: `${type} ${name} (${storage.reg ?? storage.type})`,
            provenance: "rizin-afvlj",
            name,
          }
        : {
            description: `${type} ${name} @ stack${displacement(storage.stack)}`,
            provenance: "rizin-afvlj",
            name,
            stack_displacement: storage.stack.toString(10),
          },
    );
};
