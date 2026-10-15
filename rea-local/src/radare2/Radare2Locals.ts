import { entryAddress, type Radare2Inventory } from "./Radare2Inventory.js";
import {
  radare2Reply,
  radare2VariablesSchema,
  type Radare2Function,
} from "./Radare2Values.js";

/**
 * Stack and register locals from `afvj`. Register and stack arguments are
 * parameters, so only radare2 `var` entries are reported.
 */
export const procedureLocals = async (
  inventory: Radare2Inventory,
  operation: string,
  fn: Radare2Function,
  signal?: AbortSignal,
) => {
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
            description: `${type} ${name} @ ${ref.base}${ref.offset < 0n ? "-" : "+"}0x${(ref.offset < 0n ? -ref.offset : ref.offset).toString(16)}`,
            provenance: "radare2-afvj",
            name,
            stack_displacement: ref.offset.toString(10),
          },
    );
};
