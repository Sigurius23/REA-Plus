import { z } from "zod";

import { AnalysisInputError } from "../domain/analysisErrorCore.js";

/** Shared provider search input fields. */
export const analysisSearchInput = {
  pattern: z
    .string()
    .min(1)
    .describe("The literal text or regex pattern to search for"),
  mode: z.enum(["literal", "regex"]).default("literal"),
  case_sensitive: z.boolean().default(false).describe("Whether to match case"),
  document: z.string().optional().describe("The document name"),
};

/** Filter a complete provider inventory by the shared literal/regex search input. */
export const searchAddressedItems = <
  Item extends { readonly address: string; readonly value: string },
>(
  items: readonly Item[],
  input: unknown,
): Item[] => {
  const query = z.object(analysisSearchInput).parse(input);
  let matches: (value: string) => boolean;
  if (query.mode === "regex") {
    let regex: RegExp;
    try {
      regex = new RegExp(query.pattern, query.case_sensitive ? "u" : "iu");
    } catch (cause: unknown) {
      throw new AnalysisInputError("search", { cause });
    }
    matches = (value) => regex.test(value);
  } else {
    const needle = query.case_sensitive
      ? query.pattern
      : query.pattern.toLowerCase();
    matches = (value) =>
      (query.case_sensitive ? value : value.toLowerCase()).includes(needle);
  }
  return items.filter(({ value }) => matches(value));
};
