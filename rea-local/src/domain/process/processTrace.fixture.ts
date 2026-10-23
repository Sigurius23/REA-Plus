import { EMPTY_PROCESS_CAPTURE_EXAMPLE } from "./processCaptureExample.js";
import type { ProcessTraceSpecification } from "./processTraceSpecification.js";

/** A fully journaled empty capture with checkpoints around settlement. */
export const traceCapture = {
  ...EMPTY_PROCESS_CAPTURE_EXAMPLE,
  event_journal: [
    { capture_order: 0, collection: "filesystem_checkpoints", index: 0 },
    { capture_order: 1, collection: "lifecycle", index: 0 },
    { capture_order: 2, collection: "lifecycle", index: 1 },
    { capture_order: 3, collection: "filesystem_checkpoints", index: 1 },
  ],
} as const;

/** Minimal four-event finite-traces specification over the trace capture. */
export const traceSpecification: ProcessTraceSpecification = {
  events: [
    {
      id: "before",
      source: "filesystem",
      exact: {
        name: "before",
        at_ms: 0,
        files: [],
        effects: [],
        truncated: false,
      },
      cardinality: { kind: "required" },
    },
    {
      id: "exit",
      source: "lifecycle",
      exact: { event: "exit", ...traceCapture.exit },
      cardinality: { kind: "required" },
    },
    {
      id: "settlement",
      source: "lifecycle",
      exact: { event: "settlement", ...traceCapture.settlement },
      cardinality: { kind: "required" },
    },
    {
      id: "after",
      source: "filesystem",
      exact: {
        name: "after_settlement",
        at_ms: 50,
        files: [],
        effects: [],
        truncated: false,
      },
      cardinality: { kind: "required" },
    },
  ],
  language: {
    kind: "finite_traces",
    variants: [
      {
        id: "normal",
        trace: ["before", "exit", "settlement", "after"],
      },
    ],
  },
};
