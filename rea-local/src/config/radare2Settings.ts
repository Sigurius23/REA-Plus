import { z } from "zod";

/** radare2 analysis commands a caller may select; deeper levels take longer. */
export const RADARE2_ANALYSIS_LEVELS = ["aa", "aaa", "aaaa"] as const;
export type Radare2AnalysisLevel = (typeof RADARE2_ANALYSIS_LEVELS)[number];

/** Default deadline for opening the private copy and completing analysis. */
export const DEFAULT_RADARE2_ANALYSIS_TIMEOUT_MS = 600_000;

// Node schedules delays above this signed 32-bit boundary as a 1 ms timer.
const MAX_TIMER_DELAY_MS = 2_147_483_647;

/** radare2 analysis command run once per session: aa, aaa (default) or aaaa. */
export const radare2AnalysisLevelSchema = z
  .enum(RADARE2_ANALYSIS_LEVELS)
  .default("aaa");

/** Parse the optional deadline without reading the ambient process environment. */
export const radare2AnalysisTimeoutSchema = z
  .string()
  .regex(/^[1-9]\d*$/u, "must be a positive decimal integer")
  .transform(Number)
  .pipe(z.number().int().min(1).max(MAX_TIMER_DELAY_MS))
  .default(DEFAULT_RADARE2_ANALYSIS_TIMEOUT_MS);
