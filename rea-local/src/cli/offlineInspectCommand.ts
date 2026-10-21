import type { Logger } from "pino";
import { logCliCommand } from "../cliLogging.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Result } from "../domain/result.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** One lazily composed offline reader: inspect the selection, then always close. */
interface OfflineInspectPort<Input> {
  inspect(
    input: Input,
    options?: ExecutionOptions,
  ): Promise<Result<unknown, AnalysisError>>;
  close(): Promise<void>;
}

export type OfflineInspectLoader<Input> = () => Promise<
  OfflineInspectPort<Input>
>;

/**
 * Run an offline inspection CLI command: compose the reader only when the
 * command runs, log the projected result, and close the reader afterwards.
 */
export const offlineInspectCommand =
  <Args, Options, Input>(
    logger: Logger,
    command: string,
    load: OfflineInspectLoader<Input>,
    buildInput: (args: Args, options: Options) => Input,
  ) =>
  async ({
    args,
    options,
  }: {
    readonly args: Args;
    readonly options: Options;
  }): Promise<unknown> =>
    withCommandCancellation(async (signal) => {
      // Load the reader only when this command runs, keeping CLI startup light.
      const service = await load();
      try {
        return await logCliCommand(logger, command, async () => {
          const result = await service.inspect(buildInput(args, options), {
            signal,
          });
          return result.ok ? result.value : projectAnalysisError(result.error);
        });
      } finally {
        await service.close();
      }
    });
