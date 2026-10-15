import type { JsonValue } from "../domain/jsonValue.js";

type ToolObservation = {
  readonly name: string;
  readonly arguments: Readonly<Record<string, JsonValue>>;
  readonly result: JsonValue;
};

const MAX_RAW_OBSERVATIONS_BYTES = 1_000_000;
const MAX_RAW_OBSERVATIONS = 64;

/** Bounded per-operation upstream observations retained as provider Evidence. */
export class BinaryNinjaMcpObservations {
  #items: ToolObservation[] = [];
  #bytes = 0;
  #omitted = false;

  get omitted(): boolean {
    return this.#omitted;
  }

  reset(): void {
    this.#items = [];
    this.#bytes = 0;
    this.#omitted = false;
  }

  record(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
    value: JsonValue,
  ): void {
    if (
      this.#items.length >= MAX_RAW_OBSERVATIONS ||
      this.#bytes >= MAX_RAW_OBSERVATIONS_BYTES
    ) {
      this.#omitted = true;
      return;
    }
    const observation: ToolObservation = {
      name,
      arguments: { ...args },
      result: value,
    };
    const bytes = Buffer.byteLength(JSON.stringify(observation) ?? "", "utf8");
    if (bytes > MAX_RAW_OBSERVATIONS_BYTES - this.#bytes) {
      this.#omitted = true;
      return;
    }
    this.#items.push(observation);
    this.#bytes += bytes;
  }

  rawResultFields(): Readonly<Record<string, JsonValue>> {
    return {
      observations: this.#items,
      ...(this.#omitted ? { raw_observations_omitted: true } : {}),
    };
  }
}
