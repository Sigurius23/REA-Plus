/**
 * LZString.decompressFromBase64 (lz-string 1.4, bundled with RPG Maker MV),
 * which MV uses for .rpgsave files. Output is bounded; nothing is evaluated.
 */

const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const BASE64 = new Map([...ALPHABET].map((char, index) => [char, index]));

export class LzStringError extends Error {
  override readonly name = "LzStringError";
}

/** Bits are read low to high, refilling from the next character as lz-string does. */
class BitReader {
  #value: number;
  #position = 32;
  #index = 1;

  constructor(private readonly input: string) {
    this.#value = this.word(0);
  }

  private word(index: number): number {
    if (index >= this.input.length) return 0;
    const value = BASE64.get(this.input.charAt(index));
    if (value === undefined)
      throw new LzStringError(`Invalid base64 character at ${String(index)}`);
    return value;
  }

  /** lz-string stops once it has refilled past the last character. */
  get exhausted(): boolean {
    return this.#index > this.input.length;
  }

  bits(count: number): number {
    let result = 0;
    for (let bit = 0; bit < count; bit += 1) {
      const set = (this.#value & this.#position) > 0;
      this.#position >>= 1;
      if (this.#position === 0) {
        this.#position = 32;
        this.#value = this.word(this.#index);
        this.#index += 1;
      }
      if (set) result += 2 ** bit;
    }
    return result;
  }
}

const literal = (reader: BitReader, code: number): string | null => {
  if (code === 0) return String.fromCharCode(reader.bits(8));
  if (code === 1) return String.fromCharCode(reader.bits(16));
  return null;
};

export const decompressFromBase64 = (
  input: string,
  maximumLength: number,
): string => {
  const text = input.trim();
  if (text.length === 0) throw new LzStringError("Empty compressed data");
  const reader = new BitReader(text);
  const dictionary: string[] = ["", "", ""];
  let width = 3;
  let enlarge = 4;
  const lead = reader.bits(2);
  if (lead === 2) return "";
  const first = literal(reader, lead);
  if (first === null) throw new LzStringError("Invalid first code");
  dictionary.push(first);
  let previous = first;
  const output: string[] = [first];
  let length = first.length;
  for (;;) {
    if (reader.exhausted)
      throw new LzStringError("Compressed data ended early");
    let code = reader.bits(width);
    if (code === 2) return output.join("");
    const added = literal(reader, code);
    if (added !== null) {
      dictionary.push(added);
      code = dictionary.length - 1;
      enlarge -= 1;
    }
    if (enlarge === 0) {
      enlarge = 2 ** width;
      width += 1;
    }
    let entry = dictionary[code];
    if (entry === undefined) {
      if (code !== dictionary.length)
        throw new LzStringError("Invalid dictionary reference");
      entry = previous + previous.charAt(0);
    }
    output.push(entry);
    length += entry.length;
    if (length > maximumLength)
      throw new LzStringError(
        `Decompressed save exceeds ${String(maximumLength)} characters`,
      );
    dictionary.push(previous + entry.charAt(0));
    enlarge -= 1;
    previous = entry;
    if (enlarge === 0) {
      enlarge = 2 ** width;
      width += 1;
    }
  }
};
