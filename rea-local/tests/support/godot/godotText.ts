/**
 * Compare a value as inspect_godot_file prints it with the same value as
 * Godot's var2str / to_json print it: strings by content, numbers within
 * float rounding (Godot prints single-precision values through doubles),
 * everything else exactly, ignoring spacing.
 */

const TOKEN =
  /"(?:[^"\\]|\\.)*"|-?(?:\d+\.?\d*(?:e[+-]?\d+)?|inf|nan)|[^\s"]/giu;

const tokens = (text: string): string[] => text.match(TOKEN) ?? [];

const numeric = (token: string): number | null => {
  if (/^-?inf$/iu.test(token))
    return token.startsWith("-") ? -Infinity : Infinity;
  if (/^-?nan$/iu.test(token)) return Number.NaN;
  return /^-?\d/u.test(token) ? Number(token) : null;
};

const close = (left: number, right: number): boolean =>
  (Number.isNaN(left) && Number.isNaN(right)) ||
  left === right ||
  Math.abs(left - right) <= 1e-6 * Math.max(1, Math.abs(left), Math.abs(right));

const sameToken = (left: string, right: string): boolean => {
  if (left.startsWith('"') && right.startsWith('"'))
    return JSON.parse(left) === JSON.parse(right);
  const a = numeric(left);
  const b = numeric(right);
  if (a !== null && b !== null) return close(a, b);
  return left === right;
};

export const sameGodotText = (ours: string, godot: string): boolean => {
  const left = tokens(ours);
  const right = tokens(godot);
  return (
    left.length === right.length &&
    left.every((token, index) => sameToken(token, right[index] ?? ""))
  );
};
