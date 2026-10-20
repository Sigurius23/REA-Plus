export type Edit = "same" | "removed" | "added";

/** Edits beyond this leave a sequence undiffed. */
const MAX_EDITS = 2000;

/**
 * Myers' O((N+M)D) shortest edit script, keeping only the diagonals each
 * step reached; null when more than `maxEdits` edits are needed.
 */
export const editScript = (
  left: readonly string[],
  right: readonly string[],
  maxEdits = MAX_EDITS,
): Edit[] | null => {
  const n = left.length;
  const m = right.length;
  const trace: Int32Array[] = [];
  let previous = new Int32Array(1);
  for (let d = 0; d <= Math.min(n + m, maxEdits); d += 1) {
    const current = new Int32Array(2 * d + 1);
    const at = (row: Int32Array, depth: number, k: number) =>
      row[k + depth] ?? 0;
    for (let k = -d; k <= d; k += 2) {
      let x =
        d === 0
          ? 0
          : k === -d ||
              (k !== d &&
                at(previous, d - 1, k - 1) < at(previous, d - 1, k + 1))
            ? at(previous, d - 1, k + 1)
            : at(previous, d - 1, k - 1) + 1;
      let y = x - k;
      while (x < n && y < m && left[x] === right[y]) {
        x += 1;
        y += 1;
      }
      current[k + d] = x;
      if (x >= n && y >= m) {
        trace.push(current);
        return backtrack(trace, n, m);
      }
    }
    trace.push(current);
    previous = current;
  }
  return null;
};

const backtrack = (trace: readonly Int32Array[], n: number, m: number) => {
  const edits: Edit[] = [];
  let x = n;
  let y = m;
  for (let d = trace.length - 1; d > 0; d -= 1) {
    const before = trace[d - 1] as Int32Array;
    const at = (k: number) => before[k + d - 1] ?? 0;
    const k = x - y;
    const down = k === -d || (k !== d && at(k - 1) < at(k + 1));
    const previousK = down ? k + 1 : k - 1;
    const previousX = at(previousK);
    const previousY = previousX - previousK;
    while (x > previousX && y > previousY) {
      edits.push("same");
      x -= 1;
      y -= 1;
    }
    edits.push(down ? "added" : "removed");
    x = previousX;
    y = previousY;
  }
  for (; x > 0 && y > 0; x -= 1, y -= 1) edits.push("same");
  return edits.reverse();
};
