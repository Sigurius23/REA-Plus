export type CaptureInputLimit =
  | { readonly kind: "capture-bytes"; readonly maximum: number }
  | { readonly kind: "nesting"; readonly maximum: number }
  | { readonly kind: "interfaces-per-section"; readonly maximum: number };

/** Expected malformed, unsupported or oversized producer data at a historical decoder boundary. */
export class CaptureFormatError extends Error {
  constructor(
    readonly reason: "format" | "unsupported" | "input-limit" | "limit",
    message: string,
    readonly pointer = "",
    readonly limit: CaptureInputLimit | null = null,
  ) {
    super(message);
  }
}
