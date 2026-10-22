/** Input formats the Android provider admits: one APK, or a whole XAPK bundle. */
export const APK_CONTAINER_FORMATS = ["apk", "xapk"] as const;

export type AndroidContainerFormat = (typeof APK_CONTAINER_FORMATS)[number];

/**
 * Narrow an admitted target to what the Android provider actually detected.
 * Partial observations and evidence must never claim a format the provider
 * did not gate on, so non-Android formats fail loudly here.
 */
export const admittedAndroidContainerFormat = (
  format: string,
): AndroidContainerFormat => {
  if (format === "apk" || format === "xapk") return format;
  throw new TypeError(
    `Android admission recorded an unexpected container format: ${format}`,
  );
};
