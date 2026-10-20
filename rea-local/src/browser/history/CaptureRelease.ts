import { javaScriptRuntime } from "../../domain/runtimeVersion.js";
import { javaScriptWorkerMemoryLimitBytes } from "../../process/JavaScriptWorkerMemoryLimit.js";

/** Exact upstream package profile for unchanged offline HAR validation and numeric parsing. */
export const HAR_CAPTURE_PROVIDER_IDENTITY = {
  id: "har-schema/lossless-json",
  name: "REA+ HAR capture adapter",
  version: "har-schema@2.0.0;jsonc-parser@3.3.1;lossless-json@4.3.1",
} as const;

/** Fixed V8 heap settings used by the owned HAR decoder process. */
export const HAR_CAPTURE_HEAP_LIMITS = {
  oldGenerationMiB: 192,
  semiSpaceMiB: 8,
} as const;

/** The HAR and PCAP/PCAPNG decoders run on this same executable; Bun accepts but ignores V8 heap flags. */
export const HAR_CAPTURE_HEAP_ENFORCED =
  javaScriptRuntime(process.versions).id === "node";

/** Windows Job Object commit limit replacing the ignored heap flags under Bun; otherwise null. */
export const HAR_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES =
  javaScriptWorkerMemoryLimitBytes(HAR_CAPTURE_HEAP_LIMITS.oldGenerationMiB);

/** Burp Suite XML exports converted to HAR 1.2, then decoded by the HAR profile. */
export const BURP_CAPTURE_PROVIDER_IDENTITY = {
  id: "burp-xml/har-schema",
  name: "REA+ Burp Suite export adapter",
  version: "xmldom@0.9.12;har-schema@2.0.0;lossless-json@4.3.1",
} as const;

/** Native executable profile verified with unchanged mitmproxy raw-state decoding. */
export const MITMPROXY_CAPTURE_PROVIDER_IDENTITY = {
  id: "mitmproxy-native-tnetstring",
  name: "REA+ offline native mitmproxy adapter",
  version: "12.2.3",
} as const;

/** Offline packet-capture decoder profile; frames are preserved without live attribution. */
export const PCAP_CAPTURE_PROVIDER_IDENTITY = {
  id: "rea-offline-pcap",
  name: "REA+ offline PCAP/PCAPNG adapter",
  version: "1.1.0",
} as const;

/** Fixed V8 heap settings used by the owned PCAP/PCAPNG decoder process. */
export const PCAP_CAPTURE_HEAP_LIMITS = {
  oldGenerationMiB: 192,
  semiSpaceMiB: 8,
} as const;

/** Windows Job Object commit limit replacing ignored V8 flags under Bun. */
export const PCAP_CAPTURE_PROCESS_MEMORY_LIMIT_BYTES =
  javaScriptWorkerMemoryLimitBytes(PCAP_CAPTURE_HEAP_LIMITS.oldGenerationMiB);
