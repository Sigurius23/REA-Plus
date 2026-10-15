import { MobileRuntimeProvider } from "../mobileRuntime/MobileRuntimeProvider.js";

/** Compose caller-selected Frida/Objection paths from the server environment. */
export const createMobileRuntimeProvider = (
  environment: Readonly<NodeJS.ProcessEnv>,
): MobileRuntimeProvider => new MobileRuntimeProvider({ environment });
