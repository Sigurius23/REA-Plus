import { names } from "./catalog-core.mjs";

/** Build tool-family counts and sorted tool-name lists. */
export const toolFamilyCatalog = (sources) => {
  const families = [
    {
      id: "direct",
      surface: "official-proxy",
      contracts: sources.officialContracts.OFFICIAL_TOOL_CONTRACTS,
    },
    {
      id: "enhanced",
      surface: "enhanced",
      contracts: sources.enhancedContracts.ENHANCED_TOOL_CONTRACTS,
    },
    {
      id: "native",
      surface: "native-provider",
      contracts: [
        ...sources.nativeContracts.NATIVE_TOOL_CONTRACTS,
        ...sources.binaryDiagnosticsContracts.BINARY_DIAGNOSTICS_TOOL_CONTRACTS,
      ],
    },
    {
      id: "artifact",
      surface: "artifact-provider",
      contracts: [
        ...sources.artifactContracts.ARTIFACT_TOOL_CONTRACTS,
        ...sources.evmContracts.EVM_TOOL_CONTRACTS,
        ...sources.wasmContracts.WASM_TOOL_CONTRACTS,
        ...sources.jvmContracts.JVM_TOOL_CONTRACTS,
        ...sources.il2cppContracts.IL2CPP_TOOL_CONTRACTS,
        ...sources.coverageContracts.COVERAGE_TOOL_CONTRACTS,
        ...sources.minidumpContracts.MINIDUMP_TOOL_CONTRACTS,
        ...sources.logicContracts.LOGIC_TOOL_CONTRACTS,
        ...sources.patternContracts.PATTERN_TOOL_CONTRACTS,
        ...sources.unityContracts.UNITY_TOOL_CONTRACTS,
        ...sources.gameArchiveContracts.GAME_ARCHIVE_TOOL_CONTRACTS,
        ...sources.renpyContracts.RENPY_TOOL_CONTRACTS,
        ...sources.rpgMakerContracts.RPG_MAKER_TOOL_CONTRACTS,
        ...sources.gameMakerContracts.GAMEMAKER_TOOL_CONTRACTS,
        ...sources.x64dbgContracts.X64DBG_TOOL_CONTRACTS,
        ...sources.wasmModuleContracts.WASM_MODULE_TOOL_CONTRACTS,
        ...sources.mobsfContracts.MOBSF_TOOL_CONTRACTS,
        ...sources.luaContracts.LUA_TOOL_CONTRACTS,
        ...sources.dataBlobContracts.DATA_BLOB_TOOL_CONTRACTS,
      ],
    },
    {
      id: "managed",
      surface: "managed",
      contracts: [
        ...sources.managedContracts.MANAGED_TOOL_CONTRACTS,
        ...sources.managedWorkflowContracts.MANAGED_WORKFLOW_TOOL_CONTRACTS,
      ],
    },
    {
      id: "firmware",
      surface: "firmware-provider",
      contracts: sources.firmwareContracts.FIRMWARE_TOOL_CONTRACTS,
    },
    {
      id: "android",
      surface: "android-provider",
      contracts: sources.androidContracts.ANDROID_TOOL_CONTRACTS,
    },
    {
      id: "apktool",
      surface: "apktool-provider",
      contracts: sources.apktoolContracts.APKTOOL_TOOL_CONTRACTS,
    },
    {
      id: "jeb",
      surface: "jeb-provider",
      contracts: sources.jebContracts.JEB_TOOL_CONTRACTS,
    },
    {
      id: "adb",
      surface: "adb-provider",
      contracts: sources.adbContracts.ADB_TOOL_CONTRACTS,
    },
    {
      id: "browser",
      surface: "browser-provider",
      contracts: [
        ...sources.browserContracts.BROWSER_TOOL_CONTRACTS,
        ...sources.webRuntimeContracts.WEB_RUNTIME_TOOL_CONTRACTS,
        ...sources.browserScenarioContracts.BROWSER_SCENARIO_TOOL_CONTRACTS,
        ...sources.webNetworkCaptureContracts
          .WEB_NETWORK_CAPTURE_TOOL_CONTRACTS,
      ],
    },
    {
      id: "electron",
      surface: "electron-provider",
      contracts: sources.electronContracts.ELECTRON_TOOL_CONTRACTS,
    },
    {
      id: "javascript-runtime",
      surface: "runtime-provider",
      contracts:
        sources.javascriptRuntimeObservationContracts
          .JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS,
    },
    {
      id: "application",
      surface: "application-workflow",
      contracts: [
        ...sources.applicationContracts.APPLICATION_TOOL_CONTRACTS,
        ...sources.analysisViewContracts.ANALYSIS_VIEW_TOOL_CONTRACTS,
        ...sources.webScriptContracts.WEB_SCRIPT_TOOL_CONTRACTS,
        ...sources.javascriptRecoveryContracts
          .JAVASCRIPT_RECOVERY_TOOL_CONTRACTS,
      ],
    },
    {
      id: "session",
      surface: "session",
      contracts: sources.sessionContracts.SESSION_TOOL_CONTRACTS,
    },
    {
      id: "external-mcp",
      surface: "external-mcp-provider",
      contracts: sources.externalMcpContracts.EXTERNAL_MCP_TOOL_CONTRACTS,
    },
    {
      id: "mobile-runtime",
      surface: "mobile-runtime-provider",
      contracts: sources.mobileRuntimeContracts.MOBILE_RUNTIME_TOOL_CONTRACTS,
    },
  ].map(({ id, surface, contracts }) => ({
    id,
    surface,
    count: contracts.length,
    tools: names(contracts),
  }));
  const familyTotal = families.reduce(
    (total, family) => total + family.count,
    0,
  );
  if (
    familyTotal !== sources.toolContracts.TOOL_CONTRACTS.length ||
    familyTotal !== sources.catalogIdentity.CATALOG_IDENTITY.counts.mcp_tools
  )
    throw new Error("Tool family inventory does not match TOOL_CONTRACTS");
  return { total: familyTotal, families };
};

/** Build provider identities with their sorted capability names. */
export const providerCatalog = (sources) => {
  const contractsByName = new Map(
    sources.toolContracts.TOOL_CONTRACTS.map((contract) => [
      contract.name,
      contract,
    ]),
  );
  const declaredContracts = (providerId, operations) =>
    operations.map((operation) => {
      const contract = contractsByName.get(operation);
      if (contract === undefined)
        throw new TypeError(
          `Provider ${providerId} declares an unknown analyst operation: ${operation}`,
        );
      return contract;
    });
  const {
    applicationContracts,
    reconciliationContracts,
    observationContracts,
    activeContracts,
  } = electronContractSlices(sources);
  return [
    {
      identity: sources.hopperProvider.HOPPER_PROVIDER_IDENTITY,
      contracts: declaredContracts(
        "hopper",
        sources.hopperProvider.HOPPER_OPERATIONS,
      ),
    },
    {
      identity: sources.ghidraProvider.GHIDRA_PROVIDER_IDENTITY,
      contracts: declaredContracts(
        "ghidra",
        sources.ghidraProvider.GHIDRA_OPERATIONS,
      ),
    },
    {
      identity: sources.idaProvider.IDA_PROVIDER_IDENTITY,
      contracts: declaredContracts("ida", sources.idaProvider.IDA_OPERATIONS),
    },
    {
      identity: sources.nativeProvider.NATIVE_MACOS_PROVIDER_IDENTITY,
      contracts: sources.nativeContracts.NATIVE_TOOL_CONTRACTS,
    },
    {
      identity: sources.pwntoolsProvider.PWNTOOLS_PROVIDER_IDENTITY,
      contracts:
        sources.binaryDiagnosticsContracts.BINARY_DIAGNOSTICS_TOOL_CONTRACTS.filter(
          ({ name }) => name !== "inspect_pe_resources",
        ),
    },
    {
      identity: sources.artifactProviders.PE_RESOURCES_PROVIDER,
      contracts:
        sources.binaryDiagnosticsContracts.BINARY_DIAGNOSTICS_TOOL_CONTRACTS.filter(
          ({ name }) => name === "inspect_pe_resources",
        ),
    },
    {
      identity: sources.wasmProvider.WABT_PROVIDER_IDENTITY,
      contracts: sources.wasmContracts.WASM_TOOL_CONTRACTS,
    },
    {
      identity: sources.jvmProvider.CFR_PROVIDER_IDENTITY,
      contracts: sources.jvmContracts.JVM_TOOL_CONTRACTS,
    },
    {
      identity: sources.il2cppProvider.R2UNITY_PROVIDER_IDENTITY,
      contracts: sources.il2cppContracts.IL2CPP_TOOL_CONTRACTS,
    },
    {
      identity: sources.coverageProvider.COVERAGE_LOG_PROVIDER_IDENTITY,
      contracts: sources.coverageContracts.COVERAGE_TOOL_CONTRACTS,
    },
    {
      identity: sources.minidumpProvider.MINIDUMP_PROVIDER_IDENTITY,
      contracts: sources.minidumpContracts.MINIDUMP_TOOL_CONTRACTS,
    },
    {
      identity: sources.logicProvider.LOGIC_CAPTURE_PROVIDER_IDENTITY,
      contracts: sources.logicContracts.LOGIC_TOOL_CONTRACTS,
    },
    {
      identity: sources.patternProvider.BYTE_PATTERN_PROVIDER_IDENTITY,
      contracts: sources.patternContracts.PATTERN_TOOL_CONTRACTS.filter(
        ({ name }) => name === "scan_byte_patterns",
      ),
    },
    {
      identity: sources.cheatTableProvider.CHEAT_TABLE_PROVIDER_IDENTITY,
      contracts: sources.patternContracts.PATTERN_TOOL_CONTRACTS.filter(
        ({ name }) => name === "inspect_cheat_table",
      ),
    },
    {
      identity: sources.unityProvider.UNITY_ASSETS_PROVIDER_IDENTITY,
      contracts: sources.unityContracts.UNITY_TOOL_CONTRACTS,
    },
    {
      identity: sources.gameArchiveProvider.GAME_ARCHIVE_PROVIDER_IDENTITY,
      contracts: sources.gameArchiveContracts.GAME_ARCHIVE_TOOL_CONTRACTS,
    },
    {
      identity: sources.renpyProvider.RENPY_SCRIPT_PROVIDER_IDENTITY,
      contracts: sources.renpyContracts.RENPY_TOOL_CONTRACTS,
    },
    {
      identity: sources.rpgMakerProvider.RPG_MAKER_PROVIDER_IDENTITY,
      contracts: sources.rpgMakerContracts.RPG_MAKER_TOOL_CONTRACTS,
    },
    {
      identity: sources.gameMakerProvider.GAMEMAKER_PROVIDER_IDENTITY,
      contracts: sources.gameMakerContracts.GAMEMAKER_TOOL_CONTRACTS,
    },
    {
      identity: sources.x64dbgProvider.X64DBG_PROVIDER_IDENTITY,
      contracts: sources.x64dbgContracts.X64DBG_TOOL_CONTRACTS,
    },
    {
      identity: sources.wasmModuleProvider.WASM_MODULE_PROVIDER_IDENTITY,
      contracts: sources.wasmModuleContracts.WASM_MODULE_TOOL_CONTRACTS,
    },
    {
      identity: sources.mobsfProvider.MOBSF_PROVIDER_IDENTITY,
      contracts: sources.mobsfContracts.MOBSF_TOOL_CONTRACTS,
    },
    {
      identity: sources.luaProvider.LUA_PROVIDER_IDENTITY,
      contracts: sources.luaContracts.LUA_TOOL_CONTRACTS,
    },
    {
      identity: sources.dataBlobProvider.DATA_BLOB_PROVIDER_IDENTITY,
      contracts: sources.dataBlobContracts.DATA_BLOB_TOOL_CONTRACTS,
    },
    {
      identity: sources.evmProvider.EVMOLE_PROVIDER_IDENTITY,
      contracts: sources.evmContracts.EVM_TOOL_CONTRACTS,
    },
    {
      identity: sources.artifactProviders.ARTIFACT_GRAPH_PROVIDER,
      contracts: sources.artifactContracts.ARTIFACT_TOOL_CONTRACTS,
    },
    {
      identity: sources.artifactProviders.MANAGED_STATIC_PROVIDER,
      contracts: sources.managedContracts.MANAGED_TOOL_CONTRACTS,
    },
    {
      identity: sources.artifactProviders.MANAGED_WORKFLOW_PROVIDER,
      contracts:
        sources.managedWorkflowContracts.MANAGED_WORKFLOW_TOOL_CONTRACTS,
    },
    {
      identity: sources.firmwareProvider.BINWALK_PROVIDER_IDENTITY,
      contracts: sources.firmwareContracts.FIRMWARE_TOOL_CONTRACTS.filter(
        ({ name }) => name === "inspect_firmware_regions",
      ),
    },
    {
      identity: sources.firmwareProvider.UNBLOB_PROVIDER_IDENTITY,
      contracts: sources.firmwareContracts.FIRMWARE_TOOL_CONTRACTS.filter(
        ({ name }) => name === "extract_firmware",
      ),
    },
    {
      identity: sources.androidProvider.JADX_PROVIDER_IDENTITY,
      contracts: sources.androidContracts.ANDROID_TOOL_CONTRACTS,
    },
    {
      identity: sources.apktoolProvider.APKTOOL_PROVIDER_IDENTITY,
      contracts: sources.apktoolContracts.APKTOOL_TOOL_CONTRACTS,
    },
    {
      identity: sources.jebProvider.JEB_PROVIDER_IDENTITY,
      contracts: sources.jebContracts.JEB_TOOL_CONTRACTS,
    },
    {
      identity: sources.adbProvider.ADB_PROVIDER_IDENTITY,
      contracts: sources.adbContracts.ADB_TOOL_CONTRACTS,
    },
    {
      identity: sources.webNetworkCaptureProvider.HAR_CAPTURE_PROVIDER_IDENTITY,
      contracts:
        sources.webNetworkCaptureContracts.WEB_NETWORK_CAPTURE_TOOL_CONTRACTS,
    },
    {
      identity:
        sources.webNetworkCaptureProvider.MITMPROXY_CAPTURE_PROVIDER_IDENTITY,
      contracts:
        sources.webNetworkCaptureContracts.WEB_NETWORK_CAPTURE_TOOL_CONTRACTS,
    },
    {
      identity: sources.browserIdentities.CDP_BROWSER_PROVIDER_IDENTITY,
      contracts: [
        ...sources.browserContracts.BROWSER_TOOL_CONTRACTS,
        ...sources.webRuntimeContracts.WEB_RUNTIME_TOOL_CONTRACTS,
      ],
    },
    {
      identity:
        sources.browserIdentities.PLAYWRIGHT_BROWSER_SCENARIO_PROVIDER_IDENTITY,
      contracts:
        sources.browserScenarioContracts.BROWSER_SCENARIO_TOOL_CONTRACTS,
    },
    {
      identity: sources.browserIdentities.CDP_ELECTRON_PROVIDER_IDENTITY,
      contracts: observationContracts,
    },
    {
      identity:
        sources.browserIdentities.PLAYWRIGHT_ELECTRON_ACTIVE_PROVIDER_IDENTITY,
      contracts: activeContracts,
    },
    {
      identity: sources.v8InspectorProvider.V8_INSPECTOR_PROVIDER_IDENTITY,
      contracts:
        sources.javascriptRuntimeObservationContracts
          .JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS,
    },
    {
      identity: sources.artifactProviders.JAVASCRIPT_APPLICATION_PROVIDER,
      contracts: applicationContracts,
    },
    {
      identity:
        sources.artifactProviders.JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER,
      contracts: reconciliationContracts,
    },
    {
      identity:
        sources.artifactProviders.JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER,
      contracts: sources.applicationContracts.APPLICATION_TOOL_CONTRACTS.filter(
        ({ name }) =>
          name !== "project_android_application_graph" &&
          name !== "project_apple_application_graph",
      ),
    },
    {
      identity: sources.artifactProviders.ANALYSIS_VIEW_PROVIDER,
      contracts: sources.analysisViewContracts.ANALYSIS_VIEW_TOOL_CONTRACTS,
    },
    {
      identity: sources.artifactProviders.ANDROID_APPLICATION_PROVIDER,
      contracts: sources.applicationContracts.APPLICATION_TOOL_CONTRACTS.filter(
        ({ name }) => name === "project_android_application_graph",
      ),
    },
    {
      identity: sources.artifactProviders.APPLE_APPLICATION_PROVIDER,
      contracts: sources.applicationContracts.APPLICATION_TOOL_CONTRACTS.filter(
        ({ name }) => name === "project_apple_application_graph",
      ),
    },
    {
      identity: sources.artifactProviders.WEB_SCRIPT_EXPORT_PROVIDER,
      contracts: sources.webScriptContracts.WEB_SCRIPT_TOOL_CONTRACTS,
    },
    {
      identity: sources.javascriptRecoveryProvider.WAKARU_PROVIDER_IDENTITY,
      contracts:
        sources.javascriptRecoveryContracts.JAVASCRIPT_RECOVERY_TOOL_CONTRACTS,
    },
  ]
    .map(({ identity, contracts }) => ({
      id: identity.id,
      name: identity.name,
      version: identity.version,
      capabilities: names(contracts),
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
};

const electronContractSlices = (sources) => {
  const applicationContracts =
    sources.electronContracts.ELECTRON_TOOL_CONTRACTS.filter(
      ({ name }) => name === "analyze_javascript_application",
    );
  const reconciliationContracts =
    sources.electronContracts.ELECTRON_TOOL_CONTRACTS.filter(
      ({ name }) => name === "reconcile_javascript_runtime",
    );
  const observationContracts =
    sources.electronContracts.ELECTRON_TOOL_CONTRACTS.filter(
      ({ name }) =>
        name !== "analyze_javascript_application" &&
        name !== "reconcile_javascript_runtime" &&
        name !== "capture_electron_scenario",
    );
  const activeContracts =
    sources.electronContracts.ELECTRON_TOOL_CONTRACTS.filter(
      ({ name }) => name === "capture_electron_scenario",
    );
  if (
    applicationContracts.length !== 1 ||
    reconciliationContracts.length !== 1 ||
    observationContracts.length !== 2 ||
    activeContracts.length !== 1
  )
    throw new Error("Electron provider capability ownership drifted");
  return {
    applicationContracts,
    reconciliationContracts,
    observationContracts,
    activeContracts,
  };
};
