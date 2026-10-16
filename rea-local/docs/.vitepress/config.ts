import { defineConfig } from "vitepress";

export default defineConfig({
  title: "REA+",
  description:
    "Reverse engineer binaries, applications, and runtime behavior with one CLI and MCP server.",
  lang: "en-US",
  base: "/rea/",
  themeConfig: {
    nav: [
      { text: "Get started", link: "/installation" },
      { text: "Reference", link: "/mcp-contracts" },
      { text: "Roadmap", link: "/roadmap" },
    ],
    sidebar: [
      {
        text: "Getting started",
        items: [
          { text: "Installation and setup", link: "/installation" },
          { text: "CLI and Evidence", link: "/cli" },
          { text: "Agent prompts", link: "/mcp-prompts" },
          { text: "Roadmap", link: "/roadmap" },
        ],
      },
      {
        text: "Investigation guides",
        items: [
          { text: "Native binaries", link: "/native-investigation" },
          {
            text: "JavaScript and Electron",
            link: "/javascript-artifact-reconstruction",
          },
          {
            text: "JavaScript workflows",
            link: "/javascript-application-workflows",
          },
          { text: "Browser observation", link: "/browser-observation" },
          { text: "Electron observation", link: "/electron-observation" },
          { text: "Process capture", link: "/process-capture" },
          { text: "Coverage logs", link: "/drcov-coverage" },
          { text: "Crash minidumps", link: "/minidumps" },
          { text: "AOB signatures and CE tables", link: "/byte-patterns" },
          { text: "Unity asset bundles", link: "/unity-assets" },
          { text: "Game engine archives", link: "/game-archives" },
          { text: "Compiled Ren'Py scripts", link: "/renpy-scripts" },
          { text: "RPG Maker MV/MZ games", link: "/rpgmaker-projects" },
          { text: "GameMaker data files", link: "/gamemaker-data" },
          { text: ".NET assemblies", link: "/managed-code-analysis" },
          { text: "Android applications", link: "/android-analysis" },
          { text: "JVM classes and JARs", link: "/jvm-decompilation" },
          { text: "Unity IL2CPP metadata", link: "/il2cpp-metadata" },
          { text: "Apple applications", link: "/apple-application-analysis" },
          { text: "Firmware", link: "/firmware-analysis" },
          { text: "Logic-analyzer captures", link: "/logic-captures" },
          {
            text: "Reconstruction readiness",
            link: "/reconstruction-readiness",
          },
        ],
      },
      {
        text: "Provider guides",
        collapsed: true,
        items: [
          { text: "IDA adapters", link: "/ida-provider" },
          { text: "Binary Ninja", link: "/binary-ninja-provider" },
          { text: "radare2", link: "/radare2-provider" },
          { text: "Ghidra on Windows", link: "/windows-ghidra-p0" },
          { text: "Ghidra DOS analysis", link: "/ghidra-dos" },
          { text: "Ghidra NativeAOT", link: "/ghidra-nativeaot" },
          { text: "Ghidra semantics", link: "/ghidra-provider" },
          { text: "External MCP tools", link: "/external-mcp-bridge" },
          {
            text: "Runtime instrumentation",
            link: "/mobile-runtime-instrumentation",
          },
        ],
      },
      {
        text: "Reference and development",
        collapsed: true,
        items: [
          { text: "MCP contracts", link: "/mcp-contracts" },
          { text: "Tool design", link: "/tool-design" },
          { text: "Testing", link: "/testing" },
          { text: "Releasing", link: "/releasing" },
        ],
      },
    ],
    search: { provider: "local" },
    socialLinks: [
      { icon: "github", link: "https://github.com/morluto/rea" },
      { icon: "discord", link: "https://discord.gg/GkcryMnJDM" },
    ],
    editLink: {
      pattern: "https://github.com/morluto/rea/edit/main/docs/:path",
    },
    footer: {
      message: "Released under the MIT License.",
    },
  },
});
