import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const networkEndpoints = (source: string): string[] =>
  analyzeJavaScriptStaticSource(source)
    .endpoints.filter(({ kind }) => kind === "network")
    .map(({ value }) => value);

describe("endpoint templates", () => {
  it("renders template literals, concatenation and concat with placeholders", () => {
    expect(
      networkEndpoints(`
        api.get(\`/threads/\${encodeURIComponent(id)}/interactions/\${i}/\`);
        fetch("/papers/" + paperId + "/pdf");
        api.post("/collections/".concat(id, "/papers/"));
        fetch(\`\${base}/api/v2/\${path}\`);
        fetch(\`https://\${host}/intake?\${query}\`);
        api.get(\`/nested/\${\`\${a}-\${b}\`}/x\`);
      `),
    ).toEqual([
      "/threads/{}/interactions/{}/",
      "/papers/{}/pdf",
      "/collections/{}/papers/",
      "{}/api/v2/{}",
      "https://{}/intake?{}",
      "/nested/{}-{}/x",
    ]);
  });

  it("ignores templates that are not paths or URLs, or name nothing", () => {
    expect(
      networkEndpoints(`
        cache.delete(\`session_\${Date.now()}\`);
        sites.get(\`\${kind}:\${id}\`);
        fetch(\`\${base}/\${path}?\${query}\`);
        total.get(1 + count);
      `),
    ).toEqual([]);
  });

  it("follows a local variable to the path it was given", () => {
    expect(
      networkEndpoints(`
        async function load(id, query) {
          let url = \`/study_details/\${encodeURIComponent(id)}\`;
          query && (url = \`\${url}?\${query}\`);
          const { data } = await client.get(url);
          return data;
        }
        function stream(t, i) {
          return new EventSource(\`/api/threads/\${t}/interactions/\${i}/stream/\`);
        }
        const beacon = "/track/";
        navigator.sendBeacon(beacon, payload);
      `),
    ).toEqual([
      "/study_details/{}",
      "/api/threads/{}/interactions/{}/stream/",
      "/track/",
    ]);
  });

  it("does not resolve shadowed, reassigned or non-path variables", () => {
    expect(
      networkEndpoints(`
        const url = "/outer/";
        function inner(url) { return fetch(url); }
        function block() {
          let target = "/first/";
          target = pick();
          return fetch(target);
        }
        const key = "token";
        headers.get(key);
        fetch(url);
      `),
    ).toEqual(["/outer/"]);
  });

  it("keeps let and const inside their block", () => {
    expect(
      networkEndpoints(`
        function f(flag) {
          let url = "/outer/";
          if (flag) { const url = \`/inner/\${flag}\`; fetch(url); }
          return fetch(url);
        }
      `),
    ).toEqual(["/inner/{}", "/outer/"]);
  });
});
