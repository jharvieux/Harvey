import { describe, expect, it } from "vitest";
import { detectSsrfWrapperFindings } from "./ssrf-wrapper.js";

// #1325 (#570 remainder) — near-miss shapes beyond the corpus pair (which calibration.test.ts
// scores against the committed targets/calibration/{lib/dl-fetch.ts,app/api/dl-ssrf*} fixtures).
// Each negative differs from the positive by exactly one gate.

const wrapper = `export async function downloadRemote(target: string): Promise<string> {
  const res = await fetch(target, { redirect: "follow" });
  return await res.text();
}
`;
const wrapperFile = { path: "lib/dl-fetch.ts", text: wrapper };

const taintedRoute = `import { downloadRemote } from "../../../lib/dl-fetch";
export async function GET(req: Request) {
  const url = new URL(req.url).searchParams.get("url") || "";
  const body = await downloadRemote(url);
  return new Response(body);
}
`;

describe("ssrf-wrapper (#1325 — cross-file SSRF through a wrapper name outside harvey-ssrf-fetch's curated four)", () => {
  it("flags a request-tainted call through a differently-named thin fetch wrapper, at review tier", () => {
    const findings = detectSsrfWrapperFindings([wrapperFile, { path: "app/api/proxy/route.ts", text: taintedRoute }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "Medium", precisionTier: "review" });
    expect(findings[0]?.evidence).toContain("downloadRemote");
    expect(findings[0]?.location).toContain("app/api/proxy/route.ts");
  });

  it("stays silent when the wrapper is called with a fixed, non-request URL", () => {
    const safe = taintedRoute
      .replace('const url = new URL(req.url).searchParams.get("url") || "";\n  ', "")
      .replace("downloadRemote(url)", 'downloadRemote("https://cdn.example.com/logo.png")')
      .replace("(req: Request)", "()");
    expect(detectSsrfWrapperFindings([wrapperFile, { path: "app/api/proxy-safe/route.ts", text: safe }])).toHaveLength(0);
  });

  it("stays silent on the CURATED wrapper names (fetchRemote/fetchUrl/fetchExternal/proxyFetch) — those stay harvey-ssrf-fetch's, so the two checks never double-report", () => {
    const curated = wrapper.replace("downloadRemote", "fetchRemote");
    const route = taintedRoute.replace(/downloadRemote/g, "fetchRemote");
    expect(detectSsrfWrapperFindings([{ path: "lib/dl-fetch.ts", text: curated }, { path: "app/api/proxy/route.ts", text: route }])).toHaveLength(0);
  });

  it("stays silent when the wrapper touches its parameter more than once (not a thin pass-through — e.g. a host check)", () => {
    const guarded = wrapper.replace(
      "const res = await fetch(target",
      'if (!ALLOWLIST.includes(new URL(target).hostname)) throw new Error("blocked");\n  const res = await fetch(target',
    );
    expect(detectSsrfWrapperFindings([{ path: "lib/dl-fetch.ts", text: guarded }, { path: "app/api/proxy/route.ts", text: taintedRoute }])).toHaveLength(0);
  });

  it("stays silent when the wrapper is never imported anywhere (no call site to resolve)", () => {
    expect(detectSsrfWrapperFindings([wrapperFile])).toHaveLength(0);
  });

  it("stays silent on an ordinary two-parameter helper (not a thin one-argument wrapper)", () => {
    const twoParam = wrapper.replace("downloadRemote(target: string)", "downloadRemote(target: string, opts: RequestInit)").replace("fetch(target,", "fetch(target, opts ??");
    expect(detectSsrfWrapperFindings([{ path: "lib/dl-fetch.ts", text: twoParam }, { path: "app/api/proxy/route.ts", text: taintedRoute }])).toHaveLength(0);
  });
});
