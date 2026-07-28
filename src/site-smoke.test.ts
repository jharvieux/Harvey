import { describe, expect, it } from "vitest";
import { evaluateSmoke, smokeFailed, type SmokeInput } from "./site-smoke.js";

// The fixtures below are the states MEASURED against real servers on 2026-07-28 while #1308 was
// open, not invented shapes: production (a six-day-old build), a fresh build with the Resend env
// vars unset, and the same build with them set.

const HEALTHY: SmokeInput = {
  declared: ["/", "/pricing"],
  served: ["/", "/pricing"],
  routes: [
    { path: "/", status: 200 },
    { path: "/pricing", status: 200 },
  ],
  readiness: { status: 200, configured: true },
  validation: { status: 400 },
};

function check(input: SmokeInput, name: string) {
  const found = evaluateSmoke(input).find((c) => c.name.startsWith(name));
  if (!found) throw new Error(`no check named ${name}`);
  return found;
}

describe("evaluateSmoke", () => {
  it("passes a deployment that serves what the repo declares with lead capture live", () => {
    expect(smokeFailed(evaluateSmoke(HEALTHY))).toBe(false);
  });

  it("fails, naming each dead route, when the deployment predates them (the #1308 production state)", () => {
    const stale: SmokeInput = {
      ...HEALTHY,
      served: ["/"],
      routes: [
        { path: "/", status: 200 },
        { path: "/pricing", status: 404 },
      ],
    };
    expect(smokeFailed(evaluateSmoke(stale))).toBe(true);
    expect(check(stale, "declared routes").detail).toContain("/pricing → 404");
    // Naming the drift is the point: a bare "3 checks failed" would not tell the operator the
    // deployment is behind main rather than the pages being deleted.
    expect(check(stale, "deployed sitemap").detail).toContain("/pricing");
    expect(check(stale, "deployed sitemap").detail).toContain("deployment is behind main");
  });

  it("fails when the Resend env vars are unset — every lead is being rejected", () => {
    const unconfigured: SmokeInput = { ...HEALTHY, readiness: { status: 503, configured: false } };
    expect(smokeFailed(evaluateSmoke(unconfigured))).toBe(true);
    expect(check(unconfigured, "/api/scan is configured").detail).toContain("RESEND_API_KEY");
  });

  it("reports a deployment with no readiness handler as UNKNOWN, not as configured", () => {
    // The distinction the coverage guard exists for: 405-with-no-body means this build has no
    // answer to give. Reading it as "not configured" would be a guess; reading it as
    // "configured" would be a silent pass over an unmeasured state.
    const noProbe: SmokeInput = { ...HEALTHY, readiness: { status: 405, configured: null } };
    expect(smokeFailed(evaluateSmoke(noProbe))).toBe(true);
    expect(check(noProbe, "/api/scan is configured").detail).toContain("UNKNOWN");
    expect(check(noProbe, "/api/scan is configured").detail).not.toContain("RESEND_API_KEY");
  });

  it("fails when the handler stops validating, so a broken form is not read as a healthy one", () => {
    const noValidation: SmokeInput = { ...HEALTHY, validation: { status: 500 } };
    expect(smokeFailed(evaluateSmoke(noValidation))).toBe(true);
    expect(check(noValidation, "/api/scan rejects").detail).toContain("got 500");
  });

  it("fails when the deployment serves a route the repo no longer declares", () => {
    const extra: SmokeInput = { ...HEALTHY, served: ["/", "/pricing", "/retired"] };
    expect(smokeFailed(evaluateSmoke(extra))).toBe(true);
    expect(check(extra, "deployed sitemap").detail).toContain("/retired");
  });
});
