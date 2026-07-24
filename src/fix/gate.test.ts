// #883 fix-verification gate. The load-bearing invariant: a finding is NOT reported resolved —
// and its ticket is never planned for closing — until the detector that produced it actually
// stops firing on a re-run. Proven against the REAL planted calibration class (M5 unused-param,
// same fixture discipline as detector-rerun.test.ts), not a stub.

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { findingMarker } from "../trackers/findings-to-tickets.js";
import { planWriteback } from "../trackers/verify-writeback.js";
import type { DetectorRun } from "./verify.js";
import { runGate } from "./gate.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
const PLANTED = "app/api/ar-cors-reflected-safe/route.ts";

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(rel: string, body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-gate-"));
  created.push(dir);
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), body);
  return dir;
}

function finding(o: Partial<Finding> = {}): Finding {
  return {
    id: "F-07", title: "Unused parameter", severity: "Low", confidence: "Confirmed",
    category: "Maintainability", taxonomy: "M5 — Unused parameter", location: `${PLANTED}:8`,
    status: "Open", evidence: "GET(request: Request) never reads request", impact: "dead surface",
    fix: "drop the unused parameter", value: 3, ease: 5, safety: 5, ...o,
  };
}

const firedRun = (output = "still firing"): DetectorRun => ({ detectorId: "d", fired: true, output });
const cleanRun = (output = "clean"): DetectorRun => ({ detectorId: "d", fired: false, output });

describe("runGate — a fix is not closed until the re-audit stops detecting it", () => {
  const planted = readFileSync(join(REPO_ROOT, "targets/calibration", PLANTED), "utf8");

  it("reports persistent (NOT resolved) while the detector still fires, and plans no ticket close", () => {
    const dir = scratch(PLANTED, planted); // "fix" claimed but nothing changed
    const report = runGate([finding()], dir);
    expect(report.results[0]?.status).toBe("persistent");
    expect(report.counts).toEqual({ resolved: 0, persistent: 1, regressed: 0, unverifiable: 0 });
    const plan = planWriteback(report);
    expect(plan[0]?.intent).toBe("none"); // fail-loud core: an unverified fix is never closed
    expect(plan[0]?.reason).toContain("still detected");
  });

  it("reports resolved only once the detector no longer fires, and plans the close", () => {
    const fixed = planted.replace("export async function GET(request: Request) {", "export async function GET() {");
    expect(fixed).not.toEqual(planted);
    const dir = scratch(PLANTED, fixed);
    const report = runGate([finding()], dir);
    expect(report.results[0]?.status).toBe("resolved");
    expect(planWriteback(report)[0]?.intent).toBe("closed");
  });

  it("reports unverifiable — never resolved — for a taxonomy whose detector cannot be re-run, and never closes its ticket", () => {
    // A semgrep REGISTRY rule: #1012's resolver replays only the local harvey-* rule directory (a
    // registry pack needs a network fetch), so this class is still, deliberately, unverifiable.
    const dir = scratch(PLANTED, planted);
    const f = finding({ taxonomy: "javascript.browser.security.open-redirect.js-open-redirect", location: "pages/api/redirect.js:9" });
    const report = runGate([f], dir);
    expect(report.results[0]?.status).toBe("unverifiable");
    expect(report.results[0]?.detail).toContain("no detector re-run resolver");
    const plan = planWriteback(report);
    expect(plan[0]?.intent).toBe("none");
    expect(plan[0]?.reason).toContain("never closed on faith");
  });

  it("a harvey-* finding whose file is gone from the checkout is unverifiable, NOT resolved (#1012)", () => {
    // The failure mode the semgrep resolver must not have: a deleted/moved file makes the rule match
    // nothing. That is an unscanned file, not a fixed bug — the ticket stays open with the reason.
    const dir = scratch(PLANTED, planted);
    const f = finding({ taxonomy: "harvey-open-redirect", location: "pages/api/redirect.js:18" });
    const report = runGate([f], dir);
    expect(report.results[0]?.status).toBe("unverifiable");
    expect(report.results[0]?.detail).toContain("does not exist");
    expect(planWriteback(report)[0]?.intent).toBe("none");
  });

  it("stamps each result with the ticket marker findings-to-tickets filed under, per engagement namespace", () => {
    const dir = scratch(PLANTED, planted);
    const report = runGate([finding()], dir, { engagement: "acme-q3" });
    expect(report.results[0]?.marker).toBe(findingMarker(finding(), "acme-q3"));
    expect(report.engagement).toBe("acme-q3");
  });
});

describe("runGate — prior-run deltas (the accumulated re-audit)", () => {
  it("classifies a previously-resolved finding that fires again as regressed, planned as a reopen", () => {
    const f = finding();
    const dir = scratch("noop.ts", "export {};\n");
    const prior = runGate([f], dir, { rerun: () => cleanRun() });
    expect(prior.results[0]?.status).toBe("resolved");

    const next = runGate([f], dir, { prior, rerun: () => firedRun("fires again at app/api/ar-cors-reflected-safe/route.ts:8") });
    expect(next.results[0]?.status).toBe("regressed");
    expect(next.results[0]?.previousStatus).toBe("resolved");
    const plan = planWriteback(next);
    expect(plan[0]?.intent).toBe("reopened");
    expect(plan[0]?.comment).toContain("reintroduced");
  });

  it("matches prior results by stable identity, not positional id, so re-numbered findings still carry their history", () => {
    const dir = scratch("noop.ts", "export {};\n");
    const prior = runGate([finding({ id: "F-07" })], dir, { rerun: () => cleanRun() });
    // Same finding, re-numbered by a later run (ids reshuffle per run — #457).
    const next = runGate([finding({ id: "F-42" })], dir, { prior, rerun: () => firedRun() });
    expect(next.results[0]?.status).toBe("regressed");
  });

  it("does not re-close a finding already verified resolved by the prior run", () => {
    const f = finding();
    const dir = scratch("noop.ts", "export {};\n");
    const prior = runGate([f], dir, { rerun: () => cleanRun() });
    const next = runGate([f], dir, { prior, rerun: () => cleanRun() });
    expect(next.results[0]?.status).toBe("resolved");
    const plan = planWriteback(next);
    expect(plan[0]?.intent).toBe("none");
    expect(plan[0]?.reason).toContain("already verified resolved");
  });

  it("a persistent finding never becomes regressed without a prior resolved verification", () => {
    const f = finding();
    const dir = scratch("noop.ts", "export {};\n");
    const prior = runGate([f], dir, { rerun: () => firedRun() }); // persistent, never resolved
    const next = runGate([f], dir, { prior, rerun: () => firedRun() });
    expect(next.results[0]?.status).toBe("persistent");
  });
});
