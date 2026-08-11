// #1546: the "semgrep is not runnable here" branch of rerunDetector, in a venue that ACTUALLY RUNS.
//
// Both assertions below existed already, as `it.skipIf(SEMGREP_PRESENT)` cases inside
// src/fix/detector-rerun.test.ts — a heavy-CLI-only file. Heavy CLI jobs install the mechanical
// binaries, so `SEMGREP_PRESENT` is true there and both skipped; they also skipped on any dev
// machine with semgrep installed. Net effect: `rerunDetector`'s notRun composition, including the
// registry-pack-specific reason #1368 added, was executed by NO automated venue at all.
//
// That is the coverage guard's own doctrine turned inward. A `notRun` that silently becomes a
// `resolved` tells a client their finding was fixed when nothing was measured, so the branch that
// prevents it is exactly the branch that must be watched.
//
// The skip is replaced by a module-level ENOENT fake for `semgrep` — the approach
// src/scan/semgrep.test.ts already uses and which runs in the light suite on every PR. It is
// deterministic and binary-independent, so the result no longer depends on what the runner happens
// to have installed. What it does NOT cover, stated rather than left to be discovered: a semgrep
// that IS present and fails for some other reason (a live network outage on the registry fetch).
// That path is the same `execFile` error branch with a different message, and MEASURED
// 2026-07-30 in #1368, forcing a real network failure through a dead proxy took 96s — an unusable
// test time, which is why the ENOENT shape is the one exercised here.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../findings.js";
import { rerunDetector } from "./detector-rerun.js";
import { detectorHalfClean } from "./verify.js";

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execFile: vi.fn((bin: string, args: string[], opts: unknown, callback: (err: Error | null, stdout: string, stderr: string) => void) => {
      if (bin === "semgrep") {
        const err = new Error("spawn semgrep ENOENT") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        queueMicrotask(() => callback(err, "", ""));
        return {} as never;
      }
      return actual.execFile(bin as never, args as never, opts as never, callback as never);
    }),
    execFileSync: vi.fn((bin: string, args: string[], opts?: unknown) => {
      if (bin === "semgrep") {
        const err = new Error("spawnSync semgrep ENOENT") as NodeJS.ErrnoException;
        err.code = "ENOENT";
        throw err;
      }
      return actual.execFileSync(bin, args, opts as never);
    }),
  };
});

const created: string[] = [];
afterEach(() => {
  for (const dir of created.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function scratch(rel: string, body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-rerun-offline-"));
  created.push(dir);
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), body);
  return dir;
}

const finding = (o: Partial<Finding>): Finding => ({
  id: "F", title: "t", severity: "Medium", confidence: "Confirmed", category: "Next.js/web footgun",
  taxonomy: "x", location: "x:1", status: "Open", evidence: "e", impact: "i", fix: "f",
  precisionTier: "high", value: 3, ease: 3, safety: 3, ...o,
});

// The source bodies are irrelevant — semgrep never runs. The FILE must exist, because rerunDetector
// returns a different (also correct) notRun for a missing file, and a test that passed through the
// wrong branch would be asserting the right string for the wrong reason.
const HARVEY_RULE = "harvey-open-redirect";
const REGISTRY_RULE = "javascript.browser.security.open-redirect.js-open-redirect";

describe("rerunDetector is notRun, never clean, when semgrep is not runnable (#1546)", async () => {
  it("a harvey-* rule reports semgrep's absence rather than an unearned clean", async () => {
    const dir = scratch("pages/api/redirect.js", "export default function handler(req, res) { res.redirect(302, req.query.u); }\n");
    const run = await rerunDetector(finding({ taxonomy: HARVEY_RULE, location: "pages/api/redirect.js:1" }), dir);
    expect(run.notRun).toContain("semgrep not found on PATH");
    expect(run.fired).toBe(false);
    // The half that matters commercially: a notRun must never satisfy the detector half of green.
    expect(detectorHalfClean(run)).toBe(false);
  });

  it("a registry-pack rule reports the REGISTRY-SPECIFIC reason, not just the shared failure", async () => {
    const dir = scratch("components/LocationNav.jsx", 'export default () => { window.location = new URLSearchParams(location.search).get("to"); };\n');
    const run = await rerunDetector(finding({ taxonomy: REGISTRY_RULE, confidence: "Review", location: "components/LocationNav.jsx:1" }), dir);
    expect(run.notRun).toContain("semgrep not found on PATH");
    // #1368's widened reason. Asserting only the shared "semgrep not found" half would pass with the
    // registry branch deleted, which is the coverage this file exists to add.
    expect(run.notRun).toContain("registry-pack rule");
    expect(run.notRun).toContain(REGISTRY_RULE);
    expect(detectorHalfClean(run)).toBe(false);
  });

  it("NEGATIVE CONTROL: a detector that needs no binary still runs to a real verdict under the same mock", async () => {
    // Proves the mock is scoped to semgrep and has not simply broken every re-run into notRun —
    // without this, both assertions above would pass for a reason that has nothing to do with them.
    const dir = scratch("app/api/x/route.ts", "export async function GET(request: Request) {\n  return new Response('ok');\n}\n");
    const run = await rerunDetector(finding({ taxonomy: "M5 — Unused parameter", location: "app/api/x/route.ts:1", severity: "Low" }), dir);
    expect(run.notRun).toBeUndefined();
    expect(run.fired).toBe(true);
  });
});
