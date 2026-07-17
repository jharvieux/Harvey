import { describe, expect, it } from "vitest";
import { findFreshPass, MAX_PASS_AGE_MS, type PassArtifact, ranFromPass } from "./audit-pass-artifact.js";
import type { RunContext } from "./audit-runner.js";

const NOW = Date.parse("2026-07-17T12:00:00Z");
const iso = (msAgo: number): string => new Date(NOW - msAgo).toISOString();
const DAY = 24 * 60 * 60 * 1000;

const artifact = (over: Partial<PassArtifact> = {}): PassArtifact => ({
  module: "M1",
  target: "/target",
  pass: "semantic",
  generatedAt: iso(DAY),
  ...over,
});

// A context whose artifactsDir is set and whose readArtifact returns `stored` for the M1 path.
const ctx = (stored: unknown, over: Partial<RunContext> = {}): RunContext => ({
  targetDir: "/target",
  env: { connected: false, dynamic: false, llm: false },
  exec: () => ({ ok: true, output: "" }),
  exists: () => true,
  artifactsDir: "/artifacts",
  readArtifact: () => stored,
  now: NOW,
  ...over,
});

describe("findFreshPass (#416 — derive ran only from a fresh, target-matching artifact)", () => {
  it("accepts a fresh artifact that matches the module and target", () => {
    const r = findFreshPass(ctx(artifact()), "M1");
    expect(r.fresh).toBe(true);
    if (r.fresh) expect(r.artifact.pass).toBe("semantic");
  });

  it("returns not-fresh with no reason when no artifacts dir is configured — probe keeps its normal wording", () => {
    const r = findFreshPass(ctx(artifact(), { artifactsDir: undefined }), "M1");
    expect(r).toEqual({ fresh: false });
  });

  it("returns not-fresh with no reason when the artifact file is absent", () => {
    const r = findFreshPass(ctx(artifact(), { exists: () => false }), "M1");
    expect(r).toEqual({ fresh: false });
  });

  it("REJECTS a stale artifact (older than the freshness window) and says so", () => {
    const r = findFreshPass(ctx(artifact({ generatedAt: iso(MAX_PASS_AGE_MS + DAY) })), "M1");
    expect(r.fresh).toBe(false);
    if (!r.fresh) expect(r.reason).toMatch(/stale/);
  });

  it("accepts an artifact right at the freshness boundary but rejects one just past it", () => {
    expect(findFreshPass(ctx(artifact({ generatedAt: iso(MAX_PASS_AGE_MS - 1000) })), "M1").fresh).toBe(true);
    expect(findFreshPass(ctx(artifact({ generatedAt: iso(MAX_PASS_AGE_MS + 1000) })), "M1").fresh).toBe(false);
  });

  it("REJECTS an artifact whose target does not match the audited directory", () => {
    const r = findFreshPass(ctx(artifact({ target: "/some-other-target" })), "M1");
    expect(r.fresh).toBe(false);
    if (!r.fresh) expect(r.reason).toMatch(/not the audited target/);
  });

  it("REJECTS an artifact that names a different module than the one being probed", () => {
    const r = findFreshPass(ctx(artifact({ module: "M2" })), "M1");
    expect(r.fresh).toBe(false);
    if (!r.fresh) expect(r.reason).toMatch(/different module/);
  });

  it("REJECTS an artifact with no valid timestamp — freshness cannot be judged", () => {
    const r = findFreshPass(ctx(artifact({ generatedAt: "not-a-date" })), "M1");
    expect(r.fresh).toBe(false);
    if (!r.fresh) expect(r.reason).toMatch(/generatedAt/);
  });

  it("falls back to Date.now() when no clock is injected (a year-old artifact is stale)", () => {
    const r = findFreshPass(ctx(artifact({ generatedAt: "2020-01-01T00:00:00Z" }), { now: undefined }), "M1");
    expect(r.fresh).toBe(false);
  });
});

describe("ranFromPass", () => {
  it("carries the pass findings into the outcome when present", () => {
    const out = ranFromPass(artifact({ findings: [{ id: "F1" } as never] }), "mech");
    expect(out.status).toBe("ran");
    expect(out.findings).toHaveLength(1);
    expect(out.detail).toContain("semantic pass");
  });

  it("omits findings when the pass produced none", () => {
    expect(ranFromPass(artifact(), "mech").findings).toBeUndefined();
  });
});
