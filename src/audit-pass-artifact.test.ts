import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { buildPassArtifact, findFreshPass, MAX_PASS_AGE_MS, type PassArtifact, ranFromPass, writePassArtifact } from "./audit-pass-artifact.js";
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

describe("buildPassArtifact (#448 — validate at emit, not on the next audit)", () => {
  it("rejects an empty target — the reader keys on it, so a blank one is a silent miss", () => {
    expect(() => buildPassArtifact({ module: "M1", target: "  ", pass: "semantic", generatedAt: iso(0) })).toThrow(/non-empty target/);
  });

  it("rejects a non-ISO timestamp so freshness can always be judged", () => {
    expect(() => buildPassArtifact({ module: "M1", target: "/t", pass: "semantic", generatedAt: "yesterday" })).toThrow(/generatedAt/);
  });

  it("drops empty findings/summary rather than writing hollow fields", () => {
    const a = buildPassArtifact({ module: "M2", target: "/t", pass: "dynamic", generatedAt: iso(0), findings: [] });
    expect(a.findings).toBeUndefined();
    expect(a.summary).toBeUndefined();
  });

  // #502: hotspotFocus is three-valued — true/false is recorded, undefined is left off entirely so a
  // reader can tell "recorded as un-focused" from "never recorded".
  it("carries hotspotFocus:false through, and omits the key when unset", () => {
    expect(buildPassArtifact({ module: "M1", target: "/t", pass: "semantic", generatedAt: iso(0), hotspotFocus: false }).hotspotFocus).toBe(false);
    expect(buildPassArtifact({ module: "M1", target: "/t", pass: "semantic", generatedAt: iso(0) })).not.toHaveProperty("hotspotFocus");
  });

  // #530: the M3 vitals pass carries its top-K ranking so cross-module enrichment fires in the
  // vitals-off-PATH flow. A non-empty ranking is recorded; an empty/absent one omits the key.
  it("carries the M3 top-K hotspot ranking through, and omits the key when empty", () => {
    expect(buildPassArtifact({ module: "M3", target: "/t", pass: "vitals", generatedAt: iso(0), hotspots: ["a.ts", "b.ts"] }).hotspots).toEqual(["a.ts", "b.ts"]);
    expect(buildPassArtifact({ module: "M3", target: "/t", pass: "vitals", generatedAt: iso(0), hotspots: [] })).not.toHaveProperty("hotspots");
    expect(buildPassArtifact({ module: "M3", target: "/t", pass: "vitals", generatedAt: iso(0) })).not.toHaveProperty("hotspots");
  });
});

describe("write → derive round-trip (#448 ↔ #416)", () => {
  const dir = mkdtempSync(join(tmpdir(), "harvey-pass-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  // A context that reads the real files writePassArtifact just wrote — the emit and derive sides
  // meeting on disk, which is exactly how run-audit --artifacts-dir uses them.
  const realFsCtx: RunContext = {
    targetDir: "/engagement/target",
    env: { connected: false, dynamic: false, llm: true },
    exec: () => ({ ok: true, output: "" }),
    exists: (p) => existsSync(p),
    artifactsDir: dir,
    readArtifact: (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : undefined),
    now: NOW,
  };

  it("a written artifact is read back as fresh and derives ran, findings intact", () => {
    const built = buildPassArtifact({
      module: "M1",
      target: "/engagement/target",
      pass: "semantic",
      generatedAt: iso(DAY),
      summary: "triaged",
      findings: [{ id: "TRIAGE-1" } as never],
    });
    const path = writePassArtifact(dir, built);
    expect(path).toBe(join(dir, "M1.pass.json"));

    const r = findFreshPass(realFsCtx, "M1");
    expect(r.fresh).toBe(true);
    if (r.fresh) {
      expect(r.artifact.findings).toHaveLength(1);
      expect(ranFromPass(r.artifact, "mech").status).toBe("ran");
    }
  });

  it("an artifact written for a different target is rejected on read", () => {
    writePassArtifact(dir, buildPassArtifact({ module: "M2", target: "/some/other/app", pass: "dynamic", generatedAt: iso(DAY) }));
    const r = findFreshPass(realFsCtx, "M2");
    expect(r.fresh).toBe(false);
    if (!r.fresh) expect(r.reason).toMatch(/not the audited target/);
  });
});
