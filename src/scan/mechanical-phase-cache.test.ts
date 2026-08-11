import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../findings.js";
import {
  executeMechanicalPhase,
  MECHANICAL_PHASES,
  type MechanicalPhase,
  type MechanicalPhaseCacheOptions,
} from "./mechanical-phase-cache.js";

const finding = (id: string): Finding => ({
  id,
  title: id,
  severity: "Low",
  confidence: "Likely",
  category: "test",
  taxonomy: "M1 — test",
  location: "fixture.ts:1",
  status: "Open",
  evidence: "fixture evidence",
  impact: "fixture impact",
  fix: "fixture fix",
  value: 1,
  ease: 1,
  safety: 1,
});

describe("content-addressed mechanical phase cache (#1864)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const options = (overrides: Partial<MechanicalPhaseCacheOptions> = {}): MechanicalPhaseCacheOptions => {
    const dir = overrides.dir ?? mkdtempSync(join(tmpdir(), "harvey-phase-cache-"));
    if (!overrides.dir) dirs.push(dir);
    const implementations = Object.fromEntries(MECHANICAL_PHASES.map((phase) => [phase, `implementation:${phase}`])) as Record<MechanicalPhase, string>;
    const externalInputs = Object.fromEntries(MECHANICAL_PHASES.map((phase) => [phase, { runtime: "fixture-v1" }])) as unknown as Record<MechanicalPhase, Record<string, string>>;
    return {
      dir,
      mode: "read-write",
      targetRevision: "commit-a",
      targetTree: "tree-a",
      implementation: implementations,
      externalInputs,
      ...overrides,
    };
  };

  const run = (phase: MechanicalPhase, cache: MechanicalPhaseCacheOptions, id: string = phase) =>
    executeMechanicalPhase(phase, cache, () => ({ findings: [finding(id)], scope: { unitsExamined: 1_000, description: "faithful large source fixture" } }));

  it("returns byte-equivalent normalized findings and examined scope on a real cold then warm large-fixture path", async () => {
    const cache = options();
    const cold = await run("structural-ast", cache);
    const execute = vi.fn(() => ({ findings: [finding("must-not-run")], scope: { unitsExamined: 1, description: "wrong" } }));
    const warm = await executeMechanicalPhase("structural-ast", cache, execute);
    expect(cold.cache).toBe("miss");
    expect(warm.cache).toBe("hit");
    expect(execute).not.toHaveBeenCalled();
    expect({ findings: warm.findings, scope: warm.scope }).toEqual({ findings: cold.findings, scope: cold.scope });
  });

  it("rejects a corrupt artifact, recomputes it, and emits a visible reason", async () => {
    const events: string[] = [];
    const cache = options({ onEvent: (message) => events.push(message) });
    const cold = await run("semgrep", cache);
    const artifact = join(cache.dir, "semgrep", `${cold.key}.json`);
    writeFileSync(artifact, JSON.stringify({ schema: 1, phase: "semgrep", key: cold.key, findings: [] }));
    const recomputed = await run("semgrep", cache, "fresh");
    expect(recomputed.cache).toBe("miss");
    expect(recomputed.findings[0]?.id).toBe("fresh");
    expect(events.some((event) => event.includes("CACHE REJECT semgrep") && event.includes("recomputing"))).toBe(true);
    expect(JSON.parse(readFileSync(artifact, "utf8"))).toMatchObject({ targetRevision: "commit-a", targetTree: "tree-a" });
  });

  it("rejects a well-shaped artifact whose finding payload was tampered with", async () => {
    const events: string[] = [];
    const cache = options({ onEvent: (message) => events.push(message) });
    const cold = await run("semgrep", cache);
    const artifact = join(cache.dir, "semgrep", `${cold.key}.json`);
    const parsed = JSON.parse(readFileSync(artifact, "utf8")) as { findings: { id: string }[] };
    parsed.findings[0]!.id = "tampered-but-well-shaped";
    writeFileSync(artifact, JSON.stringify(parsed));
    const recomputed = await run("semgrep", cache, "authentic");
    expect(recomputed.cache).toBe("miss");
    expect(recomputed.findings[0]?.id).toBe("authentic");
    expect(events.some((event) => event.includes("payload checksum mismatch"))).toBe(true);
  });

  it("invalidates only Semgrep when its rules/implementation move", async () => {
    const cache = options();
    await run("semgrep", cache);
    await run("structural-ast", cache);
    const changed = options({ ...cache, implementation: { ...cache.implementation, semgrep: "rules-v2" } });
    expect((await run("semgrep", changed, "semgrep-v2")).cache).toBe("miss");
    expect((await run("structural-ast", changed)).cache).toBe("hit");
  });

  it("cannot reuse a stale artifact when another phase implementation changes", async () => {
    const cache = options();
    await run("structural-ast", cache);
    const changed = options({ ...cache, implementation: { ...cache.implementation, "structural-ast": "ast-v2" } });
    const result = await run("structural-ast", changed, "ast-v2");
    expect(result.cache).toBe("miss");
    expect(result.findings[0]?.id).toBe("ast-v2");
  });

  it("invalidates every cacheable artifact when the pinned target tree changes", async () => {
    const cache = options();
    for (const phase of ["secrets-history", "semgrep", "configuration", "structural-ast"] as const) await run(phase, cache);
    const changed = options({ ...cache, targetRevision: "commit-b", targetTree: "tree-b" });
    for (const phase of ["secrets-history", "semgrep", "configuration", "structural-ast"] as const) {
      expect((await run(phase, changed, `${phase}-new-tree`)).cache).toBe("miss");
    }
  });

  it("always reruns advisory/network work and names why it is non-cacheable", async () => {
    const cache = options();
    const execute = vi.fn(() => ({ findings: [finding("advisory")], scope: { unitsExamined: 1, description: "one lockfile" } }));
    const first = await executeMechanicalPhase("dependency-advisory", cache, execute);
    const second = await executeMechanicalPhase("dependency-advisory", cache, execute);
    expect(first.cache).toBe("non-cacheable");
    expect(second.cache).toBe("non-cacheable");
    expect(first.reason).toContain("no immutable response identity");
    expect(execute).toHaveBeenCalledTimes(2);
  });

  it("forced-cold mode re-earns a hit and fails if the result changes", async () => {
    const cache = options();
    await run("semgrep", cache);
    const verify = { ...cache, mode: "verify" as const };
    await expect(run("semgrep", verify, "changed-on-cold-run")).rejects.toThrow("forced-cold result differs");
    expect((await run("semgrep", verify)).cache).toBe("recomputed");
  });

  it("a miss executes the phase; it can never be represented as assessed-clean", async () => {
    const cache = options();
    const execute = vi.fn(() => ({ findings: [finding("found-on-miss")], scope: { unitsExamined: 7, description: "seven files" } }));
    const result = await executeMechanicalPhase("configuration", cache, execute);
    expect(result.cache).toBe("miss");
    expect(execute).toHaveBeenCalledOnce();
    expect(result.findings.map((row) => row.id)).toEqual(["found-on-miss"]);
    expect(result.scope.unitsExamined).toBe(7);
  });
});
