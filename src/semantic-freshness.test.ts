import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { MAX_PASS_AGE_MS } from "./audit-pass-artifact.js";
import type { Finding } from "./findings.js";
import { SEMANTIC_CORPUS, type SemanticTarget } from "./scan/semantic-corpus.js";
import { assessSemanticArtifact, assessSemanticFreshness } from "./semantic-freshness.js";

// Anchored to the corpus's own oldest recorded date, so the tests move with the corpus instead of
// pinning a literal that a new target would silently invalidate.
const oldest = Math.min(...SEMANTIC_CORPUS.map((t) => Date.parse(t.recordedOn)));
const newest = Math.max(...SEMANTIC_CORPUS.map((t) => Date.parse(t.recordedOn)));
const DAY = 24 * 60 * 60 * 1000;
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(REPO_ROOT, "src", "cli", "validate-semantic-freshness.ts");
const temporaryDirectories: string[] = [];

// An empty corpus would make every assertion in this file pass over zero rows. Throwing at load
// says so once, rather than leaving seven green tests that measured nothing.
const first = SEMANTIC_CORPUS[0];
if (!first) throw new Error("SEMANTIC_CORPUS is empty — every assertion in this file would be vacuous");

const finding = (location: string, mechanism: string, index: number): Finding => ({
  id: `semantic-${index}`,
  title: mechanism,
  severity: "High",
  confidence: "Confirmed",
  category: "Security",
  taxonomy: "M1 — Semantic review",
  location,
  status: "Open",
  evidence: mechanism,
  impact: "fixture",
  fix: "fixture",
  value: 3,
  ease: 3,
  safety: 3,
});

const passingFindings = (target: SemanticTarget): Finding[] =>
  target.entries
    .filter((entry) => entry.kind === "positive")
    .map((entry, index) => finding(entry.locations[0] ?? "missing", entry.match[0] ?? "missing", index));

const accumulatedSlot = (target: SemanticTarget, semanticGeneratedAt: string, topGeneratedAt: string) => ({
  module: "M1",
  target: `/tmp/${target.slug}`,
  pass: "connected",
  generatedAt: topGeneratedAt,
  findings: [],
  priorPasses: [
    {
      module: "M1",
      target: `/tmp/${target.slug}`,
      pass: "semantic",
      generatedAt: semanticGeneratedAt,
      findings: passingFindings(target),
    },
  ],
});

const runFreshnessCli = (slots: (target: SemanticTarget) => unknown, now: string) => {
  const root = mkdtempSync(join(tmpdir(), "harvey-semantic-freshness-"));
  temporaryDirectories.push(root);
  for (const target of SEMANTIC_CORPUS) {
    const targetDir = join(root, target.slug);
    mkdirSync(targetDir, { recursive: true });
    writeFileSync(join(targetDir, "M1.pass.json"), JSON.stringify(slots(target)));
  }
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", CLI, "--artifacts-dir", root, "--now", now, "--json"],
    { cwd: REPO_ROOT, encoding: "utf8" },
  );
  if (result.error) throw result.error;
  return result;
};

afterEach(() => {
  for (const dir of temporaryDirectories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("assessSemanticArtifact", () => {
  const now = Date.parse("2026-09-03T00:00:00Z");
  const fresh = "2026-09-02T00:00:00Z";

  it("selects and scores a fresh semantic prior pass instead of the newer connected slot member", () => {
    const result = assessSemanticArtifact(accumulatedSlot(first, fresh, fresh), first, "/tmp/M1.pass.json", now);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.generatedAt).toBe(fresh);
    expect(result.score.positivesCaught).toBe(result.score.positivesTotal);
  });

  it("rejects a stale semantic prior pass even when the top-level connected member is fresh", () => {
    const result = assessSemanticArtifact(
      accumulatedSlot(first, "2026-07-01T00:00:00Z", fresh),
      first,
      "/tmp/M1.pass.json",
      now,
    );

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain("stale");
  });

  it("rejects fresh semantic evidence that scores below the recorded recall floor", () => {
    const result = assessSemanticArtifact(
      { module: "M1", target: "/tmp/target", pass: "semantic", generatedAt: fresh, findings: [] },
      first,
      "/tmp/M1.pass.json",
      now,
    );

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain("regressed below the recorded recall floor");
  });

  it("rejects a recorded non-vulnerability even when every positive is caught", () => {
    const target = SEMANTIC_CORPUS.find((candidate) => candidate.slug === "superredhat");
    if (!target) throw new Error("superredhat is missing from SEMANTIC_CORPUS");
    const falsePositive = finding("app/api/import/route.ts", "unauthenticated", 999);
    const result = assessSemanticArtifact(
      {
        module: "M1",
        target: "/tmp/superredhat",
        pass: "semantic",
        generatedAt: fresh,
        findings: [...passingFindings(target), falsePositive],
      },
      target,
      "/tmp/M1.pass.json",
      now,
    );

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.reason).toContain("F-N1");
  });
});

describe("validate-semantic-freshness CLI", () => {
  // Exact-head failing direction reproduced before the repair: this population exited 0 and every
  // row named the fresh top-level connected timestamp as `pass-artifact`, masking the stale semantic
  // member beneath it. The spawned production entry point now has to reject all four slots.
  it("fails an accumulated slot whose fresh non-semantic member masks stale semantic evidence", () => {
    const fresh = "2026-09-02T00:00:00Z";
    const result = runFreshnessCli(
      (target) => accumulatedSlot(target, "2026-07-01T00:00:00Z", fresh),
      "2026-09-03T00:00:00Z",
    );

    expect(result.status).toBe(1);
    const output = JSON.parse(result.stdout) as {
      rows: { source: string }[];
      semanticScores: unknown[];
      artifactProblems: { slug: string; reason: string }[];
    };
    expect(output.rows.every((row) => row.source === "corpus-record")).toBe(true);
    expect(output.semanticScores).toEqual([]);
    expect(output.artifactProblems.map((problem) => problem.slug)).toEqual(SEMANTIC_CORPUS.map((target) => target.slug));
    expect(output.artifactProblems.every((problem) => problem.reason.includes("stale"))).toBe(true);
  });

  it("passes only when every accumulated slot contains fresh semantic evidence that still scores", () => {
    const fresh = "2026-09-02T00:00:00Z";
    const result = runFreshnessCli(
      (target) => accumulatedSlot(target, fresh, fresh),
      "2026-09-03T00:00:00Z",
    );

    expect(result.status).toBe(0);
    const output = JSON.parse(result.stdout) as {
      rows: { source: string }[];
      semanticScores: { accepted: boolean }[];
      artifactProblems: unknown[];
    };
    expect(output.rows.every((row) => row.source === "pass-artifact")).toBe(true);
    expect(output.semanticScores).toHaveLength(SEMANTIC_CORPUS.length);
    expect(output.semanticScores.every((score) => score.accepted)).toBe(true);
    expect(output.artifactProblems).toEqual([]);
  });
});

describe("assessSemanticFreshness", () => {
  it("has a population to measure — an empty corpus would make every assertion below vacuous", () => {
    expect(SEMANTIC_CORPUS.length).toBeGreaterThan(0);
  });

  it("reports every corpus target as fresh while the newest recorded date is inside the window", () => {
    const r = assessSemanticFreshness(oldest + 1 * DAY, {});
    expect(r.rows).toHaveLength(SEMANTIC_CORPUS.length);
    expect(r.stale).toEqual([]);
    expect(r.rows.every((row) => row.daysLeft > 0)).toBe(true);
  });

  // The failing direction. Without this the gate is one nobody has watched go red.
  it("reports every target STALE once the clock passes the window on the newest recorded date", () => {
    const r = assessSemanticFreshness(newest + MAX_PASS_AGE_MS + DAY, {});
    expect(r.stale).toHaveLength(SEMANTIC_CORPUS.length);
    expect(r.stale.every((row) => row.daysLeft < 0)).toBe(true);
  });

  it("goes stale exactly at the window boundary, not before it", () => {
        const at = Date.parse(first.recordedOn);
    const inside = assessSemanticFreshness(at + MAX_PASS_AGE_MS, {}).rows.find((r) => r.slug === first.slug);
    const outside = assessSemanticFreshness(at + MAX_PASS_AGE_MS + 1, {}).rows.find((r) => r.slug === first.slug);
    expect(inside?.stale).toBe(false);
    expect(outside?.stale).toBe(true);
  });

  it("prefers a recorded pass artifact over the corpus record, and counts the fallbacks", () => {
        const recent = new Date(newest + 10 * DAY).toISOString();
    const r = assessSemanticFreshness(newest + 11 * DAY, { [first.slug]: recent });
    const row = r.rows.find((x) => x.slug === first.slug);
    expect(row?.source).toBe("pass-artifact");
    expect(row?.ageDays).toBe(1);
    expect(r.withoutArtifact).toBe(SEMANTIC_CORPUS.length - 1);
  });

  // A fresh artifact must be able to RESCUE a target whose corpus record has aged out — otherwise
  // the alarm could never be cleared by doing the work it asks for, only by editing the corpus.
  it("a fresh pass artifact clears a target whose corpus record is already past the window", () => {
    const clock = newest + MAX_PASS_AGE_MS + 5 * DAY;
        const withoutArtifact = assessSemanticFreshness(clock, {}).rows.find((r) => r.slug === first.slug);
    const withArtifact = assessSemanticFreshness(clock, { [first.slug]: new Date(clock - DAY).toISOString() }).rows.find(
      (r) => r.slug === first.slug,
    );
    expect(withoutArtifact?.stale).toBe(true);
    expect(withArtifact?.stale).toBe(false);
  });

  it("treats an unparseable artifact date as absent rather than as never-stale NaN", () => {
        const r = assessSemanticFreshness(newest + MAX_PASS_AGE_MS + DAY, { [first.slug]: "not-a-date" });
    const row = r.rows.find((x) => x.slug === first.slug);
    expect(row?.source).toBe("corpus-record");
    expect(row?.stale).toBe(true);
  });
});
