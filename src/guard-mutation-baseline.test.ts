import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { GUARD_SET } from "./guard-mutation-census.js";
import {
  compareGuardMutationCensus, guardMutationDigest, guardMutationReviewRequirements,
  normalizeGuardMutationCensus, parseGuardMutationBaseline, updateGuardMutationBaseline,
  type GuardMutationReceipt, type GuardMutationReview,
} from "./guard-mutation-baseline.js";
import type { StrykerMutant } from "./mutation-scan.js";

type Report = { schemaVersion: string; framework: { name: string; version: string }; files: Record<string, { source: string; mutants: StrykerMutant[] }> };
const fixture = (name: string): string => readFileSync(new URL(`./__fixtures__/guard-mutation/${name}`, import.meta.url), "utf8");
const report = (name = "measured.json"): Report => JSON.parse(fixture(name)) as Report;
const base = () => parseGuardMutationBaseline(JSON.parse(fixture("baseline.json")));
const receipt = (): GuardMutationReceipt => JSON.parse(fixture("measured.receipt.json")) as GuardMutationReceipt;
const cleanGuard = "src/ci-liveness.ts";

function normalize(r: Report, patch: (receipt: GuardMutationReceipt) => void = () => {}) {
  const capture = receipt();
  capture.reportSha256 = guardMutationDigest(JSON.stringify(r));
  for (const [file, entry] of Object.entries(r.files)) if ((GUARD_SET as readonly string[]).includes(file)) capture.sourceSha256[file] = guardMutationDigest(entry.source);
  patch(capture);
  return normalizeGuardMutationCensus(r, capture, capture.reportSha256);
}

function reviewsFor(census: ReturnType<typeof normalize>): GuardMutationReview[] {
  const now = new Date().toISOString();
  return guardMutationReviewRequirements(census).map(({ key, guard }) => ({
    key, owner: "fixture-maintainer", reviewedAt: now, reviewedBy: "fixture-reviewer", sourceCommit: census.receipt.sourceCommit,
    sourceSha256: guard.sourceSha256, reportSha256: census.receipt.reportSha256,
    reason: "Synthetic transition control, retained only to test the update boundary.",
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
  }));
}

describe("guard mutation normalization and blocking baseline (#1890)", () => {
  it("turns a zero-completed guard survivor into an explicit unscored result and retains the count/reason", () => {
    const r = report();
    const [file, entry] = Object.entries(r.files).find(([, value]) => value.mutants.some((mutant) => mutant.status === "Survived"))!;
    const survivor = entry.mutants.find((mutant) => mutant.status === "Survived")!;
    survivor.testsCompleted = 0;
    const census = normalize(r);
    const normalized = census.guards.find((guard) => guard.file === file)!.mutants.find((mutant) => mutant.status === "RuntimeError")!;
    expect(normalized).toMatchObject({ status: "RuntimeError", testsCompleted: 0 });
    expect(normalized.statusReason).toContain("Survived with 0 completed tests");
    expect(census.runnerValidity).toMatchObject({ status: "uncheckable", completedTestEvidence: { zeroCompletedSurvivors: 1 } });
    expect(compareGuardMutationCensus(census, base()).problems.join("\n")).toContain("new-unscored:");

    survivor.testsCompleted = 1;
    expect(normalize(r).runnerValidity).toMatchObject({ status: "valid", completedTestEvidence: { survived: 1, zeroCompletedSurvivors: 0 } });
  });

  it("passes the measured capture projection and conserves every declared population", () => {
    const census = normalize(report());
    expect(compareGuardMutationCensus(census, base())).toMatchObject({ ok: true, problems: [], delta: [] });
    expect(census.guards.map((g) => g.file)).toEqual([...GUARD_SET]);
    for (const g of census.guards) {
      const p = g.population;
      expect(p.attempted).toBe(p.killed + p.survived + p.noCoverage + p.unscored);
      expect(p.excluded).toBe(Number(g.state === "excluded"));
    }
  });

  it("ignores raw mutant ids and report ordering, while preserving semantic identity", () => {
    const r = report();
    r.files = Object.fromEntries(Object.entries(r.files).reverse());
    for (const [file, entry] of Object.entries(r.files)) {
      entry.mutants.reverse();
      entry.mutants.forEach((mutant, index) => { mutant.id = `${file}-${index + 9000}`; });
    }
    expect(compareGuardMutationCensus(normalize(r), base()).ok).toBe(true);
    const mutant = r.files[cleanGuard]!.mutants[0]!;
    mutant.replacement = `${mutant.replacement} /* changed mutation */`;
    mutant.status = "Survived";
    expect(compareGuardMutationCensus(normalize(r), base()).problems.join("\n")).toContain("new-survivor:");
  });

  it.each(["Survived", "NoCoverage", "CompileError", "RuntimeError", "Ignored", "Pending"] as const)("blocks a killed mutant becoming %s", (status) => {
    const r = report(); r.files[cleanGuard]!.mutants[0]!.status = status;
    const comparison = compareGuardMutationCensus(normalize(r), base());
    expect(comparison.ok).toBe(false);
    expect(comparison.problems.join("\n")).toContain(status === "Survived" ? "new-survivor:" : status === "NoCoverage" ? "new-no-coverage:" : "new-unscored:");
    if (status !== "Survived") expect(comparison.problems.join("\n")).toContain(status === "NoCoverage" ? "new-unexercised-guard:" : "new-unscored-guard:");
  });

  it("blocks a missing guard even when that guard had only killed mutants", () => {
    const r = report(); delete r.files[cleanGuard];
    expect(compareGuardMutationCensus(normalize(r), base()).problems).toContain(`missing-guard: ${cleanGuard}`);
    expect(() => updateGuardMutationBaseline(normalize(r), base(), [])).toThrow("incomplete measurement");
  });

  it("does not accept zero generated mutants, or a report with no guard measurements", () => {
    const r = report(); r.files[cleanGuard]!.mutants = [];
    expect(compareGuardMutationCensus(normalize(r), base()).problems).toContain(`unexercised-guard: ${cleanGuard} produced zero mutants`);
    const empty = report(); empty.files = {};
    expect(compareGuardMutationCensus(normalize(empty), base()).problems).toContain("empty-census: zero examined mutants is not evidence");
  });

  it("rejects stale survivors until an explicit update reduces their rows", () => {
    const census = normalize(report("survivor-killed.json"));
    expect(compareGuardMutationCensus(census, base()).problems.join("\n")).toContain("stale-survivor:");
    const updated = updateGuardMutationBaseline(census, base(), []);
    expect(updated.delta.some((line) => line.startsWith("REMOVE survivor:"))).toBe(true);
    expect(updated.baseline.reviews.length).toBe(base().reviews.length - 1);
    expect(compareGuardMutationCensus(census, updated.baseline).ok).toBe(true);
  });

  it("rejects a freshly falsified exclusion and requires actual scored data before reduction", () => {
    const census = normalize(report(), (r) => { r.exclusionChecks[0]!.outcome = "measurable"; r.exclusionChecks[0]!.exitCode = 0; });
    expect(compareGuardMutationCensus(census, base()).problems.join("\n")).toContain("stale-exclusion:");
    expect(() => updateGuardMutationBaseline(census, base(), [])).toThrow("include it in a complete mutation run");
    const measured = normalize(report("exclusion-measurable.json"), (r) => { r.exclusionChecks = []; });
    expect(compareGuardMutationCensus(measured, base()).problems.join("\n")).toContain("stale-exclusion:");
    const updated = updateGuardMutationBaseline(measured, base(), []);
    expect(updated.delta).toContain("REMOVE exclusion:src/recorded-reasons.ts");
    expect(compareGuardMutationCensus(measured, updated.baseline).ok).toBe(true);
  });

  it("does not turn an unavailable falsifier or a changed failure into a retained exclusion", () => {
    const unavailable = normalize(report(), (r) => { r.exclusionChecks[0]!.outcome = "uncheckable"; r.exclusionChecks[0]!.exitCode = 127; });
    expect(compareGuardMutationCensus(unavailable, base()).problems.join("\n")).toContain("uncheckable-exclusion:");
    expect(() => normalize(report(), (r) => { r.exclusionChecks[0]!.attempted = 0; })).toThrow("actual failed instrumentation attempt");
    const changed = normalize(report(), (r) => { r.exclusionChecks[0]!.detail = "A different failed test was observed."; });
    expect(compareGuardMutationCensus(changed, base()).problems.join("\n")).toContain("changed-exclusion-evidence:");
    expect(() => updateGuardMutationBaseline(changed, base(), [])).toThrow("requires a fresh review");
  });

  it("fails when unchanged source loses an individual mutant", () => {
    const r = report(); r.files["src/acceptance-conservation.ts"]!.mutants.shift();
    const census = normalize(r);
    expect(compareGuardMutationCensus(census, base()).problems.join("\n")).toContain("missing-mutant:");
    expect(() => updateGuardMutationBaseline(census, base(), reviewsFor(census))).toThrow("cannot reduce an unchanged source");
  });

  it("requires new owner/review evidence for source changes and new survivors", () => {
    const r = report(); r.files["src/acceptance-conservation.ts"]!.source += "\n// source changed\n";
    const census = normalize(r);
    expect(compareGuardMutationCensus(census, base()).problems.join("\n")).toContain("stale-provenance:");
    expect(() => updateGuardMutationBaseline(census, base(), [])).toThrow("last-reviewed source is stale");
    expect(compareGuardMutationCensus(census, updateGuardMutationBaseline(census, base(), reviewsFor(census)).baseline).ok).toBe(true);
    const newSurvivor = report(); newSurvivor.files[cleanGuard]!.mutants[0]!.status = "Survived";
    expect(() => updateGuardMutationBaseline(normalize(newSurvivor), base(), [])).toThrow("missing owner/remediation review");
  });

  it("binds raw bytes, original source and exact package identities to the measurement", () => {
    const r = report(); const capture = receipt();
    expect(() => normalizeGuardMutationCensus(r, capture, "0".repeat(64))).toThrow("raw report digest");
    capture.reportSha256 = guardMutationDigest(JSON.stringify(r)); capture.sourceSha256[cleanGuard] = "0".repeat(64);
    expect(() => normalizeGuardMutationCensus(r, capture, capture.reportSha256)).toThrow("source differs");
    expect(() => normalize(report(), (r) => { delete r.toolchain.packages.vitest; })).toThrow("every required package");
    expect(compareGuardMutationCensus(normalize(report(), (r) => { r.toolchain.node = "v24.20.0"; }), base()).problems.join("\n")).toContain("toolchain-changed:");
    expect(() => normalize(report(), (r) => { r.toolchain.packages["@stryker-mutator/core"]!.version = "9.6.2"; })).toThrow("toolchain disagree");
  });

  it("rejects malformed status, identity collisions, alias collisions and out-of-source locations", () => {
    const invalid = report(); invalid.files[cleanGuard]!.mutants[0]!.status = "Finished" as StrykerMutant["status"];
    expect(() => normalize(invalid)).toThrow("unknown mutant status");
    const duplicates = report(); duplicates.files[cleanGuard]!.mutants.push(duplicates.files[cleanGuard]!.mutants[0]!);
    expect(() => normalize(duplicates)).toThrow("duplicate");
    const aliases = report(); aliases.files[`./${cleanGuard}`] = aliases.files[cleanGuard]!;
    expect(() => normalize(aliases)).toThrow("duplicate normalized guard path");
    const outside = report(); outside.files[cleanGuard]!.mutants[0]!.location.end.line = 100_000;
    expect(() => normalize(outside)).toThrow("outside captured source");
  });

  it("validates required baseline population fields, every guard, mutant identities and ownership", () => {
    const original = JSON.parse(fixture("baseline.json")) as ReturnType<typeof base>;
    for (const field of ["attempted", "killed", "survived", "noCoverage", "unscored", "excluded"]) {
      const b = structuredClone(original);
      delete (b.census.guards[0]!.population as unknown as Record<string, unknown>)[field];
      expect(() => parseGuardMutationBaseline(b), field).toThrow("population fields");
    }
    const absent = structuredClone(original); absent.census.guards.pop();
    expect(() => parseGuardMutationBaseline(absent)).toThrow("every declared guard");
    const badId = structuredClone(original); badId.census.guards[0]!.mutants[0]!.id = "0".repeat(64);
    expect(() => parseGuardMutationBaseline(badId)).toThrow("identity mismatch");
    const unowned = structuredClone(original); unowned.reviews[0]!.owner = " ";
    expect(() => parseGuardMutationBaseline(unowned)).toThrow("review owner must be nonblank");
    const reasonless = structuredClone(original); delete reasonless.reviews[0]!.remediationIssue;
    expect(() => parseGuardMutationBaseline(reasonless)).toThrow("remediation issue or bounded reason");
  });

  it("expires bounded reasons but permits explicit renewal without bypassing current review validation", () => {
    const census = normalize(report()); const reviews = reviewsFor(census);
    const current = updateGuardMutationBaseline(census, undefined, reviews).baseline;
    const future = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();
    expect(() => parseGuardMutationBaseline(current, future)).toThrow("has expired");
    const previous = parseGuardMutationBaseline(current, future, true);
    expect(() => updateGuardMutationBaseline(census, previous, [], future)).toThrow("has expired");
    const renewal = reviews.map((r) => ({ ...r, reviewedAt: future, expiresAt: new Date(Date.parse(future) + 86400000).toISOString() }));
    expect(() => updateGuardMutationBaseline(census, previous, renewal, future)).not.toThrow();
    const fabricated = reviewsFor(census); fabricated[0]!.reportSha256 = "0".repeat(64);
    expect(() => updateGuardMutationBaseline(census, undefined, fabricated)).toThrow("must cite this capture");
  });
});
