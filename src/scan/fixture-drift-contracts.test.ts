import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { JscpdReport, KnipReport } from "../quality-scan.js";
import type { TruffleHogResult } from "./secrets.js";
import type { VitalsReport } from "../hotspot-scan.js";
import type { StrykerReport } from "../mutation-scan.js";
import type { LighthouseResult } from "../lighthouse.js";
import {
  checkJscpdContract,
  checkKnipContract,
  checkTruffleHogContract,
  checkVitalsContract,
  checkStrykerContract,
  checkLighthouseContract,
  checkSemgrepFixtureContract,
  checkGitleaksFixtureContract,
  classifyVitalsGitScopeFailure,
  type GitScopeSanity,
  type SemgrepContractOutput,
  type GitleaksContractResult,
} from "./fixture-drift-contracts.js";

// These guard the SHAPE the drift check (src/cli/fixture-drift.ts, needs the binaries) enforces on a
// FRESH run: each contract passes its own committed fixture with no violations, and FIRES on the
// specific #1063-class shape drift its parser would be silently killed by. A gate that has never
// fired on a known-bad input is not evidence.

function load<T>(path: string): T {
  const parsed = JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as T & { _note?: string };
  delete parsed._note;
  return parsed;
}

describe("checkJscpdContract", () => {
  const fixture = load<JscpdReport>("./__fixtures__/jscpd/jscpd-4.2.5-report.json");
  it("passes the committed jscpd 4.2.5 fixture", () => {
    expect(checkJscpdContract(fixture)).toEqual([]);
  });
  it("fires when a duplicate's line count is a string, not a number", () => {
    const broken = { ...fixture, duplicates: fixture.duplicates.map((d) => ({ ...d, lines: String(d.lines) as unknown as number })) };
    expect(checkJscpdContract(broken).join("\n")).toContain(".lines is");
  });
  it("fires when duplicates is empty (corpus produced no clones)", () => {
    expect(checkJscpdContract({ ...fixture, duplicates: [] }).join("\n")).toContain("duplicates is empty");
  });
});

describe("checkKnipContract", () => {
  const fixture = load<KnipReport>("./__fixtures__/knip/knip-5.88.1-report.json");
  it("passes the committed knip 5.88.1 fixture", () => {
    expect(checkKnipContract(fixture)).toEqual([]);
  });
  it("fires when an export record is a bare string instead of {name,line}", () => {
    const broken: KnipReport = { ...fixture, issues: fixture.issues.map((i) => ({ ...i, exports: ["neverImported"] as unknown as typeof i.exports })) };
    expect(checkKnipContract(broken).join("\n")).toContain("not a {name:string, line:number} record");
  });
  it("fires when no dead files are reported", () => {
    expect(checkKnipContract({ ...fixture, files: [] }).join("\n")).toContain("files is not a non-empty array");
  });
});

describe("checkTruffleHogContract", () => {
  const rows8 = load<TruffleHogResult[]>("./__fixtures__/trufflehog/trufflehog-3.96.0-git-unverified.json");
  const rows10 = load<TruffleHogResult[]>("./__fixtures__/trufflehog-git-history/trufflehog-3.96.0-git-history.json");
  it("passes both committed trufflehog 3.96.0 fixtures", () => {
    expect(checkTruffleHogContract(rows8)).toEqual([]);
    expect(checkTruffleHogContract(rows10)).toEqual([]);
  });
  it("fires when Verified is a string, not a boolean", () => {
    const broken = rows8.map((r) => ({ ...r, Verified: "false" as unknown as boolean }));
    expect(checkTruffleHogContract(broken).join("\n")).toContain(".Verified is not a boolean");
  });
  it("fires when the #1078 rotation_guide is gone", () => {
    const broken = rows8.map((r) => ({ ...r, ExtraData: {} }));
    expect(checkTruffleHogContract(broken).join("\n")).toContain("rotation_guide");
  });
  it("fires when no record sits at the planted path", () => {
    expect(checkTruffleHogContract([]).join("\n")).toContain("no TruffleHog records");
  });
});

describe("checkVitalsContract", () => {
  const fixture = load<VitalsReport>("../__fixtures__/vitals-report.json");
  it("passes the committed vitals 0.2.0 fixture", () => {
    expect(checkVitalsContract(fixture)).toEqual([]);
  });
  it("fires when risk_score is a string, not a number (the sort key)", () => {
    const broken: VitalsReport = { ...fixture, hotspots: fixture.hotspots.map((h) => ({ ...h, risk_score: String(h.risk_score) as unknown as number })) };
    expect(checkVitalsContract(broken).join("\n")).toContain(".risk_score is");
  });
  it("fires when a top-level array is missing", () => {
    expect(checkVitalsContract({ ...fixture, hotspots: undefined as unknown as VitalsReport["hotspots"] }).join("\n")).toContain("hotspots is not an array");
  });
});

describe("classifyVitalsGitScopeFailure", () => {
  const fixture = load<VitalsReport>("../__fixtures__/vitals-report.json");
  const emptied: VitalsReport = { ...fixture, hotspots: [], coupling: [], knowledge_risk: [] };

  it("does not fire on the committed fixture (git-derived sections are populated)", () => {
    expect(classifyVitalsGitScopeFailure(fixture)).toBeUndefined();
  });

  it("fires when all three git-derived sections are empty but an independent git log found commits with no error (#1206's observed shape)", () => {
    const withSanity = { ...emptied, _gitScopeSanity: { commits: 72, returncode: 0, stderr: null, scopeMatchesToplevel: true } };
    const reason = classifyVitalsGitScopeFailure(withSanity);
    expect(reason).toContain("#1206");
    expect(reason).toContain("72 commit(s)");
    // The claim the evidence supports. Asserting the hedge, not just the id, is what stops the
    // over-claim reappearing the next time someone rewrites the sentence.
    expect(reason).toContain("CONSISTENT WITH");
  });

  it("does NOT fire when the sections are empty and there is no independent sanity check to corroborate it", () => {
    expect(classifyVitalsGitScopeFailure(emptied)).toBeUndefined();
  });

  it("does NOT fire when the independent sanity check itself errored (can't distinguish real-empty from swallowed-failure)", () => {
    const withSanity = { ...emptied, _gitScopeSanity: { commits: 0, returncode: 128, stderr: "fatal: not a git repository", scopeMatchesToplevel: true } };
    expect(classifyVitalsGitScopeFailure(withSanity)).toBeUndefined();
  });

  // The case above short-circuits on commits === 0, so it never reaches the returncode guard and a
  // one-clause mutation there survives. This one has commits > 0 so returncode is the ONLY clause
  // that can reject it (raised by PR #1398's acceptance verifier).
  it("does NOT fire when the sanity check reported commits AND a non-zero returncode (isolates the returncode clause)", () => {
    const withSanity = { ...emptied, _gitScopeSanity: { commits: 40, returncode: 128, stderr: "fatal: bad revision", scopeMatchesToplevel: true } };
    expect(classifyVitalsGitScopeFailure(withSanity)).toBeUndefined();
  });

  it("does NOT fire when the sanity check found zero commits (a genuinely empty window is a real bug, not the #1206 flake)", () => {
    const withSanity = { ...emptied, _gitScopeSanity: { commits: 0, returncode: 0, stderr: null, scopeMatchesToplevel: true } };
    expect(classifyVitalsGitScopeFailure(withSanity)).toBeUndefined();
  });

  // The competing cause with the identical signature. Absorbing it as NOT RUN would let a regression
  // in seed.py's realpath() pass silently; it has to stay a loud contract FAIL.
  it("does NOT fire when the seeded path is not the resolved git toplevel (scope mismatch, not the swallow class)", () => {
    const withSanity = { ...emptied, _gitScopeSanity: { commits: 72, returncode: 0, stderr: null, scopeMatchesToplevel: false } };
    expect(classifyVitalsGitScopeFailure(withSanity)).toBeUndefined();
  });

  it("does NOT fire when the capture predates scopeMatchesToplevel and cannot rule the mismatch out", () => {
    const withSanity = { ...emptied, _gitScopeSanity: { commits: 72, returncode: 0, stderr: null } };
    expect(classifyVitalsGitScopeFailure(withSanity)).toBeUndefined();
  });

  it("does NOT fire when only one of the three sections is empty (not the observed all-empty shape)", () => {
    const partiallyEmptied: VitalsReport & { _gitScopeSanity: GitScopeSanity } = {
      ...fixture,
      coupling: [],
      _gitScopeSanity: { commits: 72, returncode: 0, stderr: null, scopeMatchesToplevel: true },
    };
    expect(classifyVitalsGitScopeFailure(partiallyEmptied)).toBeUndefined();
  });
});

describe("checkStrykerContract", () => {
  const fixture = load<StrykerReport>("./__fixtures__/stryker/stryker-9.6.1-m8-calibration.json");
  it("passes the committed Stryker 9.6.1 fixture", () => {
    expect(checkStrykerContract(fixture)).toEqual([]);
  });
  it("fires when a mutant status is not a string", () => {
    const files = Object.fromEntries(
      Object.entries(fixture.files).map(([k, f]) => [k, { ...f, mutants: f.mutants.map((m) => ({ ...m, status: 1 as unknown as typeof m.status })) }]),
    );
    expect(checkStrykerContract({ ...fixture, files }).join("\n")).toContain(".status is");
  });
  it("fires when files is empty", () => {
    expect(checkStrykerContract({ ...fixture, files: {} }).join("\n")).toContain("files is empty");
  });
});

describe("checkLighthouseContract", () => {
  const fixture = load<LighthouseResult>("../__fixtures__/lighthouse-report.json");
  it("passes the committed Lighthouse 13.4.0 fixture", () => {
    expect(checkLighthouseContract(fixture)).toEqual([]);
  });
  it("fires when a numeric audit's numericValue is a string (the #1063 shape)", () => {
    const broken: LighthouseResult = {
      ...fixture,
      audits: { ...fixture.audits, "largest-contentful-paint": { ...fixture.audits!["largest-contentful-paint"], numericValue: "4650" as unknown as number } },
    };
    expect(checkLighthouseContract(broken).join("\n")).toContain("numericValue is");
  });
  it("fires when categories.performance.score is missing", () => {
    expect(checkLighthouseContract({ ...fixture, categories: {} }).join("\n")).toContain("categories.performance.score");
  });
});

// #1266: FIXTURE-INVENTORY.md claimed "every CAPTURED fixture now has a drift check" — false for
// semgrep and gitleaks, which #1165 recaptured 24 minutes before #1170 landed the drift-check
// family and neither was registered in it. These two contracts close that gap.
describe("checkSemgrepFixtureContract", () => {
  const fixture = load<SemgrepContractOutput>("./__fixtures__/semgrep/semgrep-1.164.0-corpus.json");
  it("passes the committed semgrep 1.164.0 fixture", () => {
    expect(checkSemgrepFixtureContract(fixture)).toEqual([]);
  });
  it("fires when the free-count rule (harvey-service-role-in-client) no longer fires", () => {
    const broken = { ...fixture, results: fixture.results!.filter((r) => !r.check_id.endsWith("harvey-service-role-in-client")) };
    expect(checkSemgrepFixtureContract(broken).join("\n")).toContain('no result with check_id ending "harvey-service-role-in-client"');
  });
  it("fires when a registry rule's array-form cwe/owasp become bare strings (the #455 shape)", () => {
    const results = fixture.results!.map((r) =>
      r.check_id.endsWith("cors-misconfiguration.cors-misconfiguration")
        ? { ...r, extra: { ...r.extra, metadata: { ...r.extra?.metadata, cwe: "CWE-346" } } }
        : r,
    );
    expect(checkSemgrepFixtureContract({ ...fixture, results }).join("\n")).toContain("cors-misconfiguration: metadata.cwe/owasp are not both arrays");
  });
  it("fires when the bare-string cwe/owasp rule (#976) gains array-form metadata instead", () => {
    const results = fixture.results!.map((r) =>
      r.check_id.endsWith("bypass-tls-verification") ? { ...r, extra: { ...r.extra, metadata: { ...r.extra?.metadata, cwe: ["CWE-295"], owasp: ["A02:2021"] } } } : r,
    );
    expect(checkSemgrepFixtureContract({ ...fixture, results }).join("\n")).toContain("bypass-tls-verification: metadata.cwe/owasp are not both bare strings");
  });
  it("fires when results is empty", () => {
    expect(checkSemgrepFixtureContract({ ...fixture, results: [] }).join("\n")).toContain("results is empty");
  });
});

describe("checkGitleaksFixtureContract", () => {
  const fixture = load<GitleaksContractResult[]>("./__fixtures__/gitleaks/gitleaks-8.30.1-corpus.json");
  it("passes the committed gitleaks 8.30.1 fixture", () => {
    expect(checkGitleaksFixtureContract(fixture)).toEqual([]);
  });
  it("fires when the plain private-key rule no longer fires", () => {
    const broken = fixture.filter((r) => !(r.RuleID === "private-key" && r.File.endsWith("certs/key.pem")));
    expect(checkGitleaksFixtureContract(broken).join("\n")).toContain('no record with RuleID "private-key" at a File ending "certs/key.pem"');
  });
  it("fires when the #210 demo co-location breaks (the two rules land on different lines)", () => {
    const broken = fixture.map((r) => (r.RuleID === "supabase-demo-key-marker" ? { ...r, StartLine: (r.StartLine ?? 0) + 1 } : r));
    expect(checkGitleaksFixtureContract(broken).join("\n")).toContain("no longer co-locate");
  });
  it("fires when results is empty", () => {
    expect(checkGitleaksFixtureContract([]).join("\n")).toContain("no gitleaks records");
  });
});
