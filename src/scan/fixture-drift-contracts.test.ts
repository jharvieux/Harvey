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
  churnOnlySwallowDiagnosis,
  classifyFreshRun,
  renderDriftVerdict,
  VITALS_DRIFT_CONTRACT,
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
  const rows8 = load<TruffleHogResult[]>("./__fixtures__/trufflehog/trufflehog-3.97.0-git-unverified.json");
  const rows10 = load<TruffleHogResult[]>("./__fixtures__/trufflehog-git-history/trufflehog-3.97.0-git-history.json");
  it("passes both committed trufflehog 3.97.0 fixtures", () => {
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

// #1618 — the CHURN-ONLY sub-shape, which the all-empty classifier above correctly declines and
// which therefore reached CI as a bare `hotspots is empty — vitals scoring or seed drift?` (run
// 30379062498). That text points at the two causes it is NOT: git had run fine and the seed was
// intact. The whole value of this row is that it names the mechanism, so it is asserted on the
// SENTENCE, not on the fact that something was returned.
describe("churnOnlySwallowDiagnosis — hotspots empty, siblings populated (#1618)", () => {
  const fixture = load<VitalsReport>("../__fixtures__/vitals-report.json");
  const sanity: GitScopeSanity = { commits: 72, returncode: 0, stderr: null, scopeMatchesToplevel: true };
  // Run 30379062498's exact shape: only the churn-driven section is gone.
  const churnOnly = { ...fixture, hotspots: [], _gitScopeSanity: sanity };

  it("does not fire on the committed fixture", () => {
    expect(churnOnlySwallowDiagnosis(fixture)).toBeUndefined();
  });

  it("fires on the observed shape and names the mechanism, not just the symptom", () => {
    const reason = churnOnlySwallowDiagnosis(churnOnly);
    expect(reason).toContain("CHURN-ONLY swallow (#1618/#1705)");
    expect(reason).toContain("--numstat");
    expect(reason).toContain("assert_no_background_gc");
    expect(reason).toContain("72 commit(s)");
    // The hedge, asserted like #1206's: a genuine upstream scoring change produces the same
    // symptom, and a sentence that stopped saying so would be an over-claim.
    expect(reason).toContain("CONSISTENT WITH");
    expect(reason).toContain("complexity scoring");
  });

  it("fires with knowledge_risk alone populated — either sibling is enough evidence git ran", () => {
    expect(churnOnlySwallowDiagnosis({ ...churnOnly, coupling: [] })).toContain("knowledge_risk (1)");
  });

  it("does NOT fire when all three are empty — that is the #1206 shape, and it has its own classifier", () => {
    expect(churnOnlySwallowDiagnosis({ ...fixture, hotspots: [], coupling: [], knowledge_risk: [], _gitScopeSanity: sanity })).toBeUndefined();
  });

  it("still fires without a sanity capture, but drops the corroboration it does not have", () => {
    const reason = churnOnlySwallowDiagnosis({ ...fixture, hotspots: [] });
    expect(reason).toContain("CHURN-ONLY swallow");
    expect(reason).not.toContain("commit(s) with no git error");
  });

  it("REACHES THE CONTRACT: the drift output carries the named diagnosis instead of the generic line", () => {
    const violations = checkVitalsContract(churnOnly);
    expect(violations.join("\n")).toContain("CHURN-ONLY swallow");
    expect(violations.join("\n")).not.toContain("vitals scoring or seed drift?");
    // And the generic text is still what an unexplained empty table gets, so the branch above is a
    // replacement rather than a rename.
    expect(checkVitalsContract({ ...fixture, hotspots: [], coupling: [], knowledge_risk: [] }).join("\n")).toContain("vitals scoring or seed drift?");
  });

  it("IS NOT AN EXCUSE: a churn-only run is still a loud FAIL, never NOT RUN (#1618 criterion 2)", () => {
    // The decision this test records: `classifyVitalsGitScopeFailure` is NOT widened to this
    // sub-shape. Excusing it would hide both of its candidate causes — a seed corpus mutated by
    // background git maintenance, and a real upstream change to vitals' complexity scoring — behind
    // a green NOT RUN. Fed through the CLI's own options object, so this is the shipped path.
    expect(VITALS_DRIFT_CONTRACT.notRunIf(churnOnly)).toBeUndefined();
    const verdict = classifyFreshRun(VITALS_DRIFT_CONTRACT, churnOnly);
    expect(verdict.kind).toBe("drift");
    expect(verdict.kind === "drift" && verdict.violations.join("\n")).toContain("CHURN-ONLY swallow");
    expect(renderDriftVerdict("vitals", "0.2.0", verdict, "").exitCode).toBe(1);
  });
});

// #1416.4 — the notRunIf WIRING, which had no test at all: `fixture-drift.ts`'s call to it could be
// deleted and nothing in the suite noticed, so the one thing classifyVitalsGitScopeFailure exists to
// do (pre-empt the contract check) was unguarded while the classifier itself carried eight cases.
// VITALS_DRIFT_CONTRACT is the real options object the CLI hands runDrift, imported here rather than
// re-declared — a hand-built twin would prove the classifier works on a fixture, not that the CLI
// consults it.
//
// FORMER STATED BOUND (#1416.4, closed by #1727): these five cases did not reach runDrift's own
// mapping of the verdict onto stdout and an exit code (`○ … NOT RUN`, exit 0) — inducing it live
// needs vitals to return three empty sections against a seeded repo where git succeeds, which no
// offline input can produce. #1727 pulled that mapping into `renderDriftVerdict` (a pure function
// `src/cli/fixture-drift.ts` now calls, leaving only the actual print/exit unguarded), so the
// mapping itself is exercised directly below rather than needing the #1206 live shape.
describe("classifyFreshRun — the notRunIf wiring (#1416)", () => {
  const fixture = load<VitalsReport>("../__fixtures__/vitals-report.json");
  const sanity: GitScopeSanity = { commits: 72, returncode: 0, stderr: null, scopeMatchesToplevel: true };
  const swallowed = { ...fixture, hotspots: [], coupling: [], knowledge_risk: [], _gitScopeSanity: sanity };

  it("reports the #1206 shape as NOT RUN through the CLI's own vitals options", () => {
    const v = classifyFreshRun(VITALS_DRIFT_CONTRACT, swallowed);
    expect(v.kind).toBe("not-run");
    expect(v.kind === "not-run" && v.reason).toContain("72 commit(s)");
  });

  // The ordering IS the wiring. The #1206 shape violates checkVitalsContract too (three empty
  // arrays), so a contract-first runDrift would report a schema drift for a git failure and never
  // consult the classifier — the two verdicts are only distinguishable by which check runs first.
  it("proves the order matters: the same input IS a contract violation when notRunIf is absent", () => {
    expect(VITALS_DRIFT_CONTRACT.contract(swallowed).length).toBeGreaterThan(0);
    expect(classifyFreshRun({ contract: VITALS_DRIFT_CONTRACT.contract }, swallowed).kind).toBe("drift");
  });

  it("falls through to the contract when notRunIf declines — a classifier is not a mute button", () => {
    const notTheShape = { ...fixture, hotspots: [], coupling: [], knowledge_risk: [] };
    expect(VITALS_DRIFT_CONTRACT.notRunIf(notTheShape)).toBeUndefined();
    expect(classifyFreshRun(VITALS_DRIFT_CONTRACT, notTheShape).kind).toBe("drift");
  });

  it("passes a healthy fresh run, so `ok` is reachable and the two failure paths are not the only outcomes", () => {
    expect(classifyFreshRun(VITALS_DRIFT_CONTRACT, fixture).kind).toBe("ok");
  });

  it("parses the committed fixture through the CLI's own parse, dropping the `_note` the contract does not model", () => {
    const parsed = VITALS_DRIFT_CONTRACT.parse(readFileSync(new URL("../__fixtures__/vitals-report.json", import.meta.url), "utf8"));
    expect(parsed).not.toHaveProperty("_note");
    expect(VITALS_DRIFT_CONTRACT.contract(parsed)).toEqual([]);
  });
});

// #1727 — `renderDriftVerdict` is the mapping `src/cli/fixture-drift.ts`'s runDrift() delegates to
// for what to print and which exit code to use. Fed the vitals swallowed-input verdict directly
// (rather than a hand-built one) so this proves the CLI's real not-run path, not just a shape a
// test invented independently.
describe("renderDriftVerdict — the verdict → stdout/exit mapping (#1727)", () => {
  const fixture = load<VitalsReport>("../__fixtures__/vitals-report.json");
  const sanity: GitScopeSanity = { commits: 72, returncode: 0, stderr: null, scopeMatchesToplevel: true };
  const swallowed = { ...fixture, hotspots: [], coupling: [], knowledge_risk: [], _gitScopeSanity: sanity };

  it("prints NOT RUN on stdout and exits 0 for a not-run verdict", () => {
    const verdict = classifyFreshRun(VITALS_DRIFT_CONTRACT, swallowed);
    const out = renderDriftVerdict("vitals", "0.2.0", verdict, "vitals 0.2.0 over the seeded corpus");
    expect(out.message.startsWith("○ vitals-fixture-drift: NOT RUN — ")).toBe(true);
    expect(out.message).toContain("72 commit(s)");
    expect(out.stream).toBe("log");
    expect(out.exitCode).toBe(0);
  });

  it("prints an error and exits 1 for a drift verdict, naming the violations", () => {
    const out = renderDriftVerdict("jscpd", "4.2.5", { kind: "drift", violations: ["missing field: duplicates"] }, "unused");
    expect(out.message).toContain("✗ jscpd-fixture-drift: a fresh jscpd 4.2.5 run no longer matches the schema");
    expect(out.message).toContain("missing field: duplicates");
    expect(out.stream).toBe("error");
    expect(out.exitCode).toBe(1);
  });

  it("prints the pass summary on stdout and exits 0 for an ok verdict", () => {
    const out = renderDriftVerdict("knip", "5.88.1", { kind: "ok" }, "knip 5.88.1 over a rebuilt seed — 1 dead file(s)");
    expect(out.message).toBe("✓ knip-fixture-drift: knip 5.88.1 over a rebuilt seed — 1 dead file(s), schema contract holds (committed fixture and fresh run both compliant).");
    expect(out.stream).toBe("log");
    expect(out.exitCode).toBe(0);
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
