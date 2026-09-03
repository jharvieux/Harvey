import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { Finding } from "./findings.js";
import { readGitCheckoutIdentity } from "./git-checkout-identity.js";
import { SEMANTIC_CORPUS } from "./scan/semantic-corpus.js";
import { SEMANTIC_TARGET_COMMITS, requireSemanticTriageTarget, semanticCorpusTriageRules, type SemanticTriageIdentity } from "./semantic-triage.js";
import { findingsFromCompletedTriage, findingsFromRecordPassInput } from "./triage-findings.js";

const triageFinding = (overrides: Record<string, unknown> = {}) => ({
  id: "f001",
  title: "Cross-tenant invoice read",
  file: "src/app/api/invoices/[id]/route.ts",
  line: 21,
  category: "idor",
  verdict: "true_positive",
  verify_verdict: "exploitable",
  confidence: 9,
  severity: "HIGH",
  rationale: "route.ts:21 selects an arbitrary invoice id without checking company_id.",
  recommendation: "Filter by the authenticated company id.",
  vote_breakdown: { true_positive: 2, false_positive: 1, cannot_verify: 0 },
  duplicate_of: null,
  ...overrides,
});

const completed = (findings: unknown[], overrides: Record<string, unknown> = {}) => ({
  triage_completed: true,
  triage_context: { votes_per_finding: 3 },
  findings,
  ...overrides,
});

const writeGitConfig = (gitDir: string, repo = "https://github.com/example/target.git") => {
  writeFileSync(join(gitDir, "config"), `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = ${repo}\n`);
};

describe("child-process-free Git checkout identity", () => {
  it("reads a detached checkout identity directly from .git metadata", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-git-identity-detached-"));
    const gitDir = join(root, ".git");
    mkdirSync(gitDir);
    writeFileSync(join(gitDir, "HEAD"), `${"a".repeat(40)}\n`);
    writeGitConfig(gitDir);

    expect(readGitCheckoutIdentity(root)).toEqual({
      repo: "https://github.com/example/target.git",
      commit: "a".repeat(40),
    });
  });

  it("resolves a symbolic HEAD stored as a loose ref", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-git-identity-symbolic-"));
    const gitDir = join(root, ".git");
    mkdirSync(join(gitDir, "refs", "heads"), { recursive: true });
    writeFileSync(join(gitDir, "HEAD"), "ref: refs/heads/main\n");
    writeFileSync(join(gitDir, "refs", "heads", "main"), `${"b".repeat(40)}\n`);
    writeGitConfig(gitDir, "git@github.com:example/target.git");

    expect(readGitCheckoutIdentity(root)).toEqual({
      repo: "git@github.com:example/target.git",
      commit: "b".repeat(40),
    });
  });

  it("resolves a linked worktree through commondir and packed refs", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-git-identity-worktree-"));
    const commonDir = join(root, "common");
    const gitDir = join(commonDir, "worktrees", "target");
    mkdirSync(gitDir, { recursive: true });
    writeFileSync(join(root, ".git"), `gitdir: ${gitDir}\n`);
    writeFileSync(join(gitDir, "commondir"), "../..\n");
    writeFileSync(join(gitDir, "HEAD"), "ref: refs/heads/pinned\n");
    writeFileSync(join(commonDir, "packed-refs"), `# pack-refs\n${"c".repeat(40)} refs/heads/pinned\n`);
    writeGitConfig(commonDir);

    expect(readGitCheckoutIdentity(root).commit).toBe("c".repeat(40));
  });

  it("fails closed when an exact HEAD or origin cannot be read", () => {
    const noHead = mkdtempSync(join(tmpdir(), "harvey-git-identity-no-head-"));
    mkdirSync(join(noHead, ".git"));
    writeFileSync(join(noHead, ".git", "HEAD"), "ref: refs/heads/missing\n");
    writeGitConfig(join(noHead, ".git"));
    expect(() => readGitCheckoutIdentity(noHead)).toThrow(/exact 40-character/);

    const noOrigin = mkdtempSync(join(tmpdir(), "harvey-git-identity-no-origin-"));
    mkdirSync(join(noOrigin, ".git"));
    writeFileSync(join(noOrigin, ".git", "HEAD"), `${"d".repeat(40)}\n`);
    writeFileSync(join(noOrigin, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n");
    expect(() => readGitCheckoutIdentity(noOrigin)).toThrow(/remote origin URL/);
  });
});

describe("semantic-recall triage policy scope (#1947)", () => {
  const target = SEMANTIC_CORPUS.find((candidate) => candidate.slug === "cipherx");
  if (!target) throw new Error("cipherx semantic target missing");
  const identity: SemanticTriageIdentity = {
    measurement: "semantic-recall",
    slug: target.slug,
    repo: `https://github.com/${target.repo}.git`,
    commit: SEMANTIC_TARGET_COMMITS[target.slug] ?? "",
    scope: target.scope,
  };

  it("binds every member to a distinct immutable SHA", () => {
    expect(SEMANTIC_CORPUS).toHaveLength(4);
    const commits = SEMANTIC_CORPUS.map((candidate) => SEMANTIC_TARGET_COMMITS[candidate.slug]);
    expect(new Set(commits).size).toBe(4);
    expect(commits.every((commit) => typeof commit === "string" && /^[0-9a-f]{40}$/.test(commit))).toBe(true);
  });

  it("appends the planted-vulnerability exception only after exact identity validation", () => {
    const rules = semanticCorpusTriageRules("BASE RULES\n", identity);
    expect(rules).toMatch(/^BASE RULES\n/);
    expect(rules).toContain(`${target.repo}@${identity.commit}`);
    expect(rules).toContain("Do not apply generic exclusion rule 3");
    expect(rules).toContain("anon/publishable key is not a secret");
  });

  it.each([
    ["ordinary audit", { measurement: "client-audit" }],
    ["another repository", { repo: "example/ordinary-app" }],
    ["another commit", { commit: "0".repeat(40) }],
    ["another scope", { scope: "src" }],
    ["unknown corpus member", { slug: "ordinary-app" }],
  ])("refuses %s so the exception cannot reach ordinary work", (_label, change) => {
    expect(() => requireSemanticTriageTarget({ ...identity, ...change })).toThrow();
  });
});

describe("completed TRIAGE.json adapter (#1947)", () => {
  it("selects only true positives and translates the triage schema without losing scoring evidence", () => {
    const input = completed([
      triageFinding(),
      triageFinding({ id: "f002", verdict: "false_positive", severity: null, verify_verdict: null, vote_breakdown: { true_positive: 0, false_positive: 3, cannot_verify: 0 } }),
      triageFinding({ id: "f003", verdict: "duplicate", severity: null, verify_verdict: null, duplicate_of: "f001" }),
    ]);

    expect(findingsFromCompletedTriage(input)).toEqual([
      expect.objectContaining({
        id: "f001",
        title: "Cross-tenant invoice read",
        severity: "High",
        confidence: "Confirmed",
        category: "Security",
        taxonomy: "idor",
        location: "src/app/api/invoices/[id]/route.ts:21",
        evidence: "route.ts:21 selects an arbitrary invoice id without checking company_id.",
        fix: "Filter by the authenticated company id.",
        value: 3,
        ease: 3,
        safety: 3,
      }),
    ]);
  });

  it("deduplicates identical true positives deterministically regardless of input order", () => {
    const a = triageFinding({ id: "f010" });
    const b = triageFinding({ id: "f002" });
    expect(findingsFromCompletedTriage(completed([a, b])).map((finding) => finding.id)).toEqual(["f002"]);
    expect(findingsFromCompletedTriage(completed([b, a])).map((finding) => finding.id)).toEqual(["f002"]);
  });

  it("retains the legacy bare report-schema Finding[] interface", () => {
    const finding = { id: "legacy" } as Finding;
    expect(findingsFromRecordPassInput([finding])).toEqual([finding]);
  });

  it.each([
    ["incomplete triage", completed([], { triage_completed: false }), /triage_completed: true/],
    ["non-array findings", { triage_completed: true, findings: {} }, /findings array/],
    ["missing triage context", { triage_completed: true, findings: [] }, /triage_context object/],
    ["malformed true positive", completed([triageFinding({ file: "" })]), /file must be a non-empty string/],
    ["malformed false-positive votes", completed([triageFinding({ verdict: "false_positive", vote_breakdown: {} })]), /vote_breakdown.true_positive/],
    ["false-positive verdict over a TP majority", completed([triageFinding({ verdict: "false_positive" })]), /has a true-positive majority/],
    ["vote total mismatch", completed([triageFinding({ vote_breakdown: { true_positive: 2, false_positive: 0, cannot_verify: 0 } })]), /totals 2, expected 3/],
    ["verdict without majority", completed([triageFinding({ vote_breakdown: { true_positive: 1, false_positive: 1, cannot_verify: 1 } })]), /no true-positive majority/],
    ["duplicate without canonical", completed([triageFinding({ verdict: "duplicate", duplicate_of: null })]), /duplicate_of/],
    ["duplicate with unknown canonical", completed([triageFinding({ verdict: "duplicate", duplicate_of: "missing" })]), /unknown canonical finding/],
    ["duplicate chain", completed([
      triageFinding(),
      triageFinding({ id: "f002", verdict: "duplicate", severity: null, verify_verdict: null, duplicate_of: "f001" }),
      triageFinding({ id: "f003", verdict: "duplicate", severity: null, verify_verdict: null, duplicate_of: "f002" }),
    ]), /must name a non-duplicate canonical finding/],
    ["duplicate ids", completed([triageFinding(), triageFinding()]), /duplicate finding id/],
  ])("fails closed on %s", (_label, input, message) => {
    expect(() => findingsFromCompletedTriage(input)).toThrow(message as RegExp);
  });
});
