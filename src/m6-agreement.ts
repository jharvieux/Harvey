import { buildPassArtifact, type PassArtifact } from "./audit-pass-artifact.js";
import type { Finding } from "./findings.js";

// M6 two-reviewer agreement (#813) — the mechanical half of the M6 verdict protocol.
//
// M6's paid verdict is a judgment with no detector and, until #813, no defense against
// single-reviewer variance: eval runs 3 and 4 saw the same file under the same rubric and
// split on it (docs/design/m6-simplification-eval.md §3.4). The protocol's answer is two
// INDEPENDENT reviewer passes over the identical simplify-scan packet, each emitting the
// machine-readable verdict block the packet's "Verdict format" section specifies. This module
// compares two such passes: agreement is computed, never eyeballed (the repo's measure-don't-
// recall doctrine), and a split is routed to a human adjudicator — it never silently becomes
// either a finding or a spare.
//
// Fail-loud properties, all deliberate:
//   • a file reviewed by only one pass is listed, not dropped — an absent row can't be argued with;
//   • two passes claiming the same reviewer id are rejected — "independent" is the protocol's
//     load-bearing word, and a self-comparison would report vacuous agreement;
//   • passes over different targets are rejected — cross-corpus agreement is meaningless.

export interface ReviewerVerdict {
  file: string;
  verdict: "flag" | "spare";
  replacement?: string;
  confidence?: "high" | "medium" | "low";
  reason?: string;
}

export interface ReviewerPass {
  reviewer: string;
  date?: string;
  target?: string;
  verdicts: ReviewerVerdict[];
}

export function parseReviewerPass(raw: unknown, label: string): ReviewerPass {
  if (typeof raw !== "object" || raw === null) throw new Error(`${label}: not a JSON object`);
  const obj = raw as Record<string, unknown>;
  if (typeof obj.reviewer !== "string" || !obj.reviewer.trim()) {
    throw new Error(`${label}: missing "reviewer" — an anonymous pass cannot prove independence`);
  }
  if (!Array.isArray(obj.verdicts) || obj.verdicts.length === 0) {
    throw new Error(`${label}: "verdicts" must be a non-empty array`);
  }
  const seen = new Set<string>();
  const verdicts = obj.verdicts.map((v, i) => {
    if (typeof v !== "object" || v === null) throw new Error(`${label}: verdicts[${i}] is not an object`);
    const row = v as Record<string, unknown>;
    if (typeof row.file !== "string" || !row.file.trim()) throw new Error(`${label}: verdicts[${i}] has no "file"`);
    if (row.verdict !== "flag" && row.verdict !== "spare") {
      throw new Error(`${label}: verdicts[${i}] ("${row.file}") verdict must be "flag" or "spare", got ${JSON.stringify(row.verdict)}`);
    }
    if (seen.has(row.file)) {
      throw new Error(`${label}: "${row.file}" appears more than once — one verdict per file`);
    }
    seen.add(row.file);
    return {
      file: row.file,
      verdict: row.verdict,
      replacement: typeof row.replacement === "string" ? row.replacement : undefined,
      confidence: row.confidence === "high" || row.confidence === "medium" || row.confidence === "low" ? row.confidence : undefined,
      reason: typeof row.reason === "string" ? row.reason : undefined,
    } satisfies ReviewerVerdict;
  });
  return {
    reviewer: obj.reviewer,
    date: typeof obj.date === "string" ? obj.date : undefined,
    target: typeof obj.target === "string" ? obj.target : undefined,
    verdicts,
  };
}

interface AgreementReport {
  reviewers: [string, string];
  compared: number;
  agreed: number;
  bothFlag: string[];
  bothSpare: string[];
  splits: { file: string; verdicts: [ReviewerVerdict, ReviewerVerdict] }[];
  onlyA: string[];
  onlyB: string[];
}

export function compareReviewerPasses(a: ReviewerPass, b: ReviewerPass): AgreementReport {
  if (a.reviewer === b.reviewer) {
    throw new Error(`both passes claim reviewer "${a.reviewer}" — the protocol requires two INDEPENDENT reviewers, and a self-comparison would report vacuous agreement`);
  }
  if (a.target && b.target && a.target !== b.target) {
    throw new Error(`passes cover different targets ("${a.target}" vs "${b.target}") — agreement across corpora is meaningless`);
  }
  const byFileB = new Map(b.verdicts.map((v) => [v.file, v]));
  const filesA = new Set(a.verdicts.map((v) => v.file));
  const bothFlag: string[] = [];
  const bothSpare: string[] = [];
  const splits: AgreementReport["splits"] = [];
  for (const va of a.verdicts) {
    const vb = byFileB.get(va.file);
    if (!vb) continue;
    if (va.verdict === vb.verdict) (va.verdict === "flag" ? bothFlag : bothSpare).push(va.file);
    else splits.push({ file: va.file, verdicts: [va, vb] });
  }
  return {
    reviewers: [a.reviewer, b.reviewer],
    compared: bothFlag.length + bothSpare.length + splits.length,
    agreed: bothFlag.length + bothSpare.length,
    bothFlag,
    bothSpare,
    splits,
    onlyA: a.verdicts.filter((v) => !byFileB.has(v.file)).map((v) => v.file),
    onlyB: b.verdicts.filter((v) => !filesA.has(v.file)).map((v) => v.file),
  };
}

export function renderAgreementReport(report: AgreementReport): string {
  const lines: string[] = [
    `M6 two-reviewer agreement — ${report.reviewers[0]} vs ${report.reviewers[1]}`,
    "",
    `agreed ${report.agreed}/${report.compared} on the files both reviewed`,
    `  both flag  (candidate findings → human triage): ${report.bothFlag.length ? report.bothFlag.join(", ") : "none"}`,
    `  both spare: ${report.bothSpare.length ? report.bothSpare.join(", ") : "none"}`,
  ];
  if (report.splits.length) {
    lines.push("", `SPLITS — ${report.splits.length} file(s) need a human adjudicator; a split never goes straight into a report:`);
    for (const s of report.splits) {
      for (const v of s.verdicts) {
        const extras = [v.confidence && `confidence ${v.confidence}`, v.reason].filter(Boolean).join(" — ");
        lines.push(`  ${s.file}: ${v.verdict.toUpperCase()} (${extras || "no reason recorded"})`);
      }
    }
  } else {
    lines.push("", "no splits — every co-reviewed file has a unanimous verdict");
  }
  for (const [only, who] of [[report.onlyA, report.reviewers[0]], [report.onlyB, report.reviewers[1]]] as const) {
    if (only.length) {
      lines.push("", `UNCOMPARED — reviewed only by ${who} (missing from the other pass; NOT counted as agreement): ${only.join(", ")}`);
    }
  }
  lines.push("", "This is a rubric-agreement figure for this pair of passes — never quote it as M6 precision (docs/design/m6-simplification-eval.md §3).");
  return lines.join("\n");
}

// #1364: turns the UNANIMOUS-flag rows into report-schema findings for the M6 pass artifact
// (src/cli/m6-agreement.ts --artifacts-dir). Only `bothFlag` qualifies: a split has NOT been
// through the human adjudicator this protocol requires (renderAgreementReport's own "a split never
// goes straight into a report"), and a spare is not a finding — so neither is ever promoted here.
// Confidence is deliberately the WEAKER of the two reviewers' stated confidence (both "high" ⇒
// Confirmed; anything else, including a reviewer who left it unstated, ⇒ Review) — one confident
// reviewer cannot make a finding Confirmed on the other's behalf.
export function toM6Findings(a: ReviewerPass, b: ReviewerPass, report: AgreementReport): Finding[] {
  const byFileA = new Map(a.verdicts.map((v) => [v.file, v]));
  const byFileB = new Map(b.verdicts.map((v) => [v.file, v]));
  return report.bothFlag.map((file, i): Finding => {
    const va = byFileA.get(file)!;
    const vb = byFileB.get(file)!;
    const bothHighConfidence = va.confidence === "high" && vb.confidence === "high";
    const replacement = va.replacement ?? vb.replacement;
    const reasons = [va.reason, vb.reason].filter((r): r is string => !!r);
    return {
      id: `M6VER-${String(i + 1).padStart(2, "0")}`,
      title: `Hand-rolled reinvention: ${file}`,
      severity: "Info", // M6 findings are maintainability, not security — never graded (#267)
      confidence: bothHighConfidence ? "Confirmed" : "Review",
      category: "Maintainability",
      taxonomy: "M6 — Verdict: hand-rolled reinvention",
      location: file,
      status: "Open",
      evidence: reasons.length ? reasons.join(" / ") : `both reviewers (${a.reviewer}, ${b.reviewer}) independently flagged this file as a reinvention`,
      impact: "Maintenance and correctness risk from a hand-rolled reimplementation of behavior a maintained library already covers.",
      fix: replacement ? `Replace with ${replacement}.` : "Name a replacement — neither reviewer's verdict block recorded one.",
      value: 2,
      ease: 3,
      safety: 4,
    };
  });
}

// The M6 pass artifact src/cli/m6-agreement.ts writes with --artifacts-dir — the write side of the
// #416 read (findFreshPass reads M6.pass.json, mirroring the manual `record-pass --pass verdict`
// path #283's first real-target verdict used, docs/design/m6-first-real-target-verdict.md).
export function buildM6PassArtifact(a: ReviewerPass, b: ReviewerPass, report: AgreementReport, target: string, generatedAt: string): PassArtifact {
  const findings = toM6Findings(a, b, report);
  return buildPassArtifact({
    module: "M6",
    target,
    pass: "verdict",
    generatedAt,
    summary: `${a.reviewer} vs ${b.reviewer}: ${report.agreed}/${report.compared} agreed, ${findings.length} unanimous flag(s), ${report.splits.length} split(s) pending adjudication`,
    findings,
  });
}
