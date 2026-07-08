// M4 (duplication) + M5 (dead code) — shapes jscpd and knip JSON reports into
// Finding[] (src/findings.ts) for §3b of the audit report. Pure transforms only;
// src/cli/quality-scan.ts does the process invocation and file I/O.

import type { Finding } from "./findings.js";

interface JscpdFileRef {
  name: string;
  start: number;
  end: number;
}

export interface JscpdDuplicate {
  format: string;
  lines: number;
  tokens: number;
  fragment: string;
  firstFile: JscpdFileRef;
  secondFile: JscpdFileRef;
}

export interface JscpdReport {
  statistics: { total: { percentage: number; duplicatedLines: number; lines: number } };
  duplicates: JscpdDuplicate[];
}

interface KnipExportIssue {
  name: string;
  line: number;
}

export interface KnipIssue {
  file: string;
  exports: KnipExportIssue[];
  types: KnipExportIssue[];
}

export interface KnipReport {
  files: string[];
  issues: KnipIssue[];
}

const FRAGMENT_PREVIEW_LEN = 240;

function severityForClone(lines: number): Finding["severity"] {
  if (lines >= 50) return "Medium";
  if (lines >= 15) return "Low";
  return "Info";
}

// jscpd's json reporter always writes duplicates in discovery order, not
// worst-first, so re-sort by duplicated lines to surface the worst clusters.
export function jscpdToFindings(report: JscpdReport): Finding[] {
  const worst = [...report.duplicates].sort((a, b) => b.lines - a.lines);

  return worst.map((dup, i): Finding => {
    const severity = severityForClone(dup.lines);
    const fragment =
      dup.fragment.length > FRAGMENT_PREVIEW_LEN
        ? `${dup.fragment.slice(0, FRAGMENT_PREVIEW_LEN)}…`
        : dup.fragment;

    return {
      id: `M4-${String(i + 1).padStart(2, "0")}`,
      title: `Duplicated code: ${dup.firstFile.name} ↔ ${dup.secondFile.name}`,
      severity,
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "M4 — Duplication",
      location: `${dup.firstFile.name}:${dup.firstFile.start}-${dup.firstFile.end} ↔ ${dup.secondFile.name}:${dup.secondFile.start}-${dup.secondFile.end}`,
      status: "Open",
      evidence: fragment.replace(/\n/g, " / "),
      impact: `${dup.lines} duplicated lines (${dup.tokens} tokens) — a fix in one copy is a fix missed in the other.`,
      fix: "Extract the shared logic into one function/module and have both call sites use it.",
      value: severity === "Medium" ? 4 : severity === "Low" ? 3 : 2,
      ease: 4,
      safety: 4,
    };
  });
}

export function duplicationSummary(report: JscpdReport): { percentage: number; duplicatedLines: number; totalLines: number } {
  const t = report.statistics.total;
  return { percentage: t.percentage, duplicatedLines: t.duplicatedLines, totalLines: t.lines };
}

// fileLineCounts is caller-supplied (read from disk) so this stays a pure,
// testable transform — and so the reported line count is measured, not guessed.
export function knipToFindings(report: KnipReport, fileLineCounts: Record<string, number> = {}): Finding[] {
  const findings: Finding[] = [];
  let n = 0;

  for (const file of report.files) {
    n += 1;
    const lines = fileLineCounts[file];
    findings.push({
      id: `M5-${String(n).padStart(2, "0")}`,
      title: `Unused file: ${file}`,
      severity: "Low",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "M5 — Slop / dead code",
      location: file,
      status: "Open",
      evidence: "knip: file is never imported from any entry point.",
      impact: lines === undefined ? "Entire file is unreferenced." : `Entire file (${lines} lines) is unreferenced.`,
      fix: "Delete the file (confirm it isn't a planned/unwired entry point first).",
      value: 2,
      ease: 5,
      safety: 4,
    });
  }

  for (const issue of report.issues) {
    const deadExports = [...issue.exports, ...issue.types].map((e) => e.name);
    if (deadExports.length === 0) continue;
    n += 1;
    findings.push({
      id: `M5-${String(n).padStart(2, "0")}`,
      title: `Unused exports in ${issue.file}`,
      severity: "Low",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "M5 — Slop / dead code",
      location: issue.file,
      status: "Open",
      evidence: `knip: unreferenced export(s) ${deadExports.join(", ")}.`,
      impact: `${deadExports.length} unused export${deadExports.length === 1 ? "" : "s"} — exact line reduction needs a manual look (knip reports the declaration, not its body size).`,
      fix: "Delete the unused exports, or inline them if they're only used internally.",
      value: 2,
      ease: 4,
      safety: 4,
    });
  }

  return findings;
}
