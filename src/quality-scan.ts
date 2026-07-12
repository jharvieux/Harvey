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

// #232: paths jscpd should never treat as hand-maintained duplication, on top of the standard
// build/dep dirs — the three FP-triage classes an evidenced 6-repo calibration sweep named:
// generated code (including Supabase's two common CLI-generated-types filenames), vendored
// fork-mirror directories, and demo/mock-labeled files or directories. Starting list from that
// evidence; extend as new FP shapes surface.
export const JSCPD_IGNORE_GLOBS = [
  "**/node_modules/**",
  "**/dist/**",
  "**/.next/**",
  "**/generated/**",
  "**/*.gen.ts",
  "**/database.types.ts",
  "**/types_db.ts",
  "**/vendor/**",
  "**/patches/**",
  "**/*demo*/**",
  "**/*-demo-*.*",
];

function severityForClone(lines: number): Finding["severity"] {
  if (lines >= 50) return "Medium";
  if (lines >= 15) return "Low";
  return "Info";
}

// #232: jscpd matching a file against itself is how it reports internally-repetitive DATA (SVG
// icon-path tables, enum/lookup literal blocks) — not cross-file logic duplication a client could
// "extract into a shared module" (the M4 fix text). Excluded from scoring, not just re-labeled,
// since the fix recommendation genuinely doesn't apply to it.
function isCrossFileClone(dup: JscpdDuplicate): boolean {
  return dup.firstFile.name !== dup.secondFile.name;
}

// jscpd's own default gate (minLines 5 / minTokens 50) still lets through clusters the #232
// triage named explicitly as noise: shared import headers, tiny boilerplate overlaps. This raises
// the bar for what counts as real duplicated logic vs. incidental short overlap — a judgment
// call, not a measured constant; revisit if it starts hiding genuine small-but-real clones.
const MIN_SIGNIFICANT_LINES = 10;

function isSignificantClone(dup: JscpdDuplicate): boolean {
  return isCrossFileClone(dup) && dup.lines >= MIN_SIGNIFICANT_LINES;
}

// jscpd's json reporter always writes duplicates in discovery order, not
// worst-first, so re-sort by duplicated lines to surface the worst clusters.
export function jscpdToFindings(report: JscpdReport): Finding[] {
  const worst = report.duplicates.filter(isSignificantClone).sort((a, b) => b.lines - a.lines);

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
      // jscpd's clone-vs-not decision is a text match, ~100% precise (issue #72 calibration).
      precisionTier: "high",
    };
  });
}

// #232: jscpd's own statistics.total counts every raw clone it found, including the self-file
// and sub-threshold clusters jscpdToFindings now excludes — recompute so the reported percentage
// matches what the findings above actually claim. Reimplements jscpd's own
// Statistic.calculatePercentage (round(cloned/total*10000)/100, verified against
// @jscpd/core's source) rather than guessing a formula.
export function duplicationSummary(report: JscpdReport): { percentage: number; duplicatedLines: number; totalLines: number } {
  const totalLines = report.statistics.total.lines;
  const duplicatedLines = report.duplicates.filter(isSignificantClone).reduce((sum, d) => sum + d.lines, 0);
  const percentage = totalLines ? Math.round((10000 * duplicatedLines) / totalLines) / 100 : 0;
  return { percentage, duplicatedLines, totalLines };
}

// #223: knip throws (rather than reporting) when it can't resolve a target's config/plugin
// imports — most often because the target's own node_modules isn't installed. M4 (jscpd) has no
// such dependency, so a knip failure shouldn't cost the engagement its duplication findings too.
// The CLI catches the throw and substitutes this disclosure finding for the M5-* findings
// knipToFindings would otherwise have produced — a visible partial, not a silent skip, matching
// the coverage gap disclosure pattern already used for M7's Turbopack bundle-manifest gap
// (src/detectors/bundle-stats.ts, id M7B-03).
export function knipUnavailableFinding(reason: string): Finding {
  return {
    id: "M5-00",
    title: "M5 dead-code scan (knip) did not run",
    severity: "Info",
    confidence: "N/A",
    category: "Maintainability",
    taxonomy: "M5 — Slop / dead code",
    location: "(repo-wide)",
    status: "Open",
    evidence: `knip failed to run: ${reason}`,
    impact: "Dead-code coverage for this engagement is incomplete for this pass — a disclosed coverage gap, not a finding of zero dead code.",
    fix: "Install the target repo's dependencies (npm/pnpm/yarn install) so knip can resolve its config and plugin imports, then re-run `pnpm quality-scan`.",
    value: 1,
    ease: 3,
    safety: 5,
  };
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
      // knip's dead-file detection is deterministic given its entry config — ~100%
      // precise once the framework/dynamic-ref FP class is configured (issue #72).
      precisionTier: "high",
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
      // knip's dead-export detection is deterministic given its entry config — ~100%
      // precise once the framework/dynamic-ref FP class is configured (issue #72).
      precisionTier: "high",
    });
  }

  return findings;
}
