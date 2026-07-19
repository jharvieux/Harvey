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

// #361: a clone in an auth/guard/security path is the highest-value instance of M4's
// bug-multiplier framing — it's the code most likely to become an M1 finding when one copy gets
// patched and its siblings don't. One tier up, capped at Medium: still a maintainability finding
// (the copies are identical today), not a confirmed security defect.
function elevateForSecurityPath(severity: Finding["severity"]): Finding["severity"] {
  if (severity === "Info") return "Low";
  if (severity === "Low") return "Medium";
  return severity;
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
// the bar for what counts as real duplicated logic vs. incidental short overlap.
//
// #365 revisited this floor against the AI-era small-block duplication trend (GitClear 2025:
// 5+-line duplicated-block commits rose 8x during 2024). MEASURED 2026-07-16 on the #222 external
// corpus at production settings (minTokens 50): on the AI-authored target (proposit) 44 of 148
// cross-file clones — 30% — fall in the 5-9-line band this floor drops, and a fragment review
// found roughly three quarters of them genuine per-entity logic duplication (the lib/ai/tools/* and
// lib/stores/* copy-paste families, several containing organisation_id tenant-scoping), not
// boilerplate; import headers were a ~1/4 minority. On the conventional target (mvp-boilerplate)
// the band was 1 of 8. DECISION: keep the floor for individual findings (44 extra sub-10-line
// findings would triple the M4 report for little per-item action, and the #232 noise classes live
// in the same band), and DISCLOSE the dropped band as one aggregate M4-00 finding
// (subThresholdDisclosureFinding) so it is visible in the report instead of silently absorbed.
const MIN_SIGNIFICANT_LINES = 10;

function isSignificantClone(dup: JscpdDuplicate): boolean {
  return isCrossFileClone(dup) && dup.lines >= MIN_SIGNIFICANT_LINES;
}

// #365: cross-file clones jscpd DID see (they cleared its minTokens/minLines gate) but that fall
// under MIN_SIGNIFICANT_LINES. Self-file repetition stays excluded entirely (#232 — not
// extractable duplication at any size).
function isSubThresholdClone(dup: JscpdDuplicate): boolean {
  return isCrossFileClone(dup) && dup.lines < MIN_SIGNIFICANT_LINES;
}

function subThresholdDisclosureFinding(smallClones: JscpdDuplicate[]): Finding {
  const worst = [...smallClones].sort((a, b) => b.lines - a.lines);
  const totalLines = smallClones.reduce((sum, d) => sum + d.lines, 0);
  const examples = worst
    .slice(0, 3)
    .map((d) => `${d.firstFile.name}:${d.firstFile.start}-${d.firstFile.end} ↔ ${d.secondFile.name}:${d.secondFile.start}-${d.secondFile.end} (${d.lines} lines)`)
    .join("; ");
  return {
    id: "M4-00",
    title: `${smallClones.length} small cross-file clone(s) below the M4 significance floor`,
    severity: "Info",
    confidence: "Confirmed",
    category: "Maintainability",
    taxonomy: "M4 — Duplication",
    location: "(repo-wide)",
    status: "Open",
    evidence: `jscpd found ${smallClones.length} cross-file clone(s) of 5-${MIN_SIGNIFICANT_LINES - 1} duplicated lines (${totalLines} lines total), e.g. ${examples}`,
    impact:
      "Individually below the floor for an actionable duplication finding, but AI-assisted codebases concentrate genuine duplication in exactly this small-block band (#365 measured 30% of one AI-authored corpus target's cross-file clones here, ~3/4 of them real logic, though the band also holds import-header noise). Disclosed as an aggregate so the band is visible rather than silently dropped.",
    fix: "No per-item action required. If this count is large relative to the significant-clone findings above, sample the evidence pairs — repeated small blocks across per-entity files usually mean one helper should exist.",
    value: 1,
    ease: 3,
    safety: 5,
    // Same text-match precision as every other jscpd count — the COUNT is exact even though
    // each member is individually low-value.
    precisionTier: "high",
  };
}

// jscpd's json reporter always writes duplicates in discovery order, not
// worst-first, so re-sort by duplicated lines to surface the worst clusters.
export function jscpdToFindings(report: JscpdReport): Finding[] {
  const worst = report.duplicates.filter(isSignificantClone).sort((a, b) => b.lines - a.lines);

  const findings = worst.map((dup, i): Finding => {
    // #361: same signal M5 already uses for dead code — check BOTH sides, since either copy
    // sitting in a security path makes the pair a patch-divergence risk.
    // #400: a test/spec/e2e file merely naming an auth path (e.g. tests/e2e/auth/*.spec.ts) isn't
    // a per-handler authorization drift risk — exclude it the same way the #360 diverged-clone
    // pass's file selection already does (src/cli/quality-scan.ts SKIP_FILE/SKIP_DIRS).
    const securityPath =
      (touchesSecurityPath(dup.firstFile.name) && !isTestPath(dup.firstFile.name)) ||
      (touchesSecurityPath(dup.secondFile.name) && !isTestPath(dup.secondFile.name));
    const severity = securityPath ? elevateForSecurityPath(severityForClone(dup.lines)) : severityForClone(dup.lines);
    const fragment =
      dup.fragment.length > FRAGMENT_PREVIEW_LEN
        ? `${dup.fragment.slice(0, FRAGMENT_PREVIEW_LEN)}…`
        : dup.fragment;
    const baseImpact = `${dup.lines} duplicated lines (${dup.tokens} tokens) — a fix in one copy is a fix missed in the other.`;

    return {
      id: `M4-${String(i + 1).padStart(2, "0")}`,
      title: securityPath
        ? `Duplicated code in security-relevant path: ${dup.firstFile.name} ↔ ${dup.secondFile.name}`
        : `Duplicated code: ${dup.firstFile.name} ↔ ${dup.secondFile.name}`,
      severity,
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "M4 — Duplication",
      location: `${dup.firstFile.name}:${dup.firstFile.start}-${dup.firstFile.end} ↔ ${dup.secondFile.name}:${dup.secondFile.start}-${dup.secondFile.end}`,
      status: "Open",
      evidence: fragment.replace(/\n/g, " / "),
      impact: securityPath
        ? `${baseImpact} This duplicated block sits in an auth/guard/security path — if one copy is patched for a security issue, confirm the other copy(ies) were too (cross-check against the M1 authorization review).`
        : baseImpact,
      fix: "Extract the shared logic into one function/module and have both call sites use it.",
      value: severity === "Medium" ? 4 : severity === "Low" ? 3 : 2,
      ease: 4,
      safety: 4,
      // jscpd's clone-vs-not decision is a text match, ~100% precise (issue #72 calibration).
      precisionTier: "high",
    };
  });

  // #365: the dropped small-clone band, disclosed as one aggregate rather than omitted. Appended
  // after the individual findings (M4-00 is the meta row, same convention as M5-00).
  const smallClones = report.duplicates.filter(isSubThresholdClone);
  if (smallClones.length > 0) findings.push(subThresholdDisclosureFinding(smallClones));

  return findings;
}

// #232: jscpd's own statistics.total counts every raw clone it found, including the self-file
// and sub-threshold clusters jscpdToFindings now excludes — recompute so the reported percentage
// matches what the findings above actually claim. Reimplements jscpd's own
// Statistic.calculatePercentage (round(cloned/total*10000)/100, verified against
// @jscpd/core's source) rather than guessing a formula.
export function duplicationSummary(report: JscpdReport): { percentage: number; duplicatedLines: number; totalLines: number; subThresholdCloneCount: number } {
  const totalLines = report.statistics.total.lines;
  const duplicatedLines = report.duplicates.filter(isSignificantClone).reduce((sum, d) => sum + d.lines, 0);
  const percentage = totalLines ? Math.round((10000 * duplicatedLines) / totalLines) / 100 : 0;
  // #365: not part of the headline percentage (that stands behind the significant findings), but
  // surfaced so the small-clone band is visible wherever the summary is printed.
  const subThresholdCloneCount = report.duplicates.filter(isSubThresholdClone).length;
  return { percentage, duplicatedLines, totalLines, subThresholdCloneCount };
}

// #223/#505: knip throws (rather than reporting) when it can't resolve a target's config/plugin
// imports — most often because the target's own node_modules isn't installed, or (on a monorepo)
// because a per-workspace run timed out (#505: the whole-repo run hung indefinitely in knip's
// workspace-resolution stage; quality-scan now runs knip per workspace with a hard timeout
// instead). M4 (jscpd) has no such dependency, so a knip gap shouldn't cost the engagement its
// duplication findings too. The CLI catches the throw/timeout per workspace and substitutes this
// disclosure finding for the M5-* findings the affected workspace(s) would otherwise have
// produced — a visible partial, not a silent skip or a silent stall, matching the coverage gap
// disclosure pattern already used for M7's Turbopack bundle-manifest gap
// (src/detectors/bundle-stats.ts, id M7B-03). `reason` may name a single cause (whole-repo target)
// or list several workspace:cause pairs (monorepo target, partial coverage).
export function knipUnavailableFinding(reason: string): Finding {
  return {
    id: "M5-00",
    title: "M5 dead-code scan (knip) did not complete for every workspace",
    severity: "Info",
    confidence: "N/A",
    category: "Maintainability",
    taxonomy: "M5 — Slop / dead code",
    location: "(repo-wide)",
    status: "Open",
    evidence: `knip did not complete: ${reason}`,
    impact: "Dead-code coverage for this engagement is incomplete for this pass — a disclosed coverage gap, not a finding of zero dead code.",
    fix: "Install the target repo's dependencies (npm/pnpm/yarn install) so knip can resolve its config and plugin imports, then re-run `pnpm quality-scan` (raise --timeout if the gap was a timeout).",
    value: 1,
    ease: 3,
    safety: 5,
  };
}

// #505: the M4 mirror of knipUnavailableFinding — jscpd has no node_modules dependency, but a
// per-workspace run can still time out (the same whole-repo hang the issue reports, just on the
// duplication side) or crash on one workspace without losing the others' results. `M4-99` (not
// `M4-00`, which jscpdToFindings already uses for the #365 sub-threshold-clone disclosure) keeps
// this a distinct, non-colliding meta row.
export function jscpdUnavailableFinding(reason: string): Finding {
  return {
    id: "M4-99",
    title: "M4 duplication scan (jscpd) did not complete for every workspace",
    severity: "Info",
    confidence: "N/A",
    category: "Maintainability",
    taxonomy: "M4 — Duplication",
    location: "(repo-wide)",
    status: "Open",
    evidence: `jscpd did not complete: ${reason}`,
    impact: "Duplication coverage for this engagement is incomplete for this pass — a disclosed coverage gap, not a finding of zero duplication.",
    fix: "Re-run `pnpm quality-scan` with a longer --timeout, or investigate the affected workspace(s) individually.",
    value: 1,
    ease: 3,
    safety: 5,
  };
}

// #580: a knip run that completes without throwing can still have silently mis-resolved entry
// points — knip auto-detects the Vite plugin from the target's installed deps, and if that
// activation fails (vite not in deps, or declared but not actually installed) knip falls back to
// its default index.*-only entry resolution and can report most of a real Vite app's src/ as
// unused. Two independent signals, MEASURED against a synthetic Vite fixture (2026-07-18): (1) a
// mis-resolved run (no vite install at all) reported 5/7 = 71% of scanned source files unused,
// including vite.config.ts itself; the same fixture with `vite` genuinely installed dropped to
// 4/7 with vite.config.ts correctly excluded — so an implausibly high unused-file ratio is a real,
// measured tell, not a guess. (2) the scope carries Vite's own entry markers
// (vite.config.*/index.html) with vite NOT resolvable from that directory (walking node_modules up
// the tree the way Node's own resolution does) — the exact "plugin didn't activate" precondition.
// Either signal alone is enough to distrust the number (the issue's "prefer disclosure at minimum"
// bar); a target with neither is unaffected. totalSourceFiles/hasViteMarkers/viteResolvable are
// filesystem facts the CLI supplies, so this stays a pure, testable transform over them.
const UNUSED_FILE_RATIO_THRESHOLD = 0.5;
const MIN_FILES_FOR_RATIO_SIGNAL = 5;

export function knipEntryUncertainReason(
  report: KnipReport,
  totalSourceFiles: number,
  hasViteMarkers: boolean,
  viteResolvable: boolean,
): string | undefined {
  const reasons: string[] = [];
  if (totalSourceFiles >= MIN_FILES_FOR_RATIO_SIGNAL) {
    const ratio = report.files.length / totalSourceFiles;
    if (ratio > UNUSED_FILE_RATIO_THRESHOLD) {
      reasons.push(
        `${report.files.length}/${totalSourceFiles} source files (${Math.round(ratio * 100)}%) reported unused — implausibly high, a signal of mis-resolved entry points rather than genuine dead code`,
      );
    }
  }
  if (hasViteMarkers && !viteResolvable) {
    reasons.push(
      "target has vite.config.*/index.html but `vite` isn't resolvable from this scope — knip's Vite plugin auto-detection likely didn't activate, so entry resolution is unverified",
    );
  }
  return reasons.length ? reasons.join("; ") : undefined;
}

// #580: mirrors knipUnavailableFinding's spot (M5-00, "did not complete") one row down — M5-99
// covers the opposite shape: knip DID complete, but the result looks untrustworthy. Distinct from
// M4-99 (M4's own did-not-complete gap) and M5-00 by taxonomy, not just id.
export function knipEntryUncertainFinding(reason: string): Finding {
  return {
    id: "M5-99",
    title: "M5 dead-code result may be unreliable for one or more scopes",
    severity: "Info",
    confidence: "N/A",
    category: "Maintainability",
    taxonomy: "M5 — Slop / dead code",
    location: "(repo-wide)",
    status: "Open",
    evidence: `knip completed but entry resolution looks uncertain: ${reason}`,
    impact:
      "The M5 unused-file/export counts above may be significantly over- or under-stated for the affected scope(s) rather than a trustworthy measurement — a disclosed uncertainty, not a finding of confirmed dead code.",
    fix: "Add an explicit knip config for the scope (e.g. entry: index.html for a Vite app) or install the target's dependencies so knip's plugin auto-detection can activate, then re-run `pnpm quality-scan` and compare the unused-file count.",
    value: 1,
    ease: 3,
    safety: 5,
  };
}

// #505: quality-scan now runs jscpd/knip per workspace (monorepo target) rather than once over the
// whole target, so their reports need merging back into one before the existing jscpdToFindings /
// knipToFindings transforms run — those stay single-report, unchanged and still independently
// tested. Pure concatenation: file paths are already made workspace-relative-to-target by the CLI
// before merging.
export function mergeJscpdReports(reports: JscpdReport[]): JscpdReport {
  return {
    statistics: {
      total: {
        percentage: 0, // recomputed from the merged duplicates by duplicationSummary; not meaningful pre-merge
        duplicatedLines: reports.reduce((sum, r) => sum + r.statistics.total.duplicatedLines, 0),
        lines: reports.reduce((sum, r) => sum + r.statistics.total.lines, 0),
      },
    },
    duplicates: reports.flatMap((r) => r.duplicates),
  };
}

export function mergeKnipReports(reports: KnipReport[]): KnipReport {
  return {
    files: reports.flatMap((r) => r.files),
    issues: reports.flatMap((r) => r.issues),
  };
}

// #226: dead code sitting in auth/guard/middleware/security paths is a different signal than
// routine slop — jharvieux/atc's cross-tenant Critical was preceded by exactly this (a guard
// helper written and never wired in, while the app leaned on broken RLS instead). Tokenizes on
// path separators, punctuation, and camelCase boundaries so it catches `AuthGuard.tsx` /
// `useAuthMiddleware.ts` as well as `lib/security/guards.ts`, without the false hits a loose
// substring match would produce (e.g. "author"/"authors" containing "auth").
const SECURITY_PATH_KEYWORDS = new Set(["auth", "guard", "guards", "middleware", "security"]);

export function touchesSecurityPath(path: string): boolean {
  const tokens = path.split(/[^a-zA-Z0-9]+|(?<=[a-z0-9])(?=[A-Z])/).map((t) => t.toLowerCase());
  return tokens.some((t) => SECURITY_PATH_KEYWORDS.has(t));
}

// #400: same test-path shape src/cli/quality-scan.ts's SKIP_FILE/SKIP_DIRS already excludes from
// the #360 diverged-clone pass's file selection — a test naming an auth path (e.g.
// tests/e2e/auth/idp-initiated.spec.ts) is not itself a per-handler authorization check.
function isTestPath(path: string): boolean {
  return /(\.test\.|\.spec\.)|(^|\/)(__tests__|e2e)(\/|$)/.test(path);
}

// #399: v2 widening of the #360 diverged-clone pass's file-selection scope. touchesSecurityPath
// is deliberately narrow (auth/guard/middleware/security path vocabulary) and misses the AI-
// duplication vein #399 measured on proposit: per-entity copies (lib/ai/tools/*-tools.ts,
// lib/stores/*.store.ts) whose paths say nothing about security but whose bodies scope a supabase
// query by a tenant key (organisation_id, tenant_id, ...) — the same "patched one copy, missed
// the other" risk #360 targets, just outside the path vocabulary. Requires BOTH signals (not
// either alone) to keep the pass's false-positive rate defensible: a tenant-key literal alone is
// common in plain data shapes, and a supabase call alone is most of the app.
const TENANT_KEY_RE = /\b(tenant_id|tenantId|organisation_id|organizationId|organization_id|org_id|orgId|workspace_id|workspaceId)\b/;
const SUPABASE_QUERY_RE = /\.(from|rpc)\(|supabase\.(from|rpc|auth)\b|createClient\(|createServerClient\(|createClientComponentClient\(/;

export function touchesTenantSupabasePath(source: string): boolean {
  return TENANT_KEY_RE.test(source) && SUPABASE_QUERY_RE.test(source);
}

// fileLineCounts is caller-supplied (read from disk) so this stays a pure,
// testable transform — and so the reported line count is measured, not guessed.
export function knipToFindings(report: KnipReport, fileLineCounts: Record<string, number> = {}): Finding[] {
  const findings: Finding[] = [];
  let n = 0;

  for (const file of report.files) {
    n += 1;
    const lines = fileLineCounts[file];
    const securityPath = touchesSecurityPath(file);
    const unreferenced = lines === undefined ? "Entire file is unreferenced." : `Entire file (${lines} lines) is unreferenced.`;
    findings.push({
      id: `M5-${String(n).padStart(2, "0")}`,
      title: securityPath ? `Unused security-relevant file: ${file}` : `Unused file: ${file}`,
      severity: securityPath ? "Medium" : "Low",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "M5 — Slop / dead code",
      location: file,
      status: "Open",
      evidence: "knip: file is never imported from any entry point.",
      impact: securityPath
        ? `${unreferenced} Sits in an auth/guard/security path — confirm where authorization is actually enforced before assuming this is dead weight (cross-check against the M1 authorization review).`
        : unreferenced,
      fix: "Delete the file (confirm it isn't a planned/unwired entry point first).",
      value: securityPath ? 4 : 2,
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
    const securityPath = touchesSecurityPath(issue.file);
    const partialImpact = `${deadExports.length} unused export${deadExports.length === 1 ? "" : "s"} — exact line reduction needs a manual look (knip reports the declaration, not its body size).`;
    findings.push({
      id: `M5-${String(n).padStart(2, "0")}`,
      title: securityPath ? `Unused exports in security-relevant file: ${issue.file}` : `Unused exports in ${issue.file}`,
      severity: securityPath ? "Medium" : "Low",
      confidence: "Confirmed",
      category: "Maintainability",
      taxonomy: "M5 — Slop / dead code",
      location: issue.file,
      status: "Open",
      evidence: `knip: unreferenced export(s) ${deadExports.join(", ")}.`,
      impact: securityPath
        ? `${partialImpact} Defined but never called in an auth/guard/security path — confirm where authz is actually enforced before dismissing as dead weight (cross-check against the M1 authorization review).`
        : partialImpact,
      fix: "Delete the unused exports, or inline them if they're only used internally.",
      value: securityPath ? 4 : 2,
      ease: 4,
      safety: 4,
      // knip's dead-export detection is deterministic given its entry config — ~100%
      // precise once the framework/dynamic-ref FP class is configured (issue #72).
      precisionTier: "high",
    });
  }

  return findings;
}
