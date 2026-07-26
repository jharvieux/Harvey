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

// #1050: knip's per-file issue record also carries the unused-dependency verdicts it derives from
// package.json (MEASURED against knip 5.88.1 on a two-unused-dep fixture, 2026-07-25: the reporter
// emits `dependencies` and `devDependencies` as [{ name, line, col, pos }] on the package.json
// entry). They were absent from this type, so they were dropped at the type boundary and M5
// under-reported a scope brief `briefs/audit-modules.md` names explicitly — with no disclosure, so
// the absence read as a clean result. Optional because a merged/legacy report may predate them.
// #1080: the six IssueRecords keys #1050 left behind (MEASURED against knip 5.88.1's json reporter,
// node_modules/knip/dist/reporters/json.js: `initRow` builds all of these, and
// get-included-issue-types.js's defaults exclude only classMembers/nsExports/nsTypes — Harvey passes
// no --include/--exclude, so the rest are on and were silently dropped at this type boundary the
// same way dependencies/devDependencies were). `binaries` carries only `{name}` (the reporter pushes
// it directly, not through `convert()`); `duplicates` is one array of symbols PER duplicate cluster;
// `enumMembers` is keyed by the enum's own name. `owners` is the CODEOWNERS enrichment knip attaches
// to the row when the target ships a CODEOWNERS file — not an issue type, threaded into evidence
// below rather than its own finding.
export interface KnipIssue {
  file: string;
  owners?: { name: string }[];
  exports: KnipExportIssue[];
  types: KnipExportIssue[];
  dependencies?: KnipExportIssue[];
  devDependencies?: KnipExportIssue[];
  optionalPeerDependencies?: KnipExportIssue[];
  unlisted?: KnipExportIssue[];
  unresolved?: KnipExportIssue[];
  binaries?: { name: string }[];
  duplicates?: KnipExportIssue[][];
  enumMembers?: Record<string, KnipExportIssue[]>;
  catalog?: KnipExportIssue[];
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

// #1080: the project-scope subset of JSCPD_IGNORE_GLOBS worth a disclosed file count. The
// build-artifact directories (node_modules/dist/.next) are the universal, expected exclusion every
// tool applies and are never walked for a count here — walking node_modules on a real target is
// O(10^5) files for a fact nobody finds surprising. These five are Harvey-specific product-scope
// DECISIONS that silently narrow what "M4 duplication" means for the repo, which is exactly what
// read as a whole-repo figure with no disclosure (#1080) — most notably `**/*demo*/**`, a SUBSTRING
// glob that also excludes a shipped `demos/` product directory, not just mock/test-labeled paths.
export const JSCPD_DISCLOSED_GLOBS = JSCPD_IGNORE_GLOBS.filter((g) => !["**/node_modules/**", "**/dist/**", "**/.next/**"].includes(g));

// Minimal glob→RegExp translator scoped to the shapes JSCPD_IGNORE_GLOBS actually uses: a leading
// "**/" (zero or more leading path segments), a trailing "/**" (zero or more trailing path segments),
// and "*" within a segment (any run of non-separator characters). Anchored full-match against a
// POSIX-relative path. Not a general globber — deliberately narrow to what this list needs, so it
// stays auditable against the 8 patterns above rather than pulling in a transitive glob dependency
// undeclared in package.json (the exact "unlisted" defect #1080's knip fix discloses).
function globToRegExp(glob: string): RegExp {
  let g = glob;
  let prefix = "";
  let suffix = "";
  if (g.startsWith("**/")) {
    prefix = "(?:.*/)?";
    g = g.slice(3);
  }
  if (g.endsWith("/**")) {
    suffix = "(?:/.*)?";
    g = g.slice(0, -3);
  }
  const body = g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*");
  return new RegExp(`^${prefix}${body}${suffix}$`);
}

/** Does `relPath` (POSIX-relative to the scan root) match one of jscpd's own ignore globs? */
export function matchesJscpdIgnoreGlob(relPath: string): boolean {
  return JSCPD_IGNORE_GLOBS.some((g) => globToRegExp(g).test(relPath));
}

/** Does `relPath` match this specific glob? For per-glob tallying (jscpdIgnoreScopeFinding). */
export function matchesGlob(glob: string, relPath: string): boolean {
  return globToRegExp(glob).test(relPath);
}

export interface JscpdGlobMatch {
  glob: string;
  count: number;
  example?: string;
}

// #1080: one Info row naming the exclusion globs and the file count each matched, per the
// INFRA-SCOPE-00 disclosure precedent (src/scan/infra-scope.ts) — `matches` is caller-supplied
// (the CLI walks the target and tallies per JSCPD_DISCLOSED_GLOBS, src/cli/quality-scan.ts) so
// this stays a pure, testable transform.
export function jscpdIgnoreScopeFinding(matches: JscpdGlobMatch[]): Finding | undefined {
  const withHits = matches.filter((m) => m.count > 0);
  if (withHits.length === 0) return undefined;
  const total = withHits.reduce((sum, m) => sum + m.count, 0);
  const summary = withHits.map((m) => `\`${m.glob}\`: ${m.count} file${m.count === 1 ? "" : "s"}${m.example ? ` (e.g. ${m.example})` : ""}`).join("; ");
  return {
    // Same collision-avoidance reasoning as M4-SELF-00 above — outside jscpdToFindings' sequential
    // per-clone id space.
    id: "M4-SCOPE-00",
    title: `${total} file(s) excluded from M4 duplication scope by ignore globs`,
    severity: "Info",
    confidence: "N/A",
    category: "Maintainability",
    taxonomy: "M4 — Duplication",
    location: "(repo-wide)",
    status: "Open",
    evidence: `M4's jscpd pass excludes files matching these globs, on top of the standard node_modules/dist/.next build-artifact exclusion (not counted here): ${summary}. \`**/*demo*/**\` is a SUBSTRING match — it excludes a shipped \`demos/\` product directory just as readily as a mock/test-labeled path.`,
    impact:
      "The M4 duplication percentage and clone findings elsewhere in this report are computed over this narrowed file set, not the whole repo — a reader who assumes 'whole-repo' over- or under-trusts the percentage depending on how much of the excluded set is real product code (most often a demos/ directory) versus genuinely generated/vendored output.",
    fix: "If any excluded path above is real, hand-maintained product code, re-run jscpd directly over it with a narrower --ignore to get its own duplication figure.",
    value: 1,
    ease: 3,
    safety: 5,
    precisionTier: "high",
  };
}

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

// #232 excluded self-file clones on the assumption they were internally-repetitive DATA (SVG
// icon-path tables, enum/lookup literal blocks) that "extract into a shared module" doesn't apply
// to. #1080 RETRACTS that assumption as measured-false: run against a real 2755-file production
// target (2026-07-25, `pnpm exec tsx` ad hoc jscpd invocation, not a stored fixture), self-file
// clones were dominated by copy-pasted test setup/mock chains (327/431 clusters, 76%; 3178/4372
// duplicated lines, 73%) and repeated JSX render blocks (32/431, 7%) — both genuinely extractable
// (a shared test helper, a row-renderer component), not data. No SVG-icon-table or enum-literal
// cluster appeared in the sample. Still excluded from the SCORED findings below (a self-match
// pair has no cross-file "which copy is canonical" story the way a true clone does, and the
// measurement is one target, not a corpus) but see selfFileCloneDisclosureFinding (M4-SELF-00) — this is
// disclosed as a probably-actionable band pending a scoring-policy decision, not dismissed as noise.
function isCrossFileClone(dup: JscpdDuplicate): boolean {
  return dup.firstFile.name !== dup.secondFile.name;
}

function isSelfFileClone(dup: JscpdDuplicate): boolean {
  return !isCrossFileClone(dup);
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

// #1080: the self-file band #232 excludes entirely (see isCrossFileClone's header — the "it's just
// data" assumption is retracted, measured-false). Disclosed as one aggregate, same shape as
// subThresholdDisclosureFinding, so a large self-file band is visible rather than silently absorbed.
function selfFileCloneDisclosureFinding(selfClones: JscpdDuplicate[]): Finding {
  const worst = [...selfClones].sort((a, b) => b.lines - a.lines);
  const totalLines = selfClones.reduce((sum, d) => sum + d.lines, 0);
  const examples = worst
    .slice(0, 3)
    .map((d) => `${d.firstFile.name}:${d.firstFile.start}-${d.firstFile.end} ↔ :${d.secondFile.start}-${d.secondFile.end} (${d.lines} lines)`)
    .join("; ");
  return {
    // Deliberately NOT in the "M4-01"/"M4-02"/… sequential space jscpdToFindings assigns to
    // individual clone findings below — a report with that many significant clusters would collide.
    id: "M4-SELF-00",
    title: `${selfClones.length} self-file clone(s) excluded from the M4 duplication score`,
    severity: "Info",
    confidence: "Confirmed",
    category: "Maintainability",
    taxonomy: "M4 — Duplication",
    location: "(repo-wide)",
    status: "Open",
    evidence: `jscpd found ${selfClones.length} clone(s) where both copies sit in the SAME file (${totalLines} lines total), e.g. ${examples}. Excluded from the findings above and from the headline duplication percentage — the M4 fix text ("extract into a shared module") only applies across files.`,
    impact:
      "MEASURED 2026-07-25 (#1080) on a 2755-file production target: self-file clones were dominated by copy-pasted test setup/mock chains (76% of clusters, 73% of duplicated lines) and repeated JSX render blocks (7%), not primarily inert data (SVG icon tables, enum literals) as the original #232 exclusion assumed — that assumption is retracted as measured-false. Most of this band is genuinely extractable (a shared test helper, a row-renderer component); it stays out of the SCORED findings above pending a scoring-policy decision, not because it's confirmed noise.",
    fix: "No per-item action from this aggregate. Sample the evidence pairs above — a large count concentrated in test files usually means one setup helper/fixture should exist; concentrated in JSX usually means one row/row-renderer component should be extracted.",
    value: 1,
    ease: 3,
    safety: 5,
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

  // #1080: the dropped self-file band, disclosed the same way (M4-SELF-00).
  const selfClones = report.duplicates.filter(isSelfFileClone);
  if (selfClones.length > 0) findings.push(selfFileCloneDisclosureFinding(selfClones));

  return findings;
}

// #232: jscpd's own statistics.total counts every raw clone it found, including the self-file
// and sub-threshold clusters jscpdToFindings now excludes — recompute so the reported percentage
// matches what the findings above actually claim. Reimplements jscpd's own
// Statistic.calculatePercentage (round(cloned/total*10000)/100, verified against
// @jscpd/core's source) rather than guessing a formula.
export function duplicationSummary(
  report: JscpdReport,
): { percentage: number; duplicatedLines: number; totalLines: number; subThresholdCloneCount: number; selfFileCloneCount: number } {
  const totalLines = report.statistics.total.lines;
  const duplicatedLines = report.duplicates.filter(isSignificantClone).reduce((sum, d) => sum + d.lines, 0);
  const percentage = totalLines ? Math.round((10000 * duplicatedLines) / totalLines) / 100 : 0;
  // #365: not part of the headline percentage (that stands behind the significant findings), but
  // surfaced so the small-clone band is visible wherever the summary is printed.
  const subThresholdCloneCount = report.duplicates.filter(isSubThresholdClone).length;
  // #1080: same idea for the self-file band — never part of the percentage, always surfaced.
  const selfFileCloneCount = report.duplicates.filter(isSelfFileClone).length;
  return { percentage, duplicatedLines, totalLines, subThresholdCloneCount, selfFileCloneCount };
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

// #931: jscpd writing NO report is genuinely ambiguous — it's #505's clean "fewer than 2 comparable
// source files" shape, OR jscpd analysed nothing despite files being present (MEASURED on
// documenso/documenso, 3,395 files: the same commit/flags produced 0 findings at one absolute
// clone path and 1,256 at another). `comparableFileCount` is the scope's own source-file count,
// computed independently of jscpd's own file discovery — this doesn't explain the report's
// absence, it only decides whether that absence is disclosable as a coverage gap or safe to treat
// as a real zero-duplication result.
export function jscpdAnalysedNothingReason(comparableFileCount: number): string | undefined {
  if (comparableFileCount < 2) return undefined;
  return `jscpd wrote no report despite ${comparableFileCount} comparable source file(s) present under this scope — it analysed nothing`;
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

// #810: knip normally needs the TARGET's node_modules installed, because it LOADS the target's own
// knip config and every framework plugin config (vite.config.ts, next.config.ts, ...) — and those
// config files import packages that don't resolve without the deps, so knip aborts and M5 produced
// only the M5-00 "did not complete" gap (zero dead-code findings). quality-scan now RE-RUNS knip
// with every knip plugin disabled and Harvey-inferred entry points (buildDegradedKnipConfig) so no
// target config file is loaded at all — it produces dead-code findings from source alone. Those
// findings are review-tier (the unused-FILE ones are entry-graph-contingent, same as #696's
// inferred-entry path) and this M5-98 row discloses that the scope ran in that reduced mode rather
// than a clean, deps-resolved run — a visible partial per the coverage guard, not a silent degrade.
// Distinct id from M5-00 (didn't complete AT ALL) and M5-99 (completed but entry resolution looks
// untrustworthy) so the three failure/limitation shapes stay legible in the report.
export function knipReducedTierFinding(reason: string): Finding {
  return {
    id: "M5-98",
    title: "M5 dead-code scan ran in reduced (no-dependencies) mode for one or more scopes",
    severity: "Info",
    confidence: "N/A",
    category: "Maintainability",
    taxonomy: "M5 — Slop / dead code",
    location: "(repo-wide)",
    status: "Open",
    evidence: `knip could not load the target's own config, so it re-ran with all plugins disabled and Harvey-inferred entry points: ${reason}`,
    impact:
      "The M5 findings for the affected scope(s) come from a source-only run with no dependency/plugin resolution — the unused-FILE findings above are review-tier (an inferred entry graph, not the target's real one) and may over-report files that are plugin-registered entries. Real dead code is still surfaced; treat file findings as review candidates, not confirmed.",
    fix: "Install the target repo's dependencies (npm/pnpm/yarn install) so knip can load the target's own config and framework plugin configs, then re-run `pnpm quality-scan` for confirmed (non-review) file findings.",
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
// #696: inferredEntryFiles names files whose scope had NO knip config, so Harvey inferred the entry
// graph. A file "unused" under an inferred graph is not confirmed dead code — it could be a
// dynamically-registered entry Harvey's globs missed — so those FILE findings drop to review tier.
// Unused EXPORTS/TYPES are not entry-contingent in the same way and are unaffected.
export function knipToFindings(
  report: KnipReport,
  fileLineCounts: Record<string, number> = {},
  inferredEntryFiles: Set<string> = new Set(),
  // #1050: the package.json paths whose scope ran without resolving the target's own config and
  // plugins. Their unused-dependency verdicts are review tier — see the dependency block below.
  unresolvedDepScopes: Set<string> = new Set(),
): Finding[] {
  const findings: Finding[] = [];
  let n = 0;

  for (const file of report.files) {
    n += 1;
    const lines = fileLineCounts[file];
    const securityPath = touchesSecurityPath(file);
    const inferred = inferredEntryFiles.has(file);
    const unreferenced = lines === undefined ? "Entire file is unreferenced." : `Entire file (${lines} lines) is unreferenced.`;
    const securityImpact = securityPath
      ? `${unreferenced} Sits in an auth/guard/security path — confirm where authorization is actually enforced before assuming this is dead weight (cross-check against the M1 authorization review).`
      : unreferenced;
    findings.push({
      id: `M5-${String(n).padStart(2, "0")}`,
      title: securityPath ? `Unused security-relevant file: ${file}` : `Unused file: ${file}`,
      severity: securityPath ? "Medium" : "Low",
      confidence: inferred ? "Review" : "Confirmed",
      category: "Maintainability",
      taxonomy: "M5 — Slop / dead code",
      location: file,
      status: "Open",
      evidence: inferred
        ? "knip: file is never imported given Harvey-inferred entry points (target ships no knip config)."
        : "knip: file is never imported from any entry point.",
      impact: inferred
        ? `${securityImpact} Unreachable given Harvey-inferred entry points — the target ships no knip config, so this is a review candidate, not confirmed dead code.`
        : securityImpact,
      fix: inferred
        ? "Confirm the file isn't a dynamically-registered entry (route handler, plugin, config-referenced module) Harvey's inferred entry graph missed; if it's genuinely unreferenced, delete it."
        : "Delete the file (confirm it isn't a planned/unwired entry point first).",
      value: securityPath ? 4 : 2,
      ease: 5,
      safety: 4,
      // knip's dead-file detection is deterministic given its entry config — ~100% precise once the
      // framework/dynamic-ref FP class is configured (issue #72). With Harvey-inferred entries the
      // graph itself is uncertain, so those file findings are review tier, not high (#696).
      precisionTier: inferred ? "review" : "high",
    });
  }

  for (const issue of report.issues) {
    const securityPath = touchesSecurityPath(issue.file);
    // #1080: knip's CODEOWNERS enrichment on this row (present only when the target ships a
    // CODEOWNERS file) — appended to every finding built from this issue below rather than its own
    // finding, since it's routing metadata for an existing issue, not an issue of its own.
    const ownerNote = issue.owners?.length ? ` Owned by: ${issue.owners.map((o) => o.name).join(", ")}.` : "";

    // Unused VALUE exports — genuine dead code once entry config is set (#72): confirmed and
    // grade-counted, "delete or inline".
    if (issue.exports.length > 0) {
      const names = issue.exports.map((e) => e.name);
      n += 1;
      const partialImpact = `${names.length} unused export${names.length === 1 ? "" : "s"} — exact line reduction needs a manual look (knip reports the declaration, not its body size).`;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: securityPath ? `Unused exports in security-relevant file: ${issue.file}` : `Unused exports in ${issue.file}`,
        severity: securityPath ? "Medium" : "Low",
        confidence: "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: unreferenced export(s) ${names.join(", ")}.`,
        impact:
          (securityPath
            ? `${partialImpact} Defined but never called in an auth/guard/security path — confirm where authz is actually enforced before dismissing as dead weight (cross-check against the M1 authorization review).`
            : partialImpact) + ownerNote,
        fix: "Delete the unused exports, or inline them if they're only used internally.",
        value: securityPath ? 4 : 2,
        ease: 4,
        safety: 4,
        // Deterministic given entry config (#72) — but this "~100% precise" claim covers files and
        // VALUE exports only. Exported types are handled below at review tier, not here (#693).
        precisionTier: "high",
      });
    }

    // Unused exported TYPES — NOT dead code by default (#693 / AoP#566). A component `Props`/
    // options interface is normally used in-file (annotating its own component) and exported by
    // convention; knip flags the redundant `export`, not an unused type. Report as a review-tier
    // triage item — never a grade-counted "delete this".
    if (issue.types.length > 0) {
      const names = issue.types.map((t) => t.name);
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Exported-but-unreferenced type(s) in ${issue.file}`,
        severity: "Low",
        confidence: "Review",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: exported type(s) not imported by name elsewhere: ${names.join(", ")}.`,
        impact: `${names.length} exported type${names.length === 1 ? "" : "s"} with no external importer. Often not dead: component Props/option types are commonly exported by convention and used only within their own file.${ownerNote}`,
        fix: "Remove the `export` keyword if the type is only used in this file; leave it exported (with a one-line note) if it's an intentional public/convention surface — don't delete without checking.",
        value: 1,
        ease: 4,
        safety: 4,
        precisionTier: "review",
      });
    }

    // #1050: unused DEPENDENCIES — split prod from dev because they are different problems. An
    // unused runtime dependency is installed into the shipped tree, so it is supply-chain surface
    // (one more package whose maintainer, transitive tree and CVEs you carry for nothing), not just
    // tidiness; an unused devDependency is install/build weight and CI time.
    const depClasses = [
      { entries: issue.dependencies, dev: false },
      { entries: issue.devDependencies, dev: true },
    ];
    for (const { entries, dev } of depClasses) {
      if (!entries?.length) continue;
      const names = entries.map((d) => d.name);
      const label = dev ? "devDependencies" : "dependencies";
      // knip decides "unused" from the resolved import graph. A scope whose own config/plugins
      // could not be loaded (#696 inferred entries, #810's plugins-disabled retry) never saw the
      // config files that reference build-time deps, so those rows are review candidates, not
      // confirmed — the same honesty the file findings already apply.
      const unresolved = unresolvedDepScopes.has(issue.file);
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Unused ${label} declared in ${issue.file}`,
        severity: "Low",
        confidence: unresolved ? "Review" : "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: ${label} declared but never imported: ${names.join(", ")}.${unresolved ? " Entry/plugin resolution was incomplete for this scope, so config-only usages may be invisible." : ""}`,
        impact:
          (dev
            ? `${names.length} declared devDependenc${names.length === 1 ? "y" : "ies"} nothing imports — install time, lockfile churn and CI minutes spent on packages the build doesn't use.`
            : `${names.length} declared runtime dependenc${names.length === 1 ? "y" : "ies"} nothing imports — each ships into the installed tree with its own transitive packages and CVE exposure, for no functionality. Unused runtime deps are supply-chain surface, not just tidiness.`) +
          ownerNote,
        fix: unresolved
          ? `Install the target's dependencies so knip can resolve its config and plugins, re-run \`pnpm quality-scan\`, then remove whichever of ${names.join(", ")} is still reported.`
          : `Remove ${names.join(", ")} from ${label} in ${issue.file} (check for config-file-only or CLI-only usage first — knip sees imports, not shell scripts).`,
        value: dev ? 1 : 2,
        ease: 5,
        safety: 4,
        precisionTier: unresolved ? "review" : "high",
      });
    }

    // #1080: unlisted — imported in source but ABSENT from package.json (MEASURED against knip
    // 5.88.1, #1080). A supply-chain/build-reproducibility fact, not just tidiness: the import
    // resolves today only because some OTHER declared dependency happens to provide the same
    // package (a transitive hoist) or a global install — a stricter installer or a lockfile change
    // can break the build with no declared cause.
    if (issue.unlisted?.length) {
      const names = issue.unlisted.map((u) => u.name);
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Unlisted import(s) in ${issue.file}`,
        severity: "Medium",
        confidence: "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: import(s) resolved with no matching package.json entry: ${names.join(", ")}.`,
        impact: `${names.length} import${names.length === 1 ? "" : "s"} resolve today only because another declared dependency happens to provide the same package (a transitive hoist) or a global install — a supply-chain and build-reproducibility gap, not just tidiness.${ownerNote}`,
        fix: `Add ${names.join(", ")} to package.json directly (dependencies, or devDependencies if it's build/test-only) instead of relying on transitive resolution.`,
        value: 3,
        ease: 4,
        safety: 4,
        precisionTier: "high",
      });
    }

    // #1080: unresolved — an import knip could not resolve to any file/package at all.
    if (issue.unresolved?.length) {
      const names = issue.unresolved.map((u) => u.name);
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Unresolved import(s) in ${issue.file}`,
        severity: "Medium",
        confidence: "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: import specifier(s) that resolve to nothing: ${names.join(", ")}.`,
        impact: `${names.length} import${names.length === 1 ? "" : "s"} point at a module/package that does not exist from this file's location — likely a typo, a moved/renamed file, or a dependency removed without updating every call site.${ownerNote}`,
        fix: `Fix or remove the unresolved import(s): ${names.join(", ")}.`,
        value: 3,
        ease: 4,
        safety: 4,
        precisionTier: "high",
      });
    }

    // #1080: duplicates — the same symbol exported twice from one file. Not dead code, but a
    // tidiness/drift-risk signal knip surfaces separately from unused exports.
    if (issue.duplicates?.length) {
      const groups = issue.duplicates.map((g) => g.map((s) => s.name).join(" / "));
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Duplicate export(s) in ${issue.file}`,
        severity: "Low",
        confidence: "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: the same symbol is exported under more than one name: ${groups.join("; ")}.`,
        impact: `A caller can import either name for the same value — no functional bug, but two names for one symbol invites drift (one gets renamed/removed, the other doesn't) and confuses which is canonical.${ownerNote}`,
        fix: "Pick one canonical export name per symbol and update importers, or re-export the alias explicitly with a comment stating why both exist.",
        value: 1,
        ease: 4,
        safety: 4,
        precisionTier: "high",
      });
    }

    // #1080: enumMembers — enum members never referenced anywhere. Dead code inside a live enum.
    if (issue.enumMembers && Object.keys(issue.enumMembers).length > 0) {
      const parts = Object.entries(issue.enumMembers).map(([parent, members]) => `${parent}.${members.map((m) => m.name).join("/")}`);
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Unused enum member(s) in ${issue.file}`,
        severity: "Low",
        confidence: "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: enum member(s) never referenced: ${parts.join(", ")}.`,
        impact: `Dead enum members ship in the bundle and widen the type's surface with values nothing produces or consumes.${ownerNote}`,
        fix: "Remove the unused member(s), or confirm they're a deliberate public/reserved surface.",
        value: 1,
        ease: 4,
        safety: 4,
        precisionTier: "high",
      });
    }

    // #1080: optionalPeerDependencies / catalog — same "declared but nothing imports it" shape as
    // the dependencies block above, for the two dependency-declaration surfaces #1050 didn't cover.
    const namedDepClasses = [
      { entries: issue.optionalPeerDependencies, kind: "optional peer dependency", plural: "optional peer dependencies", where: "peerDependenciesMeta/peerDependencies" },
      { entries: issue.catalog, kind: "pnpm catalog entry", plural: "pnpm catalog entries", where: "the pnpm-workspace.yaml catalog" },
    ];
    for (const { entries, kind, plural, where } of namedDepClasses) {
      if (!entries?.length) continue;
      const names = entries.map((d) => d.name);
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Unused ${names.length === 1 ? kind : plural} declared in ${issue.file}`,
        severity: "Low",
        confidence: "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: ${names.length === 1 ? kind : plural} declared but never imported: ${names.join(", ")}.`,
        impact: `${names.length} declared ${names.length === 1 ? kind : plural} nothing in this scope imports — a stale declaration, or a consumer-facing surface no longer used.${ownerNote}`,
        fix: `Remove ${names.join(", ")} from ${where} if genuinely unused, or confirm it's kept for a downstream consumer.`,
        value: 1,
        ease: 5,
        safety: 4,
        precisionTier: "high",
      });
    }

    // #1080: binaries — a CLI binary nothing in the scripts/config knip scanned invokes.
    if (issue.binaries?.length) {
      const names = issue.binaries.map((b) => b.name);
      n += 1;
      findings.push({
        id: `M5-${String(n).padStart(2, "0")}`,
        title: `Unused binary/binaries declared in ${issue.file}`,
        severity: "Low",
        confidence: "Confirmed",
        category: "Maintainability",
        taxonomy: "M5 — Slop / dead code",
        location: issue.file,
        status: "Open",
        evidence: `knip: binary/binaries never invoked from any script/config knip scanned: ${names.join(", ")}.`,
        impact: `${names.length} CLI binar${names.length === 1 ? "y" : "ies"} nothing in this scope's scripts/config invokes — its backing package may itself be unused (cross-check against the unused-dependency rows above).${ownerNote}`,
        fix: `Confirm ${names.join(", ")} isn't invoked from a shell script, CI workflow, or Makefile knip doesn't parse; if genuinely unused, remove the backing package.`,
        value: 1,
        ease: 4,
        safety: 4,
        precisionTier: "review",
      });
    }
  }

  return findings;
}
