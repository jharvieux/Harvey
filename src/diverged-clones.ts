// #360: Type-3 (near-miss) clone detection for security checks — the population jscpd
// structurally cannot see. jscpd is a raw-token Rabin-Karp match: the moment a copy-pasted
// auth/tenant check is EDITED (a scoping literal changed, a statement added), it stops being an
// exact clone and drops out of M4 entirely — which is precisely when it becomes the
// "patched one copy, missed the other" bug the M4 spec calls a bug-multiplier.
//
// divergedCloneFindings' scope is deliberately narrow to keep the false-positive rate defensible:
//   - only files the caller already screened as security-relevant — path-based
//     (touchesSecurityPath, the shared #226/#361 signal) OR, since #399, content-based (a
//     supabase query scoped by a tenant-key literal, touchesTenantSupabasePath — the per-entity
//     lib/ai/tools/*/lib/stores/* copy-paste vein that sits outside the v1 path vocabulary) —
//     this pass never runs repo-wide;
//   - only function-level comparison, with a minimum token mass;
//   - consistent whole-function renames (Type-2, Baker's parameterized match) are SKIPPED:
//     a faithfully-renamed copy is plain duplication, not divergence. What fires is literal
//     drift ('tenant_id' vs 'owner_id'), inconsistent identifier mapping, or a small
//     structural edit (statement added/removed) at >=90% token similarity.
//
// #809 adds wholeRepoDivergedCloneFindings — the same divergence math, opt-in and un-scoped by
// file selection (the caller may pass any subset, including non-security files), generic wording
// and Medium severity instead of the security framing, plus a volume cap since the caller can no
// longer be relied on to hand-pick a small file set.
//
// #1095 removes the cross-file-only restriction both passes carried. It cited #232's M4 rationale
// ("self-file clones are internally-repetitive DATA — SVG icon tables, enum literals"), which was
// MEASURED FALSE on 2026-07-25 against a real 2755-file target: 76% copy-pasted test setup/mock
// chains, 7% JSX render blocks, ZERO SVG/enum clusters. Two near-identical functions in ONE file
// where a fix landed in one copy and not the other are exactly what this detector exists to catch,
// and the in-file case has WEAKER discovery cues than the cross-file one — a different filename is
// a memory jog, a second copy 300 lines down in a file you believe you have read is not. The
// nested-function subsequence pair that only same-file comparison can produce is excluded in
// compare() (isNested).
//
// The cost was MEASURED, not guessed (2026-07-26, crbnos/carbon @ 92e19c04 — 4,080 source files,
// 4,043 into the whole-repo pass, capped at MAX_WIDE_FUNCTIONS; two runs of each variant, same
// machine, same optimized build):
//   - the ALWAYS-ON security-path pass: 60-70 ms -> 90-155 ms, and 0 -> 3 diverged families on a
//     target where cross-file comparison found none;
//   - the OPT-IN whole-repo pass: 175-213 s -> 242-459 s, and 204 -> 282 families (+38%). The
//     variance is machine noise; the direction is real, and it lands where it should — same-file
//     pairs are the ones most likely to clear the length prefilter and reach the LCS.
// The same commit precomputes rawJoined/normJoined, which is why the whole-repo pass is FASTER
// than it is without this change on the pre-#1095 code (618 s on the same target) while doing
// strictly more work. MAX_WIDE_FUNCTIONS + M4-98 already bound that pass, so no new cap is added.
//
// Everything emitted is REVIEW tier (reviewFinding) — "these two checks disagree; which one is
// right?" is an adjudication question, not a mechanical verdict. Full Type-4 semantic clone
// detection remains out of scope (an open research problem; see #360).

import ts from "typescript";
import type { Finding } from "./findings.js";
import { reviewFinding } from "./review-tier.js";

export const M4_DIVERGED_TAXONOMY = "M4 — Diverged security-path clone";
// #809: the opt-in whole-repo extension's taxonomy — deliberately distinct from the taxonomy
// above so a report can tell "diverged security check" (High, always-on) apart from "diverged
// clone somewhere in the codebase" (Medium, opt-in) at a glance.
export const M4_DIVERGED_WIDE_TAXONOMY = "M4 — Diverged clone (whole-repo)";

export interface SecurityPathFile {
  /** Target-relative path, e.g. "lib/auth/require-tenant.ts". */
  path: string;
  source: string;
}

// A function below this many normalized tokens carries too little structure for "same shape,
// different literal" to mean anything — tiny guards legitimately look alike.
const MIN_FN_TOKENS = 40;
// LCS token similarity floor for the structural-edit branch. Two independently-written handlers
// in the same framework rarely exceed ~0.8; a copy-paste with one edited statement sits >0.9.
const MIN_SIMILARITY = 0.9;
// Cheap prefilter: a pair whose token counts differ by more than this ratio cannot reach
// MIN_SIMILARITY, so skip the O(n*m) LCS.
const MIN_LENGTH_RATIO = 0.8;
// #474: token sequences are joined with a separator no token can contain, so `["a","bc"]` and
// `["ab","c"]` never compare equal. It used to sit inline as a raw U+001F byte, invisible in every
// editor and diff; naming it keeps #474's guarantee legible.
const TOKEN_SEP = "\u001f";

interface FnTokens {
  path: string;
  name: string;
  startLine: number;
  endLine: number;
  /** Structure sequence: identifiers -> "ID", literals -> "LIT", everything else its own kind. */
  norm: string[];
  /** Actual token text, index-aligned with norm. */
  raw: string[];
  /** #1095: `raw`/`norm` joined ONCE at extraction. compare() ran both joins per PAIR, so the
   *  two cheap identity checks were the pass's dominant cost — O(tokens) of string allocation on
   *  every one of the O(n^2) comparisons. Precomputing makes them string-compares. */
  rawJoined: string;
  normJoined: string;
}

function isTsxPath(path: string): boolean {
  return path.endsWith(".tsx") || path.endsWith(".jsx");
}

const LITERAL_KINDS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.StringLiteral,
  ts.SyntaxKind.NoSubstitutionTemplateLiteral,
  ts.SyntaxKind.TemplateHead,
  ts.SyntaxKind.TemplateMiddle,
  ts.SyntaxKind.TemplateTail,
  ts.SyntaxKind.NumericLiteral,
  ts.SyntaxKind.BigIntLiteral,
  ts.SyntaxKind.RegularExpressionLiteral,
]);

function tokenize(text: string, tsx: boolean): { norm: string[]; raw: string[] } {
  const scanner = ts.createScanner(
    ts.ScriptTarget.Latest,
    /* skipTrivia */ true,
    tsx ? ts.LanguageVariant.JSX : ts.LanguageVariant.Standard,
    text,
  );
  const norm: string[] = [];
  const raw: string[] = [];
  for (let kind = scanner.scan(); kind !== ts.SyntaxKind.EndOfFileToken; kind = scanner.scan()) {
    if (kind === ts.SyntaxKind.Identifier || kind === ts.SyntaxKind.PrivateIdentifier) norm.push("ID");
    else if (LITERAL_KINDS.has(kind)) norm.push("LIT");
    else norm.push(String(kind));
    raw.push(scanner.getTokenText());
  }
  return { norm, raw };
}

function functionsOf(file: SecurityPathFile): FnTokens[] {
  const sf = ts.createSourceFile(
    file.path,
    file.source,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    isTsxPath(file.path) ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  const tsx = isTsxPath(file.path);
  const fns: FnTokens[] = [];

  const record = (name: string, node: ts.Node): void => {
    const { norm, raw } = tokenize(node.getText(sf), tsx);
    if (norm.length < MIN_FN_TOKENS) return;
    fns.push({
      path: file.path,
      name,
      startLine: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
      endLine: sf.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
      norm,
      raw,
      rawJoined: raw.join(TOKEN_SEP),
      normJoined: norm.join(TOKEN_SEP),
    });
  };

  const visit = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.body) {
      record(node.name?.text ?? "(anonymous)", node);
    } else if (ts.isMethodDeclaration(node) && node.body) {
      record(ts.isIdentifier(node.name) ? node.name.text : "(method)", node);
    } else if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      record(ts.isIdentifier(node.name) ? node.name.text : "(anonymous)", node.initializer);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return fns;
}

// Token-level LCS length, two-row DP. Function token counts are small (hundreds) and the caller
// prefilters on length ratio, so O(n*m) is fine at this scope.
function lcsLength(a: string[], b: string[]): number {
  let prev = new Array<number>(b.length + 1).fill(0);
  let curr = new Array<number>(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      curr[j] = a[i - 1] === b[j - 1] ? prev[j - 1]! + 1 : Math.max(prev[j]!, curr[j - 1]!);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length]!;
}

interface Divergence {
  a: FnTokens;
  b: FnTokens;
  /** Aligned token-level diffs for the norm-identical case, e.g. `'tenant_id' ↔ 'owner_id'`. */
  diffs?: string[];
  /** Similarity for the structural-edit case. */
  similarity?: number;
}

// Norm-identical pair: same structure, only identifier/literal values can differ. Returns the
// diverging positions, or null when the pair is a CONSISTENT rename (Type-2) — identifiers map
// bijectively and every literal matches — which is faithful duplication, not drift.
function alignedDivergence(a: FnTokens, b: FnTokens): string[] | null {
  const fwd = new Map<string, string>();
  const rev = new Map<string, string>();
  const diffs: string[] = [];
  for (let i = 0; i < a.norm.length; i++) {
    const ra = a.raw[i]!;
    const rb = b.raw[i]!;
    if (a.norm[i] === "LIT") {
      if (ra !== rb) diffs.push(`${ra} ↔ ${rb}`);
    } else if (a.norm[i] === "ID") {
      const mappedTo = fwd.get(ra);
      const mappedFrom = rev.get(rb);
      if ((mappedTo !== undefined && mappedTo !== rb) || (mappedFrom !== undefined && mappedFrom !== ra)) {
        diffs.push(`${ra} ↔ ${rb}`);
      } else {
        fwd.set(ra, rb);
        rev.set(rb, ra);
      }
    }
  }
  return diffs.length > 0 ? diffs : null;
}

// #1095: same-file pairs ARE compared now (see divergedCloneFindings' header), but a function
// NESTED inside another is a token SUBSEQUENCE of its parent, which LCS scores as near-identity —
// a containment relationship, not two copies that drifted. Cross-file comparison could never
// produce this pair, so the exclusion appears only now. Line ranges, not token math: exact.
function isNested(a: FnTokens, b: FnTokens): boolean {
  if (a.path !== b.path) return false;
  return (a.startLine <= b.startLine && a.endLine >= b.endLine) || (b.startLine <= a.startLine && b.endLine >= a.endLine);
}

function compare(a: FnTokens, b: FnTokens): Divergence | null {
  if (isNested(a, b)) return null;
  if (a.rawJoined === b.rawJoined) return null; // Type-1 exact — jscpd's job
  if (a.normJoined === b.normJoined) {
    const diffs = alignedDivergence(a, b);
    return diffs ? { a, b, diffs } : null; // null = consistent Type-2 rename, skip
  }
  const [shorter, longer] = a.norm.length <= b.norm.length ? [a.norm, b.norm] : [b.norm, a.norm];
  if (shorter.length / longer.length < MIN_LENGTH_RATIO) return null;
  const similarity = (2 * lcsLength(a.norm, b.norm)) / (a.norm.length + b.norm.length);
  return similarity >= MIN_SIMILARITY ? { a, b, similarity } : null;
}

const MAX_DIFFS_SHOWN = 4;
const MAX_MEMBERS_SHOWN = 5;

// #1095: two-member titles. Since same-file pairs are now compared, printing the path on both
// sides would read as a rendering bug on the common in-file case; collapse it the way
// selfFileCloneDisclosureFinding (src/quality-scan.ts) already does for jscpd's self-clones.
function pairLabel(a: FnTokens, b: FnTokens): string {
  return a.path === b.path ? `${a.path}::${a.name} ↔ ::${b.name}` : `${a.path}::${a.name} ↔ ${b.path}::${b.name}`;
}

// One finding per FAMILY (connected component of flagged pairs), not per pair. Measured
// 2026-07-16 on the #222 corpus: per-pair emission turned boxyhq's one drifted
// getServerSideProps boilerplate family (8 pages) into 21 findings — n(n-1)/2 rows for one
// review decision. A family is one adjudication: "these N copies of the same check disagree".
interface Family {
  members: FnTokens[];
  divergences: Divergence[];
}

// Union-find over the flagged pairs -> one family per connected component, largest first. Shared
// by both the security-path pass and the #809 whole-repo pass — the family-collapsing rationale
// (one adjudication per drifted group, not one per pair) applies identically to either scope.
function buildFamilies(divergences: Divergence[]): Family[] {
  const parent = new Map<FnTokens, FnTokens>();
  const find = (x: FnTokens): FnTokens => {
    const p = parent.get(x) ?? x;
    if (p === x) return x;
    const root = find(p);
    parent.set(x, root);
    return root;
  };
  for (const d of divergences) parent.set(find(d.a), find(d.b));

  const families = new Map<FnTokens, Family>();
  for (const d of divergences) {
    const root = find(d.a);
    const fam = families.get(root) ?? { members: [], divergences: [] };
    for (const fn of [d.a, d.b]) if (!fam.members.includes(fn)) fam.members.push(fn);
    fam.divergences.push(d);
    families.set(root, fam);
  }
  return [...families.values()].sort((a, b) => b.members.length - a.members.length);
}

function familyFinding(fam: Family, i: number): Finding {
  const members = [...fam.members].sort((a, b) => a.path.localeCompare(b.path) || a.startLine - b.startLine);
  const loc = (f: FnTokens): string => `${f.path}:${f.startLine}-${f.endLine}`;
  // The strongest pair is the one with aligned literal diffs (structure-identical); otherwise
  // the highest-similarity structural edit.
  const aligned = fam.divergences.filter((d) => d.diffs);
  const best = aligned[0] ?? [...fam.divergences].sort((a, b) => (b.similarity ?? 0) - (a.similarity ?? 0))[0]!;
  const pairEvidence = best.diffs
    ? `${best.a.name} (${best.a.path}) and ${best.b.name} (${best.b.path}) are structurally IDENTICAL but disagree at ${best.diffs.length} token position(s): ${best.diffs.slice(0, MAX_DIFFS_SHOWN).join("; ")}${best.diffs.length > MAX_DIFFS_SHOWN ? "; …" : ""}`
    : `${best.a.name} (${best.a.path}) and ${best.b.name} (${best.b.path}) are ${Math.round((best.similarity ?? 0) * 100)}% token-identical after normalization — a copy-pasted check with statement(s) added, removed, or reordered`;
  const memberList = members.slice(0, MAX_MEMBERS_SHOWN).map(loc).join(" ↔ ");
  const overflow = members.length > MAX_MEMBERS_SHOWN ? ` (+${members.length - MAX_MEMBERS_SHOWN} more)` : "";

  return reviewFinding({
    id: `M4-DIV-${String(i + 1).padStart(2, "0")}`,
    title:
      members.length === 2
        ? `Diverged security-path clones: ${pairLabel(members[0]!, members[1]!)}`
        : `Diverged security-path clone family (${members.length} functions): ${members[0]!.name} et al.`,
    severity: "High",
    category: "Security-relevant duplication",
    taxonomy: M4_DIVERGED_TAXONOMY,
    location: memberList + overflow,
    evidence: `${members.length} near-identical copies of one security check have drifted apart. Worst pair: ${pairEvidence}.`,
    question: "These security checks started as copies and now disagree — is the divergence intentional, and is EACH copy still individually correct for its call site?",
    impact:
      "A copy-pasted authorization/tenant check whose copies have drifted is the M4 bug-multiplier in its most dangerous form: a security fix applied to one copy was, by definition, not applied to the others. Unlike an exact clone, jscpd cannot see these pairs at all (cross-check against the M1 authorization review).",
    fix: "Diff the copies, decide which behavior is correct, and centralize the check at one choke point so future edits cannot drift.",
    okWhen: "The call sites genuinely require different scoping and each copy is individually correct — the resemblance is historical, not a broken contract.",
    notOkWhen: "The copies were meant to enforce the same rule and one carries an older or wrong check (a stale tenant filter, a weakened comparison) — the classic patched-one-copy drift.",
  });
}

// The entry point. `files` must already be the security-relevant subset (the caller applies
// touchesSecurityPath and, since #399, touchesTenantSupabasePath) — this pass is scoped, not
// repo-wide, by design (#360). For whole-repo coverage, see wholeRepoDivergedCloneFindings (#809).
export function divergedCloneFindings(files: SecurityPathFile[]): Finding[] {
  const fns = files.flatMap(functionsOf);
  const divergences: Divergence[] = [];
  for (let i = 0; i < fns.length; i++) {
    for (let j = i + 1; j < fns.length; j++) {
      const a = fns[i]!;
      const b = fns[j]!;
      const d = compare(a, b);
      if (d) divergences.push(d);
    }
  }
  return buildFamilies(divergences).map(familyFinding);
}

// #809: the whole-repo counterpart's finding shape — same evidence math (aligned literal diffs or
// LCS similarity), but generic wording and Medium (not High) severity: a hit here is NOT known to
// guard a tenant/auth boundary the way divergedCloneFindings' security-path admission guarantees,
// so it never earns the security framing. Still review tier — "did a fix land in one copy and not
// the others" is an adjudication question regardless of scope.
function wideFamilyFinding(fam: Family, i: number): Finding {
  const members = [...fam.members].sort((a, b) => a.path.localeCompare(b.path) || a.startLine - b.startLine);
  const loc = (f: FnTokens): string => `${f.path}:${f.startLine}-${f.endLine}`;
  const aligned = fam.divergences.filter((d) => d.diffs);
  const best = aligned[0] ?? [...fam.divergences].sort((a, b) => (b.similarity ?? 0) - (a.similarity ?? 0))[0]!;
  const pairEvidence = best.diffs
    ? `${best.a.name} (${best.a.path}) and ${best.b.name} (${best.b.path}) are structurally IDENTICAL but disagree at ${best.diffs.length} token position(s): ${best.diffs.slice(0, MAX_DIFFS_SHOWN).join("; ")}${best.diffs.length > MAX_DIFFS_SHOWN ? "; …" : ""}`
    : `${best.a.name} (${best.a.path}) and ${best.b.name} (${best.b.path}) are ${Math.round((best.similarity ?? 0) * 100)}% token-identical after normalization — a copy-pasted block with statement(s) added, removed, or reordered`;
  const memberList = members.slice(0, MAX_MEMBERS_SHOWN).map(loc).join(" ↔ ");
  const overflow = members.length > MAX_MEMBERS_SHOWN ? ` (+${members.length - MAX_MEMBERS_SHOWN} more)` : "";

  return reviewFinding({
    id: `M4-DIVW-${String(i + 1).padStart(2, "0")}`,
    title:
      members.length === 2
        ? `Diverged clone: ${pairLabel(members[0]!, members[1]!)}`
        : `Diverged clone family (${members.length} functions): ${members[0]!.name} et al.`,
    severity: "Medium",
    category: "Duplication debt",
    taxonomy: M4_DIVERGED_WIDE_TAXONOMY,
    location: memberList + overflow,
    evidence: `${members.length} near-identical copies of one block have drifted apart. Worst pair: ${pairEvidence}.`,
    question: "These copies started identical and now disagree — is the divergence intentional, or did a fix/behavior change land in one copy and not the other(s)?",
    impact: "An edited copy of duplicated logic is a maintenance bug-multiplier: a change (bugfix, new case, behavior tweak) applied to one copy was, by definition, not applied to the others.",
    fix: "Diff the copies, decide which behavior is correct, and centralize the logic at one choke point so future edits cannot drift.",
    okWhen: "The call sites genuinely require different behavior and each copy is individually correct — the resemblance is historical, not a broken contract.",
    notOkWhen: "The copies were meant to behave identically and one carries a stale or incomplete edit.",
  });
}

// #809: disclosed volume-cap gap, mirroring the jscpdUnavailableFinding/knipUnavailableFinding
// shape already used for M4/M5 partial coverage (src/quality-scan.ts) — a capped whole-repo pass
// is a disclosed partial, never a silent under-count (the coverage guard, CLAUDE.md).
function volumeCapFinding(consideredCount: number, cap: number): Finding {
  return reviewFinding({
    id: "M4-98",
    title: "M4 whole-repo diverged-clone pass truncated (volume cap)",
    severity: "Info",
    category: "Maintainability",
    taxonomy: M4_DIVERGED_WIDE_TAXONOMY,
    location: "(repo-wide)",
    evidence: `${consideredCount} functions were extracted repo-wide; only the first ${cap} (by path, then name) were compared to keep the whole-repo near-miss pass tractable.`,
    question: "Is the codebase past this scan's volume cap large enough that a scoped, per-package re-run is warranted for full coverage?",
    impact: "Whole-repo diverged-clone coverage is partial on a codebase this large — a disclosed volume cap, not a finding of zero further divergence in the untested remainder.",
    fix: "Re-run scoped to a subdirectory (e.g. one app/package at a time) to get full comparison coverage of the remainder.",
    okWhen: "The remainder was reviewed by a separate scoped run, or the codebase's size genuinely puts further near-miss review out of scope for this engagement.",
    notOkWhen: "No follow-up scoped run ever covers the functions this cap dropped.",
  });
}

// #1080: the security-path pass ABOVE always runs, but only over the caller's narrowFiles subset
// (touchesSecurityPath OR touchesTenantSupabasePath) — the REST of the tree is compared only when
// the opt-in --whole-repo-diverged flag is passed (#809), which run-audit never does. Before this,
// the only disclosure of that scoping was a `console.error` in src/cli/quality-scan.ts — stderr,
// never the deliverable — so a report showing a whole-repo M4 duplication percentage next to
// security-path-only diverged-clone findings read as "both covered the repo". Mirrors the
// volumeCapFinding shape (also a scope disclosure, not an adjudication) and is suppressed by the
// caller when the whole-repo pass DID run (nothing was skipped in that case).
export function divergedScopeFinding(narrowFileCount: number, eligibleFileCount: number): Finding {
  const uncovered = eligibleFileCount - narrowFileCount;
  return reviewFinding({
    id: "M4-97",
    title: "M4 diverged-clone (near-miss) pass covered only the security-relevant file subset",
    severity: "Info",
    category: "Maintainability",
    taxonomy: M4_DIVERGED_WIDE_TAXONOMY,
    location: "(repo-wide)",
    evidence: `The diverged-clone comparison ran over ${narrowFileCount} security/tenant-relevant file(s) of ${eligibleFileCount} eligible source file(s) in this scope. The remaining ${uncovered} file(s) were NOT compared for near-miss (Type-3) divergence this pass.`,
    question: "Is this codebase's non-security-path portion large/important enough that a --whole-repo-diverged re-run is warranted for full near-miss coverage?",
    impact: "A drifted copy of non-security logic elsewhere in the codebase (a bugfix or behavior change applied to one copy and not another) would not be caught by this pass — only the security/tenant-scoped subset is covered by default.",
    fix: "Re-run `pnpm quality-scan` with `--whole-repo-diverged` to cover the remainder (opt-in — noisier, review tier, no security guarantee attached, see M4-DIVW-* findings).",
    okWhen: "The engagement's risk focus is genuinely the security/tenant-isolation surface this pass already covers, or a separate --whole-repo-diverged run already covered the remainder.",
    notOkWhen: "No --whole-repo-diverged run ever covers the remainder and the codebase has significant non-security business logic where drifted duplication would matter.",
  });
}

// Default bound on how many extracted functions the whole-repo pass will pairwise-compare.
// Comparison is O(n^2) in function count (bounded further by the length-ratio window below), so a
// hard cap keeps a large codebase's scan tractable and reproducible instead of ever hanging.
const MAX_WIDE_FUNCTIONS = 4000;

// #809: whole-repo Type-3 near-miss pass (opt-in, review tier — see src/cli/quality-scan.ts's
// --whole-repo-diverged flag). Unlike divergedCloneFindings, `files` need not be security-relevant
// — callers pass the codebase (or the non-security complement of it, to avoid double-reporting
// pairs the security-path pass already covers). Two volume controls bound the O(n^2) comparison
// that a hand-picked small subset never needed:
//   - a hard cap (maxFunctions) on how many extracted functions enter comparison at all, applied
//     in a deterministic order (path, then name) so a capped run is reproducible; a cap hit is
//     DISCLOSED (M4-98), never a silent drop (the coverage guard, CLAUDE.md);
//   - a sorted sliding window keyed off the same MIN_LENGTH_RATIO compare() already enforces, so
//     pairs that could never reach MIN_SIMILARITY are never even enumerated, not just rejected —
//     this changes nothing about which pairs fire (compare() is unchanged), only how many pairs
//     the loop itself considers.
export function wholeRepoDivergedCloneFindings(files: SecurityPathFile[], opts: { maxFunctions?: number } = {}): Finding[] {
  const maxFunctions = opts.maxFunctions ?? MAX_WIDE_FUNCTIONS;
  const allFns = files.flatMap(functionsOf).sort((a, b) => a.path.localeCompare(b.path) || a.name.localeCompare(b.name));
  const capped = allFns.length > maxFunctions;
  const fns = capped ? allFns.slice(0, maxFunctions) : allFns;

  const byLength = [...fns].sort((a, b) => a.norm.length - b.norm.length);
  const divergences: Divergence[] = [];
  for (let i = 0; i < byLength.length; i++) {
    const a = byLength[i]!;
    for (let j = i + 1; j < byLength.length; j++) {
      const b = byLength[j]!;
      if (b.norm.length > a.norm.length / MIN_LENGTH_RATIO) break; // sorted ascending: nothing further can reach MIN_LENGTH_RATIO
      const d = compare(a, b);
      if (d) divergences.push(d);
    }
  }

  const findings = buildFamilies(divergences).map(wideFamilyFinding);
  if (capped) findings.push(volumeCapFinding(allFns.length, maxFunctions));
  return findings;
}
