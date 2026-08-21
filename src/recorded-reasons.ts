// #1033 — a recorded reason (a blocker, a not-run explanation, a "we can't do X") is a CLAIM ABOUT
// THE WORLD, and claims decay. Harvey has many gates against OVERclaiming and, until this file, none
// against UNDERclaiming: "X works" fails loudly when it stops being true, while "X can't be done"
// fails silently forever, because by construction nobody exercises the path it forbids. A 2026-07-24
// sweep re-tested four recorded blockers and all four were false.
//
// The fix has two halves, and both are structural rather than exhortation:
//
//   1. EMPIRICAL vs DECISIONAL. An empirical reason is re-testable against the world ("the loader
//      does not read .svelte", "no detector exists for this class"). A decisional reason awaits a
//      human ruling ("out of scope pending a privacy decision"). Only the first kind decays, so only
//      the first kind is re-tested — and a falsifier on a decisional reason is REFUSED, not merely
//      unrequired: re-running a command against a product ruling is a category error, and the noise
//      would train readers to ignore the gate. Decisional reasons are selected by kind, not by a
//      stored share of the tracker, because that population changes independently of this rule.
//   2. Every empirical reason carries the COMMAND THAT WOULD FALSIFY IT. A reason with no falsifier
//      is unfalsifiable and therefore permanent. The contract is deliberately one-way:
//      **the falsifier exits 0 when the blocker is GONE.** So `grep -q <the thing that must not
//      exist>` is the canonical shape, and a gate run that gets exit 0 is a loud stale-reason row.
//
// This generalizes revalidateNotRunReasons (#321, src/scan/external-corpus.ts), which does exactly
// this for one narrow slice — external-corpus not-run baselines, re-tested by the drift run's own
// re-attempt rather than by a stored command. Same doctrine, repo-wide, with the command written down.

import { readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { readEntriesSafe, statSafe } from "./fs-walk.js";

type ReasonKind = "empirical" | "decisional";

const KEYS = ["REASON", "KIND", "PROVENANCE", "FALSIFIER", "FALSIFIER-TIER", "OWNER", "DECISION", "TOUCHES"] as const;
type Key = (typeof KEYS)[number];
const KNOWN = new Set<string>(KEYS);

// #1072 — some empirical falsifiers can only be re-run against a live tier: a two-tenant M2 stack, a
// Lighthouse/CWV pass, a SecBench run, the paired Supabase security labs. Recording those with a
// plain FALSIFIER: forces one of two dishonesties — a fake offline proxy command that re-tests
// nothing, or an UNVERIFIABLE failure on every offline run. FALSIFIER-TIER: names the environment
// the command needs; on an offline run it is SKIPPED-with-a-reason (disclosed and counted, never
// dropped), and on the run that declares that tier available (`--tier <name>` / `--live`) it runs
// exactly like any other falsifier. A value outside this set is malformed rather than silently
// always-skipped — this is the single place a new live tier is registered (like #341's OWNERS map).
// #1311 — `supabase-connected` added: a HOSTED Supabase project plus a client-supplied credential
// (a Management API PAT for `perf-scan`, a `SUPABASE_DB_URL` for `pii-classify`'s connected tier) —
// distinct from `m2-stack` (Harvey's OWN locally-provisioned two-tenant stack, no client credential)
// and from `supabase-labs` (the paired SSL corpus, a fixed pair of local variants).
export const KNOWN_FALSIFIER_TIERS = new Set(["m2-stack", "lighthouse", "secbench", "supabase-labs", "supabase-connected"]);

// #1072 — a live-only falsifier cannot name its target in the repo: the crAPI gateway URL, the
// external clone path, the served origin are all supplied by whoever stands the tier up. The live
// falsifiers used `<crapi-gateway>`-style angle-bracket prose, and `sh -c` reads `<` as an INPUT
// REDIRECT — so `--tier secbench` did not re-test anything, it died on "No such file or directory"
// and exited 1, which this file's contract reads as "the blocker still holds". Because that syntax
// makes every unbound live target unfalsifiable by construction, a
// placeholder is now a declared BINDING: substituted from HARVEY_FALSIFIER_<NAME> on the run that
// has the tier, and UNVERIFIABLE — never executed — when unbound. Lowercase-and-hyphens only, so a
// real redirect (`< /dev/null`, `2>&1`, `<<EOF`) is not mistaken for one.
const PLACEHOLDER_TOKEN = /<([a-z][a-z0-9-]*)>/g;

function falsifierPlaceholders(command: string): string[] {
  return [...new Set([...command.matchAll(PLACEHOLDER_TOKEN)].map((m) => m[1] as string))];
}

export function placeholderEnvVar(name: string): string {
  return `HARVEY_FALSIFIER_${name.toUpperCase().replaceAll("-", "_")}`;
}

function bindingHint(names: string[]): string {
  return names.map((n) => `<${n}> → ${placeholderEnvVar(n)}`).join(", ");
}

export interface ParsedReason {
  file: string;
  /** 1-based line of the block's REASON: key. */
  line: number;
  /** 1-based line of the block's last field, so the claim census can exclude what is already triaged. */
  endLine: number;
  fields: Partial<Record<Key, string>>;
  /** Parse-time problems (unknown/duplicate field). Validation adds to these; it never mutates. */
  parseErrors: string[];
}

// A block line may be decorated as a TS/SQL/shell comment, a Markdown quote, a list bullet, or a
// table cell — the convention has to survive in prose and in code, so the decoration is stripped
// rather than each host language getting its own parser.
const DECORATION = /^[\s>|*-]*(?:\/\/+|\/\*+|#+|<!--)?\s*/;
const TRAILER = /\s*(?:-->|\*\/)\s*$/;
// >=3 chars so a Markdown "M1:" or "NB:" outside the convention can't be mistaken for a typo'd field.
const FIELD = /^([A-Z][A-Z0-9-]{2,}):\s*(.*)$/;

/**
 * Blocks are contiguous: a block opens on REASON: and closes at the first line that is not a
 * `FIELD: value` line (a blank line is the conventional terminator). Prose after a block therefore
 * needs a blank line before it, which is also what makes an unknown ALL-CAPS field a typo worth
 * reporting rather than ambiguous prose.
 */
export function parseRecordedReasons(text: string, file: string, fenced = file.endsWith(".md")): ParsedReason[] {
  const out: ParsedReason[] = [];
  let open: ParsedReason | undefined;
  // A fenced block in Markdown is documentation OF the convention (this file's own syntax template,
  // for one), not a reason recorded IN it. GitHub issue bodies are Markdown too, so `--issues`
  // passes `fenced` explicitly rather than inferring it from a pseudo-filename.
  let inFence = false;
  text.split("\n").forEach((raw, i) => {
    if (fenced && /^\s*(```|~~~)/.test(raw)) {
      inFence = !inFence;
      open = undefined;
      return;
    }
    if (inFence) return;
    const match = FIELD.exec(raw.replace(DECORATION, "").replace(TRAILER, "").trimEnd());
    if (!match) {
      open = undefined;
      return;
    }
    const key = match[1] ?? "";
    const value = (match[2] ?? "").trim();
    if (key === "REASON") {
      open = { file, line: i + 1, endLine: i + 1, fields: { REASON: value }, parseErrors: [] };
      out.push(open);
      return;
    }
    if (!open) return;
    open.endLine = i + 1;
    if (!KNOWN.has(key)) open.parseErrors.push(`unknown field ${key}: (line ${i + 1}) — known fields are ${KEYS.join(", ")}`);
    else if (open.fields[key as Key] !== undefined) open.parseErrors.push(`duplicate field ${key}: (line ${i + 1})`);
    else open.fields[key as Key] = value;
  });
  return out;
}

/** The prose and code surfaces the convention governs. `briefs/` is scanner input, not prose, but
 * carries the same kind of standing claim. */
export const DEFAULT_ROOTS = ["src", "docs", "briefs", "CLAUDE.md", "SESSION.md", "vitest.config.ts"];

// REASON: SESSION.md stays inside DEFAULT_ROOTS and inside the ratchet, despite being an actively-rewritten scratch log — a standing claim in the session log is the shape that has done the most damage here, and exempting one file would be the first entry on a suppression list this gate deliberately does not have
// KIND: decisional
// PROVENANCE: MEASURED 2026-07-31 — SESSION.md is an actively rewritten surface that can carry standing operational claims; current contribution and churn are derived by `pnpm validate-reasons --census`, never frozen in this comment
// OWNER: operator
// DECISION: #1401 — keep every governed root under the same ratchet unless the operator explicitly rules otherwise; excluding a frequently edited file would create the first suppression path for precisely the claims this gate exists to expose
// TOUCHES: SESSION.md

const SCANNED = /\.(ts|md|txt|yml|sql)$/;
// targets/ is vendored third-party source — Harvey's convention does not govern it.
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "coverage", "targets"]);

function walk(abs: string, out: string[]): void {
  const stat = statSafe(abs);
  if (!stat) return;
  if (stat.isFile()) {
    if (SCANNED.test(abs)) out.push(abs);
    return;
  }
  for (const entry of readEntriesSafe(abs).entries) {
    if (entry.isDirectory && SKIP_DIR.has(entry.name)) continue;
    walk(join(abs, entry.name), out);
  }
}

export interface SourceText {
  file: string;
  text: string;
}

export function collectSources(roots: string[], base: string): SourceText[] {
  const files: string[] = [];
  for (const root of roots) walk(resolve(base, root), files);
  return files.map((abs) => ({ file: relative(base, abs), text: readFileSync(abs, "utf8") }));
}

export function collectReasons(roots: string[], base: string): ParsedReason[] {
  return collectSources(roots, base).flatMap(({ file, text }) => parseRecordedReasons(text, file));
}

// #1246 — the gate's headline ("N blocks, all well-formed") reads as a clean bill of health over the
// repo's claims, but well-formed is a statement about the blocks that EXIST. The #1033 inventory
// found claim-shaped lines in design prose that were never triaged into empirical/decisional at
// all, and a claim outside a block is not re-tested by anything. So the
// untriaged population is COUNTED on every run rather than quoted from a doc — an unstated
// limitation reads as a clean bill of health, and a stored number stops being true.
//
// Deliberately a LOWER BOUND over a fixed vocabulary. It is still advisory — it reports a number and
// nothing has to act on it — but since #1318 it also feeds the RATCHET below, which IS a gate
// failure. Do not read the "advisory" framing as covering the ratchet.
//
// #1319 added "out of reach"/"infeasible": #957 recorded a piece as "genuinely out of reach for a
// mechanical assembly" and it landed 3h25m later in 98 lines.
//
// #1347 added "untestable" and the unverified register. Until then the census was PROSE-ONLY and the
// vocabulary was impossibility-only, so #1318's motivating source-comment examples fell outside
// it. The selection rule includes "untestable" because it reaches a known standing-claim shape.
// The unverified register covers the corresponding evidence-status shape; runtime metrics report
// the current cost of both arms instead of this comment.
const IMPOSSIBILITY_VOCABULARY = /\b(cannot|can't|can not|impossible|no way to|not possible|unable to|out of reach|infeasible|untestable)\b/i;
// "the shape was never verified" forecloses nothing — it is the honest register, and refusing it on
// an ASSUMED provenance would punish exactly the phrasing the doctrine asks for. So it is censused
// (a standing claim nothing re-tests) but kept OUT of the impossibility-register check below.
const UNVERIFIED_VOCABULARY = /\b(unverified|not (?:independently )?(?:re-)?verified|never (?:been )?verified)\b/i;
// #1410 — the positive register needs the same decay census as impossibility and the honest-negative
// register. Keep this arm exact: widening it to the bare verb reaches ordinary evidence prose,
// while punctuation/spacing variants do not make the same claim as the two-word status label.
const VERIFIED_LIVE_VOCABULARY = /\bverified live\b/i;
const CLAIM_VOCABULARY = new RegExp(
  `${IMPOSSIBILITY_VOCABULARY.source}|${UNVERIFIED_VOCABULARY.source}|${VERIFIED_LIVE_VOCABULARY.source}`,
  "i",
);

export interface UntriagedClaim {
  file: string;
  line: number;
  text: string;
}

// #1246 — collectReasons reads FILES, so a blocker recorded in a GitHub issue body or comment sits
// outside every gate in this module. Three reason blocks were posted as issue comments on #920/#921/
// #1163 (2026-07-26) and nothing re-validated them; by 2026-07-27 one had already decayed (#1163's
// "a migrationsDir-less Prisma-7 target cannot stand up", retired by prismaV7ApplyArgs in
// src/prisma-dynamic.ts) with nothing anywhere to say so. Rendering a fetched issue as the same
// SourceText the file walk produces lets the structural pass and the claim census apply unchanged.
export interface FetchedIssue {
  number: number;
  body: string;
  comments?: { body: string }[];
}

export function issueSources(issues: FetchedIssue[]): SourceText[] {
  return issues.flatMap((issue) => [
    { file: `issue #${issue.number}`, text: issue.body ?? "" },
    ...(issue.comments ?? []).map((c, i) => ({ file: `issue #${issue.number} (comment ${i + 1})`, text: c.body ?? "" })),
  ]);
}

/**
 * How much of a surface the census reads. One home for the boundary, so the CLI, the tests and the
 * disclosure line cannot drift apart.
 *
 * `comments` rather than whole-file for code, because #1347's scale trap is structural: error-message
 * strings, `not-assessed` details and test titles use the vocabulary as runtime data rather than as
 * standing claims. A runtime string can say "cannot seed" without recording a repository claim.
 * Ratcheting those code lines would make the gate all backlog and no signal;
 * comments are the selected code surface because that is where standing claims are recorded.
 *
 * `none` for the generated baseline itself (#1347's fifth criterion): since #1318 it records every
 * claim VERBATIM, so censusing it would match every governed claim against its generated copy and
 * grow in lockstep with the population it is meant to constrain.
 */
export type CensusScope = "prose" | "comments" | "none";

const CENSUS_EXCLUDED = new Set(["src/unstructured-claims-baseline.ts"]);
const COMMENT_LINE: Record<string, RegExp> = {
  ts: /^\s*(?:\/\/|\/\*|\*)/,
  yml: /^\s*#/,
  sql: /^\s*--/,
};

export function censusScope(file: string): CensusScope {
  if (CENSUS_EXCLUDED.has(file)) return "none";
  return COMMENT_LINE[file.split(".").pop() ?? ""] ? "comments" : "prose";
}

export interface ClaimScopeMetrics {
  /** Claim-shaped lines accepted by the declared prose/comment boundary and outside reason blocks. */
  accepted: UntriagedClaim[];
  /** Matching code lines rejected because source files are deliberately comment-only. */
  excludedByCommentScope: number;
  /** Accepted rows carrying the exact positive-register phrase. */
  acceptedVerifiedLive: number;
  /** Every input surface, including explicitly excluded generated surfaces. */
  sourcesByScope: Record<CensusScope, number>;
}

/**
 * Claim-shaped lines outside any reason block. Prose surfaces (`.md`, `.txt`, issue bodies) are read
 * whole; code surfaces are read comment-lines-only — see `censusScope`. A trailing comment on a line
 * of code (`foo(); // cannot X`) is not read, which keeps this the lower bound it has always been.
 */
export function claimScopeMetrics(sources: SourceText[], reasons: ParsedReason[]): ClaimScopeMetrics {
  const accepted: UntriagedClaim[] = [];
  let excludedByCommentScope = 0;
  let acceptedVerifiedLive = 0;
  const sourcesByScope: Record<CensusScope, number> = { prose: 0, comments: 0, none: 0 };

  for (const { file, text } of sources) {
    const scope = censusScope(file);
    sourcesByScope[scope] += 1;
    if (scope === "none") continue;
    const comment = scope === "comments" ? COMMENT_LINE[file.split(".").pop() ?? ""] : undefined;
    const triaged = reasons.filter((r) => r.file === file);
    let inFence = false;
    text.split("\n").forEach((raw, i) => {
      if (/^\s*(```|~~~)/.test(raw)) inFence = !inFence;
      if (inFence || !CLAIM_VOCABULARY.test(raw)) return;
      if (comment && !comment.test(raw)) {
        excludedByCommentScope += 1;
        return;
      }
      const line = i + 1;
      if (triaged.some((r) => line >= r.line && line <= r.endLine)) return;
      accepted.push({ file, line, text: raw.trim() });
      if (VERIFIED_LIVE_VOCABULARY.test(raw)) acceptedVerifiedLive += 1;
    });
  }

  return { accepted, excludedByCommentScope, acceptedVerifiedLive, sourcesByScope };
}

/** Compatibility surface for existing ratchet consumers; the shared traversal owns the population. */
export function untriagedClaims(sources: SourceText[], reasons: ParsedReason[]): UntriagedClaim[] {
  return claimScopeMetrics(sources, reasons).accepted;
}

// #1318 (Gate 6 of #1320) — the census above is advisory, and an advisory number that nobody has to
// act on permits claim-shaped lines to accumulate outside the registry. The
// ratchet makes it strictly NON-WORSENING without demanding anyone migrate the backlog: the count
// may fall, never rise.
//
// Per FILE rather than one total, for two reasons. A single number is satisfied by deleting a claim
// in one doc and adding one in another — the population is unchanged and the gate stays green. And
// a per-file breach can NAME the lines to look at, which a global delta cannot: #1318's acceptance
// asks for the new lines, because otherwise the fix is a guessing game.
//
// A COUNT alone does not get there, which is why the baseline records each claim VERBATIM. Printing
// every claim line in the breaching file is the guessing game with extra steps: the first cut of
// this gate did exactly that and a real breach printed the whole file population with nothing
// marking which row was new. Matching
// the current lines against the recorded ones as a MULTISET reduces that to the actual delta, and it
// makes a baseline bump reviewable: the diff shows the new claims, not a number going up.
//
// #1399 — AND THE GATE NOW SCORES THAT TEXT, not the count. It used to record verbatim and score
// counts, which is a boundary with a consequence the old note here did not state: a baselined claim
// could be REWRITTEN INTO A STRONGER OR MATERIALLY DIFFERENT CLAIM and the gate stayed green,
// because the count never moved. See claimDrift below for the measurement that found it, the one
// that priced the extra churn, and the reason a per-row comparison is the right trade.
//
// Deliberately no exemption list. Suppressing a file recreates exactly the invisibility this exists
// to remove; the way past a breach is to write the claim as a falsifiable block, or to bump that
// file's baseline in a diff a human reads.
type ClaimBaseline = Record<string, number>;

/** Line counts from the verbatim baseline, for the report line only — the GATE scores text (#1399). */
export function claimCounts(baseline: Record<string, string[]>): ClaimBaseline {
  return Object.fromEntries(Object.entries(baseline).map(([file, texts]) => [file, texts.length]));
}

/**
 * Which of a file's current claim lines are NOT accounted for by its baseline. A multiset, so a
 * claim written twice needs two baseline entries. Whenever the count breaches, at least
 * (now - baseline) lines come back `isNew` — the marking cannot silently produce an empty set and
 * leave the author with nothing to act on.
 */
export function markNewClaims(baselineLines: string[], current: UntriagedClaim[]): { claim: UntriagedClaim; isNew: boolean }[] {
  const unclaimed = new Map<string, number>();
  for (const text of baselineLines) unclaimed.set(text, (unclaimed.get(text) ?? 0) + 1);
  return current.map((claim) => {
    const left = unclaimed.get(claim.text) ?? 0;
    if (left === 0) return { claim, isNew: true };
    unclaimed.set(claim.text, left - 1);
    return { claim, isNew: false };
  });
}

// #1401 — THE FAILURE MESSAGE USED TO MISATTRIBUTE BLAME. The ratchet is repo-wide over source, so a
// breaching line can sit in a file the author never opened: multiple PRs hit that in one session
// (#1387 through `src/fp-rules.test.ts`, arriving from #1383 mid-flight; #1397 through
// `src/recorded-reasons.test.ts` on a rebase; and #1347's own executor through several files after
// `main` gained `src/scan/rule-corpus-pairing.ts`). The reader's first move is to hunt for a defect
// in their own diff, and the repair — "just regenerate the baseline" — is one keystroke from
// "allowlist my own new claims", which is the loophole the gate exists to close. So the row says
// where it came from, and the repo-wide scoring is left alone: narrowing the gate to the diff would
// let a claim added by a PR that touches nothing else escape entirely.
type ClaimOrigin =
  | { known: false; why: string }
  | { known: true; sha: string; subject: string; authoredHere: boolean };

export function attributeClaim(
  claim: UntriagedClaim,
  blame: (file: string, line: number) => { sha: string; subject: string } | undefined,
  branchShas: Set<string> | undefined,
): ClaimOrigin {
  // A shallow CI checkout blames every line to one grafted commit, which would attribute EVERY row
  // to this branch — worse than saying nothing, because it reads as a confident answer.
  if (!branchShas) return { known: false, why: "no commit range against the base branch — a shallow checkout (`actions/checkout` defaults to depth 1) cannot attribute a line. Re-run locally, or fetch the base." };
  const at = blame(claim.file, claim.line);
  if (!at) return { known: false, why: `git blame could not read ${claim.file}:${claim.line} — an uncommitted line has no commit yet` };
  return { known: true, sha: at.sha, subject: at.subject, authoredHere: branchShas.has(at.sha) };
}

export function claimCensusByFile(claims: { file: string }[]): ClaimBaseline {
  const out: ClaimBaseline = {};
  for (const c of claims) out[c.file] = (out[c.file] ?? 0) + 1;
  return out;
}

interface ClaimDrift {
  file: string;
  /** Current claim lines the baseline does not account for. Any row here is a gate failure. */
  added: UntriagedClaim[];
  /**
   * Baseline lines no longer present. A REWORD produces one of each; a retirement, only these.
   * Since #1685 a row here is a gate failure too — see claimDrift.
   */
  dropped: string[];
  baseline: number;
  now: number;
}

/**
 * #1399 — THE GATE SCORES TEXT, NOT COUNTS, because a count is satisfied by rewriting a claim in
 * place. MEASURED 2026-07-28 by the acceptance verifier on PR #1387: editing `src/audit-runners.ts`'s
 * baselined "with no live DB" to "lacking a live DB" left `pnpm validate-reasons` at exit 0 with the
 * per-file count unchanged. The consequence, which the old disclosure did not state, is that a
 * baselined claim could be rewritten into a STRONGER or materially different one in silence — and
 * since #1347 widened the census to source comments, the population of that loophole is where this
 * repo's confident-register claims actually live (the taint-source block falsified in #1344).
 *
 * The baseline already records every claim VERBATIM, so this needs no new data — only for the
 * comparison to use it. A file absent from the baseline has an implicit budget of zero, so a new doc
 * full of claims still breaches, and this strictly subsumes the count ratchet: if a file's count
 * rises, at least (now − baseline) lines come back in `added`.
 *
 * The cost was measured before this rule was accepted: per-row comparison added breaches only when
 * governed wording changed, rather than on every innocuous edit. That selection property is stable;
 * storing the then-current commit and breach totals here would not be.
 *
 * #1685 — A DROPPED ROW FAILS TOO, so the recorded set can only shrink DELIBERATELY. Until now the
 * gate fired on `added` alone, and a baseline row whose claim had been reworded away, moved or
 * deleted sat in `unstructured-claims-baseline.ts` forever: failing nothing, telling nobody, and
 * inflating the backlog number the gate prints as its own headline — a claim about the past, which
 * is the exact decay this whole module exists to catch. The sibling `test-only-exports` ratchet
 * already works this way: a baseline row that has since gained a production caller FAILS, so a
 * human prunes it in a diff rather than letting the count fall in silence. Auto-pruning instead
 * would be the same defect pointing the other way.
 *
 * The initial migration measured no dead rows before enabling the failure. The durable rule is that
 * every future dead row must fail until deliberately pruned; current totals come from claimDrift.
 */
export function claimDrift(baseline: Record<string, string[]>, current: UntriagedClaim[]): ClaimDrift[] {
  const byFile = new Map<string, UntriagedClaim[]>();
  for (const c of current) byFile.set(c.file, [...(byFile.get(c.file) ?? []), c]);
  return [...new Set([...Object.keys(baseline), ...byFile.keys()])]
    .map((file) => {
      const recorded = baseline[file] ?? [];
      const now = byFile.get(file) ?? [];
      const marked = markNewClaims(recorded, now);
      const matched = new Map<string, number>();
      for (const m of marked.filter((x) => !x.isNew)) matched.set(m.claim.text, (matched.get(m.claim.text) ?? 0) + 1);
      const dropped = recorded.filter((text) => {
        const left = matched.get(text) ?? 0;
        if (left === 0) return true;
        matched.set(text, left - 1);
        return false;
      });
      return { file, added: marked.filter((m) => m.isNew).map((m) => m.claim), dropped, baseline: recorded.length, now: now.length };
    })
    .filter((d) => d.added.length > 0 || d.dropped.length > 0)
    .sort((a, b) => b.added.length + b.dropped.length - (a.added.length + a.dropped.length));
}

export function claimTotal(census: ClaimBaseline): number {
  return Object.values(census).reduce((n, c) => n + c, 0);
}

const PROVENANCE_FORM = /^(MEASURED|TRIED|ASSUMED) (\d{4}-\d{2}-\d{2})\b/;
// A falsifier that is a placeholder is worse than a missing one: it satisfies the gate while
// re-testing nothing.
const PLACEHOLDER = /^(n\/?a|tbd|todo|none|unknown|\?+)$/i;

// #1646 — THE COMMAND AN AUTHOR EXERCISES IS NOT ALWAYS THE COMMAND THE GATE RUNS. In a Claude Code
// agent shell, `grep` is a shell function installed by ~/.claude/shell-snapshots/snapshot-zsh-*.sh
// that re-execs the CLI as `ugrep`; it forwards to the real binary only for a short flag allow-list.
// `--revalidate` runs falsifiers through `spawnSync("sh", ["-c", …])` and an Actions `run:` step uses
// `bash -e {0}`, and NEITHER inherits that function — so the same command can be exercised by its
// author and answer the opposite way in the venue that scores it.
//
// An exhaustive flag-spelling probe found the ONLY divergence is
// `-v` combined with suppressed output — wrapper 1, `/usr/bin/grep` 0, on the same file and
// predicate. `-c`, `-L`, `-o` and `-m`, which #1646 asked about, agree. So the ban is `-v`, not a
// vague "prefer git grep".
//
// The production occurrence that exposed this used `grep -qv` and measured opposite answers under
// `sh -c` and the agent shell against the same tree. That is #1345's shape exactly: a falsifier whose
// answer depends on who ran it re-tests nothing. Current occurrence counts are irrelevant to the ban.
//
// A `grep` inside `sh -c '…'` is exempt, and not as a convenience: `sh -c` starts a new process that
// inherits no zsh functions. MEASURED 2026-07-31 — `sh -c "grep -qv beta f"` exits 0 from inside the
// agent shell, agreeing with /usr/bin/grep, while the same words unwrapped exit 1. `git grep`,
// `command grep` and an absolute path are exempt for the same reason: the function shadows the bare
// word only.
const SH_C_SEGMENT = /\bsh -c '[^']*'/g;
const GREP_INVOCATION = /(?:^|[\s|;&(])((?:git\s+|command\s+|\/\S*\/)?grep)((?:\s+-{1,2}[^\s'"]+)*)/g;

/** The first bare-`grep` invocation in `command` that uses `-v`, or undefined. */
function shadowedInvertGrep(command: string): string | undefined {
  for (const m of command.replace(SH_C_SEGMENT, " ").matchAll(GREP_INVOCATION)) {
    if (m[1] !== "grep") continue;
    const flags = m[2] ?? "";
    if (/\s--invert-match\b/.test(flags) || /\s-[A-Za-z]*v/.test(flags)) return `grep${flags}`;
  }
  return undefined;
}

// #1647 — a git pathspec is NOT a shell glob. Without `:(glob)` magic git matches with wildmatch and
// WM_PATHNAME off, so a bare `*` already crosses `/` and `**/` therefore requires at least one
// intervening directory. A checkout probe proved the bare form omitted every top-level `src/*.ts`
// path while the `:(glob)` form included them; the exact file totals are intentionally not retained.
// The falsifier that shipped with that pathspec exited 1 — "still blocked" — with a production
// importer planted at src/__probe.ts, which is the one answer a falsifier may never give wrongly.
const UNGLOBBED_DOUBLE_STAR = /'((?::\([^)]*\))?[^']*\*\*[^']*)'/g;

/** The first `**`-bearing git pathspec in `command` that lacks `:(glob)` magic, or undefined. */
function unglobbedPathspec(command: string): string | undefined {
  if (!/\bgit\s+(?:grep|ls-files|log|diff)\b/.test(command)) return undefined;
  for (const m of command.matchAll(UNGLOBBED_DOUBLE_STAR)) {
    const spec = m[1] as string;
    if (!/^:\([^)]*\bglob\b[^)]*\)/.test(spec)) return spec;
  }
  return undefined;
}

// #1319 — A SUPERVISED PATH PRODUCES A RELAY, NOT A SILENT CLOSE. No executor has ever recorded
// "asked the operator, was refused", while grants are routine and on the record (#1141, #1205,
// #1216) — yet "that path is supervised" silently terminated acceptance criteria in #945, #1056,
// #472 and #381. Supervision is not a fact a command can re-test; it is a question awaiting a human.
// So a reason that cites a supervised path AS its blocker must be decisional, and its DECISION: must
// name where the operator was actually asked. A DECISION with no issue ref and no path is a relay
// with no venue, which is the silent close wearing a field name.
//
// The path list mirrors CLAUDE.md's "Sensitive paths — never auto-change" section, which is the
// authority; package.json/pnpm-lock.yaml are deliberately absent (operator ruling 2026-07-27 — a
// folk belief that they were supervised was blocking five separate pieces of work).
//
// A supervised path appears in a reason two ways and only one of them is a blocker. "…the operator
// ruling behind it is recorded in docs/design/infrastructure-out-of-scope.md" CITES the path;
// "…because .github/workflows/ is supervised" BLOCKS on it. Co-occurrence of the two vocabularies
// anywhere in the text cannot tell them apart — the citation above was refused by the first cut of
// this check. So the supervision predicate must ATTACH to the path: the path is the SUBJECT of it
// ("<path> is supervised", "<path>, which needs an operator ruling", "the <path> file is
// protected"), or the OBJECT of a prohibition ("cannot edit <path>", "a supervised path like
// <path>"). A path that is merely named, cited or described stays untouched.
const SUPERVISED_PATH = String.raw`(?:\.github/workflows[\w./-]*|CLAUDE\.md|report-template/findings\.[\w.-]*|docs/[\w./-]*\.md)`;
const SUPERVISED_STATE = String.raw`(?:supervised|sensitive|protected|human-owned|off-limits|never auto-change)`;
const OPERATOR_RULING = String.raw`operator (?:approval|sign-?off|ruling|permission)`;
// Up to three words of noun between the path and its predicate: "<path> file is supervised".
const NOUN_GAP = String.raw`(?:,? which)?(?:\s+\w+){0,3}`;
const SUPERVISION_CITED_AS_BLOCKER = new RegExp(
  [
    `${SUPERVISED_PATH}${NOUN_GAP}\\s+(?:is|are|remains?|stays?|being)\\s+(?:an?\\s+)?${SUPERVISED_STATE}`,
    `${SUPERVISED_PATH}${NOUN_GAP}\\s+(?:needs?|requires?|awaits?)\\s+(?:an?\\s+)?${OPERATOR_RULING}`,
    `(?:${SUPERVISED_STATE} path|(?:cannot|can't|must not|may not|not allowed to|never)\\s+(?:auto-)?(?:edit|change|modify|touch|write to))[^.;\\n]{0,40}?${SUPERVISED_PATH}`,
  ].join("|"),
  "i",
);
// #1319 first shipped this as /#\d+|\//, where ANY slash counted — "pending a go/no-go" passed as a
// venue. The documented contract is an issue ref or a decision record, so require one of those.
const RELAY_VENUE = /#\d+|https?:\/\/\S+|\b[\w-]+(?:\/[\w.-]+)*\.(?:md|txt|ya?ml|json)\b/;

/**
 * `exists` answers "is this a path in the checkout" — injected so validation and derivation stay
 * pure and testable. It defaults to accepting everything, so a caller with no filesystem gets the
 * structural checks and simply skips the path-existence ones.
 */
export function validateRecordedReason(r: ParsedReason, exists: (path: string) => boolean = () => true): string[] {
  const errors = [...r.parseErrors];
  const f = r.fields;
  if (!f.REASON) errors.push("REASON: is empty");

  const kind = f.KIND?.toLowerCase();
  if (kind !== "empirical" && kind !== "decisional") {
    errors.push(`KIND: must be "empirical" (re-testable against the world) or "decisional" (awaits a human ruling), got ${f.KIND ? `"${f.KIND}"` : "nothing"}`);
  }
  if (!f.PROVENANCE) errors.push('PROVENANCE: missing — tag it MEASURED/TRIED/ASSUMED plus the date, e.g. "ASSUMED 2026-07-25"');
  else if (!PROVENANCE_FORM.test(f.PROVENANCE)) errors.push(`PROVENANCE: must start "MEASURED|TRIED|ASSUMED YYYY-MM-DD", got "${f.PROVENANCE}"`);

  const claim = f.REASON ?? "";
  // #1319 — A BUDGET LIMIT MUST NOT BORROW IMPOSSIBILITY'S VOCABULARY. Four claims recorded in this
  // repo asserted that the world forecloses something while actually describing the author's
  // remaining afternoon: #951's "a full pull is out of budget" (the next executor pulled the whole
  // stack and shipped a merged live proof 26 minutes later, finding a real bug the guess would have
  // missed), #957's "genuinely out of reach for a mechanical assembly" (98 lines, 3h25m later, no
  // new dependency), #52's "correctly NOT mechanically detectable" (detectors now exist for all
  // three named classes) and #873's "our mechanical tier structurally cannot see that shape" (the
  // function it needed had shipped a week earlier). A budget claim invites the next person to just
  // do it; an impossibility claim closes the file, and closes it SILENTLY, because by construction
  // nobody exercises a path recorded as foreclosed.
  //
  // PROVENANCE already separates the two registers: ASSUMED means nobody went and looked. So
  // impossibility vocabulary on an ASSUMED reason is refused. The author has three honest exits, all
  // one line: measure it and say MEASURED, name the real constraint (time), or ask the question.
  // Matched literally, including inside a denial ("not technically impossible") — the check reads
  // words, not sentences, and re-tagging a denial as MEASURED is the cheaper correction.
  const impossibility = IMPOSSIBILITY_VOCABULARY.exec(claim)?.[0];
  if (impossibility && PROVENANCE_FORM.exec(f.PROVENANCE ?? "")?.[1] === "ASSUMED") {
    errors.push(`REASON: says "${impossibility}" on an ASSUMED provenance — that is impossibility's vocabulary spent on a claim nobody tested (#1319). Four such claims were falsified in 2026-07, one of them 26 minutes later. Go look and re-tag it MEASURED/TRIED, or name the real constraint ("not attempted this round; the pull is ~20s"), or ask it as a question ("does the token store expose non-owner reads?") — a question invites the next person to test it, an assertion closes the file.`);
  }
  if (SUPERVISION_CITED_AS_BLOCKER.test(claim)) {
    if (kind === "empirical") {
      errors.push("REASON: cites a supervised path as the blocker, so this is decisional, not empirical (#1319) — no command re-tests whether the operator has approved. Record it as decisional with an OWNER and a DECISION naming where the operator was asked; a supervised path produces a RELAY, never a silent stop.");
    } else if (f.DECISION && !RELAY_VENUE.test(f.DECISION)) {
      errors.push(`DECISION: "${f.DECISION}" names no venue for a supervised-path blocker (#1319) — point at the issue the operator question is recorded on (\`#1234\`) or the decision record that holds it. A relay nobody can find is the silent close wearing a field name.`);
    }
  }

  const tier = f["FALSIFIER-TIER"];
  if (kind === "empirical") {
    if (!f.FALSIFIER) errors.push("FALSIFIER: missing — an empirical reason with no re-test command is unfalsifiable and therefore permanent (#1033). Write a command that EXITS 0 WHEN THE BLOCKER IS GONE.");
    else if (PLACEHOLDER.test(f.FALSIFIER)) errors.push(`FALSIFIER: "${f.FALSIFIER}" is a placeholder, not a command — it would satisfy this gate while re-testing nothing`);
    if (f.OWNER) errors.push("OWNER: belongs on a decisional reason (who makes the ruling); an empirical reason is settled by its FALSIFIER, not by a person");
    if (tier !== undefined && !KNOWN_FALSIFIER_TIERS.has(tier)) errors.push(`FALSIFIER-TIER: "${tier}" is not a registered live tier — a typo would make this falsifier silently always-skipped. Known tiers: ${[...KNOWN_FALSIFIER_TIERS].join(", ")} (register a new one in KNOWN_FALSIFIER_TIERS, #1072)`);
    const inverted = f.FALSIFIER ? shadowedInvertGrep(f.FALSIFIER) : undefined;
    if (inverted) {
      errors.push(`FALSIFIER: \`${inverted}\` inverts a BARE \`grep\` (#1646). In a Claude Code agent shell \`grep\` is a function re-execing as ugrep, whose \`-v\` exit status disagrees with /usr/bin/grep's — so this command answers one way when its author exercises it and the other way under \`sh -c\`, which is what --revalidate and CI actually run. Express the exclusion as a git pathspec (\`git grep -q … -- ':(glob,exclude)…'\`), count with \`grep -c\` and test the number, or call \`/usr/bin/grep\`.`);
    }
    const unglobbed = f.FALSIFIER ? unglobbedPathspec(f.FALSIFIER) : undefined;
    if (unglobbed) {
      errors.push(`FALSIFIER: git pathspec '${unglobbed}' uses \`**\` without \`:(glob)\` magic (#1647). Git matches pathspecs with WM_PATHNAME off, so a bare \`*\` already crosses \`/\` and \`**/\` instead demands an intervening directory — 'src/**/*.ts' silently matches nothing at the top level of src/. Write ':(glob)src/**/*.ts' (and ':(glob,exclude)…' for the negations), or drop the \`**\`.`);
    }
    const unbindable = f.FALSIFIER ? falsifierPlaceholders(f.FALSIFIER) : [];
    if (unbindable.length > 0 && tier === undefined) {
      errors.push(`FALSIFIER: names placeholder(s) ${bindingHint(unbindable)} but declares no FALSIFIER-TIER. Offline the command is run as written, where the shell reads \`<${unbindable[0]}>\` as an input redirect — it exits non-zero without testing anything, which reads as "the blocker holds" forever. Either write real paths, or tag the tier so the placeholders become run-time bindings (#1072).`);
    }
  }
  if (kind === "decisional") {
    if (f.FALSIFIER) errors.push("FALSIFIER: refused on a decisional reason — a human ruling is not re-testable by command, and sweeping it into the re-validation gate produces noise that discredits the gate (#1033)");
    if (tier !== undefined) errors.push("FALSIFIER-TIER: refused on a decisional reason — it qualifies a FALSIFIER, which a decisional reason must not carry (#1072)");
    if (!f.OWNER) errors.push("OWNER: missing — a decisional reason needs the person or role who makes the ruling");
    if (!f.DECISION) errors.push("DECISION: missing — point at the decision record (a doc path or issue ref) the ruling lives in");
  }
  // A TOUCHES: path that does not exist is the subsystem-drift version of #1072's redirect bug:
  // `git log -- <typo>` reports zero commits forever, so the reason looks watched and is not.
  for (const p of declaredTouches(r)) {
    if (!exists(p)) errors.push(`TOUCHES: "${p}" is not a path in this checkout — \`git log -- ${p}\` can only ever report zero commits, so this reason reads as drift-watched while nothing watches it`);
  }
  return errors;
}

export function reasonKind(r: ParsedReason): ReasonKind | undefined {
  const k = r.fields.KIND?.toLowerCase();
  return k === "empirical" || k === "decisional" ? k : undefined;
}

function reasonDate(r: ParsedReason): string | undefined {
  return PROVENANCE_FORM.exec(r.fields.PROVENANCE ?? "")?.[2];
}

function declaredTouches(r: ParsedReason): string[] {
  return (r.fields.TOUCHES ?? "").split(/[,\s]+/).filter(Boolean);
}

// #1246 — TOUCHES: was optional, so subsystemDrift — the half that catches the #1035 shape without
// re-running anything — watched only reasons whose author happened to declare it. Making it
// MANDATORY was the other option and is rejected: the seeded
// negative controls in .github/workflows/reasons-drift.yml plant reasons carrying no TOUCHES, so a
// structural failure would make all three exit non-zero for the WRONG reason — a green job whose own
// controls no longer prove anything is the false-green this whole family exists to kill.
//
// So the paths are DERIVED from the falsifier the author already wrote: a token naming a path that
// exists in this checkout is a subsystem the claim depends on. Existence is the whole filter, which
// is why a `<placeholder>`, a `/tmp` scratch file and a bare flag all drop out without a special
// case; requiring a `/` keeps a bare `src/` (which would put every commit under every reason) out.
const PATH_TOKEN = /[\w.@-]+(?:\/[\w.@*-]+)+/g;

export function watchedPaths(r: ParsedReason, exists: (path: string) => boolean): string[] {
  // node_modules is not in this repo's history, so a derived path under it would be watched in name
  // only — `git log --` on it reports zero commits forever, which is what the unwatched count exists
  // to distinguish from a genuinely quiet subsystem.
  const derived = [...(r.fields.FALSIFIER ?? "").matchAll(PATH_TOKEN)].map((m) => m[0]).filter((p) => !p.startsWith("node_modules/") && exists(p));
  return [...new Set([...declaredTouches(r), ...derived])];
}

type RevalidationStatus = "holds" | "STALE" | "UNVERIFIABLE" | "SKIPPED-LIVE";

interface RevalidationRow {
  file: string;
  line: number;
  claim: string;
  status: RevalidationStatus;
  detail: string;
}

export interface FalsifierResult {
  /** Process exit code; null for a signal, a timeout, or a command that never started. */
  code: number | null;
  output: string;
}

// 127 is the shell's "command not found". A mistyped falsifier exits non-zero, which under the
// contract below would read as "the blocker still holds" — the exact silent-pass this file exists to
// prevent — so it is called out as UNVERIFIABLE instead. Same for a signal/timeout (code null).
//
// `availableTiers` names the live tiers this run can exercise (empty offline). A falsifier tagged
// FALSIFIER-TIER whose tier is not available is SKIPPED-LIVE — disclosed and counted, not run and
// not a failure. Skipping it silently, or failing it as UNVERIFIABLE, would recreate the #1072
// defect this field exists to fix.
//
// `binding` resolves a `<placeholder>` in the command to the operator-supplied path/URL for this
// run. An unbound placeholder is UNVERIFIABLE rather than executed, because running it as written
// produces a non-zero exit indistinguishable from "the blocker holds".
export function revalidateReasons(
  reasons: ParsedReason[],
  run: (command: string) => FalsifierResult,
  availableTiers: Set<string> = new Set(),
  binding: (placeholder: string) => string | undefined = () => undefined,
): RevalidationRow[] {
  return reasons.flatMap((r): RevalidationRow[] => {
    if (reasonKind(r) !== "empirical") return [];
    const command = r.fields.FALSIFIER;
    if (!command) return [];
    const base = { file: r.file, line: r.line, claim: r.fields.REASON ?? "" };
    const tier = r.fields["FALSIFIER-TIER"];
    const placeholders = falsifierPlaceholders(command);
    if (tier !== undefined && !availableTiers.has(tier)) {
      const bindings = placeholders.length > 0 ? ` That run must also bind ${bindingHint(placeholders)}.` : "";
      return [{ ...base, status: "SKIPPED-LIVE" as const, detail: `live-only falsifier not run — its tier "${tier}" is not available on this run. Re-run where that tier exists: \`--tier ${tier}\` (or \`--live\`).${bindings} \`${command}\`` }];
    }
    const unbound = placeholders.filter((p) => binding(p) === undefined);
    if (unbound.length > 0) {
      return [{ ...base, status: "UNVERIFIABLE" as const, detail: `falsifier has unbound placeholder(s) — set ${bindingHint(unbound)} and re-run. It was NOT executed: as written the shell reads \`<${unbound[0]}>\` as an input redirect and exits non-zero, which is indistinguishable from the blocker still holding. \`${command}\`` }];
    }
    const resolved = placeholders.reduce((c, p) => c.replaceAll(`<${p}>`, binding(p) as string), command);
    const { code, output } = run(resolved);
    if (code === null || code === 127) {
      return [{ ...base, status: "UNVERIFIABLE" as const, detail: `falsifier could not be run (${code === null ? "signal/timeout" : "command not found"}): \`${resolved}\` — a reason whose re-test cannot execute is as unguarded as one with no re-test at all. ${output.trim().slice(0, 200)}` }];
    }
    if (code === 0) {
      return [{ ...base, status: "STALE" as const, detail: `FALSIFIED: \`${resolved}\` now exits 0, which by this reason's own contract means the blocker is GONE — the text says otherwise. Re-verify, then delete the reason and do the work it was deferring, or correct the claim. ${output.trim().slice(0, 200)}` }];
    }
    return [{ ...base, status: "holds" as const, detail: `\`${resolved}\` exits ${code} — reason still holds` }];
  });
}

interface SubsystemDriftRow {
  file: string;
  line: number;
  claim: string;
  detail: string;
}

// The complement to re-running falsifiers, and the higher-yield half for the shape that actually
// broke: #1035's reason asserted knip could not run without node_modules while a sibling module grew
// exactly that path a week later. Nobody had to re-run anything to catch it — the referenced
// subsystem had moved since the reason was recorded. Reported for review rather than as a failure:
// a sibling commit is evidence to go look, not proof the claim died, and failing on it would make
// the gate cry wolf on every merge.
export function subsystemDrift(
  reasons: ParsedReason[],
  commitsSince: (paths: string[], since: string) => string[],
  exists: (path: string) => boolean = () => false,
): SubsystemDriftRow[] {
  return reasons.flatMap((r) => {
    const paths = watchedPaths(r, exists);
    const since = reasonDate(r);
    if (paths.length === 0 || !since) return [];
    const commits = commitsSince(paths, since);
    if (commits.length === 0) return [];
    return [{
      file: r.file,
      line: r.line,
      claim: r.fields.REASON ?? "",
      detail: `${commits.length} commit(s) landed on ${paths.join(", ")} since this reason was recorded (${since}): ${commits.slice(0, 5).join(", ")} — re-read it before relying on it`,
    }];
  });
}
