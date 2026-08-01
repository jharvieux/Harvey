// #1827 — a corpus header that states a tier or a count must be derivable from the rows below it.
//
// THE DEFECT CLASS. A `*.entries.ts` file opens with a prose header explaining why its rows carry
// the tiers they do. The rows then move — a class graduates, a batch is re-tiered — and the prose
// does not. Nothing derives the claim from the data, so each instance is found only when a human
// happens to read the file. Three were found BY HAND in two days, in three different files:
// m9-authz.entries.ts (#1683, corrected in #1825), a third corrected in #1801, and
// b15-nextjs-authz.entries.ts (#1827), whose header still said `The two "none" rows` for eleven
// hours after #1811 graduated one of them to `review`.
//
// It matters more than a stale comment usually does because these headers are the stated rationale
// for a tier assignment: they are what a reader consults to decide whether a `none` row is a
// by-design boundary or outstanding work. A header claiming two gaps where one exists routes
// someone to look for a detector that already shipped — the false-decline shape
// docs/runbooks/false-decline-audit.md exists to catch.
//
// WHAT THIS GATE READS. Comment trivia only (via the TypeScript scanner, so a `//` inside a row's
// `note` string is not mistaken for prose). Consecutive comment lines are joined into a BLOCK before
// matching, because #1342 measured two bounds invisible purely because the author pressed return
// mid-phrase. Ground truth is the module's OWN exported array, loaded at runtime — not a second
// reading of the same text.
//
// WHAT IT FOUND. MEASURED 2026-08-01 over the whole population — 46 entries files, 1676 comment
// lines. 17 claims resolved, 5 of them contradicted their own rows, in THREE files. Only one of the
// three was known: b15's, the instance #1827 was filed for. The other two had never been found by
// hand and are older than the sweep that prompted this — b7-auth.entries.ts said "EVERY entry here
// is `review` tier" while P-CORS-REFLECTED-OBJLIT has been `high` since #645, and m7.entries.ts
// called its three positives `"connected"` after #1499 re-tiered them to `"local"`. So the class
// was never three; it was at least five, and its population is not zero.
//
// SCOPE OF THIS GATE, stated here so its own silence is not read as coverage. It resolves four
// claim shapes and no others:
//
//   count      a numeral next to a quoted tier and a row noun    — `The two "none" rows`
//   universal  every/all/each + a row noun + a quoted tier       — ``Every positive is `review` tier``
//   row        a row id declared in this file next to a tier     — ``P-MW-SOLE-AUTHZ … `none` ``
//   row-gap    a row id declared in this file next to a gapKind  — `P-CLIENT-RENDER-AUTHZ MEASURED GAP`
//
// Everything else is INVISIBLE to the PASS/FAIL, so a green run is a statement about that
// vocabulary and not about the prose. What it is not is SILENT: every tier or gap token the
// extractor could not resolve into a claim is counted per file by `residual` and ratcheted against
// RESIDUAL_BASELINE, so new unread claim-ish prose fails until someone looks at it, and a baseline
// row that has since become readable fails as STALE. The CLI prints each residual line verbatim.
//
// Four deliberate bounds inside the vocabulary, each one measured against a real header rather than
// imagined:
//
// 1. HISTORICAL NARRATION IS NOT READ. A header legitimately narrates what a row USED to be
//    (`Every row here used to be "connected"`, b8-supa.entries.ts:5 — true as history, false as a
//    present claim), and the same goes for a counterfactual (`the six "measured gaps" WOULD BE an
//    unfalsifiable claim`). Tense is not mechanically decidable, so a clause carrying a marker from
//    HISTORICAL_MARKERS is dropped to residual rather than judged. This costs recall on purpose: a
//    header stating its CURRENT claim in the past tense is not read by this gate.
// 2. A COUNT IS CHECKED ONLY DOWNWARD, because prose does not say whether it means the file or a
//    named subset — b16's "All three remain `review` tier" is about three rows in a file with six.
//    A subset can never exceed the file, so `actual >= n` is the sound half, and it is also the
//    direction every instance of this defect has taken: a graduation moves the count DOWN. A ZERO
//    claim is exempt and checked exactly, being vacuous as a subset claim. What this misses is a
//    header that UNDER-counts.
// 3. A `row` claim asserts only that the row's ACTUAL tier is AMONG the tiers named beside it, not
//    that it is the only one named. That is what lets `graduated from "none" to "review"` pass
//    while still failing a row whose tier appears nowhere in the sentence naming it.
// 4. THE SPACED PHRASE "measured gap" IS NOT COUNTED, only the hyphenated field form. b8-supa's
//    "the first live run … recorded one measured gap" is ordinary English in a file with no `none`
//    row at all. The spaced form still reads as a ROW claim, where the id disambiguates it.
//
// Two genres are excluded outright: recorded-reason blocks (#1033 — their PROVENANCE quotes
// corpus-wide gate output, and `pnpm validate-reasons` owns them), and clauses whose subject is a
// row id this file does not declare (m9-authz legitimately describes b15's P-MW-SOLE-AUTHZ, for
// which this file's rows are the wrong denominator). Both are counted as residual, not dropped.
//
// REASON: a header claim phrased outside the four shapes above — or inside a past-tense construction — is invisible to this gate's PASS/FAIL, so a green run is a statement about that vocabulary and not about every claim in the prose
// KIND: empirical
// PROVENANCE: MEASURED 2026-08-01 — `pnpm exec tsx src/cli/validate-entries-headers.ts --list` reports 46 entries files, 1676 comment lines, 17 resolved claims and 55 tokens the vocabulary could not read, each printed with its file, line and text.
// FALSIFIER: test -f src/cli/validate-entries-headers.ts || exit 127; pnpm exec tsx src/cli/validate-entries-headers.ts --residual-count > /tmp/harvey-entries-residual.txt 2>/dev/null || exit 127; test "$(tail -1 /tmp/harvey-entries-residual.txt)" = "0" && exit 0 || exit 1
// TOUCHES: src/scan/calibration src/entries-header-drift.ts

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";
import { readNamesSafe } from "./fs-walk.js";

const ENTRIES_DIR = "src/scan/calibration";

const TIERS = ["high", "review", "none", "local", "connected", "hosted"] as const;
type Tier = (typeof TIERS)[number];

// gapKind's two values. "measured-gap" is outstanding work, "by-design" an accepted boundary
// (src/scan/calibration/types.ts) — a header miscounting them misreports the same thing a tier
// count does, so they share the claim machinery.
type GapKind = "measured-gap" | "by-design";

export interface EntryRow {
  id: string;
  expectedTier?: string;
  gapKind?: string;
}

// A numeral the header could use for a count. "no"/"zero" are the ZERO claims — "this corpus has no
// open measured gap left" (owasp-react.entries.ts) is as derivable as any other number.
const NUMERALS: Record<string, number> = {
  no: 0,
  zero: 0,
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  eleven: 11,
  twelve: 12,
};

const ROW_NOUN = /\b(rows?|positives?|negatives?|entries|entry|members?|gaps?)\b/i;
const UNIVERSAL = /\b(every|all|each)\b/gi;

// A bare digit run is only a quantifier when nothing marks it as an issue ref (`#425`), a spec
// section (`§4a`), a date part (`2026-07-31`), a percentage or a fraction. Without these guards
// `As of #425 … at the "none" tier` extracted `count(none) == 425` — MEASURED, it was the first
// false claim this extractor produced.
const DIGIT_QUANTIFIER = /(?<![#§\d.\-/\w])(\d{1,3})(?![\d%\-/])/g;

// Dropping a window to residual on any of these is what keeps the gate off a header's history
// section. Deliberately generous: a missed claim is counted as residual, a misread one is a false
// failure, and only the second erodes trust in the gate.
// Past tense, and also the SUBJUNCTIVE: `Without it the six "measured gaps" would be an
// unfalsifiable claim` describes a counterfactual, not the rows as they stand.
const HISTORICAL_MARKERS =
  /\b(used to|use to|was|were|had|has since|have since|formerly|previously|prior|originally|until|no longer|stopped|superseded|supersedes|old|before|graduated|retired|deleted|removed|re-?tiered|re-?ruled|moved|would|could|should|instead of|rather than)\b/i;

// A claim does not cross a sentence, a semicolon or an em-dash, so the CLAUSE holding a tier token
// is its context — not a fixed character span. MEASURED 2026-08-01: the span version read
// `P-RLS-DISABLED in the base corpus — the three positives below are "connected"` and
// `P-MW-SOLE-AUTHZ is the one member still "none"` as the same shape; the em-dash is what tells the
// file-scoped claim from the one whose subject lives in another file. A `.` is only a boundary when
// whitespace follows, so `auth.yml` and `1.2.6` stay intact.
// A colon is a boundary in prose ("does not have: a rule STARTING to fire …") but NOT the one
// inside `expectedTier: "connected"`, which is the commonest way a header states a tier at all.
const CLAUSE_BOUNDARY = /(?<=[.;])\s+|(?<=:)\s+(?![`"'])|\s+[—–]\s+/;
// Inside its clause, the quantifier still has to be NEAR the tier it governs: `Every positive is a
// crisp … match, so all ten land `high`` carries both a universal and a numeral, and the one that
// governs `high` is the nearer.
const QUANTIFIER_SPAN = 60;
// Row ids as they are written in this corpus (P-… positives, N-… negatives, M7-P-… and friends).
// Used only to ask whether the ids in a clause belong to THIS file.
const ROW_ID_SHAPE = /\b[A-Z][A-Z0-9]*-[A-Z0-9][A-Z0-9-]{2,}\b/g;

interface CommentLine {
  line: number;
  text: string;
}

// Comment trivia only. A `//` inside a `note:` string is data, not prose, and the scanner is what
// tells the two apart — a line-based reader cannot.
export function commentLines(src: string): CommentLine[] {
  const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, src);
  const out: CommentLine[] = [];
  let kind = scanner.scan();
  while (kind !== ts.SyntaxKind.EndOfFileToken) {
    if (kind === ts.SyntaxKind.SingleLineCommentTrivia || kind === ts.SyntaxKind.MultiLineCommentTrivia) {
      const start = scanner.getTokenStart();
      const before = src.slice(0, start);
      const firstLine = before.split("\n").length;
      scanner.getTokenText().split("\n").forEach((l, i) => out.push({ line: firstLine + i, text: l }));
    }
    kind = scanner.scan();
  }
  return out;
}

interface CommentBlock {
  // Joined, comment-marker-stripped text of a run of consecutive comment lines.
  text: string;
  // Character offset in `text` -> source line, so a match reports where it actually is.
  lineAt: (offset: number) => number;
}

function stripMarkers(line: string): string {
  return line.replace(/^\s*(\/\/+|\/\*+|\*+\/?)\s?/, "").replace(/\*\/\s*$/, "").trim();
}

// A recorded-reason block (#1033) is a different genre with its own gate: its PROVENANCE quotes a
// command's output over the WHOLE corpus, not a claim about this file's rows. m9-authz's
// `… 3 by design, 1 measured-gap` is `validate-calibration`'s corpus-wide tally, and reading it as
// a claim about m9-authz's own six rows is a category error. Structure and re-testing of these
// blocks belong to `pnpm validate-reasons`.
const RECORDED_REASON_KEY = /^(REASON|KIND|PROVENANCE|FALSIFIER|FALSIFIER-TIER|OWNER|DECISION|TOUCHES):/;

// A run of consecutive comment lines is ONE block: a claim that wraps across a line break must
// still be matchable (#1342 measured two bounds invisible for exactly that reason).
export function commentBlocks(src: string): CommentBlock[] {
  const lines = commentLines(src);
  const blocks: CommentBlock[] = [];
  let current: { parts: string[]; offsets: number[]; lines: number[] } | null = null;
  let prevLine = -10;

  const flush = () => {
    if (!current) return;
    const { parts, offsets, lines: srcLines } = current;
    const text = parts.join(" ");
    blocks.push({
      text,
      lineAt: (offset) => {
        let best = srcLines[0] ?? 1;
        for (let i = 0; i < offsets.length; i++) {
          const o = offsets[i];
          if (o !== undefined && o <= offset) best = srcLines[i] ?? best;
        }
        return best;
      },
    });
    current = null;
  };

  for (const { line, text } of lines) {
    const stripped = stripMarkers(text);
    if (RECORDED_REASON_KEY.test(stripped)) {
      flush();
      prevLine = line;
      continue;
    }
    if (line !== prevLine + 1) flush();
    if (!current) current = { parts: [], offsets: [], lines: [] };
    const offset = current.parts.reduce((n, p) => n + p.length + 1, 0);
    current.parts.push(stripped);
    current.offsets.push(offset);
    current.lines.push(line);
    prevLine = line;
  }
  flush();
  return blocks;
}

export type Claim =
  | { kind: "count"; subject: Tier | GapKind; n: number; line: number; text: string }
  | { kind: "universal"; subject: Tier; line: number; text: string }
  | { kind: "row"; id: string; tiers: Tier[]; line: number; text: string }
  | { kind: "row-gap"; id: string; gap: GapKind; line: number; text: string };

export interface ResidualToken {
  line: number;
  token: string;
  reason: "no-quantifier-or-noun" | "historical-narration" | "cross-file-row-reference";
  text: string;
}

// A tier named in a quoted/backticked form. Bare English `none` ("none feed the free count") is not
// a tier token — requiring the quoting is what keeps the extractor off ordinary prose.
const TIER_TOKEN = new RegExp(`["'\`](${TIERS.join("|")})["'\`]`, "gi");
const GAP_TOKEN = /(measured[-\s]gaps?|by[-\s]design\s+gaps?)/gi;

// The quantifier nearest the tier token, or null. Returning the NEAREST is what decides between a
// universal and a count when a sentence carries both.
function nearestQuantifier(before: string): { kind: "universal" } | { kind: "count"; n: number } | null {
  const words = Object.keys(NUMERALS).join("|");
  const candidates: { at: number; value: { kind: "universal" } | { kind: "count"; n: number } }[] = [];
  for (const m of before.matchAll(new RegExp(`\\b(${words})\\b`, "gi"))) {
    candidates.push({ at: m.index, value: { kind: "count", n: NUMERALS[(m[1] ?? "").toLowerCase()] as number } });
  }
  for (const m of before.matchAll(DIGIT_QUANTIFIER)) {
    candidates.push({ at: m.index, value: { kind: "count", n: Number(m[1]) } });
  }
  for (const m of before.matchAll(UNIVERSAL)) {
    candidates.push({ at: m.index, value: { kind: "universal" } });
  }
  return candidates.sort((a, b) => b.at - a.at)[0]?.value ?? null;
}

interface Extraction {
  claims: Claim[];
  residual: ResidualToken[];
}

// A universal only reads as one when the row noun follows the quantifier directly. Without this,
// `Used here for genuine gaps, each naming its tracking issue — read "none" as …` — a LEGEND
// defining what "none" means — extracted "every tiered row is none" over a corpus of ten.
const UNIVERSAL_PHRASE = new RegExp(`\\b(every|all|each)\\s+(?:\\w+\\s+){0,2}${ROW_NOUN.source.slice(2, -2)}`, "i");

interface Clause {
  text: string;
  start: number;
}

function clauses(text: string): Clause[] {
  const out: Clause[] = [];
  let at = 0;
  for (const part of text.split(CLAUSE_BOUNDARY)) {
    if (part === undefined) continue;
    const start = text.indexOf(part, at);
    out.push({ text: part, start: start < 0 ? at : start });
    at = (start < 0 ? at : start) + part.length;
  }
  return out;
}

export function extractClaims(block: CommentBlock, rowIds: readonly string[]): Extraction {
  const claims: Claim[] = [];
  const residual: ResidualToken[] = [];

  for (const clause of clauses(block.text)) {
    const { text } = clause;
    const idsHere = [...text.matchAll(ROW_ID_SHAPE)].map((m) => m[0]);
    const local = idsHere.filter((id) => rowIds.includes(id));
    const foreign = idsHere.filter((id) => !rowIds.includes(id));

    const consider = (
      token: string,
      subject: Tier | GapKind,
      start: number,
      end: number,
      isTier: boolean,
      countable = true,
    ) => {
      const line = block.lineAt(clause.start + start);
      const snippet = text.replace(/\s+/g, " ").trim();

      // A row id in the same clause as a tier or a gap kind is a claim about THAT row, whatever the
      // quantifier. Reading it does not depend on tense: `graduated from "none" to "review"` names
      // the current tier too, which is why a row claim asks only that the actual tier is AMONG
      // those named.
      if (local.length > 0) {
        if (isTier) {
          const tiers = [
            ...new Set([...text.matchAll(new RegExp(TIER_TOKEN.source, "gi"))].map((m) => (m[1] ?? "").toLowerCase() as Tier)),
          ];
          for (const id of local) claims.push({ kind: "row", id, tiers, line, text: snippet });
        } else {
          for (const id of local) claims.push({ kind: "row-gap", id, gap: subject as GapKind, line, text: snippet });
        }
        return;
      }
      // The clause's subject is a row this file does not declare, so the file's own rows are the
      // wrong denominator for it — m9-authz.entries.ts legitimately describes b15's P-MW-SOLE-AUTHZ.
      if (foreign.length > 0) {
        residual.push({ line, token, reason: "cross-file-row-reference", text: snippet });
        return;
      }
      if (HISTORICAL_MARKERS.test(text)) {
        residual.push({ line, token, reason: "historical-narration", text: snippet });
        return;
      }
      const before = text.slice(Math.max(0, start - QUANTIFIER_SPAN), start);
      const quantifier = countable && ROW_NOUN.test(text) ? nearestQuantifier(before) : null;
      if (quantifier === null) {
        residual.push({ line, token, reason: "no-quantifier-or-noun", text: snippet });
        return;
      }
      if (quantifier.kind === "count") {
        claims.push({ kind: "count", subject, n: quantifier.n, line, text: snippet });
        return;
      }
      // "every measured gap" names a set with no total to check it against, unlike "every row is
      // `review`", which the file's own tiered rows answer.
      if (isTier && UNIVERSAL_PHRASE.test(before)) claims.push({ kind: "universal", subject: subject as Tier, line, text: snippet });
      else residual.push({ line, token, reason: "no-quantifier-or-noun", text: snippet });
    };

    for (const m of text.matchAll(TIER_TOKEN)) {
      consider(m[0], (m[1] ?? "").toLowerCase() as Tier, m.index, m.index + m[0].length, true);
    }
    for (const m of text.matchAll(GAP_TOKEN)) {
      // The SPACED phrase "measured gap" is ambiguous between the gapKind field value and ordinary
      // English — b8-supa's "the first live run … recorded one measured gap" is a sentence about a
      // run, in a file with no `none` row at all. Only the hyphenated field form is counted; the
      // spaced one is still read as a ROW claim, because a row id in the clause disambiguates it.
      const countable = /-/.test(m[0]);
      consider(m[0], /by[-\s]design/i.test(m[0]) ? "by-design" : "measured-gap", m.index, m.index + m[0].length, false, countable);
    }
  }

  const seen = new Set<string>();
  return {
    claims: claims.filter((c) => {
      const key = JSON.stringify(c);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
    residual,
  };
}

export interface Violation {
  file: string;
  line: number;
  claim: string;
  stated: string;
  actual: string;
  text: string;
}

function tierCount(rows: readonly EntryRow[], subject: Tier | GapKind): number {
  if (subject === "measured-gap" || subject === "by-design") {
    // gapKind is only meaningful with expectedTier "none" and defaults to "by-design" there
    // (src/scan/calibration/types.ts), so the default must be applied or every unset row reads as
    // neither kind and a by-design count is understated.
    return rows.filter((r) => r.expectedTier === "none" && (r.gapKind ?? "by-design") === subject).length;
  }
  return rows.filter((r) => r.expectedTier === subject).length;
}

export function checkClaims(file: string, rows: readonly EntryRow[], claims: readonly Claim[]): Violation[] {
  const out: Violation[] = [];
  for (const claim of claims) {
    if (claim.kind === "count") {
      const actual = tierCount(rows, claim.subject);
      // A count in prose may be scoped to a NAMED SUBSET rather than to the file — b16's "All three
      // remain `review` tier" is about the three rows the paragraph just discussed, in a file with
      // six. Whether the scope is the file or a subset is not mechanically decidable, so only the
      // sound half is judged: a subset can never be larger than the file, and a graduation moves
      // the count DOWN, which is the direction every instance of this defect has taken. A zero
      // claim is exempt — "this corpus has no open measured gap left" is vacuous as a subset claim
      // and is the strongest form of it, so it is checked exactly.
      const wrong = claim.n === 0 ? actual !== 0 : actual < claim.n;
      if (wrong) {
        out.push({
          file,
          line: claim.line,
          claim: claim.n === 0 ? `no ${claim.subject} rows` : `at least ${claim.n} ${claim.subject} rows`,
          stated: String(claim.n),
          actual: String(actual),
          text: claim.text,
        });
      }
      continue;
    }
    if (claim.kind === "universal") {
      const tiered = rows.filter((r) => r.expectedTier !== undefined);
      const offenders = tiered.filter((r) => r.expectedTier !== claim.subject);
      if (tiered.length === 0 || offenders.length > 0) {
        out.push({
          file,
          line: claim.line,
          claim: `every tiered row is ${claim.subject}`,
          stated: `all ${tiered.length} tiered rows are "${claim.subject}"`,
          actual:
            tiered.length === 0
              ? "no row in this file carries an expectedTier at all"
              : offenders.map((r) => `${r.id}=${r.expectedTier}`).join(", "),
          text: claim.text,
        });
      }
      continue;
    }
    if (claim.kind === "row-gap") {
      const row = rows.find((r) => r.id === claim.id);
      if (!row) continue;
      // gapKind is only meaningful with expectedTier "none" (types.ts), so a row that has since
      // graduated is not a gap of either kind — which is exactly the drift #1827 is about.
      const actual = row.expectedTier === "none" ? (row.gapKind ?? "by-design") : `not a gap (tier "${row.expectedTier}")`;
      if (actual !== claim.gap) {
        out.push({
          file,
          line: claim.line,
          claim: `gap kind of ${claim.id}`,
          stated: claim.gap,
          actual,
          text: claim.text,
        });
      }
      continue;
    }
    const row = rows.find((r) => r.id === claim.id);
    if (!row) continue;
    const actual = row.expectedTier;
    if (actual === undefined) continue;
    if (!claim.tiers.includes(actual as Tier)) {
      out.push({
        file,
        line: claim.line,
        claim: `tier of ${claim.id}`,
        stated: claim.tiers.map((t) => `"${t}"`).join(" / ") || "(none named)",
        actual: `"${actual}"`,
        text: claim.text,
      });
    }
  }
  return out;
}

export function entriesFiles(dir = ENTRIES_DIR): string[] {
  return readNamesSafe(dir)
    .filter((f) => f.endsWith(".entries.ts"))
    .sort()
    .map((f) => join(dir, f));
}

// Ground truth comes from the module's OWN exported array, evaluated — deliberately not from a
// second textual read of the file the claims live in.
export async function loadRows(file: string): Promise<EntryRow[]> {
  const mod = (await import(pathToFileURL(join(process.cwd(), file)).href)) as Record<string, unknown>;
  const arrays = Object.values(mod).filter((v): v is EntryRow[] => Array.isArray(v));
  if (arrays.length !== 1) {
    throw new Error(`${file}: expected exactly one exported array of rows, found ${arrays.length}`);
  }
  return arrays[0] as EntryRow[];
}

export interface FileReport {
  file: string;
  rows: number;
  commentLines: number;
  claims: Claim[];
  residual: ResidualToken[];
  violations: Violation[];
}

export async function auditEntriesHeaders(files = entriesFiles()): Promise<FileReport[]> {
  const reports: FileReport[] = [];
  for (const file of files) {
    const rows = await loadRows(file);
    const src = readFileSync(file, "utf8");
    const ids = rows.map((r) => r.id);
    const claims: Claim[] = [];
    const residual: ResidualToken[] = [];
    for (const block of commentBlocks(src)) {
      const e = extractClaims(block, ids);
      claims.push(...e.claims);
      residual.push(...e.residual);
    }
    reports.push({
      file,
      rows: rows.length,
      commentLines: commentLines(src).length,
      claims,
      residual,
      violations: checkClaims(file, rows, claims),
    });
  }
  return reports;
}

// The ratchet over what the vocabulary could NOT read. A file whose residual count rises has gained
// claim-ish prose this gate does not judge; one whose count falls has a stale row here. Both fail,
// so the list can only move deliberately — the same shape as test-only-exports.baseline.json.
// Numbers MEASURED 2026-08-01 by `pnpm exec tsx src/cli/validate-entries-headers.ts --list`.
const RESIDUAL_BASELINE: Readonly<Record<string, number>> = {
  "b10-deps.entries.ts": 1,
  "b11-crypto.entries.ts": 2,
  "b12-nextconfig.entries.ts": 2,
  "b15-nextjs-authz.entries.ts": 2,
  "b16-storage-secdef.entries.ts": 1,
  "b17-race-unscoped.entries.ts": 2,
  "b2-deps.entries.ts": 2,
  "b22-gha-permissions.entries.ts": 2,
  "b24-connected-postgrest-realtime.entries.ts": 2,
  "b3-injection.entries.ts": 2,
  "b4-xss.entries.ts": 2,
  "b5-headers.entries.ts": 2,
  "b6-crypto.entries.ts": 3,
  "b7-auth.entries.ts": 1,
  "b8-supa.entries.ts": 3,
  "b9-secrets.entries.ts": 2,
  "m10.entries.ts": 2,
  "m4-m5.entries.ts": 1,
  "m7-initplan-static.entries.ts": 2,
  "m7.entries.ts": 2,
  "m9-authz.entries.ts": 4,
  "m9-checks.entries.ts": 1,
  "owasp-multitenant.entries.ts": 6,
  "owasp-react.entries.ts": 4,
  "secrets.entries.ts": 2,
};

interface RatchetFinding {
  file: string;
  baseline: number;
  actual: number;
}

export function residualRatchet(reports: readonly FileReport[]): {
  risen: RatchetFinding[];
  stale: RatchetFinding[];
  total: number;
} {
  const risen: RatchetFinding[] = [];
  const stale: RatchetFinding[] = [];
  let total = 0;
  const seen = new Set<string>();
  for (const r of reports) {
    const name = r.file.split("/").pop() as string;
    seen.add(name);
    const baseline = RESIDUAL_BASELINE[name] ?? 0;
    const actual = r.residual.length;
    total += actual;
    if (actual > baseline) risen.push({ file: name, baseline, actual });
    if (actual < baseline) stale.push({ file: name, baseline, actual });
  }
  for (const [name, baseline] of Object.entries(RESIDUAL_BASELINE)) {
    if (!seen.has(name)) stale.push({ file: name, baseline, actual: 0 });
  }
  return { risen, stale, total };
}
