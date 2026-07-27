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
//      would train readers to ignore the gate (decisional is ~45% of the open tracker, measured).
//   2. Every empirical reason carries the COMMAND THAT WOULD FALSIFY IT. A reason with no falsifier
//      is unfalsifiable and therefore permanent. The contract is deliberately one-way:
//      **the falsifier exits 0 when the blocker is GONE.** So `grep -q <the thing that must not
//      exist>` is the canonical shape, and a gate run that gets exit 0 is a loud stale-reason row.
//
// This generalizes revalidateNotRunReasons (#321, src/scan/external-corpus.ts), which does exactly
// this for one narrow slice — external-corpus not-run baselines, re-tested by the drift run's own
// re-attempt rather than by a stored command. Same doctrine, repo-wide, with the command written down.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

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
export const KNOWN_FALSIFIER_TIERS = new Set(["m2-stack", "lighthouse", "secbench", "supabase-labs"]);

// #1072 — a live-only falsifier cannot name its target in the repo: the crAPI gateway URL, the
// external clone path, the served origin are all supplied by whoever stands the tier up. All five
// were written as `<crapi-gateway>`-style angle-bracket prose, and `sh -c` reads `<` as an INPUT
// REDIRECT — so `--tier secbench` did not re-test anything, it died on "No such file or directory"
// and exited 1, which this file's contract reads as "the blocker still holds". Five of five live
// falsifiers were unfalsifiable by construction and reported green (measured 2026-07-27). So a
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

const SCANNED = /\.(ts|md|txt|yml|sql)$/;
// targets/ is vendored third-party source — Harvey's convention does not govern it.
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "coverage", "targets"]);

function walk(abs: string, out: string[]): void {
  const stat = statSync(abs, { throwIfNoEntry: false });
  if (!stat) return;
  if (stat.isFile()) {
    if (SCANNED.test(abs)) out.push(abs);
    return;
  }
  for (const entry of readdirSync(abs, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIP_DIR.has(entry.name)) continue;
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
// measured 86 claim-shaped lines across 33 of 51 design docs that were never triaged into
// empirical/decisional at all, and a claim outside a block is not re-tested by anything. So the
// untriaged population is COUNTED on every run rather than quoted from a doc — an unstated
// limitation reads as a clean bill of health, and a stored number stops being true.
//
// Deliberately a LOWER BOUND over a fixed vocabulary of standing-impossibility phrasings, and
// prose-only: the same inventory measured docs/design carrying 2 provenance tags against src/'s 119,
// so prose is the weak surface. Advisory, never a gate failure — a hard gate over a heuristic gets
// argued down or suppressed, and what this needs to do is stay visible while the number shrinks.
//
// #1319 added "out of reach"/"infeasible": #957 recorded a piece as "genuinely out of reach for a
// mechanical assembly" and it landed 3h25m later in 98 lines. The same vocabulary drives the
// impossibility-register check below, so the two cannot drift apart.
const CLAIM_VOCABULARY = /\b(cannot|can't|can not|impossible|no way to|not possible|unable to|out of reach|infeasible)\b/i;

interface UntriagedClaim {
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

/** Callers pass the prose surfaces they want censused; the vocabulary is not tuned for code. */
export function untriagedClaims(sources: SourceText[], reasons: ParsedReason[]): UntriagedClaim[] {
  return sources.flatMap(({ file, text }) => {
    const triaged = reasons.filter((r) => r.file === file);
    const out: UntriagedClaim[] = [];
    let inFence = false;
    text.split("\n").forEach((raw, i) => {
      if (/^\s*(```|~~~)/.test(raw)) inFence = !inFence;
      if (inFence || !CLAIM_VOCABULARY.test(raw)) return;
      const line = i + 1;
      if (triaged.some((r) => line >= r.line && line <= r.endLine)) return;
      out.push({ file, line, text: raw.trim() });
    });
    return out;
  });
}

const PROVENANCE_FORM = /^(MEASURED|TRIED|ASSUMED) (\d{4}-\d{2}-\d{2})\b/;
// A falsifier that is a placeholder is worse than a missing one: it satisfies the gate while
// re-testing nothing.
const PLACEHOLDER = /^(n\/?a|tbd|todo|none|unknown|\?+)$/i;

// #1319 — A BUDGET LIMIT MUST NOT BORROW IMPOSSIBILITY'S VOCABULARY. Four claims recorded in this
// repo asserted that the world forecloses something while actually describing the author's remaining
// afternoon: #951's "a full pull is out of budget" (the next executor pulled the whole stack and
// shipped a merged live proof 26 minutes later, finding a real bug the guess would have missed),
// #957's "genuinely out of reach for a mechanical assembly" (98 lines, 3h25m later, no new
// dependency), #52's "correctly NOT mechanically detectable" (detectors now exist for all three
// named classes) and #873's "our mechanical tier structurally cannot see that shape" (the function
// it needed had shipped a week earlier). A budget claim invites the next person to just do it; an
// impossibility claim closes the file, and closes it SILENTLY, because by construction nobody
// exercises a path recorded as foreclosed.
//
// PROVENANCE already separates the two registers: ASSUMED means nobody went and looked. So
// impossibility vocabulary on an ASSUMED reason is refused. The author has three honest exits, all
// one line: measure it and say MEASURED, name the real constraint (time), or ask the question.
// Matched literally, including inside a denial ("not technically impossible") — the check reads
// words, not sentences, and re-tagging a denial as MEASURED is the cheaper correction.
function impossibilityPhrase(claim: string): string | undefined {
  return CLAIM_VOCABULARY.exec(claim)?.[0];
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
// folk belief that they were supervised was blocking five separate pieces of work). Both halves must
// match: a reason that merely MENTIONS .github/workflows/ci.yml is describing CI, not citing
// supervision, and several legitimate reasons here do exactly that.
const SUPERVISED_PATH = /\.github\/workflows|CLAUDE\.md|report-template\/findings\.|docs\/[\w./-]*\.md/;
const SUPERVISION_CITED = /\bsupervised|\bsensitive path|\bprotected path|\bnever auto-change|\boperator (approval|sign-?off|ruling|permission)/i;
const RELAY_VENUE = /#\d+|\//;

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
  const impossibility = impossibilityPhrase(claim);
  if (impossibility && PROVENANCE_FORM.exec(f.PROVENANCE ?? "")?.[1] === "ASSUMED") {
    errors.push(`REASON: says "${impossibility}" on an ASSUMED provenance — that is impossibility's vocabulary spent on a claim nobody tested (#1319). Four such claims were falsified in 2026-07, one of them 26 minutes later. Go look and re-tag it MEASURED/TRIED, or name the real constraint ("not attempted this round; the pull is ~20s"), or ask it as a question ("does the token store expose non-owner reads?") — a question invites the next person to test it, an assertion closes the file.`);
  }
  if (SUPERVISED_PATH.test(claim) && SUPERVISION_CITED.test(claim)) {
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
// re-running anything — watched only the 9 of 15 empirical reasons whose author happened to declare
// it (measured 2026-07-27). Making it MANDATORY was the other option and is rejected: the three
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
