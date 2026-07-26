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

export interface ParsedReason {
  file: string;
  /** 1-based line of the block's REASON: key. */
  line: number;
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
export function parseRecordedReasons(text: string, file: string): ParsedReason[] {
  const out: ParsedReason[] = [];
  let open: ParsedReason | undefined;
  // A fenced block in Markdown is documentation OF the convention (this file's own syntax template,
  // for one), not a reason recorded IN it.
  const fenced = file.endsWith(".md");
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
      open = { file, line: i + 1, fields: { REASON: value }, parseErrors: [] };
      out.push(open);
      return;
    }
    if (!open) return;
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

export function collectReasons(roots: string[], base: string): ParsedReason[] {
  const files: string[] = [];
  for (const root of roots) walk(resolve(base, root), files);
  return files.flatMap((abs) => parseRecordedReasons(readFileSync(abs, "utf8"), relative(base, abs)));
}

const PROVENANCE_FORM = /^(MEASURED|TRIED|ASSUMED) (\d{4}-\d{2}-\d{2})\b/;
// A falsifier that is a placeholder is worse than a missing one: it satisfies the gate while
// re-testing nothing.
const PLACEHOLDER = /^(n\/?a|tbd|todo|none|unknown|\?+)$/i;

export function validateRecordedReason(r: ParsedReason): string[] {
  const errors = [...r.parseErrors];
  const f = r.fields;
  if (!f.REASON) errors.push("REASON: is empty");

  const kind = f.KIND?.toLowerCase();
  if (kind !== "empirical" && kind !== "decisional") {
    errors.push(`KIND: must be "empirical" (re-testable against the world) or "decisional" (awaits a human ruling), got ${f.KIND ? `"${f.KIND}"` : "nothing"}`);
  }
  if (!f.PROVENANCE) errors.push('PROVENANCE: missing — tag it MEASURED/TRIED/ASSUMED plus the date, e.g. "ASSUMED 2026-07-25"');
  else if (!PROVENANCE_FORM.test(f.PROVENANCE)) errors.push(`PROVENANCE: must start "MEASURED|TRIED|ASSUMED YYYY-MM-DD", got "${f.PROVENANCE}"`);

  const tier = f["FALSIFIER-TIER"];
  if (kind === "empirical") {
    if (!f.FALSIFIER) errors.push("FALSIFIER: missing — an empirical reason with no re-test command is unfalsifiable and therefore permanent (#1033). Write a command that EXITS 0 WHEN THE BLOCKER IS GONE.");
    else if (PLACEHOLDER.test(f.FALSIFIER)) errors.push(`FALSIFIER: "${f.FALSIFIER}" is a placeholder, not a command — it would satisfy this gate while re-testing nothing`);
    if (f.OWNER) errors.push("OWNER: belongs on a decisional reason (who makes the ruling); an empirical reason is settled by its FALSIFIER, not by a person");
    if (tier !== undefined && !KNOWN_FALSIFIER_TIERS.has(tier)) errors.push(`FALSIFIER-TIER: "${tier}" is not a registered live tier — a typo would make this falsifier silently always-skipped. Known tiers: ${[...KNOWN_FALSIFIER_TIERS].join(", ")} (register a new one in KNOWN_FALSIFIER_TIERS, #1072)`);
  }
  if (kind === "decisional") {
    if (f.FALSIFIER) errors.push("FALSIFIER: refused on a decisional reason — a human ruling is not re-testable by command, and sweeping it into the re-validation gate produces noise that discredits the gate (#1033)");
    if (tier !== undefined) errors.push("FALSIFIER-TIER: refused on a decisional reason — it qualifies a FALSIFIER, which a decisional reason must not carry (#1072)");
    if (!f.OWNER) errors.push("OWNER: missing — a decisional reason needs the person or role who makes the ruling");
    if (!f.DECISION) errors.push("DECISION: missing — point at the decision record (a doc path or issue ref) the ruling lives in");
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

function touchedPaths(r: ParsedReason): string[] {
  return (r.fields.TOUCHES ?? "").split(/[,\s]+/).filter(Boolean);
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
export function revalidateReasons(reasons: ParsedReason[], run: (command: string) => FalsifierResult, availableTiers: Set<string> = new Set()): RevalidationRow[] {
  return reasons.flatMap((r): RevalidationRow[] => {
    if (reasonKind(r) !== "empirical") return [];
    const command = r.fields.FALSIFIER;
    if (!command) return [];
    const base = { file: r.file, line: r.line, claim: r.fields.REASON ?? "" };
    const tier = r.fields["FALSIFIER-TIER"];
    if (tier !== undefined && !availableTiers.has(tier)) {
      return [{ ...base, status: "SKIPPED-LIVE" as const, detail: `live-only falsifier not run — its tier "${tier}" is not available on this run. Re-run where that tier exists: \`--tier ${tier}\` (or \`--live\`). \`${command}\`` }];
    }
    const { code, output } = run(command);
    if (code === null || code === 127) {
      return [{ ...base, status: "UNVERIFIABLE" as const, detail: `falsifier could not be run (${code === null ? "signal/timeout" : "command not found"}): \`${command}\` — a reason whose re-test cannot execute is as unguarded as one with no re-test at all. ${output.trim().slice(0, 200)}` }];
    }
    if (code === 0) {
      return [{ ...base, status: "STALE" as const, detail: `FALSIFIED: \`${command}\` now exits 0, which by this reason's own contract means the blocker is GONE — the text says otherwise. Re-verify, then delete the reason and do the work it was deferring, or correct the claim. ${output.trim().slice(0, 200)}` }];
    }
    return [{ ...base, status: "holds" as const, detail: `\`${command}\` exits ${code} — reason still holds` }];
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
export function subsystemDrift(reasons: ParsedReason[], commitsSince: (paths: string[], since: string) => string[]): SubsystemDriftRow[] {
  return reasons.flatMap((r) => {
    const paths = touchedPaths(r);
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
