// Gate 4 of the #1320 prevention program (#1317): a bound recorded in a comment must appear in the
// finding it bounds.
//
// The defect this catches is not dishonesty. The engineer knew the rule's limit, wrote it down, and
// wrote it into a YAML comment — a venue the client never reads. What ships is a finding that
// silently overstates what was checked, and "an unstated limitation reads as a clean bill of
// health" (CLAUDE.md). The repo already has the disclosure-row family for scope a MODULE cannot
// assess; this is the same principle one level down, at the individual rule.
//
// The mechanism: a semgrep rule whose attached comments declare a bound must carry a scope sentence
// in its own `message`, because `message` is the only text in a rule that reaches the deliverable.
//
// SCOPE OF THIS GATE, stated here so its own silence is not read as coverage: it matches a fixed
// vocabulary of bound-declaring phrases (BOUND_MARKERS) over `src/scan/rules/semgrep/*.yml`, and a
// bound phrased outside that vocabulary is invisible to it. "Corresponding" is approximated: a
// marker in the message PLUS at least one distinctive term shared with the comment that declared
// the bound — enough to reject a contentless "SCOPE: none", not enough to judge whether the
// sentence describes the same bound. A lower bound on the defect, not a census of it. The TS/AST
// detectors and the conditional-scan (`scanLocal`) shape are #1317's 4b, tracked separately.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const RULES_DIR = "src/scan/rules/semgrep";

type BoundMarker = { readonly name: string; readonly re: RegExp };

// Deliberately narrow. The four in #1317's spec (NOTE:/LIMITATION:/does not cover/not assessed)
// plus the close cousins actually in use in this repo's rule files. A broad net catches pattern
// mechanics rather than bounds — "does not match" was measured on 2026-07-27 to fire 12 times here,
// every one of them a description of correct NON-firing ("a short TTL (e.g. 300) does not match"),
// which is the rule's intended edge and not an unassessed class. A gate that cries wolf gets an
// ignore list, and an ignore list is the invisibility this gate exists to remove.
const NEGATED = String.raw`(do(es)? not|do(es)? ?n[o']t|will not|wo ?n[o']t|cannot|ca ?n[o']t)`;
export const BOUND_MARKERS: readonly BoundMarker[] = [
  { name: "NOTE:", re: /\bNOTE:/ },
  { name: "LIMITATION:", re: /\bLIMITATIONS?:/i },
  { name: "CAVEAT", re: /\bcaveats?\b/i },
  { name: "SCOPE", re: /\bscoped to\b|\bscope of (this|the) (check|rule|gate)\b/i },
  { name: "does not cover", re: new RegExp(String.raw`\b${NEGATED} cover\b`, "i") },
  { name: "not assessed", re: /\b(not|un)[- ]?assess(ed|es)?\b/i },
  { name: "does not detect", re: new RegExp(String.raw`\b${NEGATED} detect\b`, "i") },
  { name: "does not catch", re: new RegExp(String.raw`\b${NEGATED} catch\b`, "i") },
  { name: "blind to", re: /\bblind to\b/i },
  { name: "out of scope", re: /\bout of scope\b/i },
  { name: "false negative", re: /\bfalse[- ]negatives?\b/i },
  { name: "only covers", re: /\bonly (covers|detects|catches|matches|flags)\b/i },
];

// Terms too generic to prove the message is talking about the same bound the comment declared —
// they are the vocabulary OF a scope sentence, so matching on them would let any scope sentence
// correspond to any bound.
const GENERIC = new Set([
  "assess", "assessed", "assesses", "because", "caveat", "caveats", "check", "checks", "cover",
  "covers", "detect", "detects", "harvey", "limitation", "match", "matches", "review", "rules",
  "scope", "scoped", "semgrep", "shape", "shapes", "there", "these", "this", "those", "which",
  "while", "would",
]);

// Hyphens split rather than join, so a comment's "hosting-layer" still corresponds to a message's
// "hosting layer" — the same bound, punctuated differently.
function distinctiveTerms(text: string): Set<string> {
  const words = text.toLowerCase().match(/[a-z]{5,}/g) ?? [];
  return new Set(words.filter((w) => !GENERIC.has(w)));
}

export type SemgrepRule = {
  readonly file: string;
  readonly id: string;
  readonly line: number;
  readonly comments: readonly CommentLine[];
  readonly message: string;
};

export type CommentLine = { readonly line: number; readonly text: string };

const RULE_START = /^ {2}- id: (\S+)\s*$/;
const COMMENT = /^\s*#\s?(.*)$/;
// A rule's preamble sits at the list's own indent; a comment indented deeper belongs to the
// pattern block it annotates, and stays with the rule it is inside.
const PREAMBLE_COMMENT = /^ {2}#/;
const MESSAGE_START = /^ {4}message: >\s*$/;

// The rule files are hand-maintained and uniformly shaped (110/110 rules use `    message: >`), so
// this reads them line-wise rather than pulling in a YAML parser for four keys. parseSemgrepRules
// throws on a rule with no message: silently returning "" would make every such rule trivially
// pass, which is the failure mode this whole gate is about.
export function parseSemgrepRules(text: string, file: string): SemgrepRule[] {
  const lines = text.split("\n");
  const starts: { id: string; index: number }[] = [];
  lines.forEach((line, index) => {
    const m = RULE_START.exec(line);
    if (m?.[1]) starts.push({ id: m[1], index });
  });

  // The comment block directly above a `- id:`, walked upward and stopped by a blank or non-comment
  // line, is that rule's own preamble — that is where this repo writes a rule's rationale and its
  // bounds. It also has to be SUBTRACTED from the preceding rule's body, or every preamble is
  // attributed to two rules and the gate reports the neighbour's bound as this rule's.
  const preambleStart = (index: number): number => {
    let j = index;
    while (j > 0 && PREAMBLE_COMMENT.test(lines[j - 1] ?? "")) j--;
    return j;
  };

  return starts.map(({ id, index }, i) => {
    const next = starts[i + 1]?.index;
    const end = next === undefined ? lines.length : preambleStart(next);
    const comments: CommentLine[] = [];
    for (let j = preambleStart(index); j < index; j++) {
      const m = COMMENT.exec(lines[j] ?? "");
      if (m) comments.push({ line: j + 1, text: m[1] ?? "" });
    }
    for (let j = index; j < end; j++) {
      const m = COMMENT.exec(lines[j] ?? "");
      if (m) comments.push({ line: j + 1, text: m[1] ?? "" });
    }

    const msgAt = lines.slice(index, end).findIndex((l) => MESSAGE_START.test(l));
    if (msgAt === -1) throw new Error(`${file}: rule ${id} has no \`message: >\` block`);
    const body: string[] = [];
    for (let j = index + msgAt + 1; j < end; j++) {
      const line = lines[j] ?? "";
      if (line.trim() === "") continue;
      if (!line.startsWith("      ")) break;
      body.push(line.trim());
    }

    return { file, id, line: index + 1, comments, message: body.join(" ") };
  });
}

type MarkerHit = { readonly marker: string; readonly line: number; readonly text: string };

export function commentBounds(rule: SemgrepRule): MarkerHit[] {
  return rule.comments.flatMap((c) =>
    BOUND_MARKERS.filter((m) => m.re.test(c.text)).map((m) => ({ marker: m.name, line: c.line, text: c.text })),
  );
}

type VenueVerdict = "no-bound-recorded" | "stated" | "no-scope-sentence" | "unrelated-scope-sentence";

export function verdict(rule: SemgrepRule, hits: readonly MarkerHit[]): VenueVerdict {
  if (hits.length === 0) return "no-bound-recorded";
  if (!BOUND_MARKERS.some((m) => m.re.test(rule.message))) return "no-scope-sentence";
  const declared = distinctiveTerms(hits.map((h) => h.text).join(" "));
  const stated = distinctiveTerms(rule.message);
  return [...declared].some((t) => stated.has(t)) ? "stated" : "unrelated-scope-sentence";
}

type VenueViolation = {
  readonly file: string;
  readonly id: string;
  readonly line: number;
  readonly verdict: Exclude<VenueVerdict, "no-bound-recorded" | "stated">;
  readonly hits: readonly MarkerHit[];
};

export function loadSemgrepRules(): SemgrepRule[] {
  const dir = resolve(dirname(fileURLToPath(import.meta.url)), "..", RULES_DIR);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".yml"))
    .sort()
    .flatMap((f) => parseSemgrepRules(readFileSync(resolve(dir, f), "utf8"), `${RULES_DIR}/${f}`));
}

export function auditDisclosureVenue(rules: readonly SemgrepRule[]): VenueViolation[] {
  return rules.flatMap((rule) => {
    const hits = commentBounds(rule);
    const v = verdict(rule, hits);
    if (v === "no-bound-recorded" || v === "stated") return [];
    return [{ file: rule.file, id: rule.id, line: rule.line, verdict: v, hits }];
  });
}
