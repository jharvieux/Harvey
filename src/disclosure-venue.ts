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
// SCOPE OF THIS GATE, stated here so its own silence is not read as coverage. Three bounds:
//
// 1. VOCABULARY, NARROWED BUT NOT REMOVED (#1342). It matches a fixed set of bound-declaring
//    phrases (BOUND_MARKERS) over `src/scan/rules/semgrep/*.yml`, and a bound phrased outside that
//    vocabulary is invisible to the PASS/FAIL. #1342 chose to WIDEN the vocabulary (its option (a))
//    rather than invert the gate to "every rule is bound-bearing unless exempted" (its option (b)):
//    (b) removes the vocabulary dependence permanently but needs a scope sentence or an exemption
//    on all 110 rules, and an exemption list of ~90 entries IS the invisibility this gate exists to
//    remove — the same objection the BOUND_MARKERS comment below records against a broad net.
//    Widening was done three times against a re-measured population, not once against the issue's
//    estimate: the issue named ~9 rules; the first widening ("can't see", "heuristic") plus matching
//    across a LINE WRAP found 17, and a further pass ("can't prove/confirm/tell", "exploitability
//    depends") found 10 more. 27 rules gained a client-legible scope sentence. Two of the 17 were
//    invisible for a reason #1342 did not know about: their bound was already inside the ORIGINAL
//    12-phrase vocabulary and split across two comment lines, so per-line matching never saw it.
//    What remains is (i) prose outside even the widened net — counted by residualBoundish, every
//    rule triaged in BOUND_TRIAGE, and the CLI fails on an untriaged one; and (ii) comment lines
//    belonging to no rule (file headers and the shared YAML anchor blocks), counted and named by
//    unattributedBounds on every run rather than left silent.
//
//    REASON: a bound phrased outside the 15 marker phrases is still invisible to this gate's PASS/FAIL, so a green run is a statement about that vocabulary and not about the rule set; what it is not is SILENT, because the residual is counted and each residual rule triaged
//    KIND: empirical
//    PROVENANCE: MEASURED 2026-07-28 — `pnpm exec tsx src/cli/validate-disclosure-venue.ts --residual-count` reports 6 rules carrying bound-ish prose the markers do not recognise, against 40 rules the markers do recognise (up from 13 before this widening).
//    FALSIFIER: test -f src/cli/validate-disclosure-venue.ts || exit 127; pnpm exec tsx src/cli/validate-disclosure-venue.ts --residual-count > /tmp/harvey-residual-count.txt 2>/dev/null || exit 127; test "$(tail -1 /tmp/harvey-residual-count.txt)" = "0" && exit 0 || exit 1
//    TOUCHES: src/scan/rules/semgrep src/disclosure-venue.ts
//
// 2. CORRESPONDENCE IS APPROXIMATED, NOT JUDGED — a marker in the message PLUS at least one
//    distinctive term shared with the comment that declared the bound, tested against the SCOPE
//    SENTENCE only (see scopeSentence). It is a keyword overlap, so it OVER-REFUSES in one
//    direction: a complete, correct, client-legible paraphrase that happens to share no 5-letter
//    term with the comment is rejected as `unrelated-scope-sentence`. Recorded example — comment
//    "LIMITATION: dynamically-interpolated selectors are unhandled by the shape below", message
//    "...SCOPE OF THIS CHECK: only a string literal written inline is examined; a value built at
//    runtime from concatenation or a template is outside what this rule can see" — a faultless
//    disclosure, refused. The two texts share NO content word, which is why the whole overlap
//    family refuses it: measured 2026-07-27 (#1320 bounds audit) over five variants — exact terms,
//    prefix-5 stemming, a suffix-stripping stemmer, character 4-gram Jaccard, TF-IDF cosine — all
//    five refuse this pair, and the 4-gram variant additionally breaks 4 of the 13 committed
//    bounded rules. So the over-refusal is a property of OVERLAP, re-measurable rather than
//    assumed. It is NOT a property of every mechanical rule: a substance floor (the scope sentence
//    must carry >= 4 distinctive terms of its own) accepts the paraphrase and still refuses the
//    contentless sticker on all 13 — but it accepts 156/156 MISMATCHED comment/scope pairs, where
//    exact overlap refuses 123 of them, so it is not a correspondence check at all and was not
//    adopted. The open question, untested here because no offline model is available: does an
//    embedding or LLM adjudicator accept this pair while still refusing the 156? That is what
//    would replace the overlap; a cheaper lexical rule is measured not to.
//    An author hitting this should NOT parrot a word to appease the gate: reword the COMMENT to
//    the plain terms the message uses (the comment is the internal note; the message is the
//    deliverable, and the message should win).
//
//    REASON: every lexical-overlap variant tried refuses a correct paraphrase that shares no content word with the comment it discloses, and the one non-overlap alternative measured (a >= 4-distinctive-term substance floor) removes the over-refusal only by accepting every mismatched pair
//    KIND: empirical
//    PROVENANCE: MEASURED 2026-07-27 — five overlap variants (exact / prefix-5 / suffix-stripping stemmer / char 4-gram Jaccard / TF-IDF cosine) scored against the recorded paraphrase, the contentless-sticker control and all 13 committed bounded rules, plus a 13x12 mismatched-pair cross-run; exact overlap refuses 123/156 mismatched pairs, the substance floor 0/156.
//    FALSIFIER: pnpm exec vitest run src/disclosure-venue.test.ts -t "over-refuses a correct paraphrase" > /tmp/harvey-dv.log 2>&1; grep -q "1 passed" /tmp/harvey-dv.log && exit 1 || { grep -q "1 failed" /tmp/harvey-dv.log && exit 0 || exit 127; }
//    TOUCHES: src/disclosure-venue.ts
//
// 3. SEMGREP ONLY, and now only HALF of 4b is still open. The conditional-scan (`scanLocal`) shape
//    #1330 named is CLOSED: src/conditional-scan.ts checks it over the SHAPE rather than over any
//    comment vocabulary, and `src/scan/supabase.ts`'s local mode now emits SB-SCOPE-00 naming the
//    three checks hosted mode runs and it cannot. (That count is three, not the two the issue
//    named — the mechanical diff found `checkAuthConfig` omitted with no comment about it at all,
//    which is exactly the case a vocabulary check cannot reach.) What is STILL open is the other
//    half: a bound written in a TS/AST DETECTOR's own source comments, which no gate reads.
//
//    REASON: a bound written in a TS/AST detector's source comments is outside what any gate reads — this one parses `src/scan/rules/semgrep/*.yml` and src/conditional-scan.ts checks call-shape, not prose — so neither says anything about whether a detector's recorded limit reaches the finding it bounds
//    KIND: empirical
//    PROVENANCE: MEASURED 2026-07-31 — #1330's population grep re-run over src/scan + src/detectors still reports 11 non-test files carrying comment lines that declare a bound no disclosure gate parses; the conditional-omission half it also covered is now gated (`pnpm exec tsx src/cli/validate-conditional-scan.ts`, negative control `--seed-omission`). The falsifier below was rewritten off `grep -qv` (#1646): under a Claude Code agent shell that form answered 0 — "blocker gone" — against the same tree `sh -c` answered 1 on, so which verdict you got depended on who ran it. Re-exercised both directions in three shells at the new form.
//    FALSIFIER: test -d src/scan || exit 127; test -d src/detectors || exit 127; git grep -qE '^ *//.*(LIMITATION:|does not cover|not assessed|blind to|only covers)' -- ':(glob)src/scan/**/*.ts' ':(glob)src/detectors/**/*.ts' ':(glob,exclude)src/**/*.test.ts' && exit 1 || exit 0
//    TOUCHES: src/scan src/detectors
//
// A lower bound on the defect, not a census of it.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { readNamesSafe } from "./fs-walk.js";
import { fileURLToPath } from "node:url";

export const RULES_DIR = "src/scan/rules/semgrep";

type BoundMarker = { readonly name: string; readonly re: RegExp };

// Deliberately narrow. The four in #1317's spec (NOTE:/LIMITATION:/does not cover/not assessed)
// plus the close cousins actually in use in this repo's rule files. A broad net catches pattern
// mechanics rather than bounds — the negated form of "match" was measured on 2026-07-27 to hit 16
// comment lines across 15 rules (20 lines counting the file-header comments no rule owns), every
// one of them a description of correct NON-firing ("a short TTL (e.g. 300) does not match"), which
// is the rule's intended edge and not an unassessed class. A gate that cries wolf gets an ignore
// list, and an ignore list is the invisibility this gate exists to remove. Re-measure rather than
// trusting the number — the PR that added this gate quoted 12, which was wrong:
//   grep -hiE "^ *#.*(does not|doesn't|do not|don't|cannot|can't|will not|won't) match\b" \
//     src/scan/rules/semgrep/*.yml | wc -l    # 20 on 2026-07-27; 16 of them owned by a rule
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
  // #1342. The two phrasings the 2026-07-27 census found doing the most invisible work. Both are a
  // stated limit on what the rule KNOWS, which is exactly what this gate is about: "can't see" names
  // a fact the rule structurally cannot reach, and "a heuristic" says the match is evidence rather
  // than proof. `harvey-open-url-sink` and its file-neighbour `harvey-href-js-url` record the SAME
  // bound 30 lines apart; only the neighbour was caught, because its comment happened to contain
  // "scoped to". A gate whose coverage turns on which synonym an engineer reached for is measuring
  // vocabulary, not disclosure.
  { name: "cannot see", re: new RegExp(String.raw`\b(cannot|ca ?n[o']t) (see|prove|confirm|tell)\b`, "i") },
  { name: "heuristic", re: /\bheuristics?\b/i },
  // Third pass over the same census: "a static rule can't PROVE no allowlist runs elsewhere" and
  // "exploitability DEPENDS on the deploy network" are the same declaration as "can't see" — a named
  // class the finding does not settle — and were the two phrasings left standing after the first
  // widening. Measured 2026-07-28 over the residual population, not guessed from the issue text.
  { name: "exploitability depends", re: /\bexploitability depends\b/i },
];

// The gate's own gaming vector, named in #1330: the cheapest way to go green is to DELETE the bound
// comment rather than state it, which moves the limitation from an unread venue to no venue at all.
// Nothing detected that, because an un-bounded rule is indistinguishable from one that never had a
// bound. This is the ratchet: a rule on this list that still EXISTS and no longer declares a bound
// is a regression and fails. Rules leave the list only by being deleted or renamed, which is why
// the check keys on the id still being present.
export const BOUNDED_RULES: readonly string[] = [
  "harvey-aead-decipher-no-final", "harvey-argument-injection", "harvey-auth-admin-in-client",
  "harvey-authed-no-role-check", "harvey-body-parser-no-limit", "harvey-client-trusted-role",
  "harvey-crlf-header-injection", "harvey-csrf-missing", "harvey-dangerously-set-inner-html-prop",
  "harvey-dangerously-set-inner-html-stored", "harvey-edgefn-secret-fallback", "harvey-href-js-url",
  "harvey-html-template-literal", "harvey-idor-param", "harvey-incomplete-sanitize",
  "harvey-internal-state-response", "harvey-isr-revalidate-nosecret",
  "harvey-jsx-prop-spread-injection", "harvey-jwt-decode-noverify", "harvey-jwt-sign-noexpiry",
  "harvey-mass-assignment-bare", "harvey-missing-frame-options", "harvey-missing-hsts",
  "harvey-missing-nosniff", "harvey-nosql-injection", "harvey-open-redirect", "harvey-open-url-sink",
  "harvey-permissive-cors-bare", "harvey-pg-mass-assignment", "harvey-plaintext-password",
  "harvey-postmessage-no-origin", "harvey-redos-literal", "harvey-secret-in-url-param",
  "harvey-sensitive-response-cached", "harvey-server-action-noauth", "harvey-ssrf-fetch",
  "harvey-static-iv", "harvey-vite-service-role-in-client", "harvey-xxe-parse",
  "harvey-zero-row-update",
  // #1273 — the sink-coverage widening. harvey-path-traversal MOVED here out of BOUND_TRIAGE: its
  // comments now record a real bound (the `root` option it does not read) rather than only the
  // pattern mechanics they described before, so the marker vocabulary sees it and its message
  // states it. The three new rules arrive bounded rather than joining the residual.
  "harvey-path-traversal", "harvey-xpath-injection", "harvey-ldap-injection",
  "harvey-csv-formula-injection",
];

// A deliberately WIDER net than BOUND_MARKERS, used only to measure the vocabulary's residual — the
// bound-ish prose the markers still cannot see. It is not a gate on its own (it catches pattern
// mechanics by design, which is exactly why the markers stay narrow); it exists so "how much does
// this gate still miss?" has a number that is re-derived on every run instead of recalled from a
// census someone ran once.
const RESIDUAL_MARKERS: readonly RegExp[] = [
  /\bmay live elsewhere\b/i,
  /\bno dataflow\b/i,
  new RegExp(String.raw`\b(cannot|ca ?n[o']t) (prove|span|reach|follow|know|read|resolve)\b`, "i"),
  /\bnot flagged\b/i,
  /\bdeliberately (left out|excluded|omitted)\b/i,
  /\bstays out\b/i,
  /\boutside what\b/i,
  /\bsingle-file\b/i,
  /\bfalse positives?\b/i,
  /\bnot a (proof|certainty|guarantee)\b/i,
  /\bno (proof|guarantee)\b/i,
  /\bnot exhaustive\b/i,
  /\bdepends on\b/i,
];

export function residualBoundish(rules: readonly SemgrepRule[]): SemgrepRule[] {
  return rules.filter((r) => commentBounds(r).length === 0 && r.comments.some((c) => RESIDUAL_MARKERS.some((re) => re.test(c.text))));
}

// #1342 criterion 3. Every rule residualBoundish reports must appear here with a disposition, and
// every entry here must still be residual — the CLI fails on either mismatch, so a new rule with
// bound-ish prose cannot join the set unread and a triaged rule cannot quietly stop being triaged.
// "We looked and it was nothing" and "we never looked" are the same silence otherwise.
export const BOUND_TRIAGE: readonly { readonly id: string; readonly disposition: string }[] = [
  { id: "harvey-service-role-in-client", disposition: "pattern mechanics — 'correctly NOT flagged' describes an intended non-firing (a server-only file), which is the rule's edge, not a class it leaves unassessed" },
  { id: "harvey-prototype-pollution", disposition: "pattern mechanics — 'a source that cannot reach' explains why three candidate source extensions were REJECTED as recall theatre; the rejected shapes are not reachable defects" },
  { id: "harvey-spawn-shell-true", disposition: "pattern mechanics — 'deliberately excluded' describes the DIVISION OF LABOUR with the argv-array rules, which do cover the excluded family; nothing is unassessed" },
  { id: "harvey-unsafe-deserialization", disposition: "genuine bound — scope sentence written into the message ('depends on the deserialization library actually in use'); its phrasing is outside the marker vocabulary, so the sentence is voluntary rather than gate-held" },
  { id: "harvey-template-autoescape-off", disposition: "genuine bound — scope sentence written into the message ('whether user data actually flows through this template is not traced'); same voluntary status as above" },
];

// Terms too generic to prove the message is talking about the same bound the comment declared —
// they are the vocabulary OF a scope sentence, so matching on them would let any scope sentence
// correspond to any bound.
// A marker's OWN words belong here too, or the marker supplies the overlap it is supposed to be
// evidence for: "caveat", "limitation" and "scoped" were already listed for that reason, and #1342
// adds "cannot"/"heuristic" on the same footing when it adds those markers.
const GENERIC = new Set([
  "assess", "assessed", "assesses", "because", "cannot", "caveat", "caveats", "check", "checks",
  "cover", "covers", "detect", "detects", "harvey", "heuristic", "heuristics", "limitation",
  "match", "matches", "review", "rules", "scope", "scoped", "semgrep", "shape", "shapes", "there",
  "these", "this", "those", "which", "while", "would",
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

// #1342: markers run over the rule's comment block JOINED, not line by line, because a bound wraps.
// `harvey-jwt-sign-noexpiry` writes "…this rule can't" and "see whether expiresIn lives inside it"
// on consecutive lines, and per-line matching cannot see the phrase at all — a bound made invisible
// by the column at which the author pressed return. Each hit is attributed back to the lines it
// actually spans, so the correspondence check below still gets the bound's own vocabulary rather
// than the whole preamble's (which would let any scope sentence correspond to any bound).
export function commentBounds(rule: SemgrepRule): MarkerHit[] {
  const spans: { start: number; end: number; comment: CommentLine }[] = [];
  let joined = "";
  for (const comment of rule.comments) {
    if (joined) joined += " ";
    const start = joined.length;
    joined += comment.text;
    spans.push({ start, end: joined.length, comment });
  }

  return BOUND_MARKERS.flatMap((m) => {
    const global = new RegExp(m.re.source, m.re.flags.includes("g") ? m.re.flags : `${m.re.flags}g`);
    return [...joined.matchAll(global)].map((hit) => {
      const from = hit.index;
      const to = from + hit[0].length;
      const covered = spans.filter((s) => s.end > from && s.start < to);
      return {
        marker: m.name,
        line: covered[0]?.comment.line ?? rule.line,
        text: covered.map((s) => s.comment.text).join(" "),
      };
    });
  });
}

type VenueVerdict = "no-bound-recorded" | "stated" | "no-scope-sentence" | "unrelated-scope-sentence";

// A finding's message has two halves: what the rule found, written before anyone thought about
// bounds, and the scope sentence added to disclose one. Only the second half is the disclosure, so
// only the second half may be evidence of it. Measured 2026-07-27: testing correspondence against
// the WHOLE message let a literally contentless "SCOPE OF THIS CHECK: nothing worth naming" pass on
// 9 of the 13 bounded rules, because some unrelated word in the descriptive half supplied the
// shared term. The marker's own position is where the disclosure starts.
export function scopeSentence(message: string): string | null {
  let at = -1;
  for (const m of BOUND_MARKERS) {
    const hit = m.re.exec(message);
    if (hit && (at === -1 || hit.index < at)) at = hit.index;
  }
  return at === -1 ? null : message.slice(at);
}

export function verdict(rule: SemgrepRule, hits: readonly MarkerHit[]): VenueVerdict {
  if (hits.length === 0) return "no-bound-recorded";
  const scope = scopeSentence(rule.message);
  if (scope === null) return "no-scope-sentence";
  const declared = distinctiveTerms(hits.map((h) => h.text).join(" "));
  const stated = distinctiveTerms(scope);
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
  return [...loadSemgrepRuleFiles()].flatMap(([file, text]) => parseSemgrepRules(text, file));
}

// #1342, criterion 4 — the structural half. A comment line that sits above the first `- id:`, or
// between rules at a shallower indent, belongs to NO rule: file headers and the shared YAML anchor
// blocks (`&request_source`, `&dom_source`) live there. A bound recorded on a shared anchor applies
// to every rule that uses it, and a PER-RULE gate structurally cannot attribute it to anyone — so
// it is never anyone's bound and disappears. Propagating anchor bounds to every consumer was the
// alternative and was rejected: one line on `*request_source` would make ~20 rules bounded on the
// anchor's wording rather than their own, which is a worse disclosure, not a better one. So the
// gate COUNTS and NAMES them instead. Same contract as SEM-SCOPE-00: a counted, named row, never
// an absence.
type UnattributedBound = { readonly file: string; readonly line: number; readonly text: string };

export function unattributedBounds(rules: readonly SemgrepRule[], files: ReadonlyMap<string, string>): {
  readonly commentLines: number;
  readonly unattributed: number;
  readonly bearing: readonly UnattributedBound[];
} {
  let commentLines = 0;
  let unattributed = 0;
  const bearing: UnattributedBound[] = [];
  for (const [file, text] of files) {
    const owned = new Set(rules.filter((r) => r.file === file).flatMap((r) => r.comments.map((c) => c.line)));
    text.split("\n").forEach((line, i) => {
      if (!/^\s*#/.test(line)) return;
      commentLines++;
      if (owned.has(i + 1)) return;
      unattributed++;
      const body = COMMENT.exec(line)?.[1] ?? "";
      if (BOUND_MARKERS.some((m) => m.re.test(body))) bearing.push({ file, line: i + 1, text: body });
    });
  }
  return { commentLines, unattributed, bearing };
}

export function loadSemgrepRuleFiles(): Map<string, string> {
  const dir = resolve(dirname(fileURLToPath(import.meta.url)), "..", RULES_DIR);
  return new Map(
    readNamesSafe(dir)
      .filter((f) => f.endsWith(".yml"))
      .sort()
      .map((f) => [`${RULES_DIR}/${f}`, readFileSync(resolve(dir, f), "utf8")]),
  );
}

export function boundedRatchet(rules: readonly SemgrepRule[]): string[] {
  const present = new Map(rules.map((r) => [r.id, r]));
  return BOUNDED_RULES.filter((id) => {
    const rule = present.get(id);
    return rule !== undefined && commentBounds(rule).length === 0;
  });
}

export function auditDisclosureVenue(rules: readonly SemgrepRule[]): VenueViolation[] {
  return rules.flatMap((rule) => {
    const hits = commentBounds(rule);
    const v = verdict(rule, hits);
    if (v === "no-bound-recorded" || v === "stated") return [];
    return [{ file: rule.file, id: rule.id, line: rule.line, verdict: v, hits }];
  });
}
