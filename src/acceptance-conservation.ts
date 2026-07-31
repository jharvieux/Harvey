// Gate 1 + Gate 2 of the prevention program (#1315, #1316) — conservation of ACCEPTANCE CRITERIA.
//
// Harvey already has a conservation gate one layer down: a detector can work while its finding
// never reaches the deliverable, so validate-conservation asserts produced == delivered. The issue
// tracker has the identical defect one layer UP. `Closes #N` fires on merge with nothing verifying
// N's acceptance criteria — a PR can do real work, pass every check, and close an issue whose bar
// it did not meet. Same shape, different layer: **stated is not met**. An audit of 562 closed
// issues on 2026-07-27 found ~60 closed with unmet criteria, and in almost every case the executor
// was HONEST in the PR body and the merge happened anyway (#1206's body was headed
// "## Does NOT close #1206"; #743's contained a section headed "Why this stays open").
//
// The mechanism: a PR carrying a closing keyword must map EVERY acceptance bullet in the issue it
// closes to exactly one of three dispositions, in the PR body:
//
//   ACCEPTANCE #1315.1 met: <evidence — a command, a file path, or a test name>
//   ACCEPTANCE #1315.2 split: #1400
//   ACCEPTANCE #1315.3 relayed: <the operator question, which must also be recorded ON the issue>
//   ACCEPTANCE #1315 no-stated-criteria: <what the bar was>   ← only when the issue states none
//
// An unmapped bullet fails. A `met` with no evidence shape fails — a bare "done" is an unmapped
// bullet wearing a disposition. `relayed` is first-class because the audits found "supervised path"
// TERMINATING issues rather than producing a question, while no executor has ever recorded "asked
// the operator, was refused" and grants are demonstrably routine.
//
// Gate 2 (#1316) is the `split` disposition's liveness half, and is what makes `split` trustworthy:
// deferring to an issue nobody checked was still open is indistinguishable in outcome from not
// deferring at all. #715 deferred to #161, which had closed NINE MINUTES earlier, and #161's own
// closing comment deferred the same work back to #715 (verified 2026-07-27: #161 closed
// 2026-07-22T01:46:54Z, #715 at 01:55:56Z). Both closed; the work vanished for 16 days. So every
// remainder reference is checked on three separate conditions — exists, OPEN, cross-linked from the
// original — and the report names WHICH failed, never just that one did.
//
// The two bounds that shape the code below: (1) only bullets at the SHALLOWEST indent of the
// acceptance section are criteria — deeper bullets read as elaboration and are counted and
// reported, not silently dropped; (2) the evidence check reaches TRUTH only as far as a lookup can
// carry it — given an EvidenceWorld it stats a cited path, resolves a `pnpm <script>` against
// package.json and holds a quoted test name to the suite, and beyond that (a `node`/`docker`/shell
// command, and any command's OUTPUT) it is still a shape check. It raises the floor; it is not a
// reviewer. The COMPLETE list — including the residual looseness in each evidence shape, what a
// green `cross-linked` row does and does not prove, and which bounds the #1320 audit FALSIFIED on
// 2026-07-27 — is `docs/design/acceptance-conservation.md`, "Deliberate, disclosed bounds", which
// is authoritative. Do not treat this comment as the full set.

// VENUE PARITY (#1562). Both gates read the SAME surface set — this body, every linked PR body, and
// every comment on the issue — and a criterion may be dispositioned exactly ONCE across all of them.
// They did not always agree: the PR-level check read the PR body alone, so a PR whose dispositions
// were ALSO recorded as issue comments passed it, merged, and was then re-opened by the close-time
// gate reading the union. MEASURED 2026-07-30: PRs #1517 and #1519 went green, merged, and the close
// gate re-opened all four issues they closed (#1305, #825, #1469, #1280). A gate that says "safe to
// merge" about a state that is not is a pure false negative, and it surfaces after the merge, where
// it is most expensive. The parity is achieved by TIGHTENING the PR check — never by loosening the
// close check — and both now run the same `checkAcceptance` over the same venues.

type Disposition = "met" | "split" | "relayed";

interface Criterion {
  /** 1-based, in order of appearance — the index a disposition line names. */
  index: number;
  text: string;
}

/** `url` is the comment permalink, so #1603's flag can name a surface a human can open. */
export interface IssueComment {
  body: string;
  url?: string;
}

export interface IssueRecord {
  number: number;
  state: "OPEN" | "CLOSED";
  body: string;
  comments: IssueComment[];
  /**
   * The PRs GitHub links to this issue as closing it (`closedByPullRequestsReferences`, which the
   * Development sidebar populates too). It lives HERE and not on a caller-supplied input because
   * both gates read their venue set out of the lookup: two lists kept in step is precisely what
   * broke on the comments (#1562) and then again on this field (#1581), where an issue with TWO
   * linked PRs was a venue set the close path read and the PR path did not.
   */
  linkedPrs?: { ref: string; body: string }[];
}

/**
 * A closing reference as the body wrote it. `repo` is set only when the reference names ANOTHER
 * repository — `owner/repo#7` or an issue URL. Both resolve: `gh issue view 2196 --repo
 * OWASP/CheatSheetSeries` exits 0 (measured 2026-07-27), so the earlier `NOT ASSESSED` row was a
 * property of the lookup this gate chose, not of the reference.
 */
export interface ClosingRef {
  repo?: string;
  number: number;
  /** As written: `#1315`, `owner/repo#7`, or the URL. Used in the report so the reader sees their own text. */
  ref: string;
}

/** A surface disposition lines are read out of, labelled so a DUPLICATE can name where both copies live. */
interface Venue {
  label: string;
  text: string;
}

const PR_BODY = "the PR body";

/** `undefined` means the issue DOES NOT EXIST. A fetch that merely failed must never reach here. */
export type IssueLookup = (issue: number, repo?: string) => IssueRecord | undefined;

/**
 * The only `gh` failure a lookup may turn into `undefined`, and therefore into `✗ … does not exist`.
 *
 * A REPOSITORY that fails to resolve is ambiguous: a private repo this token cannot read fails with
 * the same message as one that was never created. Treating that as "does not exist" states as fact
 * something the lookup cannot know — the exact conflation the invariant above forbids — so it is
 * excluded here and the caller stops instead (exit 2, the gate could not RUN). The cross-repo lookup
 * that widened this to `repository` had a live population of 0 of the last 60 merged PRs, which is
 * how a wrong sentinel survives unnoticed.
 */
export function issueDoesNotExist(stderr: string): boolean {
  return /could not resolve to an? (?:issue|pull request)\b/i.test(stderr);
}

interface DispositionLine {
  issue: number;
  index: number;
  disposition: Disposition;
  detail: string;
  line: number;
  /** Which surface it was read from. A line number alone leaves the reader guessing which of two venues holds a duplicate. */
  venue: string;
  /**
   * The next line, when it reads as prose continuing this one (#1565). The parser is line-by-line
   * and does NOT join it, so evidence that wraps is judged on its first line alone — the rejection
   * every real executor hit hardest, because it punishes exactly the thorough evidence the gate
   * asks for. Carried here so the failure can SAY that rather than reporting a mystery.
   */
  wrappedInto?: string;
}

interface NoCriteriaLine {
  issue: number;
  bar: string;
  line: number;
  venue: string;
}

interface RemainderRef {
  remainder: number;
  /** The issue the work was split OUT OF, when the reference is a `split` disposition. */
  original?: number;
  line: number;
  venue: string;
}

interface ParsedBody {
  closes: ClosingRef[];
  /** Closing references whose form resolves to no readable issue — disclosed, never dropped. */
  unresolvedCloses: string[];
  dispositions: DispositionLine[];
  noCriteria: NoCriteriaLine[];
  remainders: RemainderRef[];
  parseErrors: string[];
}

const DECORATION = /^[\s>|*+-]*(?:\[[ xX]\]\s*)?/;
const HEADING = /^(#{1,6})\s+(.*?)\s*$/;
const BOLD_HEADING = /^\*\*(.+?)\*\*:?\s*$/;
const ACCEPTANCE_HEADING = /^\**\s*acceptance\b/i;
const BULLET = /^(\s*)(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s*)?(\S.*)$/;
const CHECKLIST = /^\s*[-*+]\s+\[[ xX]\]\s+(\S.*)$/;

// GitHub's closing-keyword parser is NEGATION-BLIND: "does not close #19" closes #19. This regex is
// deliberately just as blind, because the gate has to see exactly what the merge will act on — a
// gate that read the negation would let the exact PR bodies the audits found ("## Does NOT close
// #1206") walk straight through it.
const CLOSING = /\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s*:?\s+(?<ref>(?:[\w.-]+\/[\w.-]+)?#\d+|https?:\/\/\S+\/issues\/\d+)/gi;

const DISPOSITION_LINE = /^ACCEPTANCE\s+#(\d+)\.(\d+)\s+(met|split|relayed)\s*:\s*(\S.*)$/i;
const NO_CRITERIA_LINE = /^ACCEPTANCE\s+#(\d+)\s+no-stated-criteria\s*:\s*(\S.*)$/i;
const REMAINDER_LINE = /^remainder\s*:\s*#(\d+)\b/i;

const lines = (text: string): string[] => text.replace(/\r\n/g, "\n").split("\n");
const strip = (line: string): string => line.replace(DECORATION, "");

/**
 * #1565 — the near-miss diagnoses. The grammar is exact and the parser is line-by-line, so a line
 * that ALMOST parses fell through to "malformed, expected <grammar>" and the criterion it meant to
 * map was then reported as UNMAPPED somewhere else in the output. Every shape below was hit by a
 * real executor on 2026-07-30 and cost a round trip, because the only way to discover the rule was
 * to trip over it. Each one says what is wrong with THAT LINE.
 */
function malformedDisposition(line: string): string {
  const grammar = "expected `ACCEPTANCE #<issue>.<n> <met|split|relayed>: <detail>` or `ACCEPTANCE #<issue> no-stated-criteria: <bar>`";

  const perCriterionNoCriteria = /^ACCEPTANCE\s+#(\d+)\.(\d+)\s+no-stated-criteria\b/i.exec(line);
  if (perCriterionNoCriteria) {
    return `malformed ACCEPTANCE line — \`no-stated-criteria\` is a WHOLE-ISSUE declaration and takes no criterion number, so \`#${perCriterionNoCriteria[1]}.${perCriterionNoCriteria[2]}\` cannot carry it. Write \`ACCEPTANCE #${perCriterionNoCriteria[1]} no-stated-criteria: <what the bar was>\`, and only when the issue states no criteria at all — an issue that DOES state them needs one \`met|split|relayed\` line per bullet. Got: ${line}`;
  }

  const verdict = /^ACCEPTANCE\s+#(\d+)\.(\d+)\s+(met|split|relayed)\b\s*(.*)$/i.exec(line);
  if (verdict) {
    const [, issue, index, word, rest = ""] = verdict;
    const head = `ACCEPTANCE #${issue}.${index} ${word!.toLowerCase()}`;
    if (/^[—–-]/.test(rest)) {
      return `malformed ACCEPTANCE line — the verdict is separated from its evidence by a dash (\`${rest.charAt(0)}\`); the grammar needs a COLON and nothing else. Write \`${head}: ${rest.replace(/^[—–-]\s*/, "") || "<detail>"}\`. Got: ${line}`;
    }
    if (rest.startsWith("(")) {
      const paren = /^\(([^)]*)\)\s*:?\s*(.*)$/.exec(rest);
      return `malformed ACCEPTANCE line — a parenthetical sits between the verdict and the colon, and the grammar allows nothing there. Write \`${head}: ${paren?.[2] || "<detail>"}\`${paren?.[1] ? ` and fold "${paren[1]}" into the detail` : ""}. Got: ${line}`;
    }
    if (/^:\s*$/.test(rest) || rest === "") {
      return `malformed ACCEPTANCE line — \`${head}\` carries no detail after the colon, and an empty detail is an unmapped bullet with a label on it. Got: ${line}`;
    }
    return `malformed ACCEPTANCE line — \`${head}\` must be followed by \`: <detail>\` with nothing between the verdict and the colon; ${grammar}. Got: ${line}`;
  }

  const unknownVerdict = /^ACCEPTANCE\s+#(\d+)\.(\d+)\s+([\w-]+)\b/i.exec(line);
  if (unknownVerdict) {
    return `malformed ACCEPTANCE line — \`${unknownVerdict[3]}\` is not a disposition; the three are \`met\`, \`split\` and \`relayed\`. ${grammar}. Got: ${line}`;
  }

  return `malformed ACCEPTANCE line — ${grammar}, got: ${line}`;
}

/**
 * Whether the line after a disposition reads as PROSE CONTINUING it, rather than as the next piece
 * of structure. Deliberately conservative: anything that is itself a disposition, a remainder, a
 * heading, a bullet or a fence is structure, and a blank line ends the paragraph. Used only to
 * DECORATE a failure that has already happened, never to create one — so a false positive costs a
 * misleading hint, never a wrong verdict.
 */
function wrapContinuation(next: string | undefined): string | undefined {
  if (next === undefined || next.trim() === "") return undefined;
  if (BULLET.test(next) || /^\s*(?:#{1,6}\s|```|>|\|)/.test(next)) return undefined;
  const text = next.trim();
  const structure = /^ACCEPTANCE\s+#/i.test(text)
    || REMAINDER_LINE.test(text)
    || /\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b\s*:?\s+(?:[\w.-]+\/[\w.-]+)?#\d/i.test(text);
  return structure ? undefined : text;
}

/**
 * A bold pseudo-heading (`**Like this.**`) carries no level, so it ranks BELOW `######` — deliberately.
 * The section then ends only at a heading AT OR ABOVE the acceptance heading's own level, which is
 * what stops `**This one matters.**` or a `###` sub-heading from cutting the section short. It used
 * to: `## Acceptance / - one / **This one matters.** / - two / - three` parsed as ONE criterion and
 * reported nothing, so two bullets vanished from a gate whose entire purpose is that nothing vanishes
 * silently. When the acceptance heading is ITSELF bold, level 7 == level 7, so the next bold line
 * still ends it and that convention keeps working.
 */
function heading(line: string): { level: number; text: string } | undefined {
  const h = HEADING.exec(line);
  if (h) return { level: h[1]!.length, text: h[2]! };
  const b = BOLD_HEADING.exec(line);
  return b ? { level: 7, text: b[1]! } : undefined;
}

interface ParsedCriteria {
  criteria: Criterion[];
  /** Bullets nested under a criterion. Elaboration, not separately dispositioned — reported so the choice is visible. */
  nestedFolded: number;
  source: "acceptance-section" | "checklist" | "none";
}

export function parseAcceptanceCriteria(body: string): ParsedCriteria {
  const all = lines(body);
  let start = -1;
  let startLevel = 0;
  let end = all.length;
  for (let i = 0; i < all.length; i++) {
    const h = heading(all[i]!);
    if (h === undefined) continue;
    if (start === -1) {
      if (ACCEPTANCE_HEADING.test(h.text)) {
        start = i + 1;
        startLevel = h.level;
      }
    } else if (h.level <= startLevel) {
      end = i;
      break;
    }
  }

  if (start === -1) {
    // No Acceptance section. A checklist anywhere in the body is the other convention this repo
    // uses; an issue with neither has NO stated criteria, which is where this failure is easiest,
    // so it is reported as such rather than passing on an empty set.
    const items = all.flatMap((l) => CHECKLIST.exec(l)?.[1] ?? []);
    return {
      criteria: items.map((text, i) => ({ index: i + 1, text })),
      nestedFolded: 0,
      source: items.length > 0 ? "checklist" : "none",
    };
  }

  const bullets = all.slice(start, end).flatMap((l) => {
    const m = BULLET.exec(l);
    return m ? [{ indent: m[1]!.length, text: m[2]! }] : [];
  });
  if (bullets.length === 0) return { criteria: [], nestedFolded: 0, source: "none" };
  const top = Math.min(...bullets.map((b) => b.indent));
  const criteria = bullets.filter((b) => b.indent === top).map((b, i) => ({ index: i + 1, text: b.text }));
  return { criteria, nestedFolded: bullets.length - criteria.length, source: "acceptance-section" };
}

/**
 * #1603 — the bar a comment MOVED. Every criterion this gate grades comes out of the issue BODY, and
 * a later comment that replaces the bar is invisible to it: #1595's body carried 3 bullets, a comment
 * carried 4 that said "Supersedes the acceptance in the body above", the operator directed the work
 * against the revised list, and the gate logged `✓ #1595: 3/3 criteria dispositioned` — three for
 * three against a bar that no longer applied (run 30598147578).
 *
 * The gate does NOT grade against the comment; see SUPERSEDING_CONVENTION for why that decision went
 * the way it did. It reports the comment so a human reads it.
 *
 * Two shapes fire, drawn from the whole population rather than from intuition (see the census in
 * `src/cli/superseded-acceptance-census.ts`): a heading that ANNOUNCES an acceptance list followed by
 * bullets — `## Acceptance`, `## Acceptance criteria (revised)`, `## Revised acceptance — collapse on
 * EVIDENCE, not position` — or an unchecked `- [ ]` checklist, which is the other convention this
 * repo writes criteria in and is what #1595's own comment used under a heading no bare-word pattern
 * would have matched.
 *
 * REPORTING against a bar looks identical to SETTING one until you read the bullets, and the repo
 * writes far more of the former. Three exclusions guard against that: a comment carrying
 * `ACCEPTANCE #n.m <verdict>:` lines (every executor's disposition record); the close gate's own
 * banner, which is posted under a HUMAN token on this repo — measured on #1384 — so an author check
 * does not see it; and a bullet list whose own items already carry verdicts (`[x]`, ✅/❌,
 * "**done**", "— MET"), which is a status report wearing an `## Acceptance` heading. MEASURED
 * 2026-07-31 against the whole population (893 closed issues, 707 comments): with none of the three
 * applied the flag count is 66; the committed state (all three) is 12. Only two of the three are
 * earned by a census false positive — the banner exclusion alone takes 12 back up to 63 if dropped,
 * the verdict-ratio exclusion alone to 15. The disposition-record exclusion has a MEASURED
 * population of zero in this census (dropping it alone leaves the count at 12) — it is defensible
 * defensive code, not something this census demonstrates a need for.
 */
const ACCEPTANCE_ANNOUNCE = /^\**\s*(?:revised|updated|corrected|amended|new|replacement|final|restated)?\s*acceptance\b/i;
const UNCHECKED_BOX = /^\s*[-*+]\s+\[ \]\s+\S/;
const CLOSE_GATE_BANNER = /^\**\s*Acceptance conservation \(#\d+\)/im;
const BULLET_VERDICT = /\[[xX]\]|✅|❌|\*\*\s*(?:done|met|not met|shipped|held)\b|\b(?:MET|DONE)\b/;

/**
 * #1603's third and fourth criteria: the DECISION, and the convention that follows from it, recorded
 * where an executor reads — this gate's own output, which every executor runs pre-flight.
 *
 * FLAGGED, NOT AUTHORITATIVE. The gate keeps grading the body. Grading the comment instead would
 * mean swapping the bar on a heuristic read of prose, and the census that sized this measured 1
 * false positive in 12 (#1435's status report). In that direction the gate would grade against a
 * COMPLETION REPORT — every bullet already "met" — which is strictly worse than grading a stale bar,
 * and it is the self-serving narrowing the whole mechanism exists to catch. A warning costs one
 * human read when it misfires.
 */
const SUPERSEDING_CONVENTION =
  "The convention (#1603): a revision belongs in the issue BODY, which is the graded surface — edit it there. "
  + "If you cannot, disposition against the revised list and say in the PR body which list you graded. "
  + "Falsifier for the convention: `pnpm exec tsx src/cli/superseded-acceptance-census.ts` — any NEW flagged comment on an issue closed after 2026-07-31 is the convention not being followed.";

interface SupersedingComment {
  url: string;
  /** The heading that announced the list, or `a checklist` when the checkbox shape fired. */
  heading: string;
  bullets: number;
}

export function supersedingAcceptanceComments(comments: readonly { body: string; url?: string }[]): SupersedingComment[] {
  const found: SupersedingComment[] = [];
  for (const [i, c] of comments.entries()) {
    const all = lines(c.body);
    if (all.some((l) => DISPOSITION_LINE.test(strip(l)) || NO_CRITERIA_LINE.test(strip(l)))) continue;
    if (CLOSE_GATE_BANNER.test(c.body)) continue;
    const url = c.url ?? `comment ${i + 1}`;
    const boxes = all.filter((l) => UNCHECKED_BOX.test(l)).length;
    let hit: SupersedingComment | undefined;
    for (let j = 0; j < all.length && hit === undefined; j++) {
      const h = heading(all[j]!);
      if (h === undefined || !ACCEPTANCE_ANNOUNCE.test(h.text)) continue;
      // Bounded at the next heading AT OR ABOVE this one's level, exactly as parseAcceptanceCriteria
      // bounds the body's section. Counting to the end of the comment instead let a LATER section's
      // bullets dilute the verdict ratio below, which is how #1174's `- [x]`-only acceptance report
      // survived the filter on the strength of three unrelated bullets under a different heading.
      let close = all.length;
      for (let k = j + 1; k < all.length; k++) {
        const next = heading(all[k]!);
        if (next !== undefined && next.level <= h.level) { close = k; break; }
      }
      const bullets = all.slice(j + 1, close).filter((l) => BULLET.test(l));
      const verdicts = bullets.filter((l) => BULLET_VERDICT.test(l)).length;
      // Two, not one: a single bullet under an "Acceptance…" heading is prose about the existing
      // bar far more often than it is a new one, and the whole-population census says so.
      if (bullets.length >= 2 && verdicts * 2 < bullets.length) hit = { url, heading: h.text, bullets: bullets.length };
    }
    if (hit === undefined && boxes >= 2) hit = { url, heading: "a checklist (no acceptance heading)", bullets: boxes };
    if (hit !== undefined) found.push(hit);
  }
  return found;
}

/**
 * `#7`, `owner/repo#7` and `https://github.com/owner/repo/issues/7` are the three forms GitHub's own
 * closing parser accepts, so all three have to resolve here or the gate is silent on a real close.
 * A cross-repo form naming THIS repo is normalised to a bare one — same issue, so it must not be
 * fetched down a second path and reported twice. **Normalisation needs `repo`**: with none supplied
 * there is nothing to compare an owner against, so a body citing both `#7` and `owner/repo#7` is
 * fetched and reported twice. The CLI resolves the current repo when `--repo` is not passed; a
 * library caller that omits it gets the un-normalised behaviour.
 *
 * `undefined` means the reference resolves to no readable issue. `Closes
 * https://github.com/orgs/acme/projects/1/issues/5` has more than two path segments before
 * `/issues/`, matches neither branch, and used to THROW — killing the CLI with a Node stack trace at
 * exit 1 ("the gate failed") instead of its documented exit 2, and replacing a disclosed row with a
 * crash. It is disclosed as NOT ASSESSED instead: GitHub's own closing parser does not act on that
 * shape either, so nothing closes, but the gate says what it could not read rather than going quiet.
 */
function closingRef(ref: string, repo?: string): ClosingRef | undefined {
  const bare = /^#(\d+)$/.exec(ref);
  if (bare) return { number: Number(bare[1]), ref };
  const scoped = /^([\w.-]+\/[\w.-]+)#(\d+)$/.exec(ref) ?? /^https?:\/\/[^/]+\/([\w.-]+\/[\w.-]+)\/issues\/(\d+)/.exec(ref);
  if (!scoped) return undefined;
  const owner = scoped[1]!;
  const number = Number(scoped[2]);
  return owner.toLowerCase() === repo?.toLowerCase() ? { number, ref } : { repo: owner, number, ref };
}

export function parseBody(prBody: string, repo?: string, venue: string = PR_BODY): ParsedBody {
  const closes: ClosingRef[] = [];
  const unresolvedCloses: string[] = [];
  for (const m of prBody.matchAll(CLOSING)) {
    const ref = m.groups!.ref!;
    const parsed = closingRef(ref, repo);
    if (parsed) closes.push(parsed);
    else if (!unresolvedCloses.includes(ref)) unresolvedCloses.push(ref);
  }

  const dispositions: DispositionLine[] = [];
  const noCriteria: NoCriteriaLine[] = [];
  const remainders: RemainderRef[] = [];
  const parseErrors: string[] = [];

  const all = lines(prBody);
  // A fenced code block is QUOTATION, not assertion (#1696). The comment that REPORTS a malformed
  // disposition quotes the offending line verbatim — read live, that quote poisons its venue
  // permanently, so the issue documenting a malformation could never again close green. The same
  // reading would let a well-formed line quoted as an example silently map a criterion. State is
  // per-venue by construction: parseBody runs once per body/comment, so an unclosed fence cannot
  // leak into the next venue.
  let inFence = false;
  all.forEach((raw, i) => {
    if (/^\s*(?:```|~~~)/.test(raw)) {
      inFence = !inFence;
      return;
    }
    if (inFence) return;
    const line = strip(raw).trim();
    const d = DISPOSITION_LINE.exec(line);
    if (d) {
      const wrappedInto = wrapContinuation(all[i + 1]);
      dispositions.push({
        issue: Number(d[1]),
        index: Number(d[2]),
        disposition: d[3]!.toLowerCase() as Disposition,
        detail: d[4]!.trim(),
        line: i + 1,
        venue,
        ...(wrappedInto === undefined ? {} : { wrappedInto }),
      });
      return;
    }
    const n = NO_CRITERIA_LINE.exec(line);
    if (n) {
      noCriteria.push({ issue: Number(n[1]), bar: n[2]!.trim(), line: i + 1, venue });
      return;
    }
    // A line that names an issue NUMBER and parses as neither is MALFORMED, not absent. Dropping it
    // silently is how a typo'd disposition becomes an unmapped bullet nobody sees. The `#\d` is what
    // separates a real attempt from the `#<issue>` placeholders in .github/pull_request_template.md,
    // which survive in the raw body GitHub hands back even though the reader never sees them.
    if (/^ACCEPTANCE\s+#\d/i.test(line)) {
      parseErrors.push(`${venue}, line ${i + 1}: ${malformedDisposition(line)}`);
      return;
    }
    const r = REMAINDER_LINE.exec(line);
    if (r) remainders.push({ remainder: Number(r[1]), line: i + 1, venue });
  });

  for (const d of dispositions.filter((x) => x.disposition === "split")) {
    const target = /#(\d+)/.exec(d.detail);
    if (target) remainders.push({ remainder: Number(target[1]), original: d.issue, line: d.line, venue });
  }

  const byRef = new Map(closes.map((c) => [`${c.repo ?? ""}#${c.number}`, c]));
  return { closes: [...byRef.values()], unresolvedCloses, dispositions, noCriteria, remainders, parseErrors };
}

/**
 * The facts about this checkout that let evidence be checked for TRUTH and not only for SHAPE.
 *
 * Three of the five evidence shapes name something whose existence is a lookup, not a judgement,
 * and the gate shipped checking none of them (#1320 bounds audit, 2026-07-27). Measured over the
 * `met` lines of the last 60 merged PRs (11 lines across 2 PRs — every other merged body predates
 * the convention) by replaying this module's own parser and filters: **11** cited repo-relative
 * paths, all of which exist (17 raw `FILE_PATH` matches before the "contains a `/` and its first
 * segment is a top-level entry" filter — quote the filtered number, since the raw one counts foreign
 * trees and bare filenames the gate deliberately leaves alone); **3/3** `pnpm <script>` references
 * name a real `package.json` script; **8/9** quoted spans name a real test, 6 quoting the title
 * exactly and 2 quoting a real title truncated at its em-dash, which is why a prefix counts (see
 * `namesATest`). The ninth is the bare word `"cross-linked"` — correctly not a test name, as is the
 * doc's own counterexample `"it all looks great"`. So an invented path, an invented script and a
 * quoted sentence are all mechanically separable from the real thing, and "it cannot tell a real
 * command from an invented one" was true only of the unchecked ones.
 *
 * Supplied by the caller so the module stays pure and the hermetic self-test stays hermetic. When
 * it is absent the gate falls back to the shape-only floor and SAYS SO, rather than reporting a
 * truth check it did not run.
 */
export interface EvidenceWorld {
  /** Top-level entries of the repo root. A cited path whose first segment is not one of these is about some other tree and is left alone. */
  topLevelEntries: ReadonlySet<string>;
  /** Whether a repo-relative path resolves in this checkout. */
  pathExists: (path: string) => boolean;
  /** The names in `package.json`'s `scripts`. */
  scripts: ReadonlySet<string>;
  /** Every `it`/`test`/`describe` title in the suite. */
  testNames: ReadonlySet<string>;
}

// JS regex alternation is first-match, not longest-match, so an extension that is a PREFIX of
// another (js/json, ts/tsx, js/jsx, md/mdx) gets TRUNCATED — a real citation of an existing file is
// then reported as pointing at a nonexistent one, on the acceptance gate's OWN evidence path.
// #1266 fixed that by ORDERING, which fixes one pair at a time and left two live: MEASURED
// 2026-07-31 against the real checkout, `targets/calibration/components/AdminPanel.jsx` (one of 26
// tracked `.jsx` files) extracted as `AdminPanel.js`, and `docs/a.mdx` as `docs/a.md` (0 tracked
// `.mdx` today — latent, not live). The `(?!\w)` boundary fixes the CLASS: a prefix match is
// refused outright, so a future extension added in the wrong place stops being able to reintroduce
// this. Order is kept longest-first anyway so the two mechanisms agree rather than one masking
// the other.
const FILE_PATH_SOURCE = String.raw`[\w./-]+\.(?:tsx|ts|jsx|js|mjs|cjs|json|mdx|md|ya?ml|sql|sh|py|toml)(?!\w)(?::\d+)?`;
const FILE_PATH = new RegExp(FILE_PATH_SOURCE, "g");
const BACKTICKED = /`([^`]+)`/g;
const QUOTED_SPAN = /"([^"]{8,})"/g;

/** pnpm's own subcommands: their argument is a binary, a package or a directory, never a `scripts` key. */
const PNPM_PASSTHROUGH = new Set([
  "exec", "dlx", "install", "i", "add", "remove", "rm", "uninstall", "un", "update", "up", "why",
  "list", "ls", "link", "unlink", "audit", "outdated", "init", "create", "store", "config", "patch",
  "dedupe", "rebuild", "prune", "fetch",
]);

// `-r`/`--filter <pkg>`/`-C <dir>` run the script out of ANOTHER package's manifest, which this
// checkout's root `scripts` set cannot answer, so the reference is left unchecked rather than
// reported as invented — `pnpm --filter site build` is a correct workspace command.
const SELECTS_ANOTHER_PACKAGE = new Set(["-r", "--recursive", "-F", "--filter", "--filter-prod", "-C", "--dir"]);

/**
 * The `scripts` keys a `met` line names — read ONLY inside a backticked span, and never from a token
 * that is a flag.
 *
 * The old shape was `/\bpnpm\s+(?:run\s+)?([\w:-]+)/g`, which read the token after `pnpm` as a script
 * name whatever it was. It therefore told the author of `` `pnpm --filter site build` `` that
 * `pnpm --filter` "is not a script in package.json", and read the prose *"ran pnpm and it worked"*
 * as an invented `pnpm and`. A false REJECT that denies a TRUE statement is the one failure this
 * check must not produce: the whole claim of the truth pass is that an invention is separable from
 * the real thing, and it stopped being separable the moment a correct command failed it.
 *
 * Requiring the backticks is what kills the prose case, and it costs nothing on the population it
 * was measured against: all 3 `pnpm <script>` references in the last 60 merged PRs' `met` lines are
 * backticked (measured 2026-07-27). An unbackticked `pnpm verify` is no longer truth-checked —
 * disclosed in docs/design/acceptance-conservation.md.
 */
function citedScripts(text: string): string[] {
  const names: string[] = [];
  for (const span of text.matchAll(BACKTICKED)) {
    const tokens = span[1]!.trim().split(/\s+/);
    for (let t = 0; t < tokens.length; t++) {
      if (tokens[t] !== "pnpm") continue;
      let i = t + 1;
      while (i < tokens.length && tokens[i]!.startsWith("-") && !SELECTS_ANOTHER_PACKAGE.has(tokens[i]!)) i++;
      if (SELECTS_ANOTHER_PACKAGE.has(tokens[i] ?? "")) continue;
      const name = tokens[i] === "run" ? tokens[i + 1] : tokens[i];
      if (name !== undefined && /^[\w:-]+$/.test(name) && !PNPM_PASSTHROUGH.has(name)) names.push(name);
    }
  }
  return names;
}

/**
 * A quoted span names a test when the suite holds that title, OR when a title STARTS with it at a
 * word boundary. The prefix half is not a loosening for its own sake: 2 of the 9 quoted spans
 * measured over the last 60 merged PRs are correct citations of real titles truncated at the title's
 * em-dash (`"NEGATIVE CONTROL: a remainder pointing at a CLOSED issue fails"`, whose title continues
 * `— the #715 → #161 shape`). Exact set membership scored both as misses, and a check that refuses a
 * correct citation of a real test is the same false-REJECT defect as the `pnpm` one above.
 */
function namesATest(span: string, world: EvidenceWorld): boolean {
  if (world.testNames.has(span)) return true;
  return [...world.testNames].some((t) => t.startsWith(span) && /\s/.test(t.charAt(span.length)));
}

// A bare "done" is an unmapped bullet wearing a disposition (#1315). These are the shapes that
// carry something a reader can go and check; without an EvidenceWorld the list is a floor, not a
// judgement of truth — WITH one, the three checkable shapes are also checked.
const EVIDENCE_SHAPES: { name: string; re: RegExp }[] = [
  // A backticked run of plain English words is not a command: `` `all good` `` passed the old
  // /`[^`]{4,}`/ and pointed at nothing. So the span must either be a single token (a path, a flag,
  // an identifier) or contain a character English prose does not use. `pnpm verify` is two plain
  // words and no longer matches HERE — it matches the command shape below, which is what it is.
  { name: "a backticked command, path or identifier", re: /`(?=[^`]{4,}`)(?:[^`\s]+|[^`]*[^`A-Za-z\s][^`]*)`/ },
  { name: "a command", re: /\b(?:pnpm|npm|npx|node|tsx|vitest|git|gh|semgrep|docker|make|curl|psql)\s+\S/ },
  // Same source as FILE_PATH, so the shape check and the truth check can never disagree about what
  // a path is — this line carried its OWN hand-copied alternation, still in the pre-#1266 order.
  { name: "a file path", re: new RegExp(FILE_PATH_SOURCE) },
  { name: "a quoted test name", re: /"[^"]{8,}"/ },
  // The old /\b[0-9a-f]{7,40}\b/ matched ordinary English — "defaced", "accede", "facade" are all
  // 6-7 letters drawn from [a-f] — and any 7-digit number, so "run 90131391124 was green" read as a
  // commit reference. A sha MIXES digits and hex letters; a run of only one or only the other is
  // prose or a number. Cost of the narrowing: an all-digit or all-[a-f] short sha prefix is no
  // longer recognised AS a sha (disclosed in docs/design/acceptance-conservation.md) — cite it
  // inside backticks, or name the command, instead.
  { name: "a commit sha", re: /\b(?=[0-9a-f]{7,40}\b)(?=[0-9a-f]*[0-9])(?=[0-9a-f]*[a-f])[0-9a-f]+\b/ },
];

const BARE_ASSERTION = /^(?:done|yes|ok|okay|completed?|verified|works?|fixed|met|n\/a|na|as stated|as described|implemented|shipped|true)\b[.!]*$/i;

/** Paths the evidence cites that are ABOUT this repo — the only ones whose absence is a defect. */
function citedRepoPaths(text: string, world: EvidenceWorld): string[] {
  return [...text.matchAll(FILE_PATH)]
    .map((m) => m[0].replace(/:\d+$/, ""))
    .filter((p) => p.includes("/") && world.topLevelEntries.has(p.split("/")[0]!));
}

export function evidenceProblems(detail: string, world?: EvidenceWorld): string[] {
  const text = detail.trim();
  if (BARE_ASSERTION.test(text)) return [`\`met\` carries a bare assertion ("${text}"), which is an unmapped bullet with a label on it — name the command run and its output, the test, or the file:line`];
  if (text.length < 12) return [`\`met\` evidence is ${text.length} characters — too short to point at anything`];

  const problems: string[] = [];
  if (world) {
    for (const p of citedRepoPaths(text, world)) {
      if (!world.pathExists(p)) problems.push(`\`met\` cites \`${p}\`, which does not exist in this checkout — evidence that points at nothing is an assertion with a file extension`);
    }
    for (const name of citedScripts(text)) {
      if (!world.scripts.has(name)) {
        problems.push(`\`met\` cites \`pnpm ${name}\`, which is not a script in package.json — name the command that was actually run`);
      }
    }
  }
  if (problems.length > 0) return problems;

  // The quoted shape is the loosest: any 8+ characters between quotes. With a world it is held to
  // its own claim — a quoted TEST NAME is one the suite actually contains. Without one it stays a
  // shape. A quote that is not a test title does not fail the line by itself; the line simply has
  // to carry one of the other shapes, which every real `met` line measured already did.
  const held = EVIDENCE_SHAPES.filter((s) => {
    if (s.name !== "a quoted test name" || !world) return s.re.test(text);
    return [...text.matchAll(QUOTED_SPAN)].some((m) => namesATest(m[1]!, world));
  });
  if (held.length === 0) {
    // The shape NAMES alone left the author guessing what a passing line looks like (#1565, mode 6),
    // so one is shown. `pnpm verify` unbackticked matches the command shape but is not truth-checked;
    // the example backticks it, which is the form the measured population already uses.
    return [`\`met\` evidence names none of: ${EVIDENCE_SHAPES.map((s) => s.name).join(", ")}${world ? " (a quoted span counts only when the suite contains that test title)" : ""}. An assertion is not evidence — a line that passes looks like \`ACCEPTANCE #<issue>.<n> met: \`pnpm verify\` green; src/foo.ts:42 now throws\``];
  }
  return [];
}

interface CriterionVerdict {
  index: number;
  text: string;
  disposition?: Disposition;
  detail?: string;
  problems: string[];
}

interface IssueVerdict {
  issue: number;
  /** The reference as the body wrote it — `#1315` or `owner/repo#7`. */
  ref: string;
  exists: boolean;
  criteria: CriterionVerdict[];
  nestedFolded: number;
  source: ParsedCriteria["source"];
  noStatedCriteria?: string;
  problems: string[];
  /**
   * #1603 — comments on this issue that carry their own acceptance list. NOT graded (see
   * SUPERSEDING_CONVENTION); reported so the reader knows the bar may have moved. Deliberately not
   * folded into `problems`: `ok` must not turn on a heuristic read of prose.
   */
  supersedingComments: SupersedingComment[];
  ok: boolean;
}

type ConditionStatus = "pass" | "fail" | "not-assessed";

interface Condition {
  name: "exists" | "open" | "cross-linked";
  status: ConditionStatus;
  detail: string;
}

interface RemainderVerdict {
  remainder: number;
  original?: number;
  conditions: Condition[];
  ok: boolean;
}

interface AcceptanceReport {
  closes: ClosingRef[];
  /** Closing references this gate could not resolve to an issue. Reported, and not counted as a close. */
  unresolvedCloses: string[];
  /** False when no EvidenceWorld was supplied — the run checked shape only, and says so. */
  evidenceVerified: boolean;
  /** The venues that supplied at least one disposition line, in the order they were read. */
  venuesContributing: string[];
  issues: IssueVerdict[];
  remainders: RemainderVerdict[];
  parseErrors: string[];
  /** True when the PR carries neither a closing keyword nor a remainder — the gate's green no-op. */
  noop: boolean;
  ok: boolean;
}

function checkRemainder(ref: RemainderRef, lookup: IssueLookup, closes: ClosingRef[]): RemainderVerdict {
  const record = lookup(ref.remainder);
  const conditions: Condition[] = [];

  conditions.push(record
    ? { name: "exists", status: "pass", detail: `#${ref.remainder} exists` }
    : { name: "exists", status: "fail", detail: `#${ref.remainder} does not exist — the deferral points at nothing` });

  if (!record) {
    conditions.push({ name: "open", status: "not-assessed", detail: "cannot read the state of an issue that does not exist" });
    conditions.push({ name: "cross-linked", status: "not-assessed", detail: "cannot cross-link to an issue that does not exist" });
    return { remainder: ref.remainder, original: ref.original, conditions, ok: false };
  }

  conditions.push(record.state === "OPEN"
    ? { name: "open", status: "pass", detail: `#${ref.remainder} is OPEN` }
    : { name: "open", status: "fail", detail: `#${ref.remainder} is CLOSED — deferring to a closed issue is indistinguishable in outcome from not deferring at all (#715 → #161, which had closed nine minutes earlier)` });

  // For a `split` the original is known. A bare `remainder: #X` line names none, so every issue this
  // PR closes is a candidate — and a PR that closes nothing has no original to check against, which
  // is reported as not-assessed rather than passed.
  const originals: ClosingRef[] = ref.original !== undefined ? [{ number: ref.original, ref: `#${ref.original}` }] : closes;
  if (originals.length === 0) {
    conditions.push({ name: "cross-linked", status: "not-assessed", detail: "this PR closes no issue, so there is no original to cross-link from" });
  } else {
    // ANY mention of the remainder number anywhere in the original's body or comments satisfies
    // this — the check is that the number is DISCOVERABLE from the issue, not that the sentence
    // around it describes the deferral. Disclosed in docs/design/acceptance-conservation.md.
    //
    // REASON: the cross-linked condition accepts any mention of the remainder number in the original, including a historical aside describing no deferral, and the obvious tightening (require a deferral word near the mention) is measured right on only 3 of 5 real pairs — it wrongly refuses #1317 -> #1342, whose cross-link reads "Gate 4a residual filed as #1342"
    // KIND: empirical
    // PROVENANCE: MEASURED 2026-07-27 — the deferral-vocabulary rule scored against five real pairs (#1316 -> #1260, #1317 -> #1330, #1307 -> #1328, #1317 -> #1342, #1315 -> #1341); it correctly refuses the recorded false accept and correctly passes two, and wrongly refuses one, which is the same vocabulary defect #1342 records against Gate 4's own BOUND_MARKERS.
    // FALSIFIER: pnpm exec vitest run src/acceptance-conservation.test.ts -t "a historical aside satisfies cross-linked" > /tmp/harvey-xlink.log 2>&1; grep -q "1 passed" /tmp/harvey-xlink.log && exit 1 || { grep -q "1 failed" /tmp/harvey-xlink.log && exit 0 || exit 127; }
    // TOUCHES: src/acceptance-conservation.ts
    const linked = originals.filter((o) => {
      const orig = lookup(o.number, o.repo);
      return orig !== undefined && new RegExp(`#${ref.remainder}\\b`).test([orig.body, ...orig.comments.map((c) => c.body)].join("\n"));
    });
    conditions.push(linked.length > 0
      ? { name: "cross-linked", status: "pass", detail: `${linked.map((o) => o.ref).join(", ")} references #${ref.remainder}` }
      : { name: "cross-linked", status: "fail", detail: `none of ${originals.map((o) => o.ref).join(", ")} references #${ref.remainder} in its body or comments — comment the cross-link on the original so the deferral is discoverable from the issue, not only from this PR` });
  }

  return { remainder: ref.remainder, original: ref.original, conditions, ok: conditions.every((c) => c.status !== "fail") };
}

function checkIssue(target: ClosingRef, parsed: ParsedBody, lookup: IssueLookup, world?: EvidenceWorld): IssueVerdict {
  const issue = target.number;
  const record = lookup(issue, target.repo);
  if (!record) {
    return { issue, ref: target.ref, exists: false, criteria: [], nestedFolded: 0, source: "none", problems: [`${target.ref} does not exist — a closing keyword pointing at nothing`], supersedingComments: [], ok: false };
  }

  const { criteria, nestedFolded, source } = parseAcceptanceCriteria(record.body);
  const declaredNone = parsed.noCriteria.find((n) => n.issue === issue);
  const problems: string[] = [];
  const supersedingComments = supersedingAcceptanceComments(record.comments);

  if (criteria.length === 0) {
    if (!declaredNone) {
      problems.push(`#${issue} states no acceptance criteria (no \`## Acceptance\` section, no checklist) and this PR body declares no bar. An issue with no criteria is where closing-with-unmet-criteria is EASIEST, so it is not a silent pass — add \`ACCEPTANCE #${issue} no-stated-criteria: <what the bar was>\``);
    } else if (declaredNone.bar.trim().length < 12) {
      problems.push(`#${issue} no-stated-criteria names a bar of ${declaredNone.bar.trim().length} characters — say what the bar actually was`);
    }
    return { issue, ref: target.ref, exists: true, criteria: [], nestedFolded, source, noStatedCriteria: declaredNone?.bar, problems, supersedingComments, ok: problems.length === 0 };
  }

  if (declaredNone) {
    problems.push(`#${issue} declares \`no-stated-criteria\` but the issue states ${criteria.length} — the escape hatch is for issues that have none`);
  }

  const mine = parsed.dispositions.filter((d) => d.issue === issue);
  // #1565: print the criteria the gate PARSED, not just how many there are. Numbering is positional
  // over the issue's own bullets, and an author renumbering against the RENDERED issue is reading a
  // different list from the gate's — the two differ exactly when the parse is the defect.
  const parsedList = criteria.map((c) => `${c.index}. ${c.text.slice(0, 90)}`).join("  |  ");
  for (const d of mine.filter((d) => d.index < 1 || d.index > criteria.length)) {
    problems.push(`${d.venue}, line ${d.line}: disposition names criterion #${issue}.${d.index}, but #${issue} states ${criteria.length}. Numbering is POSITIONAL over the bullets this gate parsed from the ${source} — renumber against these: ${parsedList}`);
  }

  const verdicts = criteria.map((c): CriterionVerdict => {
    const matched = mine.filter((d) => d.index === c.index);
    if (matched.length === 0) {
      return { ...c, problems: [`UNMAPPED — no disposition. Add \`ACCEPTANCE #${issue}.${c.index} <met|split|relayed>: <detail>\``] };
    }
    if (matched.length > 1) {
      const where = matched.map((m) => `${m.venue}, line ${m.line}`).join("; ");
      return { ...c, problems: [`#${issue}.${c.index} is mapped ${matched.length} times — ${where} — and a criterion takes exactly one disposition. Every venue is read CUMULATIVELY (this body, every linked PR body, and every comment on #${issue}), so keep ONE copy and neutralise the other before merging`] };
    }
    const d = matched[0]!;
    const verdict: CriterionVerdict = { ...c, disposition: d.disposition, detail: d.detail, problems: [] };
    if (d.disposition === "met") {
      const evidence = evidenceProblems(d.detail, world);
      verdict.problems.push(...evidence);
      // #1565: the wrap. The parser reads line by line, so a long correct `met` whose evidence runs
      // onto the next line is judged on its first line alone and fails for a reason the message
      // never stated. Attached ONLY to an evidence failure, so it explains a rejection rather than
      // creating one.
      if (evidence.length > 0 && d.wrappedInto !== undefined) {
        verdict.problems.push(`the evidence was TRUNCATED AT A LINE BREAK — ${d.venue}, line ${d.line} is read to its end and line ${d.line + 1} ("${d.wrappedInto.slice(0, 70)}") is NOT joined to it. Put the whole disposition on one line`);
      }
    }
    if (d.disposition === "split" && !/#\d+/.test(d.detail)) {
      verdict.problems.push("`split` names no remainder issue — a split with no live remainder is a deletion (#1316)");
    }
    if (d.disposition === "relayed") {
      // The question has to be ON THE ISSUE, not in the PR body: a PR body is archived at merge and
      // the operator does not read it, so a question recorded only there is a question nobody was
      // asked. Mechanically this proves a question was recorded, not that it is the RIGHT one.
      const asked = record.comments.some((c) => c.body.includes("?"));
      if (!asked) verdict.problems.push(`\`relayed\` but #${issue} carries no comment containing a question — record the question ON THE ISSUE, where the operator reads it, not in this PR body`);
    }
    return verdict;
  });

  const ok = problems.length === 0 && verdicts.every((v) => v.problems.length === 0);
  return { issue, ref: target.ref, exists: true, criteria: verdicts, nestedFolded, source, problems, supersedingComments, ok };
}

interface AcceptanceExtras {
  /**
   * The PR whose body was passed as `prBody`, as GitHub refs it. It is EXCLUDED from the linked-PR
   * venues so the PR under test is not read twice: an open PR carrying a closing keyword already
   * appears in its issue's `closedByPullRequestsReferences`, and reading it as both `the PR body`
   * and `linked PR #N` would report every criterion as mapped twice.
   */
  selfPr?: string;
  /**
   * Closing references GitHub itself records that no body regex can see: `closingIssuesReferences`,
   * which the Development sidebar populates with no keyword in the body at all. Without them the PR
   * check green-no-ops on a PR that WILL close an issue on merge — the same false negative as the
   * venue gap, reached by a different route.
   */
  linkedCloses?: ClosingRef[];
}

/**
 * Every surface OTHER than the body under test that disposition lines are read out of, for one
 * closing reference. Both gates call this and nothing else, so the venue sets stay identical.
 */
function venuesOf(c: ClosingRef, lookup: IssueLookup, selfPr?: string): Venue[] {
  const record = lookup(c.number, c.repo);
  if (!record) return [];
  return [
    ...(record.linkedPrs ?? [])
      .filter((pr) => pr.ref !== selfPr)
      .map((pr) => ({ label: `linked PR ${pr.ref}`, text: pr.body })),
    ...record.comments.map((cm, i) => ({ label: `${c.ref} comment ${i + 1}`, text: cm.body })),
  ];
}

export function checkAcceptance(prBody: string, lookup: IssueLookup, repo?: string, world?: EvidenceWorld, extras?: AcceptanceExtras): AcceptanceReport {
  const parsed = parseBody(prBody, repo);
  const byRef = new Map([...parsed.closes, ...(extras?.linkedCloses ?? [])].map((c) => [`${c.repo ?? ""}#${c.number}`, c]));
  const closes = [...byRef.values()];

  const absorb = (v: Venue): void => {
    const p = parseBody(v.text, repo, v.label);
    parsed.dispositions.push(...p.dispositions);
    parsed.noCriteria.push(...p.noCriteria);
    parsed.remainders.push(...p.remainders);
    parsed.parseErrors.push(...p.parseErrors);
  };
  // THE PARITY STEP. Every venue the close path reads is collected HERE, for both paths: the linked
  // PR bodies and the issue's own comments, out of the one lookup. #1562 did this for comments;
  // #1581 found the same divergence one field over, on an issue closed by TWO linked PRs.
  for (const c of closes) {
    for (const v of venuesOf(c, lookup, extras?.selfPr)) absorb(v);
  }

  // Two venues repeating one deferral is one deferral, not two — the duplicate DISPOSITION is what
  // fails, and a second identical remainder row underneath it just says the same thing twice.
  const seen = new Set<string>();
  parsed.remainders = parsed.remainders.filter((r) => {
    const key = `${r.original ?? ""}#${r.remainder}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const venuesContributing = [...new Set([...parsed.dispositions, ...parsed.noCriteria, ...parsed.remainders].map((x) => x.venue))];
  // An unresolvable closing reference keeps the run OUT of the green no-op: a body carrying one is
  // not a body carrying nothing, and the no-op's early return would swallow its disclosure row.
  const noop = closes.length === 0 && parsed.remainders.length === 0 && parsed.unresolvedCloses.length === 0;
  const issues = closes.map((c) => checkIssue(c, parsed, lookup, world));
  const remainders = parsed.remainders.map((r) => checkRemainder(r, lookup, closes));
  const ok = parsed.parseErrors.length === 0 && issues.every((i) => i.ok) && remainders.every((r) => r.ok);
  return { closes, unresolvedCloses: parsed.unresolvedCloses, evidenceVerified: world !== undefined, venuesContributing, issues, remainders, parseErrors: parsed.parseErrors, noop, ok };
}

export function formatAcceptance(report: AcceptanceReport): string {
  // The two gates share one job and one check context, so each states its own relevance verdict
  // FIRST. GitHub's required-checks list is branch-level — there is no per-PR-type requirement — so
  // the scoping has to live here, and a green no-op has to say WHY it was a no-op. An unexplained
  // green is indistinguishable from a check that did nothing because it was broken.
  const gate1Refs = report.closes.map((c) => c.ref);
  // A `split` that names no issue number produces no remainder REFERENCE, so it must not be
  // reported as "no split disposition" — that reads as nothing deferred when something was.
  const numberlessSplits = report.issues.flatMap((i) => i.criteria).filter((c) => c.disposition === "split").length - report.remainders.filter((r) => r.original !== undefined).length;
  const gate2Noop = numberlessSplits > 0
    ? `○ Gate 2 (remainder liveness, #1316): NO-OP — ${numberlessSplits} \`split\` disposition(s) name no issue number, so there is no remainder whose liveness could be checked. Gate 1 fails them.`
    : "○ Gate 2 (remainder liveness, #1316): NO-OP — no `remainder:` line and no `split` disposition, so nothing is deferred to another issue.";
  // "no closing keyword" would be FALSE when one was found and could not be read. A green with the
  // wrong reason attached is the unexplained green wearing a sentence.
  const gate1Head = gate1Refs.length > 0
    ? `● Gate 1 (acceptance criteria, #1315): ${gate1Refs.length} closing reference(s) — ${gate1Refs.join(", ")}.`
    : report.unresolvedCloses.length > 0
      ? `● Gate 1 (acceptance criteria, #1315): ${report.unresolvedCloses.length} closing reference(s), none of which resolve to an issue this gate can read — see the NOT ASSESSED row(s) below.`
      : "○ Gate 1 (acceptance criteria, #1315): NO-OP — this PR body carries no closing keyword, so no issue closes on merge and there are no criteria to conserve.";
  const out: string[] = [
    gate1Head,
    report.remainders.length === 0
      ? gate2Noop
      : `● Gate 2 (remainder liveness, #1316): ${report.remainders.length} remainder reference(s) — ${report.remainders.map((r) => `#${r.remainder}`).join(", ")}.`,
    "",
  ];
  if (report.noop) return `${out.join("\n")}✓ nothing for either gate to assert on this PR.`;

  // Which surfaces were actually read, whenever more than one contributed. A duplicate disposition
  // is invisible until the reader knows the gate read BOTH places, and the failure message below
  // names venues that would otherwise appear from nowhere.
  if (report.venuesContributing.length > 1) {
    out.push(`ℹ ${report.venuesContributing.length} venues supplied disposition lines and are read CUMULATIVELY — ${report.venuesContributing.join(", ")}. A criterion may be dispositioned exactly once ACROSS ALL of them.`);
  }

  for (const e of report.parseErrors) out.push(`✗ ${e}`);

  // Shape-only is a WEAKER run than the default, so it is disclosed rather than left to look
  // identical to a verified one — an unstated limitation reads as a clean bill of health.
  if (!report.evidenceVerified) {
    out.push("ℹ NOT ASSESSED  no checkout supplied, so `met` evidence was checked for SHAPE only — a cited path, `pnpm` script or test title was not confirmed to exist.");
  }

  for (const ref of report.unresolvedCloses) {
    out.push(`ℹ NOT ASSESSED  closing reference \`${ref}\` resolves to neither \`#N\`, \`owner/repo#N\` nor \`https://<host>/<owner>/<repo>/issues/N\`, so this gate could not read the issue it names and its acceptance criteria were NOT checked. GitHub's own closing parser does not act on this shape either, so nothing closes on merge — but that is a claim about GitHub, not a check this gate ran.`);
  }

  for (const issue of report.issues) {
    const head = issue.ok ? "✓" : "✗";
    if (!issue.exists) {
      out.push(`${head} ${issue.ref}: ${issue.problems.join("; ")}`);
      continue;
    }
    const dispositioned = issue.criteria.filter((c) => c.disposition).length;
    out.push(`${head} ${issue.ref}: ${dispositioned}/${issue.criteria.length} criteria dispositioned (from the ${issue.source === "none" ? "issue's absent criteria" : issue.source})`);
    if (issue.nestedFolded > 0) {
      out.push(`    ℹ ${issue.nestedFolded} nested bullet(s) folded into their parent criterion — read as elaboration, not separately dispositioned`);
    }
    if (issue.noStatedCriteria) out.push(`    no-stated-criteria: ${issue.noStatedCriteria}`);
    for (const s of issue.supersedingComments) {
      out.push(`    ⚠ THE BAR MAY HAVE MOVED (#1603): ${issue.ref} carries a comment with its own acceptance list — ${s.bullets} bullet(s) under "${s.heading}" — at ${s.url}`);
      out.push(`        The ${issue.criteria.length} criteria graded above come from the issue BODY and nothing else. ${SUPERSEDING_CONVENTION}`);
    }
    for (const p of issue.problems) out.push(`    ✗ ${p}`);
    for (const c of issue.criteria) {
      const label = c.disposition ? `${c.disposition}` : "—";
      out.push(`    ${c.problems.length === 0 ? "✓" : "✗"} ${issue.issue}.${c.index} [${label}] ${c.text.slice(0, 110)}`);
      for (const p of c.problems) out.push(`        ✗ ${p}`);
    }
  }

  for (const r of report.remainders) {
    const origin = r.original !== undefined ? ` (split out of #${r.original})` : "";
    out.push(`${r.ok ? "✓" : "✗"} remainder #${r.remainder}${origin}`);
    for (const c of r.conditions) {
      const mark = c.status === "pass" ? "✓" : c.status === "fail" ? "✗" : "ℹ";
      out.push(`    ${mark} ${c.name}: ${c.detail}`);
    }
  }

  // The verdict names WHICH gate failed. A dead remainder reported as "a criterion this PR did not
  // account for" sends the reader to the wrong half of the gate.
  const gate1Failed = report.parseErrors.length > 0 || report.issues.some((i) => !i.ok);
  const gate2Failed = report.remainders.some((r) => !r.ok);
  out.push("");
  out.push(report.ok
    ? "✓ every acceptance bullet of every issue this PR closes is mapped, and every remainder is live."
    : `✗ acceptance conservation FAILED — ${[
        gate1Failed ? "an issue would close with a criterion this PR did not account for" : "",
        gate2Failed ? "a deferral points at an issue that is closed or does not exist, which is indistinguishable in outcome from not deferring at all" : "",
      ].filter(Boolean).join("; and ")}.`);
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------
// #1341 — the residual Gate 1 leaves open: it reads PR BODIES, and an issue can close with no PR
// body to read. Two paths, both live in this repo. A BARE CLICK in the UI touches no PR and no
// merge, so nothing runs at all (11 of the last 120 closed issues closed this way, measured
// 2026-07-28; 4 of them opened by a human, #1130 and #1155 with stated criteria and no disposition
// anywhere). The DEVELOPMENT SIDEBAR links a PR to an issue without a closing keyword in the body,
// so the issue closes on merge and the body-reading gate sees nothing to check — the worse of the
// two, because it looks like a normal PR-driven close.
//
// WHERE THE DISPOSITION LIVES FOR A NON-PR CLOSE (the decision #1341 asks to be recorded): an issue
// COMMENT in the same `ACCEPTANCE #<issue>.<n> <disposition>: <detail>` format. It is the only
// venue that exists on every close path — there is no PR on a bare click — it is where the operator
// already reads, and it survives the close, which a PR body archived at merge does not. So this
// check reads ONE surface set: every linked PR's body plus every comment on the issue, and holds
// the union to exactly the rules a PR body is held to. A PR that already carries its dispositions
// therefore passes here unchanged; nothing has to be written twice.

interface ClosedIssueInput {
  issue: number;
  /**
   * Bot-opened issues are the one exemption, and it is disclosed rather than silent: the alert-path
   * drills (#1287) open, comment on and close a tracking issue under the job token, and 7 of the 11
   * bare-click closes measured on 2026-07-28 were exactly that. They are not work items and state no
   * criteria, so holding them to this gate would produce a standing false alarm on machinery whose
   * whole purpose is alarms.
   */
  authorIsBot: boolean;
}

interface ClosedIssueReport {
  issue: number;
  /** Which surfaces supplied a disposition line — named, so a pass says where its evidence came from. */
  contributed: string[];
  surfacesRead: string[];
  /** Set when the gate deliberately did not assess this close. */
  notAssessed?: string;
  report?: AcceptanceReport;
  ok: boolean;
}

export function checkClosedIssue(input: ClosedIssueInput, lookup: IssueLookup, repo?: string, world?: EvidenceWorld): ClosedIssueReport {
  // Both the linked PR bodies and the comments come from the LOOKUP, not from a second field on the
  // input — one collection point is what makes this gate and the PR gate agree BY CONSTRUCTION
  // rather than by two lists being kept in step. Keeping them in step is exactly what failed on
  // 2026-07-30 for the comments (#1562) and again for the linked PRs (#1581).
  const ref: ClosingRef = { number: input.issue, ref: `#${input.issue}` };
  const surfacesRead = venuesOf(ref, lookup).map((v) => v.label);

  if (input.authorIsBot) {
    return { issue: input.issue, contributed: [], surfacesRead, notAssessed: "opened by a bot — a tracking or drill issue, not a work item with acceptance criteria", ok: true };
  }

  const report = checkAcceptance(`Closes #${input.issue}`, lookup, repo, world);
  return { issue: input.issue, contributed: report.venuesContributing, surfacesRead, report, ok: report.ok };
}

export function formatClosedIssue(r: ClosedIssueReport): string {
  const head = `Acceptance conservation on close (#1341) — #${r.issue}`;
  if (r.notAssessed) return `${head}\n\nℹ NOT ASSESSED  ${r.notAssessed}`;
  const where = r.contributed.length > 0
    ? `● Surfaces read: ${r.surfacesRead.join(", ")}.`
    : `○ No disposition record on any of the ${r.surfacesRead.length} surface(s) read${r.surfacesRead.length > 0 ? ` (${r.surfacesRead.join(", ")})` : " — this issue closed with no linked PR and no comments, i.e. a bare click"}.`;
  return `${head}\n\n${where}\n\n${formatAcceptance(r.report!)}`;
}

/**
 * ONE terminal state for a failed close (#1696), decided here so the rule has a failing direction
 * in the suite instead of living as an `if` in the CLI. The gate used to re-open only ONCE — "the
 * label is the memory" — so the terminal state of a failed close depended on whether the label was
 * already present: first failure re-opened (back in the queue), repeat failure stood CLOSED with
 * only the label as a trace, which reads as completed to `gh issue list` and every reader who is
 * not on the issue page. MEASURED 2026-07-31: all 10 issues then carrying `acceptance-unaccounted`
 * closed were in exactly that state, every one still failing the gate when re-run read-only — the
 * standing record had reached nobody, ten out of ten times. The deliberate-human-override concern
 * the once-rule served is priced at one comment line per criterion, so re-opening every time is a
 * fight only with bookkeeping that stays defective.
 */
export function closeActions(ok: boolean, alreadyLabelled: boolean): { comment: boolean; addLabel: boolean; reopen: boolean; removeLabel: boolean } {
  if (!ok) return { comment: true, addLabel: true, reopen: true, removeLabel: false };
  return { comment: false, addLabel: false, reopen: false, removeLabel: alreadyLabelled };
}

/**
 * What the workflow posts on the issue when the check fails. A gate whose failure is a red tick on a
 * branch nobody watches is the alert path #1287 found four of — this one lands where the person who
 * closed the issue will see it, and says the two ways out.
 */
export function closeFailureComment(r: ClosedIssueReport): string {
  return [
    "**Acceptance conservation (#1341): this issue closed with criteria nothing accounted for.**",
    "",
    "```",
    formatClosedIssue(r),
    "```",
    "",
    "Two ways to clear it, both one edit:",
    "",
    `- Comment on this issue with one \`ACCEPTANCE #${r.issue}.<n> <met|split|relayed>: <detail>\` line per criterion, then close it again.`,
    "- Or close it through a PR whose body carries those lines, which Gate 1 already checks.",
    "",
    "Neither is a formality: an issue closed with an unmet criterion is the defect epic #1320 exists to close, and ~60 of 562 closed issues were found in exactly that state on 2026-07-27.",
  ].join("\n");
}

// ---------------------------------------------------------------------------------------------
// Negative controls (#1315/#1316 both require one). A gate that has only ever been seen passing is
// indistinguishable from one that cannot fail — this repo has shipped exactly that twice. Each
// seeder THROWS when it cannot plant its violation, because a seed that silently plants nothing
// followed by a green run is the failure mode the control exists to rule out.

export function seedDropDisposition(body: string): { body: string; dropped: string } {
  const all = lines(body);
  const i = all.map((l) => DISPOSITION_LINE.test(strip(l).trim())).lastIndexOf(true);
  if (i === -1) throw new Error("cannot seed: this body carries no `ACCEPTANCE #<issue>.<n>` disposition line to drop");
  return { body: [...all.slice(0, i), ...all.slice(i + 1)].join("\n"), dropped: all[i]!.trim() };
}

export function seedBareEvidence(body: string): { body: string; replaced: string } {
  const all = lines(body);
  const i = all.findIndex((l) => DISPOSITION_LINE.exec(strip(l).trim())?.[3]?.toLowerCase() === "met");
  if (i === -1) throw new Error("cannot seed: this body carries no `met` disposition whose evidence could be hollowed out");
  const m = DISPOSITION_LINE.exec(strip(all[i]!).trim())!;
  const seeded = [...all];
  seeded[i] = `ACCEPTANCE #${m[1]}.${m[2]} met: done`;
  return { body: seeded.join("\n"), replaced: all[i]!.trim() };
}

export function seedRemainder(body: string, issue: number): string {
  return `${body}\n\nremainder: #${issue}\n`;
}

/**
 * A hermetic scenario for the CI negative control: no network, no live issue state, so the proof
 * that the gate can fail does not depend on the PR that happens to be under test. The vitest suite
 * scores the same scenario, so there is one fixture rather than two that can drift apart.
 */
const said = (...bodies: string[]): IssueComment[] => bodies.map((body, i) => ({ body, url: `https://example.invalid/selftest#comment-${i + 1}` }));

const SELFTEST_ISSUES: IssueRecord[] = [
  {
    number: 9001,
    state: "OPEN",
    body: [
      "A synthetic issue used only by the acceptance gate's own negative control.",
      "",
      "## Acceptance",
      "- The parser reads criteria out of an `## Acceptance` section.",
      "  - a nested bullet, which is elaboration and not its own criterion",
      "- A remainder reference is checked on all three conditions.",
      "- The operator is asked rather than the issue being closed on a blocker.",
    ].join("\n"),
    comments: said("Split the second criterion out to #9002.", "Operator: should the gate read commit messages as well as the PR body?"),
  },
  { number: 9002, state: "OPEN", body: "Remainder of #9001.", comments: [] },
  { number: 9003, state: "CLOSED", body: "A closed issue, for the Gate 2 control.", comments: [] },
  {
    // The section-truncation control. A standalone bold line used to END the acceptance section, so
    // this issue parsed as ONE criterion and the last two vanished with nothing reported — silent
    // omission inside the gate whose whole subject is silent omission.
    number: 9004,
    state: "OPEN",
    body: ["## Acceptance", "- one", "", "**This one matters.**", "", "- two", "- three"].join("\n"),
    comments: [],
  },
  {
    // The VENUE-PARITY control (#1562): an issue whose dispositions are ALSO recorded as comments.
    // A PR body repeating them maps every criterion twice, which is the #1517/#1519 shape — and the
    // PR-level check used to pass it because it read one venue.
    number: 9005,
    state: "OPEN",
    body: ["## Acceptance", "- the gate reads the same venues on both paths", "- a duplicate disposition names both venues"].join("\n"),
    comments: said(
      "ACCEPTANCE #9005.1 met: `pnpm exec vitest run src/acceptance-conservation.test.ts` — all green",
      "ACCEPTANCE #9005.2 met: src/acceptance-conservation.ts now names both venues",
    ),
  },
  {
    // The TWO-LINKED-PR control (#1581): the same venue divergence one field over. The close path
    // read every linked PR body and the PR path read none of them, so an issue closed by two PRs
    // that both disposition it passed at merge time and failed at close time.
    number: 9006,
    state: "OPEN",
    body: ["## Acceptance", "- both gates read every linked PR body", "- neither reads the PR under test twice"].join("\n"),
    comments: [],
    linkedPrs: [
      { ref: "#9200", body: "refs #9006\n\nACCEPTANCE #9006.1 met: src/acceptance-conservation.ts collects venues in one place\nACCEPTANCE #9006.2 met: src/acceptance-conservation.test.ts covers the two-PR arrangement" },
      { ref: "#9201", body: "refs #9006\n\nACCEPTANCE #9006.1 met: src/acceptance-conservation.ts collects venues in one place\nACCEPTANCE #9006.2 met: src/acceptance-conservation.test.ts covers the two-PR arrangement" },
    ],
  },
];

export const SELFTEST_BODY = [
  "Closes #9001",
  "",
  "ACCEPTANCE #9001.1 met: `pnpm exec vitest run src/acceptance-conservation.test.ts` — all green",
  "ACCEPTANCE #9001.2 split: #9002",
  "ACCEPTANCE #9001.3 relayed: asked on the issue — should the gate read commit messages too?",
].join("\n");

// Hand-written violating bodies, one per rule, kept literal rather than derived: a seeder that
// mutates SELFTEST_BODY can only plant what SELFTEST_BODY already contains, and these two rules are
// about text the healthy body deliberately does not contain.
const SELFTEST_HEX_PROSE_BODY = [
  "Closes #9001",
  "",
  // "defaced" is seven letters drawn from [a-f]; the sha shape used to read it as a commit.
  "ACCEPTANCE #9001.1 met: defaced accede facade nonsense words",
  "ACCEPTANCE #9001.2 split: #9002",
  "ACCEPTANCE #9001.3 relayed: asked on the issue — should the gate read commit messages too?",
].join("\n");

const SELFTEST_TRUNCATED_SECTION_BODY = [
  "Closes #9004",
  "",
  "ACCEPTANCE #9004.1 met: `pnpm exec vitest run src/acceptance-conservation.test.ts` — all green",
].join("\n");

export const SELFTEST_LOOKUP: IssueLookup = (n, repo) => (repo ? undefined : SELFTEST_ISSUES.find((i) => i.number === n));

/**
 * A STUB checkout, so the two truth checks are exercised by CI's hermetic control without the
 * scenario depending on the working tree. A world built from the real repo would make the control's
 * verdict move whenever a file or a script was renamed.
 */
export const SELFTEST_WORLD: EvidenceWorld = {
  topLevelEntries: new Set(["src"]),
  pathExists: (p) => p === "src/acceptance-conservation.ts" || p === "src/acceptance-conservation.test.ts",
  scripts: new Set(["verify"]),
  testNames: new Set(["a dropped disposition leaves an UNMAPPED bullet"]),
};

const SELFTEST_INVENTED_PATH_BODY = [
  "Closes #9001",
  "",
  "ACCEPTANCE #9001.1 met: src/definitely-not-here.ts:40 now throws",
  "ACCEPTANCE #9001.2 split: #9002",
  "ACCEPTANCE #9001.3 relayed: asked on the issue — should the gate read commit messages too?",
].join("\n");

const SELFTEST_INVENTED_SCRIPT_BODY = [
  "Closes #9001",
  "",
  "ACCEPTANCE #9001.1 met: `pnpm validate-everything` — 25 files, 0 failures",
  "ACCEPTANCE #9001.2 split: #9002",
  "ACCEPTANCE #9001.3 relayed: asked on the issue — should the gate read commit messages too?",
].join("\n");

const SELFTEST_DOUBLE_VENUE_BODY = [
  "Closes #9005",
  "",
  "ACCEPTANCE #9005.1 met: `pnpm exec vitest run src/acceptance-conservation.test.ts` — all green",
  "ACCEPTANCE #9005.2 met: src/acceptance-conservation.ts now names both venues",
].join("\n");

// The Development sidebar: GitHub records the close, the body says nothing, and a body-only gate
// green-no-ops on a PR that WILL close #9001 on merge.
const SELFTEST_SIDEBAR_BODY = "Refactors the seeder. refs #9001\n";

interface SelftestCase {
  name: string;
  body: string;
  extras?: AcceptanceExtras;
  expect: "pass" | "fail";
}

interface CloseSelftestCase {
  name: string;
  input: ClosedIssueInput;
  /** Per-case, because the issue's COMMENTS are one of the venues under test. */
  lookup: IssueLookup;
  expect: "pass" | "fail";
}

/**
 * #1341's negative control, one case per close path in both directions. Hermetic, like the PR-body
 * one above: it needs no network and no live issue state, so a green CI run means "this gate passed
 * AND it can still fail" on a workflow run that had no failing close to look at.
 */
export function closeSelftestCases(): CloseSelftestCase[] {
  const dispositions = [
    "ACCEPTANCE #9001.1 met: `pnpm exec vitest run src/acceptance-conservation.test.ts` — all green",
    "ACCEPTANCE #9001.2 split: #9002",
    "ACCEPTANCE #9001.3 relayed: asked on the issue — should the gate read commit messages too?",
  ];
  const base = { issue: 9001, authorIsBot: false };
  // Appends to #9001's own prose comments, which is how a real issue looks — and keeps the `relayed`
  // criterion's question comment in place, so this fixture does not pass for the wrong reason. The
  // linked PRs go on the LOOKUP too (#1581): the input carries the issue, never the venue set.
  const venues = (extra: string[], linkedPrs?: { ref: string; body: string }[]): IssueLookup => (n, repo) => {
    const record = SELFTEST_LOOKUP(n, repo);
    return record !== undefined && n === 9001 ? { ...record, comments: [...record.comments, ...said(...extra)], linkedPrs } : record;
  };
  const commented = (extra: string[]): IssueLookup => venues(extra);
  return [
    { name: "BARE CLICK, no disposition anywhere — the #743 shape", input: { ...base }, lookup: SELFTEST_LOOKUP, expect: "fail" },
    { name: "BARE CLICK with the dispositions recorded as issue comments", input: { ...base }, lookup: commented(dispositions), expect: "pass" },
    {
      name: "DEVELOPMENT SIDEBAR — a linked PR whose body carries no closing keyword and no dispositions",
      input: { ...base },
      lookup: venues([], [{ ref: "#9100", body: "Refactors the seeder. refs #9001" }]),
      expect: "fail",
    },
    {
      name: "DEVELOPMENT SIDEBAR with the dispositions in the linked PR's body",
      input: { ...base },
      lookup: venues([], [{ ref: "#9100", body: `Refactors the seeder. refs #9001\n\n${dispositions.join("\n")}` }]),
      expect: "pass",
    },
    {
      name: "a partial record — one criterion mapped, two left unaccounted",
      input: { ...base },
      lookup: commented([dispositions[0]!]),
      expect: "fail",
    },
    {
      name: "a `met` hollowed out to a bare assertion in an issue comment",
      input: { ...base },
      lookup: commented(["ACCEPTANCE #9001.1 met: done", ...dispositions.slice(1)]),
      expect: "fail",
    },
    {
      // VENUE PARITY, close side (#1562): the same lines in the linked PR AND in a comment. It has
      // always failed here — the PR-level twin below is the case that used to pass.
      name: "the same dispositions in BOTH the linked PR body and an issue comment",
      input: { ...base },
      lookup: venues(dispositions, [{ ref: "#9100", body: `refs #9001\n\n${dispositions.join("\n")}` }]),
      expect: "fail",
    },
    {
      // #1696's likely input: `met —` instead of `met:`. #1645 gave it a distinct malformed-line
      // diagnostic naming the exact line; this case keeps the CLOSE path FAILING on it, so a later
      // decision to normalise the separator is a deliberate fixture edit, never a silent pass.
      name: "a near-miss separator — `met —` instead of `met:` in an issue comment",
      input: { ...base },
      lookup: commented([
        "ACCEPTANCE #9001.1 met — `pnpm exec vitest run src/acceptance-conservation.test.ts` — all green",
        ...dispositions.slice(1),
      ]),
      expect: "fail",
    },
    { name: "a bot-opened tracking issue is not assessed", input: { ...base, authorIsBot: true }, lookup: SELFTEST_LOOKUP, expect: "pass" },
  ];
}

export function selftestCases(): SelftestCase[] {
  return [
    { name: "the healthy body passes", body: SELFTEST_BODY, expect: "pass" },
    { name: "the same dispositions in the PR body AND an issue comment — the #1517/#1519 shape", body: SELFTEST_DOUBLE_VENUE_BODY, expect: "fail" },
    { name: "a Development-sidebar close GitHub records and the body does not mention", body: SELFTEST_SIDEBAR_BODY, extras: { linkedCloses: [{ number: 9001, ref: "#9001" }] }, expect: "fail" },
    { name: "an issue closed by TWO linked PRs that both disposition it — the #1581 shape", body: "Closes #9006\n", expect: "fail" },
    { name: "a dropped disposition leaves a bullet unmapped", body: seedDropDisposition(SELFTEST_BODY).body, expect: "fail" },
    { name: "a `met` hollowed out to a bare assertion", body: seedBareEvidence(SELFTEST_BODY).body, expect: "fail" },
    { name: "a remainder pointing at a CLOSED issue", body: seedRemainder(SELFTEST_BODY, 9003), expect: "fail" },
    { name: "a remainder pointing at an issue that does not exist", body: seedRemainder(SELFTEST_BODY, 9999), expect: "fail" },
    { name: "a `met` whose only sha-shaped evidence is English words spelt in hex letters", body: SELFTEST_HEX_PROSE_BODY, expect: "fail" },
    { name: "an acceptance section whose bullets sit below a standalone bold line", body: SELFTEST_TRUNCATED_SECTION_BODY, expect: "fail" },
    { name: "a `met` citing a repo path that does not exist", body: SELFTEST_INVENTED_PATH_BODY, expect: "fail" },
    { name: "a `met` citing a `pnpm` script that is not in package.json", body: SELFTEST_INVENTED_SCRIPT_BODY, expect: "fail" },
  ];
}
