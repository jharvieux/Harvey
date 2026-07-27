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
// Two deliberate, disclosed bounds. (1) Only bullets at the SHALLOWEST indent of the acceptance
// section are criteria; deeper bullets read as elaboration and are counted and reported, not
// silently dropped. (2) The evidence check proves the SHAPE of evidence, not its truth — it can
// tell "done" from "`pnpm verify` — 25 files, 0 failures", and it cannot tell a real command from
// an invented one. It raises the floor; it is not a reviewer.

type Disposition = "met" | "split" | "relayed";

interface Criterion {
  /** 1-based, in order of appearance — the index a disposition line names. */
  index: number;
  text: string;
}

export interface IssueRecord {
  number: number;
  state: "OPEN" | "CLOSED";
  body: string;
  comments: string[];
}

/** `undefined` means the issue DOES NOT EXIST. A fetch that merely failed must never reach here. */
export type IssueLookup = (issue: number) => IssueRecord | undefined;

interface DispositionLine {
  issue: number;
  index: number;
  disposition: Disposition;
  detail: string;
  line: number;
}

interface NoCriteriaLine {
  issue: number;
  bar: string;
  line: number;
}

interface RemainderRef {
  remainder: number;
  /** The issue the work was split OUT OF, when the reference is a `split` disposition. */
  original?: number;
  line: number;
}

interface ParsedBody {
  closes: number[];
  /** Closing references this gate cannot resolve with a repo-scoped lookup. Disclosed, not dropped. */
  unresolvableCloses: string[];
  dispositions: DispositionLine[];
  noCriteria: NoCriteriaLine[];
  remainders: RemainderRef[];
  parseErrors: string[];
}

const DECORATION = /^[\s>|*+-]*(?:\[[ xX]\]\s*)?/;
const HEADING = /^#{1,6}\s+(.*?)\s*$/;
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

function headingText(line: string): string | undefined {
  return HEADING.exec(line)?.[1] ?? BOLD_HEADING.exec(line)?.[1];
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
  let end = all.length;
  for (let i = 0; i < all.length; i++) {
    const heading = headingText(all[i]!);
    if (heading === undefined) continue;
    if (start === -1) {
      if (ACCEPTANCE_HEADING.test(heading)) start = i + 1;
    } else {
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

export function parseBody(prBody: string, repo?: string): ParsedBody {
  const closes: number[] = [];
  const unresolvableCloses: string[] = [];
  for (const m of prBody.matchAll(CLOSING)) {
    const ref = m.groups!.ref!;
    const bare = /^#(\d+)$/.exec(ref);
    const scoped = repo ? new RegExp(`^${repo.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}#(\\d+)$`, "i").exec(ref) : null;
    if (bare) closes.push(Number(bare[1]));
    else if (scoped) closes.push(Number(scoped[1]));
    else unresolvableCloses.push(ref);
  }

  const dispositions: DispositionLine[] = [];
  const noCriteria: NoCriteriaLine[] = [];
  const remainders: RemainderRef[] = [];
  const parseErrors: string[] = [];

  lines(prBody).forEach((raw, i) => {
    const line = strip(raw).trim();
    const d = DISPOSITION_LINE.exec(line);
    if (d) {
      dispositions.push({
        issue: Number(d[1]),
        index: Number(d[2]),
        disposition: d[3]!.toLowerCase() as Disposition,
        detail: d[4]!.trim(),
        line: i + 1,
      });
      return;
    }
    const n = NO_CRITERIA_LINE.exec(line);
    if (n) {
      noCriteria.push({ issue: Number(n[1]), bar: n[2]!.trim(), line: i + 1 });
      return;
    }
    // A line that names an issue NUMBER and parses as neither is MALFORMED, not absent. Dropping it
    // silently is how a typo'd disposition becomes an unmapped bullet nobody sees. The `#\d` is what
    // separates a real attempt from the `#<issue>` placeholders in .github/pull_request_template.md,
    // which survive in the raw body GitHub hands back even though the reader never sees them.
    if (/^ACCEPTANCE\s+#\d/i.test(line)) {
      parseErrors.push(`line ${i + 1}: malformed ACCEPTANCE line — expected \`ACCEPTANCE #<issue>.<n> <met|split|relayed>: <detail>\` or \`ACCEPTANCE #<issue> no-stated-criteria: <bar>\`, got: ${line}`);
      return;
    }
    const r = REMAINDER_LINE.exec(line);
    if (r) remainders.push({ remainder: Number(r[1]), line: i + 1 });
  });

  for (const d of dispositions.filter((x) => x.disposition === "split")) {
    const target = /#(\d+)/.exec(d.detail);
    if (target) remainders.push({ remainder: Number(target[1]), original: d.issue, line: d.line });
  }

  return { closes: [...new Set(closes)], unresolvableCloses, dispositions, noCriteria, remainders, parseErrors };
}

// A bare "done" is an unmapped bullet wearing a disposition (#1315). These are the shapes that
// carry something a reader can go and check; the list is a floor, not a judgement of truth.
const EVIDENCE_SHAPES: { name: string; re: RegExp }[] = [
  { name: "a backticked command or output", re: /`[^`]{4,}`/ },
  { name: "a command", re: /\b(?:pnpm|npm|npx|node|tsx|vitest|git|gh|semgrep|docker|make|curl|psql)\s+\S/ },
  { name: "a file path", re: /[\w./-]+\.(?:ts|tsx|js|mjs|cjs|json|md|ya?ml|sql|sh|py|toml)(?::\d+)?/ },
  { name: "a quoted test name", re: /"[^"]{8,}"/ },
  { name: "a commit sha", re: /\b[0-9a-f]{7,40}\b/ },
];

const BARE_ASSERTION = /^(?:done|yes|ok|okay|completed?|verified|works?|fixed|met|n\/a|na|as stated|as described|implemented|shipped|true)\b[.!]*$/i;

export function evidenceProblems(detail: string): string[] {
  const text = detail.trim();
  if (BARE_ASSERTION.test(text)) return [`\`met\` carries a bare assertion ("${text}"), which is an unmapped bullet with a label on it — name the command run and its output, the test, or the file:line`];
  if (text.length < 12) return [`\`met\` evidence is ${text.length} characters — too short to point at anything`];
  if (!EVIDENCE_SHAPES.some((s) => s.re.test(text))) {
    return [`\`met\` evidence names none of: ${EVIDENCE_SHAPES.map((s) => s.name).join(", ")}. An assertion is not evidence`];
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
  exists: boolean;
  criteria: CriterionVerdict[];
  nestedFolded: number;
  source: ParsedCriteria["source"];
  noStatedCriteria?: string;
  problems: string[];
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
  closes: number[];
  unresolvableCloses: string[];
  issues: IssueVerdict[];
  remainders: RemainderVerdict[];
  parseErrors: string[];
  /** True when the PR carries neither a closing keyword nor a remainder — the gate's green no-op. */
  noop: boolean;
  ok: boolean;
}

const mentions = (record: IssueRecord | undefined, issue: number): boolean =>
  record !== undefined && new RegExp(`#${issue}\\b`).test([record.body, ...record.comments].join("\n"));

function checkRemainder(ref: RemainderRef, lookup: IssueLookup, closes: number[]): RemainderVerdict {
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
  const originals = ref.original !== undefined ? [ref.original] : closes;
  if (originals.length === 0) {
    conditions.push({ name: "cross-linked", status: "not-assessed", detail: "this PR closes no issue, so there is no original to cross-link from" });
  } else {
    const linked = originals.filter((o) => mentions(lookup(o), ref.remainder));
    conditions.push(linked.length > 0
      ? { name: "cross-linked", status: "pass", detail: `#${linked.join(", #")} references #${ref.remainder}` }
      : { name: "cross-linked", status: "fail", detail: `none of #${originals.join(", #")} references #${ref.remainder} in its body or comments — comment the cross-link on the original so the deferral is discoverable from the issue, not only from this PR` });
  }

  return { remainder: ref.remainder, original: ref.original, conditions, ok: conditions.every((c) => c.status !== "fail") };
}

function checkIssue(issue: number, parsed: ParsedBody, lookup: IssueLookup): IssueVerdict {
  const record = lookup(issue);
  if (!record) {
    return { issue, exists: false, criteria: [], nestedFolded: 0, source: "none", problems: [`#${issue} does not exist — a closing keyword pointing at nothing`], ok: false };
  }

  const { criteria, nestedFolded, source } = parseAcceptanceCriteria(record.body);
  const declaredNone = parsed.noCriteria.find((n) => n.issue === issue);
  const problems: string[] = [];

  if (criteria.length === 0) {
    if (!declaredNone) {
      problems.push(`#${issue} states no acceptance criteria (no \`## Acceptance\` section, no checklist) and this PR body declares no bar. An issue with no criteria is where closing-with-unmet-criteria is EASIEST, so it is not a silent pass — add \`ACCEPTANCE #${issue} no-stated-criteria: <what the bar was>\``);
    } else if (declaredNone.bar.trim().length < 12) {
      problems.push(`#${issue} no-stated-criteria names a bar of ${declaredNone.bar.trim().length} characters — say what the bar actually was`);
    }
    return { issue, exists: true, criteria: [], nestedFolded, source, noStatedCriteria: declaredNone?.bar, problems, ok: problems.length === 0 };
  }

  if (declaredNone) {
    problems.push(`#${issue} declares \`no-stated-criteria\` but the issue states ${criteria.length} — the escape hatch is for issues that have none`);
  }

  const mine = parsed.dispositions.filter((d) => d.issue === issue);
  for (const d of mine.filter((d) => d.index < 1 || d.index > criteria.length)) {
    problems.push(`line ${d.line}: disposition names criterion #${issue}.${d.index}, but #${issue} states ${criteria.length}`);
  }

  const verdicts = criteria.map((c): CriterionVerdict => {
    const matched = mine.filter((d) => d.index === c.index);
    if (matched.length === 0) {
      return { ...c, problems: [`UNMAPPED — no disposition. Add \`ACCEPTANCE #${issue}.${c.index} <met|split|relayed>: <detail>\``] };
    }
    if (matched.length > 1) {
      return { ...c, problems: [`mapped ${matched.length} times (lines ${matched.map((m) => m.line).join(", ")}) — a criterion takes exactly one disposition`] };
    }
    const d = matched[0]!;
    const verdict: CriterionVerdict = { ...c, disposition: d.disposition, detail: d.detail, problems: [] };
    if (d.disposition === "met") verdict.problems.push(...evidenceProblems(d.detail));
    if (d.disposition === "split" && !/#\d+/.test(d.detail)) {
      verdict.problems.push("`split` names no remainder issue — a split with no live remainder is a deletion (#1316)");
    }
    if (d.disposition === "relayed") {
      // The question has to be ON THE ISSUE, not in the PR body: a PR body is archived at merge and
      // the operator does not read it, so a question recorded only there is a question nobody was
      // asked. Mechanically this proves a question was recorded, not that it is the RIGHT one.
      const asked = record.comments.some((c) => c.includes("?"));
      if (!asked) verdict.problems.push(`\`relayed\` but #${issue} carries no comment containing a question — record the question ON THE ISSUE, where the operator reads it, not in this PR body`);
    }
    return verdict;
  });

  const ok = problems.length === 0 && verdicts.every((v) => v.problems.length === 0);
  return { issue, exists: true, criteria: verdicts, nestedFolded, source, problems, ok };
}

export function checkAcceptance(prBody: string, lookup: IssueLookup, repo?: string): AcceptanceReport {
  const parsed = parseBody(prBody, repo);
  const noop = parsed.closes.length === 0 && parsed.remainders.length === 0 && parsed.unresolvableCloses.length === 0;
  const issues = parsed.closes.map((n) => checkIssue(n, parsed, lookup));
  const remainders = parsed.remainders.map((r) => checkRemainder(r, lookup, parsed.closes));
  const ok = parsed.parseErrors.length === 0 && issues.every((i) => i.ok) && remainders.every((r) => r.ok);
  return { closes: parsed.closes, unresolvableCloses: parsed.unresolvableCloses, issues, remainders, parseErrors: parsed.parseErrors, noop, ok };
}

export function formatAcceptance(report: AcceptanceReport): string {
  const out: string[] = [];
  if (report.noop) {
    return "✓ no closing keyword and no `remainder:` line in this PR body — nothing closes, so there are no criteria to conserve.";
  }

  for (const e of report.parseErrors) out.push(`✗ ${e}`);

  // Named, counted, and non-fatal: a cross-repo or URL-form closing reference cannot be resolved by
  // a repo-scoped lookup, and an unstated limitation reads as a clean bill of health.
  for (const ref of report.unresolvableCloses) {
    out.push(`ℹ NOT ASSESSED  closing reference \`${ref}\` — this gate resolves \`#N\` in this repo only. Its criteria are unchecked.`);
  }

  for (const issue of report.issues) {
    const head = issue.ok ? "✓" : "✗";
    if (!issue.exists) {
      out.push(`${head} #${issue.issue}: ${issue.problems.join("; ")}`);
      continue;
    }
    const dispositioned = issue.criteria.filter((c) => c.disposition).length;
    out.push(`${head} #${issue.issue}: ${dispositioned}/${issue.criteria.length} criteria dispositioned (from the ${issue.source === "none" ? "issue's absent criteria" : issue.source})`);
    if (issue.nestedFolded > 0) {
      out.push(`    ℹ ${issue.nestedFolded} nested bullet(s) folded into their parent criterion — read as elaboration, not separately dispositioned`);
    }
    if (issue.noStatedCriteria) out.push(`    no-stated-criteria: ${issue.noStatedCriteria}`);
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

  out.push("");
  out.push(report.ok
    ? "✓ every acceptance bullet of every issue this PR closes is mapped, and every remainder is live."
    : "✗ acceptance conservation FAILED — an issue would close with a criterion this PR did not account for.");
  return out.join("\n");
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
    comments: ["Split the second criterion out to #9002.", "Operator: should the gate read commit messages as well as the PR body?"],
  },
  { number: 9002, state: "OPEN", body: "Remainder of #9001.", comments: [] },
  { number: 9003, state: "CLOSED", body: "A closed issue, for the Gate 2 control.", comments: [] },
];

export const SELFTEST_BODY = [
  "Closes #9001",
  "",
  "ACCEPTANCE #9001.1 met: `pnpm exec vitest run src/acceptance-conservation.test.ts` — all green",
  "ACCEPTANCE #9001.2 split: #9002",
  "ACCEPTANCE #9001.3 relayed: asked on the issue — should the gate read commit messages too?",
].join("\n");

export const SELFTEST_LOOKUP: IssueLookup = (n) => SELFTEST_ISSUES.find((i) => i.number === n);

interface SelftestCase {
  name: string;
  body: string;
  expect: "pass" | "fail";
}

export function selftestCases(): SelftestCase[] {
  return [
    { name: "the healthy body passes", body: SELFTEST_BODY, expect: "pass" },
    { name: "a dropped disposition leaves a bullet unmapped", body: seedDropDisposition(SELFTEST_BODY).body, expect: "fail" },
    { name: "a `met` hollowed out to a bare assertion", body: seedBareEvidence(SELFTEST_BODY).body, expect: "fail" },
    { name: "a remainder pointing at a CLOSED issue", body: seedRemainder(SELFTEST_BODY, 9003), expect: "fail" },
    { name: "a remainder pointing at an issue that does not exist", body: seedRemainder(SELFTEST_BODY, 9999), expect: "fail" },
  ];
}
