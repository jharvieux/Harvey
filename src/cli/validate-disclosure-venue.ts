// pnpm exec tsx src/cli/validate-disclosure-venue.ts [--list] [--seed-violation]
//
// Gate 4 of the #1320 prevention program (#1317). A semgrep rule whose comments declare a bound
// must state that bound in its own `message` — the only text in a rule that reaches the client's
// deliverable. A bound that lives only in the YAML is, from the client's side, an unstated
// limitation, and an unstated limitation reads as a clean bill of health.
//
// --list       prints every rule with a recorded bound, passing or not, so the population the gate
//              is judging is visible rather than inferred from a violation count of zero.
// --seed-violation  the negative control: appends a synthetic bounded rule with a bound-free
//              message to the parsed set. It MUST exit non-zero. A gate only ever seen passing is
//              indistinguishable from one that cannot fail (#350/#1065).
// --seed-dead-arm   the same, for the #1665 half: appends the pre-#1657 harvey-ldap-injection shape
//              (one block-level focus over a four-arm disjunction) and MUST exit non-zero.
//
// The gate's own scope, and the 4b half that is not built, are stated in src/disclosure-venue.ts.

import "./sync-stdio.js";
import {
  BOUND_MARKERS,
  BOUND_TRIAGE,
  RULES_DIR,
  auditDisclosureVenue,
  boundTriageSourceProblems,
  boundedRatchet,
  commentBounds,
  loadSemgrepRuleFiles,
  loadSemgrepRules,
  residualBoundish,
  tsDetectorFilesRead,
  unattributedBounds,
  type SemgrepRule,
} from "../disclosure-venue.js";
import { auditRuleReach, unreachedMessageTokens } from "../rule-claim-reach.js";
import { recordMeasured } from "../ci-liveness.js";

// #1665's negative control, and the defect it reconstructs: harvey-ldap-injection as it stood before
// #1657, where one block-level `focus-metavariable: $OPTS` sat over four arms and only `search`
// bound it — so bind/compare/modify matched nothing while the message enumerated all four.
const SEEDED_DEAD_ARM_DOC = `rules:
  - id: harvey-seeded-dead-arm
    message: >
      A seeded finding whose message enumerates four call sites its patterns do not all reach.
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $C.search($BASE, $OPTS, ...)
              - pattern: $C.bind($DN, ...)
              - pattern: $C.modify($DN, $CHANGE, ...)
          - focus-metavariable: $OPTS
`;

// One seed per way the gate can fail. Seeding only the first would leave the correspondence half
// unproven — a gate whose second branch has never been seen firing is a gate with one branch.
//
// The second seed is shaped like a REAL rule message on purpose: a descriptive half that reuses
// the comment's vocabulary, then a contentless sticker where the disclosure belongs. A one-sentence
// descriptive half made that seed weaker than the population it guards — measured 2026-07-27, the
// contentless sticker substituted on all 13 committed bounded rules still PASSED on 9 of them,
// because a word in the descriptive half supplied the overlap. This seed fails only because
// correspondence is now tested against the scope sentence alone.
export const SEEDED_RULES: readonly SemgrepRule[] = [
  {
    file: `${RULES_DIR}/__seeded__.yml`,
    id: "harvey-seeded-no-scope-sentence",
    line: 1,
    comments: [{ line: 1, text: "NOTE: this rule does not cover the interpolated form." }],
    message: "A seeded finding whose message says nothing about what it did not look at.",
  },
  {
    file: `${RULES_DIR}/__seeded__.yml`,
    id: "harvey-seeded-unrelated-scope-sentence",
    line: 2,
    comments: [{ line: 2, text: "NOTE: this rule does not cover the interpolated form." }],
    message:
      "A seeded finding: an interpolated value reaches the sink on this line, so the string it builds" +
      " is attacker-controlled at runtime. SCOPE OF THIS CHECK: nothing worth naming.",
  },
];

function main(): void {
  const seed = process.argv.includes("--seed-violation");
  const rules = [...loadSemgrepRules(), ...(seed ? SEEDED_RULES : [])];
  const bounded = rules.filter((r) => commentBounds(r).length > 0);
  const violations = auditDisclosureVenue(rules);
  const residual = residualBoundish(rules).map((r) => r.id);

  // Bare number only, so the recorded reason in src/disclosure-venue.ts has a falsifier that exits
  // 0 exactly when the vocabulary's residual reaches zero.
  if (process.argv.includes("--residual-count")) {
    console.log(residual.length);
    return;
  }

  // #1714. Bare number, for the same reason: the recorded blocker in src/disclosure-venue.ts says a
  // TS/AST detector's bound comments are read by no gate, so its falsifier reads THIS — the count of
  // TS detector sources on the gate's own scan surface — instead of the population of such comments.
  if (process.argv.includes("--ts-detector-surface")) {
    console.log(tsDetectorFilesRead(loadSemgrepRuleFiles()).length);
    return;
  }

  console.log(`Disclosure venue (gate 4, #1317) — ${RULES_DIR}`);
  console.log(`  rules scanned:            ${rules.length}`);
  console.log(`  with a recorded bound:    ${bounded.length}`);
  console.log(`  bound stated in message:  ${bounded.length - violations.length}`);
  console.log(`  bound comment-only:       ${violations.length}`);
  if (seed) console.log(`  (--seed-violation: ${SEEDED_RULES.length} synthetic bounded rules appended; both must appear below)`);

  // #1342 criterion 4: what this gate does NOT judge, counted and named rather than left silent.
  const unattributed = unattributedBounds(rules, loadSemgrepRuleFiles());
  console.log(`\nNOT ASSESSED BY THIS GATE, so its silence above is not read as coverage:`);
  console.log(
    `  comment lines belonging to no rule: ${unattributed.unattributed} of ${unattributed.commentLines}` +
      ` — file headers and the shared YAML anchor blocks. ${unattributed.bearing.length} carry a bound marker:`,
  );
  for (const b of unattributed.bearing) console.log(`    ${b.file}:${b.line}  ${b.text}`);
  console.log(
    `  A bound on a shared anchor applies to every rule using it, and a per-rule gate cannot attribute it` +
      `\n  to anyone. Counted here instead of propagated: one line on *request_source would make ~20 rules` +
      `\n  bounded on the anchor's wording rather than their own, which is a worse disclosure, not a better one.`,
  );
  console.log(`  rules carrying bound-ish prose outside the marker vocabulary: ${residual.length}, each triaged:`);
  console.log(
    `  BOUND — RESIDUAL VOCABULARY: this count is derived only from the fixed RESIDUAL_MARKERS` +
      ` vocabulary. It is a lower bound on bound-ish prose, not a census of every residual rule.`,
  );
  console.log(
    `  BOUND — TRIAGE CONTENT: each disposition must quote a verbatim source excerpt, proving the` +
      ` source was located. The gate cannot prove the interpretation is correct; it proves noticed` +
      ` and source-linked, not read correctly.`,
  );
  for (const t of BOUND_TRIAGE) console.log(`    ${t.id}: source "${t.sourceExcerpt}" — ${t.disposition}`);

  if (process.argv.includes("--list")) {
    console.log("\nRules carrying a recorded bound:");
    for (const r of bounded) {
      const ok = violations.some((v) => v.id === r.id && v.file === r.file) ? "COMMENT-ONLY" : "in message  ";
      console.log(`  ${ok}  ${r.id}  (${r.file}:${r.line})`);
    }
  }

  const untriaged = residual.filter((id) => !BOUND_TRIAGE.some((t) => t.id === id));
  const stale = BOUND_TRIAGE.filter((t) => !residual.includes(t.id)).map((t) => t.id);
  const sourceProblems = boundTriageSourceProblems(rules);
  if (untriaged.length > 0 || stale.length > 0 || sourceProblems.length > 0) {
    if (untriaged.length > 0) {
      console.error(
        `\n✗ ${untriaged.length} rule(s) carry bound-ish prose this gate's vocabulary cannot see and have no` +
          `\n  recorded disposition: ${untriaged.join(", ")}` +
          `\n  Read each against the source and add it to BOUND_TRIAGE — either "genuine bound, scope sentence` +
          `\n  written" or "pattern mechanics, and why". An unread one is indistinguishable from an unnoticed one.`,
      );
    }
    if (stale.length > 0) {
      console.error(`\n✗ ${stale.length} BOUND_TRIAGE entr(ies) no longer match a residual rule: ${stale.join(", ")}`);
    }
    if (sourceProblems.length > 0) {
      console.error(`\n✗ ${sourceProblems.length} BOUND_TRIAGE source citation(s) do not match the rule comments:`);
      for (const problem of sourceProblems) console.error(`  ${problem}`);
    }
    process.exit(1);
  }

  // The deletion vector (#1330): a rule that HAD a recorded bound and still exists must still have
  // one. Deleting the comment is the cheapest way to make the check above green.
  const lostBounds = boundedRatchet(rules);
  if (lostBounds.length > 0) {
    console.error(
      `\n✗ ${lostBounds.length} rule(s) recorded a bound in BOUNDED_RULES, still exist, and no longer declare one:` +
        `\n  ${lostBounds.join(", ")}` +
        `\n  Deleting the comment is not a fix — it moves the limitation from an unread venue to no venue at all.` +
        `\n  If the rule genuinely no longer has that bound, remove it from BOUNDED_RULES in the same commit and` +
        `\n  say why in the PR body.`,
    );
    process.exit(1);
  }

  if (violations.length > 0) {
    console.error(
      `\n✗ ${violations.length} rule(s) declare a bound in a comment and never state it in the finding they emit.`,
    );
    for (const v of violations) {
      console.error(`\n  ${v.id}  ${v.file}:${v.line}  (${v.verdict})`);
      for (const h of v.hits) console.error(`    [${h.marker}] line ${h.line}: ${h.text}`);
    }
    console.error(
      "\nFix by writing the bound into the rule's own `message` — the shape #1256 used for harvey-redos-literal:" +
        "\n  a SCOPE sentence naming what the rule does NOT assess, so its silence elsewhere is not read as a" +
        "\n  clean bill of health. Deleting the comment is not a fix; it moves the limitation from an unread" +
        "\n  venue to no venue at all.",
    );
    process.exit(1);
  }

  // #1665, the other direction: gate 4 above asks whether a bound in the COMMENTS reached the
  // message. This asks whether a capability the MESSAGE advertises is reachable by the patterns —
  // the direction that reaches the client, because it over-claims rather than under-claims.
  const ruleFiles = new Map(loadSemgrepRuleFiles());
  if (process.argv.includes("--seed-dead-arm")) ruleFiles.set(`${RULES_DIR}/__seeded__.yml`, SEEDED_DEAD_ARM_DOC);
  const reach = auditRuleReach(ruleFiles);
  const unreachedTokens = unreachedMessageTokens(ruleFiles);
  console.log(
    `\nRule-claim reach (#1665) — ${reach.focusBlocks} \`patterns\` blocks carry a focus-metavariable;` +
      ` ${reach.dead.length} arm(s) can never bind it.`,
  );
  console.log(
    `  Reported, not gated: ${unreachedTokens.reduce((n, h) => n + h.tokens.length, 0)} backticked identifier(s) in a` +
      ` message are absent from that rule's own patterns, over ${unreachedTokens.length} rule(s) —` +
      `\n  measured 2026-07-31 to be remediation text or a stated exclusion in 13 of 13 cases, so it names the fix,` +
      `\n  not a gap. Read them when the count moves: ${unreachedTokens.map((h) => h.id).join(", ")}`,
  );
  if (reach.dead.length > 0) {
    console.error(
      `\n✗ ${reach.dead.length} pattern arm(s) sit under a \`focus-metavariable\` they never bind, with nothing else in` +
        `\n  the conjunction binding it either — those arms match nothing while the rule's message advertises them.`,
    );
    for (const d of reach.dead) console.error(`  ${d.id} (${d.file})  focus ${d.focus}  dead arm: ${d.arm}`);
    console.error(
      "\nFix by giving each arm its own `focus-metavariable` on the argument that arm binds — the shape #1657 used" +
        "\nfor harvey-ldap-injection, where bind/compare/modify had been dead for the rule's whole life.",
    );
    process.exit(1);
  }

  // #1568: this job short-circuits to a green no-op on an irrelevant diff, so "green" and "scored"
  // are different facts here and the receipt is what tells them apart. Recorded AFTER the verdict,
  // and only on the passing path — a run that exited above never reached its measuring phase.
  recordMeasured("disclosure-venue", rules.length, `semgrep rules read for a comment-declared bound (${bounded.length} bounded)`);

  console.log(
    `\n✓ every rule with a recorded bound states it in its message, and every rule that had one still does.` +
      `\n  Lower bound, not a census — this number is about ${BOUND_MARKERS.length} bound-declaring phrases, not about the` +
      `\n  rule set. A bound phrased outside that vocabulary is invisible to the PASS/FAIL above; the residual is` +
      `\n  counted and triaged in the section above, never left silent. "Corresponding" is a shared distinctive term in the SCOPE SENTENCE, not a` +
      `\n  judgement, so it over-refuses a correct paraphrase that shares no wording with the comment` +
      `\n  (reword the comment to the message's plain terms; do not parrot a word). See src/disclosure-venue.ts.`,
  );
}

main();
