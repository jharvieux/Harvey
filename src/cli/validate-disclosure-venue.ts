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
//
// The gate's own scope, and the 4b half that is not built, are stated in src/disclosure-venue.ts.

import {
  BOUND_MARKERS,
  RULES_DIR,
  auditDisclosureVenue,
  commentBounds,
  loadSemgrepRules,
  type SemgrepRule,
} from "../disclosure-venue.js";

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

  console.log(`Disclosure venue (gate 4, #1317) — ${RULES_DIR}`);
  console.log(`  rules scanned:            ${rules.length}`);
  console.log(`  with a recorded bound:    ${bounded.length}`);
  console.log(`  bound stated in message:  ${bounded.length - violations.length}`);
  console.log(`  bound comment-only:       ${violations.length}`);
  if (seed) console.log(`  (--seed-violation: ${SEEDED_RULES.length} synthetic bounded rules appended; both must appear below)`);

  if (process.argv.includes("--list")) {
    console.log("\nRules carrying a recorded bound:");
    for (const r of bounded) {
      const ok = violations.some((v) => v.id === r.id && v.file === r.file) ? "COMMENT-ONLY" : "in message  ";
      console.log(`  ${ok}  ${r.id}  (${r.file}:${r.line})`);
    }
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

  console.log(
    `\n✓ every rule with a recorded bound states it in its message.` +
      `\n  Lower bound, not a census — this number is about ${BOUND_MARKERS.length} bound-declaring phrases, not about the` +
      `\n  rule set. A bound phrased outside that vocabulary is invisible here; ~9 such rules are known` +
      `\n  and named in #1342. "Corresponding" is a shared distinctive term in the SCOPE SENTENCE, not a` +
      `\n  judgement, so it over-refuses a correct paraphrase that shares no wording with the comment` +
      `\n  (reword the comment to the message's plain terms; do not parrot a word). See src/disclosure-venue.ts.`,
  );
}

main();
