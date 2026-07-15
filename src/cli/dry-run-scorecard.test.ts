// Guards the hand-kept mappings in dry-run-scorecard.ts against the drift that this file exists to
// catch: a rule lands (e.g. #220's checkMigrationPolicySemantics), nobody re-keys the answer key,
// and a bug the mechanical tier now catches keeps scoring "requires-live-run" — under-reporting our
// own lead module on a Critical. The scorecard can't self-check (moduleRan is by design a human
// claim), but the claim "no mechanical module reaches this bug" is falsifiable against the real
// findings the scan produced.
//
// KNOWN CEILING, stated rather than implied: the location-anchored guard only catches drift where a
// new rule fires AT the bug's planted location. It caught RLS-AUTH-ROLE's stale mapping (rls.sql:38)
// and would have caught RLS-USING-TRUE's (#337 fires at rls.sql:31); it did NOT catch RLS-DISABLED's,
// because checkMigrationRlsStatic reports an absence at the CREATE site (schema.sql:35) while
// GROUND-TRUTH addresses the bug at the absence site (rls.sql:41-43). An address-mismatched rule
// still needs a human to notice. Making that automatic would mean matching on bug CLASS rather than
// location — tracked as a follow-up.
//
// It also guards the failure mode one level up, which no amount of per-bug checking can see: a bug
// that GROUND-TRUTH plants but the scorecard never maps at all is absent from scorecard.json rather
// than reported as a gap. That is how rows 9–12 stayed invisible through every prior scorecard.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AUTOMATED_REPLAY_IDS } from "../pentest/verify.js";
import { GROUND_TRUTH_BUGS } from "./dry-run-scorecard.js";

interface RawFinding {
  taxonomy: string;
  location: string;
  mechanical?: boolean;
}

const findings = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "dry-run", "findings.json"), "utf8")) as RawFinding[];

// "supabase/migrations/…_rls.sql:41-43" → the file and every line the bug is planted across, so a
// finding anchored anywhere in that span counts as reaching it.
function plantedAt(bugLocation: string): { file: string; lines: number[] } | null {
  const m = /^(.*):(\d+)(?:-(\d+))?$/.exec(bugLocation);
  if (!m) return null;
  const start = Number(m[2]);
  const end = m[3] ? Number(m[3]) : start;
  return { file: m[1]!, lines: Array.from({ length: end - start + 1 }, (_, i) => start + i) };
}

function mechanicalFindingsAt(file: string, lines: number[]): RawFinding[] {
  return findings.filter((f) => f.mechanical === true && lines.some((n) => f.location.startsWith(`${file}:${n}`)));
}

describe("GROUND_TRUTH_BUGS mappings vs. the findings the scan really produced", () => {
  // The moduleRan:false population is the M2 dynamic-tier bugs (GROUND-TRUTH rows 9–12). Their
  // claim is NOT "no mechanical rule fires at my line" — it is "my detection is a live-behavior
  // probe that this static pass never ran", so the location guard below is the wrong instrument for
  // them (their GROUND-TRUTH locations are whole files, with no line to anchor on, precisely
  // because the bug is in the route's runtime behavior rather than at a specific statement). Each
  // claim type therefore gets the check that can actually falsify it: dynamic bugs must name a real
  // registered M2 replay, and the rest must have no mechanical finding at their planted line.
  const dynamic = GROUND_TRUTH_BUGS.filter((b) => !b.moduleRan && b.expectedModule.includes("M2 dynamic pen-test replay"));
  const notRunMechanical = GROUND_TRUTH_BUGS.filter((b) => !b.moduleRan && !dynamic.includes(b));

  it.each(dynamic.map((b) => [b.id, b] as const))(
    "%s claims an M2 replay detects it — src/pentest/verify.ts really registers a replay under that id",
    (id, bug) => {
      // Falsifies the excuse rather than trusting it: "needs a live run" is only honest while a
      // probe for this bug actually exists. Delete the replay (or typo the id) and the bug becomes
      // undetectable by ANY tier — which must fail here, not sit in scorecard.json as a live-run
      // promise no code can keep.
      expect(AUTOMATED_REPLAY_IDS, `${bug.id} is mapped to an M2 replay ("${bug.expectedModule}") but no replay is registered under that id in src/pentest/verify.ts`).toContain(id);
    },
  );

  it.each(notRunMechanical.map((b) => [b.id, b] as const))(
    "%s claims no mechanical module reaches it — no mechanical finding is anchored at its planted location",
    (_id, bug) => {
      const planted = plantedAt(bug.location);
      expect(planted, `${bug.id}'s location is not a file:line — the guard cannot check it`).not.toBeNull();

      const reached = mechanicalFindingsAt(planted!.file, planted!.lines);
      expect(
        reached,
        `${bug.id} is mapped moduleRan:false ("${bug.expectedModule}") but the mechanical tier drew a finding at its planted location: ` +
          `${reached.map((f) => `"${f.taxonomy}" at ${f.location}`).join("; ")}. ` +
          `If that rule reasons about this bug's class, re-key the mapping to moduleRan:true with an honest matcher.`,
      ).toEqual([]);
    },
  );

  // Guards the two files against drifting apart, which is how rows 9–12 went unlisted: they were
  // added to GROUND-TRUTH (#145–#148) and nothing required the scorecard to acknowledge them, so
  // `requires-live-run: 0` kept claiming nothing awaited a live run. A bug this pass can't judge
  // still needs an entry saying so; an unmapped bug isn't `missed`, it's invisible. Parsing the
  // answer key is the only check that fails when a row is added or removed rather than drifting
  // along with it. Note this demands an ENTRY per planted bug, not a static verdict per bug — a
  // dynamic bug satisfies it with moduleRan:false and a reason.
  it("has an entry for every bug GROUND-TRUTH plants — an unmapped bug is invisible in scorecard.json, not 'missed'", () => {
    const groundTruth = readFileSync(join(import.meta.dirname, "..", "..", "targets", "calibration", "GROUND-TRUTH.md"), "utf8");
    // The planted-bug tables are the only ones keyed by a leading row NUMBER (`| 9 | SHADOW-API… |`);
    // every later corpus table is keyed by a string id, so this can't over-collect from them.
    const planted = [...groundTruth.matchAll(/^\| *\d+ *\| *([A-Z0-9-]+) *\|/gm)].map((m) => m[1]!);
    expect(planted.length, "parsed no planted-bug rows out of GROUND-TRUTH.md — the table format changed and this guard is silently vacuous").toBeGreaterThanOrEqual(12);

    const mapped = new Set(GROUND_TRUTH_BUGS.map((b) => b.id));
    expect(
      planted.filter((id) => !mapped.has(id)),
      "GROUND-TRUTH plants these bugs but GROUND_TRUTH_BUGS has no entry, so scorecard.json omits them entirely. " +
        "Add an entry: if no module in this pass detects it, map moduleRan:false with the reason and matches:()=>false — never leave it out.",
    ).toEqual([]);
  });

  it("scores every bug mapped moduleRan:true as caught — a matcher that no longer fires is drift too", () => {
    const claimedCaught = GROUND_TRUTH_BUGS.filter((b) => b.moduleRan && !b.expectedModule.includes("but no rule"));
    // RAN_SEMGREP_NO_RULE bugs are excluded above: they are the tier's honest, known ceiling.
    const notFiring = claimedCaught.filter((b) => !findings.some((f) => b.matches(f)));
    expect(notFiring.map((b) => b.id)).toEqual([]);
  });
});
