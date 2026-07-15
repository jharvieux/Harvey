// Guards the hand-kept mappings in dry-run-scorecard.ts against the drift that this file exists to
// catch: a rule lands (e.g. #220's checkMigrationPolicySemantics), nobody re-keys the answer key,
// and a bug the mechanical tier now catches keeps scoring "requires-live-run" — under-reporting our
// own lead module on a Critical. The scorecard can't self-check (moduleRan is by design a human
// claim), but the claim "no mechanical module reaches this bug" is falsifiable against the real
// findings the scan produced.
//
// KNOWN CEILING, stated rather than implied: this guard anchors on the bug's planted location, so it
// only catches drift where the new rule fires AT that location. It caught RLS-AUTH-ROLE's stale
// mapping (rls.sql:38) and would have caught RLS-USING-TRUE's (#337 fires at rls.sql:31); it did
// NOT catch RLS-DISABLED's, because checkMigrationRlsStatic reports an absence at the CREATE site
// (schema.sql:35) while GROUND-TRUTH addresses the bug at the absence site (rls.sql:41-43). An
// address-mismatched rule still needs a human to notice. Making that automatic would mean matching
// on bug CLASS rather than location — tracked as a follow-up.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
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
  // Currently EMPTY, and that is the honest state, not a broken guard: since #337 re-mapped
  // RLS-USING-TRUE, no bug claims moduleRan:false, so this case list generates nothing and the
  // second test below carries the weight. Kept rather than deleted — it is the guard that fires
  // the moment anyone re-introduces a "no mechanical module reaches this" claim, which is exactly
  // when the claim needs checking.
  const notRun = GROUND_TRUTH_BUGS.filter((b) => !b.moduleRan);

  it.each(notRun.map((b) => [b.id, b] as const))(
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

  it("scores every bug mapped moduleRan:true as caught — a matcher that no longer fires is drift too", () => {
    const claimedCaught = GROUND_TRUTH_BUGS.filter((b) => b.moduleRan && !b.expectedModule.includes("but no rule"));
    // RAN_SEMGREP_NO_RULE bugs are excluded above: they are the tier's honest, known ceiling.
    const notFiring = claimedCaught.filter((b) => !findings.some((f) => b.matches(f)));
    expect(notFiring.map((b) => b.id)).toEqual([]);
  });
});
