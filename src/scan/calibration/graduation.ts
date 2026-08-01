// #1677 — the graduation guard for `expectedTier: "none"` corpus rows, scoped by NEIGHBOUR
// TAXONOMY rather than by the width of the row's `match` key.
//
// A `none` row exists to fail loud if its class ever graduates into a mechanical rule. `scoreEntry`
// implements that as "any finding relevant to the entry means a rule graduated", and relevance runs
// through the entry's `match` keys — so the guard is only ever as wide as the key. On a fixture
// where another class ALREADY fires, that forces the key narrow (or the row reports a graduation on
// day one, gets silenced, and the guard is gone). Narrow costs the other direction: a real
// graduation whose wording the key did not anticipate slips past silently.
//
// MEASURED 2026-07-31, `runMechanicalScan` over targets/calibration: 5 `none` rows, 2 of them on a
// fixture where another class already fires (#1708 re-tiered the sixth, P-CLIENT-HOOK-URL-PARAM,
// out of this population once harvey-path-traversal graduated onto it). This is the contract that
// replaces the tuning:
//
//   • The graduation set is EVERY finding on the fixture — the entry's `match` keys are not
//     consulted — MINUS the taxonomies the entry declares in `neighbourTaxonomies`.
//   • A finding carrying an undeclared taxonomy is a GRADUATION. It fires whatever the new rule
//     calls itself, which is what a key can never do.
//   • A declared taxonomy that no longer fires on the fixture is STALE and fails too. The list is a
//     measurement, and a measurement nobody re-runs is how the exclusion silently outgrows what it
//     was measured against.
//   • `neighbourTaxonomies` on anything but a `none` row is a corpus error: nothing reads it there,
//     so it would be a claim with no venue.
//
// This does not replace `scoreEntry`'s `none` branch; it is the wider second guard beside it. The
// live gate (src/cli/validate-calibration.ts) scores both and fails on either.

import { darkenEntry, type CorpusEntry } from "../calibration.js";
import type { Finding } from "../../findings.js";

// The entry's relevant findings under the SHIPPED predicate, obtained by difference from
// darkenEntry() rather than by re-implementing relevantFindings() — a re-implementation is a second
// predicate that can drift from the one the gate scores with.
function relevantFor(entry: CorpusEntry, findings: Finding[]): Finding[] {
  const remaining = new Set(darkenEntry(entry, findings));
  return findings.filter((f) => !remaining.has(f));
}

interface GraduationRow {
  id: string;
  location: string;
  /** Taxonomies on the fixture that the entry does not declare as a neighbour — a graduation. */
  graduated: string[];
  /** Declared neighbours that did not fire on this run — a decayed measurement. */
  stale: string[];
  /** Declared neighbours confirmed firing on this run. */
  confirmed: string[];
  pass: boolean;
  detail: string;
}

export function scoreGraduationGuards(corpus: readonly CorpusEntry[], findings: Finding[]): GraduationRow[] {
  const rows: GraduationRow[] = [];
  for (const entry of corpus) {
    if (entry.kind !== "positive" || entry.expectedTier !== "none") continue;
    const declared = entry.neighbourTaxonomies ?? [];
    const onFixture = [...new Set(relevantFor({ ...entry, match: undefined }, findings).map((f) => f.taxonomy))];
    const graduated = onFixture.filter((t) => !declared.includes(t)).sort();
    const confirmed = declared.filter((t) => onFixture.includes(t));
    const stale = declared.filter((t) => !onFixture.includes(t));
    const pass = graduated.length === 0 && stale.length === 0;
    const detail = graduated.length
      ? `GRADUATION: ${graduated.length} undeclared taxonom(ies) now fire on ${entry.location} — ${graduated.join("; ")}. Re-tier this row, or (if the class is genuinely a neighbour, not this row's class) declare it in neighbourTaxonomies with the reason.`
      : stale.length
        ? `STALE NEIGHBOUR: ${stale.join("; ")} no longer fire(s) on ${entry.location}. The declaration is a measurement that has decayed — drop it, so the guard narrows back to what is really there.`
        : `gap holds — ${onFixture.length} finding taxonom(ies) on the fixture, all ${confirmed.length} declared neighbour(s) still firing`;
    rows.push({ id: entry.id, location: entry.location, graduated, stale, confirmed, pass, detail });
  }
  return rows;
}

/** Rows declaring neighbours they have no venue to be read in — see the contract note above. */
export function misplacedNeighbourDeclarations(corpus: readonly CorpusEntry[]): CorpusEntry[] {
  return corpus.filter((e) => e.neighbourTaxonomies !== undefined && !(e.kind === "positive" && e.expectedTier === "none"));
}
