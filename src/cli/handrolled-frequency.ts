// Measures real per-shape frequency of the M6 hand-rolled catalogue's YES/MAYBE entries across a
// PROVENANCE-TAGGED corpus (#406 item 1, #413) — so detector batch 2 is ordered by measurement,
// not judgment, AND so "common in AI-generated code" can finally be checked against genuinely
// AI-authored repos instead of the mostly-professional six.
//
//   pnpm handrolled-frequency
//
// Clones each pinned repo read-only, loads product code the same way detect-static does
// (loadSources + NON_PRODUCT), then counts:
//   • the 5 SHIPPED classes by running detectHandrolledFindings itself — the detector IS the
//     measurement (package.json files stay in the input so the class-merge dep-gate behaves
//     exactly as it does in production);
//   • the unshipped YES/MAYBE shapes by the stated signatures in src/scan/handrolled-frequency.ts.
// Shapes with no honest signature are printed as UNMEASURED with the reason — never a junk count.
//
// #413: the corpus is two lists — EXTERNAL_CORPUS (six full-baseline repos, now provenance-tagged)
// plus AI_FREQUENCY_CORPUS (AI-authored, frequency-only). Every repo carries a provenance tier, so
// the output separates the AI-generated/ai-assisted signal from the professional blend and names
// which of the catalogue's measured-zero YES shapes fire on AI code.
//
// These are shape-presence counts by stated signature: NOT detector precision, NOT recall, and no
// precision number of any kind is claimed for M6 (#265). Results are recorded in
// docs/design/m6-corpus-frequency.md; rerun this command to regenerate them.
//
// NOT part of `pnpm verify` (network: clones the corpus), same stance as corpus-drift.ts.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { cloneAtPin } from "../scan/corpus-clone.js";
import { buildFrequencyTargets, MEASURED_SHAPES, SHIPPED_SHAPES, UNMEASURED_SHAPES, type FrequencyTier } from "../scan/handrolled-frequency.js";

// A repo is either the organic tier of its provenance, or "curated" if it is an intentionally-
// vulnerable teaching repo (its shape mix is authored, not organic — #413).
type Tier = FrequencyTier;

// #1524: buildFrequencyTargets() dedupes the EXTERNAL_CORPUS/AI_FREQUENCY_CORPUS overlap so a
// shared slug (cravab, flori-web, effective) contributes to sumForTier's aggregate exactly once —
// see its own doc comment in src/scan/handrolled-frequency.ts for why and which entry wins.
const targets = buildFrequencyTargets();

// The 17 YES entries the 2026-07-16 run measured at ZERO across all six corpus repos (the reason
// they were deferred). #413's core question: do any fire on AI-authored code?
const ZERO_YES_ENTRIES = new Set([3, 4, 11, 13, 16, 23, 24, 27, 30, 44, 53, 61, 68, 76, 89, 95, 98]);

interface TableRow {
  entry: number;
  verdict: string;
  name: string;
  unit: string;
  perRepo: Map<string, number>;
  total: number;
}

const rows = new Map<number, TableRow>();
const row = (entry: number, verdict: string, name: string, unit: string): TableRow => {
  let r = rows.get(entry);
  if (!r) {
    r = { entry, verdict, name, unit, perRepo: new Map(), total: 0 };
    rows.set(entry, r);
  }
  return r;
};

// Product LOC each repo contributes, so a per-KLOC aggregate can normalise the large repos
// (effective is ~500k LOC — an unnormalised sum would be dominated by tree size, not shape density).
const productLoc = new Map<string, number>();

for (const target of targets) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-freq-${target.slug}-`));
  console.error(`=== ${target.slug} [${target.tier}] (${target.repo} @ ${target.commit.slice(0, 8)}) ===`);
  try {
    cloneAtPin(target.repo, target.commit, dir);
    const files = loadSources(dir).filter((f) => !NON_PRODUCT.test(f.path));
    const product = files.filter((f) => /\.(ts|tsx|jsx|mjs)$/.test(f.path));
    productLoc.set(target.slug, product.reduce((acc, f) => acc + f.text.split("\n").length, 0));

    const findings = detectHandrolledFindings(files);
    for (const s of SHIPPED_SHAPES) {
      const n = findings.filter((f) => f.taxonomy === s.taxonomy).length;
      const r = row(s.entry, "SHIPPED", s.name, "findings");
      r.perRepo.set(target.slug, n);
      r.total += n;
    }
    for (const s of MEASURED_SHAPES) {
      const n = product.reduce((acc, f) => acc + s.count(f), 0);
      const r = row(s.entry, s.verdict, s.name, s.unit);
      r.perRepo.set(target.slug, n);
      r.total += n;
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const slugs = targets.map((t) => t.slug);
const sortedRows = [...rows.values()].sort((a, b) => a.entry - b.entry);
const out: string[] = [];
out.push(`Corpus (${targets.length} repos):`);
for (const t of targets) out.push(`  - ${t.slug} [${t.tier}] ${t.repo}@${t.commit.slice(0, 8)} — ${productLoc.get(t.slug) ?? 0} product LOC`);
out.push("");
out.push(`| # | Verdict | Shape | Unit | ${slugs.join(" | ")} | Total |`);
out.push(`|---|---|---|---|${slugs.map(() => "---:").join("|")}|---:|`);
for (const r of sortedRows) {
  out.push(`| ${r.entry} | ${r.verdict} | ${r.name} | ${r.unit} | ${slugs.map((s) => r.perRepo.get(s) ?? 0).join(" | ")} | ${r.total} |`);
}

// Per-tier aggregate. "Indicators" is a mixed-unit sum (matches/files/findings) — an order of
// magnitude, not arithmetic — so the per-KLOC figure is stated the same way, as a density hint.
const sumForTier = (tier: Tier): { indicators: number; loc: number; repos: string[] } => {
  const repos = targets.filter((t) => t.tier === tier).map((t) => t.slug);
  const indicators = sortedRows.reduce((acc, r) => acc + repos.reduce((a, s) => a + (r.perRepo.get(s) ?? 0), 0), 0);
  const loc = repos.reduce((a, s) => a + (productLoc.get(s) ?? 0), 0);
  return { indicators, loc, repos };
};
const perKloc = (indicators: number, loc: number): string => (loc === 0 ? "n/a" : (indicators / (loc / 1000)).toFixed(2));

out.push("");
out.push("Per-provenance-tier aggregate (mixed-unit indicator sum — read as an order of magnitude):");
for (const tier of ["professional", "ai-assisted", "ai-generated", "unclear", "curated"] as Tier[]) {
  const { indicators, loc, repos } = sumForTier(tier);
  if (repos.length === 0) continue;
  out.push(`  ${tier}: ${indicators} indicators over ${loc} LOC (${repos.length} repos: ${repos.join(", ")}) = ${perKloc(indicators, loc)}/KLOC`);
}
// The headline the issue asks for: organic AI (ai-generated + ai-assisted, curated EXCLUDED) vs professional.
const aiRepos = targets.filter((t) => t.tier === "ai-generated" || t.tier === "ai-assisted").map((t) => t.slug);
const aiInd = sortedRows.reduce((acc, r) => acc + aiRepos.reduce((a, s) => a + (r.perRepo.get(s) ?? 0), 0), 0);
const aiLoc = aiRepos.reduce((a, s) => a + (productLoc.get(s) ?? 0), 0);
const prof = sumForTier("professional");
out.push("");
out.push(`HEADLINE — organic AI (ai-generated + ai-assisted, curated excluded) vs professional:`);
out.push(`  AI          : ${aiInd} indicators over ${aiLoc} LOC = ${perKloc(aiInd, aiLoc)}/KLOC (${aiRepos.join(", ")})`);
out.push(`  professional: ${prof.indicators} indicators over ${prof.loc} LOC = ${perKloc(prof.indicators, prof.loc)}/KLOC (${prof.repos.join(", ")})`);

// #413's core question: which of the 17 measured-zero YES entries now fire on AI code?
const nonProfRepos = new Set(targets.filter((t) => t.tier !== "professional").map((t) => t.slug));
out.push("");
out.push("Measured-zero YES entries (17) — do any fire on AI/non-professional repos?");
const nowFiring = sortedRows.filter((r) => ZERO_YES_ENTRIES.has(r.entry)).map((r) => {
  const hits = [...r.perRepo.entries()].filter(([s, n]) => n > 0 && nonProfRepos.has(s));
  return { entry: r.entry, name: r.name, unit: r.unit, hits, total: hits.reduce((a, [, n]) => a + n, 0) };
});
for (const f of nowFiring.filter((f) => f.hits.length > 0)) {
  out.push(`  FIRES  ${f.entry} (${f.name}) — ${f.total} ${f.unit}: ${f.hits.map(([s, n]) => `${s}=${n}`).join(", ")}`);
}
const stillZero = nowFiring.filter((f) => f.hits.length === 0).map((f) => f.entry);
out.push(`  still zero on every non-professional repo (${stillZero.length}): ${stillZero.join(", ")}`);

out.push("");
out.push("Measured frequency order (total desc, zeros last by entry number):");
const ranked = [...rows.values()].sort((a, b) => b.total - a.total || a.entry - b.entry);
out.push(ranked.map((r) => `${r.entry}:${r.total}`).join("  "));

out.push("");
out.push(`UNMEASURED (${UNMEASURED_SHAPES.length} shapes — no honest signature; a reasoned gap, not a zero):`);
for (const s of UNMEASURED_SHAPES) out.push(`  - ${s.entry} (${s.verdict}) ${s.name}: ${s.reason}`);

out.push("");
out.push("Honesty: shape-presence counts by the stated signatures in src/scan/handrolled-frequency.ts —");
out.push("not detector precision, not recall; no precision number of any kind is claimed for M6 (#265).");

console.log(out.join("\n"));
