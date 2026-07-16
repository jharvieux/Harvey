// Measures real per-shape frequency of the M6 hand-rolled catalogue's YES/MAYBE entries on the
// 6-repo external corpus (#406 item 1) — so detector batch 2 is ordered by measurement, not
// judgment (the catalogue's own "Honesty note on ranking" names this as the follow-up).
//
//   pnpm handrolled-frequency
//
// Clones each pinned corpus commit read-only, loads product code the same way detect-static does
// (loadSources + NON_PRODUCT), then counts:
//   • the 5 SHIPPED classes by running detectHandrolledFindings itself — the detector IS the
//     measurement (package.json files stay in the input so the class-merge dep-gate behaves
//     exactly as it does in production);
//   • the unshipped YES/MAYBE shapes by the stated signatures in src/scan/handrolled-frequency.ts.
// Shapes with no honest signature are printed as UNMEASURED with the reason — never a junk count.
//
// These are shape-presence counts by stated signature: NOT detector precision, NOT recall, and no
// precision number of any kind is claimed for M6 (#265). Results are recorded in
// docs/design/m6-corpus-frequency.md; rerun this command to regenerate them.
//
// NOT part of `pnpm verify` (network: clones six repos), same stance as corpus-drift.ts.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { cloneAtPin } from "../scan/corpus-clone.js";
import { EXTERNAL_CORPUS } from "../scan/external-corpus.js";
import { MEASURED_SHAPES, SHIPPED_SHAPES, UNMEASURED_SHAPES } from "../scan/handrolled-frequency.js";

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

for (const target of EXTERNAL_CORPUS) {
  const dir = mkdtempSync(join(tmpdir(), `harvey-freq-${target.slug}-`));
  console.error(`=== ${target.slug} (${target.repo} @ ${target.commit.slice(0, 8)}) ===`);
  try {
    cloneAtPin(target.repo, target.commit, dir);
    // Same product-code definition as detect-static: loadSources' walk minus test/story/fixture
    // files. package.json stays in the detector's input (dep-gate); regex signatures run over the
    // source-extension files only.
    const files = loadSources(dir).filter((f) => !NON_PRODUCT.test(f.path));
    const product = files.filter((f) => /\.(ts|tsx|jsx|mjs)$/.test(f.path));

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

const slugs = EXTERNAL_CORPUS.map((t) => t.slug);
const out: string[] = [];
out.push(`Corpus: ${EXTERNAL_CORPUS.map((t) => `${t.repo}@${t.commit.slice(0, 8)}`).join(", ")}`);
out.push("");
out.push(`| # | Verdict | Shape | Unit | ${slugs.join(" | ")} | Total |`);
out.push(`|---|---|---|---|${slugs.map(() => "---:").join("|")}|---:|`);
for (const r of [...rows.values()].sort((a, b) => a.entry - b.entry)) {
  out.push(`| ${r.entry} | ${r.verdict} | ${r.name} | ${r.unit} | ${slugs.map((s) => r.perRepo.get(s) ?? 0).join(" | ")} | ${r.total} |`);
}

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
