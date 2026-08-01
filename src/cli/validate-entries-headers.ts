// pnpm exec tsx src/cli/validate-entries-headers.ts [--list] [--residual-count] [--seed-drift]
//
// #1827. A `*.entries.ts` header that states a tier or a count must be derivable from the rows in
// its own file. Three headers outlived their rows in two days and every one was found by a human
// reading the file; this derives the claim from the exported array instead.
//
// --list            prints the population — files, comment lines, every claim the vocabulary
//                   resolved and every token it could not — so a green run is legible as a
//                   partial read rather than inferred from a violation count of zero.
// --residual-count  prints only the unread-token total, last line, for the recorded reason's
//                   falsifier in src/entries-header-drift.ts.
// --seed-drift      the negative control: rewrites one file's header IN MEMORY to state a tier
//                   count its rows contradict, and MUST exit non-zero. A gate only ever seen
//                   passing is indistinguishable from one that cannot fail (#350/#1065).
//
// The gate's own scope and its two deliberate bounds are stated in src/entries-header-drift.ts.

import "./sync-stdio.js";
import { readFileSync } from "node:fs";
import {
  auditEntriesHeaders,
  checkClaims,
  commentBlocks,
  entriesFiles,
  extractClaims,
  loadRows,
  residualRatchet,
} from "../entries-header-drift.js";
import type { Violation } from "../entries-header-drift.js";

const args = new Set(process.argv.slice(2));

async function main(): Promise<number> {
  const reports = await auditEntriesHeaders();
  const ratchet = residualRatchet(reports);

  if (args.has("--residual-count")) {
    console.log(String(ratchet.total));
    return 0;
  }

  // Prints the RESIDUAL_BASELINE body for a human to paste and disclose in the PR — never written
  // in place, for the same reason test-only-exports refuses to bump itself silently.
  if (args.has("--update-residual")) {
    for (const r of reports.filter((x) => x.residual.length > 0).sort((a, b) => a.file.localeCompare(b.file))) {
      console.log(`  ${JSON.stringify(r.file.split("/").pop())}: ${r.residual.length},`);
    }
    return 0;
  }

  const claims = reports.flatMap((r) => r.claims);
  const violations = reports.flatMap((r) => r.violations);
  const commentTotal = reports.reduce((n, r) => n + r.commentLines, 0);

  if (args.has("--list")) {
    for (const r of reports) {
      if (r.claims.length === 0 && r.residual.length === 0) continue;
      console.log(`\n${r.file}  (${r.rows} rows, ${r.commentLines} comment lines)`);
      for (const c of r.claims) {
        const stated =
          c.kind === "count"
            ? `count(${c.subject}) == ${c.n}`
            : c.kind === "universal"
              ? `every tiered row == ${c.subject}`
              : c.kind === "row"
              ? `${c.id} tier among [${c.tiers.join(", ")}]`
              : `${c.id} gapKind == ${c.gap}`;
        console.log(`  CLAIM    :${c.line}  ${stated}`);
        console.log(`           ${c.text.slice(0, 150)}`);
      }
      for (const t of r.residual) {
        console.log(`  residual :${t.line}  ${t.token}  (${t.reason})`);
        console.log(`           ${t.text.slice(0, 150)}`);
      }
    }
    console.log("");
  }

  console.log(
    `POPULATION  ${reports.length} entries files, ${commentTotal} comment lines, ` +
      `${claims.length} derivable claims resolved, ${ratchet.total} tokens the vocabulary could not read`,
  );

  if (args.has("--seed-drift")) return seedDrift();

  let failed = false;
  const report = (vs: readonly Violation[]) => {
    for (const v of vs) {
      console.log(`GATE FAIL — header contradicts its rows: ${v.file}:${v.line}`);
      console.log(`  claim   ${v.claim}`);
      console.log(`  header  ${v.stated}`);
      console.log(`  rows    ${v.actual}`);
      console.log(`  text    ${v.text.slice(0, 200)}`);
    }
  };
  if (violations.length > 0) {
    report(violations);
    failed = true;
  }
  for (const r of ratchet.risen) {
    console.log(
      `GATE FAIL — unread claim-ish prose added: ${r.file} has ${r.actual} tokens the vocabulary ` +
        `cannot judge, baseline ${r.baseline}. Reword it into a derivable claim, or raise ` +
        `RESIDUAL_BASELINE and say why in the PR body.`,
    );
    failed = true;
  }
  for (const r of ratchet.stale) {
    console.log(
      `GATE FAIL — STALE RESIDUAL_BASELINE: ${r.file} baseline ${r.baseline}, actual ${r.actual}. ` +
        `Lower it so the disclosed unread count stays true.`,
    );
    failed = true;
  }

  console.log(failed ? "ENTRIES HEADER GATE FAIL" : "ENTRIES HEADER GATE PASS");
  return failed ? 1 : 0;
}

// Seeds a contradiction the way the real defect arrives: the header keeps its wording and the ROWS
// move underneath it. Reading the seeded count from the file's own prose would let the control
// re-derive its expectation from the source the check reads, which is how four guards in this repo
// turned out to be copies of the thing they guarded.
async function seedDrift(): Promise<number> {
  const file = entriesFiles().find((f) => f.endsWith("b15-nextjs-authz.entries.ts"));
  if (!file) {
    console.log("SEED UNAVAILABLE — b15-nextjs-authz.entries.ts not found; cannot exercise the control");
    return 127;
  }
  const rows = await loadRows(file);
  const src = readFileSync(file, "utf8");
  const ids = rows.map((r) => r.id);
  const claims = commentBlocks(src).flatMap((b) => extractClaims(b, ids).claims);
  const counted = claims.filter((c) => c.kind === "count");
  if (counted.length === 0) {
    console.log(`SEED UNAVAILABLE — no count claim in ${file} to contradict`);
    return 127;
  }
  // Move the ROWS, not the prose: every row that the header counts loses its tier.
  const seeded = rows.map((r) => ({ ...r, expectedTier: r.expectedTier === undefined ? undefined : "high" }));
  const violations = checkClaims(file, seeded, claims);
  if (violations.length === 0) {
    console.log(`SEED FAILED TO FIRE — retiering every row of ${file} produced no violation`);
    return 1;
  }
  console.log(`SEEDED DRIFT — ${violations.length} violation(s) after retiering every row of ${file}:`);
  for (const v of violations) console.log(`  ${v.file}:${v.line} ${v.claim}: header ${v.stated}, rows ${v.actual}`);
  console.log("NEGATIVE CONTROL OK — the gate fails when the rows contradict the header");
  return 1;
}

process.exit(await main());
