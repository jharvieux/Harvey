// #1660 — the reproduction command for the M5 single-use-helper exemption's "caller-awaits"
// sub-breakdown shipped in `src/detectors/slop.ts`'s evidence string and source comment. Prefers
// a mechanism over a comment: re-run this against the current pins any time the number is
// suspected to have drifted, rather than trusting the last hand-typed figure.
//
//   pnpm exec tsx src/cli/measure-m5-caller-await.ts <target-dir> [<target-dir> ...]
//
// Prints, per target and summed, how many single-use-helper candidates fire vs. are spared by
// each seam-outcome class, and — of the "spared-caller-awaits" class — how many have a caller
// whose await touches the helper's result under the #1660-settled predicate
// (`callerAwaitTouchesHelperResult`, dataflow through a one-hop local binding) vs. never touch it.
// Pure AST walk, no install needed (single-file/one-hop cross-file resolution only, same as the
// detector itself), so it runs directly against a shallow clone.

import "./sync-stdio.js";
import { basename } from "node:path";
import { classifySingleUseHelperCandidates } from "../detectors/slop.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";

const targets = process.argv.slice(2);
if (targets.length === 0) {
  console.error("usage: pnpm exec tsx src/cli/measure-m5-caller-await.ts <target-dir> [<target-dir> ...]");
  process.exit(2);
}

let totalFires = 0;
let totalSparedCallerAwaits = 0;
let totalSparedAsyncNoProof = 0;
let totalTouches = 0;
let totalNeverTouches = 0;

for (const dir of targets) {
  const sources = loadSources(dir).filter((f) => !NON_PRODUCT.test(f.path));
  const rows = classifySingleUseHelperCandidates(sources);
  let fires = 0;
  let sparedCallerAwaits = 0;
  let sparedAsyncNoProof = 0;
  let touches = 0;
  let neverTouches = 0;
  for (const r of rows) {
    if (r.outcome.startsWith("fires")) fires++;
    else if (r.outcome === "spared-caller-awaits") {
      sparedCallerAwaits++;
      if (r.awaitTouchesResult) touches++;
      else neverTouches++;
    } else if (r.outcome === "spared-async-no-proof-sync") sparedAsyncNoProof++;
  }
  console.log(`${basename(dir)}: fires=${fires} spared-caller-awaits=${sparedCallerAwaits} (touches=${touches} never-touches=${neverTouches}) spared-async-no-proof-sync=${sparedAsyncNoProof}`);
  totalFires += fires;
  totalSparedCallerAwaits += sparedCallerAwaits;
  totalSparedAsyncNoProof += sparedAsyncNoProof;
  totalTouches += touches;
  totalNeverTouches += neverTouches;
}

const totalSpared = totalSparedCallerAwaits + totalSparedAsyncNoProof;
console.log(
  `\nTOTAL over ${targets.length} target(s): fires=${totalFires} spared=${totalSpared} (spared-caller-awaits=${totalSparedCallerAwaits} [touches=${totalTouches} never-touches=${totalNeverTouches}], spared-async-no-proof-sync=${totalSparedAsyncNoProof})`,
);
