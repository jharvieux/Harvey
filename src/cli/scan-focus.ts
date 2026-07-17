// #442 — render an M1 semantic-pass focus brief from an M3 hotspot file.
//
//   pnpm scan-focus <m3-hotspot-file> [--out focus.md]
//
// <m3-hotspot-file> is the newline-ranked list `hotspot-scan.ts --hotspots-out` writes (the same file
// M8's `mutation-scan --hotspots` and M6's `simplify-scan --hotspots` consume). The brief is meant to
// be appended to the `/vuln-scan` pass's `--extra` inputs alongside docs/scan-extras.txt, so semantic
// review is prioritized on the hottest files. Prints to stdout, or writes --out.
//
// Thin I/O wrapper per the repo convention — the transform is the tested pure function in
// src/scan-focus.ts.
import { readFileSync, writeFileSync } from "node:fs";
import { buildScanFocus, parseHotspots } from "../scan-focus.js";

const args = process.argv.slice(2);
const hotspotsArg = args.find((a) => !a.startsWith("--"));
const outIdx = args.indexOf("--out");
const outPath = outIdx >= 0 ? args[outIdx + 1] : undefined;

if (!hotspotsArg) {
  console.error("usage: pnpm scan-focus <m3-hotspot-file> [--out focus.md]");
  process.exit(2);
}

const hotspots = parseHotspots(readFileSync(hotspotsArg, "utf8"));
let brief: string;
try {
  brief = buildScanFocus(hotspots);
} catch (err) {
  console.error(`M1: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

if (outPath) {
  writeFileSync(outPath, brief);
  console.error(`M1 vuln-scan focus brief: ${hotspots.length} hotspot(s) → ${outPath}`);
  console.error(`Pass it to the semantic pass: /vuln-scan --extra docs/scan-extras.txt --extra ${outPath}`);
} else {
  console.log(brief);
}
