// Scan CLI entry point.
//   pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>] [--out <file>]
//
// Prints a Finding[] JSON array to stdout (or writes it to --out).

import { writeFileSync } from "node:fs";
import type { Finding } from "../findings.js";
import { runMechanicalScan } from "../scan/mechanical.js";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function emit(findings: Finding[]): void {
  const json = JSON.stringify(findings, null, 2);
  const out = arg("--out");
  if (out) writeFileSync(out, json);
  else console.log(json);
}

function main(): void {
  if (process.argv.includes("--mechanical")) {
    const dir = arg("--dir") ?? process.cwd();
    const bundle = arg("--bundle");
    emit(runMechanicalScan({ dir, bundleDir: bundle }));
    return;
  }
  console.error("usage: scan --mechanical --dir <path> [--bundle <path>] [--out <file>]");
  process.exit(2);
}

main();
