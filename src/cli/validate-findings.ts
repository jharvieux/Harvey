// Validate an engagement's findings.json before rendering the report.
//   pnpm validate:findings <findings.json>

import { readFileSync } from "node:fs";
import { validateFindings } from "../findings.js";

const path = process.argv[2];
if (!path) {
  console.error("usage: pnpm validate:findings <findings.json>");
  process.exit(2);
}

const { ok, errors } = validateFindings(JSON.parse(readFileSync(path, "utf8")));
if (!ok) {
  for (const e of errors) console.error(`✗ ${e}`);
  process.exit(1);
}
console.log(`✓ ${path} is a valid findings document`);
