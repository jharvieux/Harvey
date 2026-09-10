// Validate an engagement's findings.json before rendering the report.
//   pnpm validate:findings <findings.json>

import "./sync-stdio.js";
import { existsSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { validateFindings, type ValidationResult } from "../findings.js";
import { validateDryRunFamily } from "../dry-run-artifacts.js";

const path = process.argv[2];
if (!path) {
  console.error("usage: pnpm validate:findings <findings.json>");
  process.exit(2);
}

function validateFile(file: string): ValidationResult {
  // Check before reading the report: interrupted directory activation leaves no current path,
  // and the family validator explains how to recover the retained complete previous directory.
  const canonicalName = basename(file) === "findings-report.json";
  const knownFamily = resolve(file) === resolve(import.meta.dirname, "../../dry-run/findings-report.json") || existsSync(join(dirname(file), "artifact-family.json"));
  if (canonicalName && (knownFamily || !existsSync(file))) return validateDryRunFamily(dirname(file));
  const document = JSON.parse(readFileSync(file, "utf8")) as unknown;
  if (typeof document === "object" && document !== null && "artifactLinkage" in document) {
    if (canonicalName) return validateDryRunFamily(dirname(file));
    return { ok: false, errors: ["A linked dry-run report must be validated as findings-report.json alongside its retained artifact family; a renamed standalone copy cannot prove its source linkage."] };
  }
  // Older dry-run reports predate linkage. Preserve normal schema validation for an unrelated
  // engagement that happens to use the same filename, but never bless a legacy dry-run alone.
  if (canonicalName && typeof document === "object" && document !== null && "meta" in document &&
      typeof document.meta === "object" && document.meta !== null && "auditor" in document.meta &&
      document.meta.auditor === "Harvey dry-run harness (src/cli/dry-run.ts)") return validateDryRunFamily(dirname(file));
  return validateFindings(document);
}
const { ok, errors } = validateFile(path);
if (!ok) {
  for (const e of errors) console.error(`✗ ${e}`);
  process.exit(1);
}
console.log(`✓ ${path} is a valid findings document`);
