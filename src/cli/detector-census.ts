// Authoritative per-module detector census. "Measure, don't recall": the count of distinct
// detectors each module ships is DERIVED from source here, never quoted from memory or a doc.
//
// Registry-owned mechanical producers carry their own module/taxonomy metadata. Non-mechanical
// engines are attributed by OWNING FILE (the map below), with a taxonomy "Mx —" prefix
// overriding the file-owner for files that emit more than one module's findings:
//   - Semgrep taint/pattern rules — src/scan/rules/semgrep/*.yml (`id: harvey-*`). All M1.
//   - TS/AST detectors — distinct `taxonomy:` strings in the owned files.
//   - M10 classification rows — the [regex, "LABEL", "CATEGORY", …] table in pii-classify.mjs.
//
// A new mechanical scan producer must join the registry; its discovery gate fails otherwise. A
// detector in another engine still joins OWNERS. M2 is dynamic/generative (a probe matrix of every
// table × persona × verb) — its taxonomy count is the static finding classes only; M3 wraps the
// external vitals plugin. Both caveats are printed so the integer is never over-read as recall.
//
// Run: pnpm detector-census
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isDirectorySafe, readEntriesSafe } from "../fs-walk.js";
import {
  MECHANICAL_REGISTRY,
  operatorMechanicalScopeRows,
  validateMechanicalEngineRegistry,
} from "../scan/mechanical-engine-registry.js";

const ROOT = new URL("../..", import.meta.url).pathname;
const registryProblems = validateMechanicalEngineRegistry(ROOT);
if (registryProblems.length > 0) throw new Error(`mechanical engine registry invalid:\n${registryProblems.join("\n")}`);

// file (repo-relative) or directory → the module that owns the detectors it defines.
const OWNERS: Record<string, string> = {
  "src/scan/supabase-config.ts": "M1",
  "src/scan/supabase-advisors.ts": "M1",
  "src/scan/supabase-splinter.ts": "M1",
  "src/scan/supabase.ts": "M1",
  "src/scan/ext-coverage.ts": "M1", // #1065 — the extension half of the same disclosure family, filed under M1 with its siblings
  "src/scan/git-history-secret-gate.ts": "M1",
  "src/pentest": "M2",
  "src/hotspot-scan.ts": "M3",
  "src/quality-scan.ts": "M4", // jscpd duplication + #360 diverged-clone near-miss
  "src/detectors/slop.ts": "M5",
  "src/detectors/perf-code.ts": "M7",
  "src/detectors/bundle-stats.ts": "M7",
  "src/detectors/asset-weight.ts": "M7",
  "src/detectors/hook-deps.ts": "M7",
  "src/scan/prisma-schema-perf.ts": "M7",
  "src/scan/prisma-app-perf.ts": "M7",
  "src/detectors/test-intent.ts": "M8",
  "src/detectors/vitest-intent.ts": "M8",
  "src/detectors/app-router.ts": "M9",
  "src/detectors/boundary-model.ts": "M9", // #916 — framework-agnostic boundary model + not-assessed rows
  "src/detectors/remix-adapter.ts": "M9", // #917 — Remix / React Router 7 adapter
  "src/detectors/tanstack-adapter.ts": "M9", // #918 — TanStack Start adapter
  "src/pii-protection-review.ts": "M10", // #1043 — per-column protection verdict on the connected tier, plus its not-assessed row
};

function walk(dir: string, out: string[] = []): string[] {
  for (const { path: p, isDirectory } of readEntriesSafe(dir).entries) {
    if (isDirectory) walk(p, out);
    else out.push(p);
  }
  return out;
}

const MODULES = Array.from({ length: 10 }, (_, i) => `M${i + 1}`);
const detectors = new Map<string, Set<string>>(MODULES.map((m) => [m, new Set<string>()]));
const registryOwnedFiles = new Set(MECHANICAL_REGISTRY.flatMap((definition) => definition.implementations.map((implementation) => implementation.file)));
for (const row of operatorMechanicalScopeRows()) {
  for (const taxonomy of row.taxonomies) detectors.get(row.module)!.add(`tax:${taxonomy}`);
}

// 1. Semgrep rules — the security dir is the M1 rule set.
for (const f of walk(join(ROOT, "src/scan/rules/semgrep")).filter((p) => p.endsWith(".yml"))) {
  for (const m of readFileSync(f, "utf8").matchAll(/^\s*-?\s*id:\s*(harvey-[a-z0-9-]+)/gm)) {
    if (m[1]) detectors.get("M1")!.add(`semgrep:${m[1]}`);
  }
}

// 2. TS/AST detectors — distinct taxonomy per owned file; "Mx —" prefix overrides the file-owner.
for (const [rel, owner] of Object.entries(OWNERS)) {
  if (registryOwnedFiles.has(rel)) throw new Error(`${rel} is registry-owned and must not be copied into detector-census OWNERS`);
  const abs = join(ROOT, rel);
  const files = isDirectorySafe(abs)
    ? walk(abs).filter((p) => p.endsWith(".ts") && !p.endsWith(".test.ts"))
    : [abs];
  for (const f of files) {
    for (const m of readFileSync(f, "utf8").matchAll(/taxonomy:\s*[`"']([^`"']+)/g)) {
      if (!m[1]) continue;
      const tax = m[1].trim();
      const prefixed = /^(M\d+)\b/.exec(tax)?.[1];
      const mod = prefixed && detectors.has(prefixed) ? prefixed : owner;
      detectors.get(mod)!.add(`tax:${tax}`);
    }
  }
}

// 3. M10 classification rows — [/regex/, "LABEL", "CATEGORY", …].
const pii = readFileSync(join(ROOT, "tools/pii-classify.mjs"), "utf8");
for (const m of pii.matchAll(/^\s*\[\/.*\/[a-z]*,\s*"([A-Z_]+)",\s*"[A-Z_]+"/gm)) {
  if (m[1]) detectors.get("M10")!.add(`pii:${m[1]}`);
}

const NOTE: Record<string, string> = {
  M2: "dynamic — generative probe matrix (table×persona×verb); count = static finding classes",
  M3: "wraps external vitals plugin; count = hotspot signal classes",
  M4: "jscpd + diverged-clone; duplication engine is largely the external jscpd tool",
  M6: "non-grading indicators — 5 of these are shipped in the free report today",
  M8: "static test-intent detectors; full mutation (Stryker) is external, not counted here",
  M10: "PII/PHI/PCI classifier pattern rows",
};

console.log("Per-module detector census (measured from source):\n");
console.log("  module   detectors   note");
let total = 0;
for (const m of MODULES) {
  const n = detectors.get(m)!.size;
  total += n;
  console.log(`  ${m.padEnd(7)}  ${String(n).padStart(8)}   ${NOTE[m] ?? ""}`);
}
console.log(`\n  TOTAL distinct detectors across all modules: ${total}`);
console.log(
  "\nThis counts DETECTORS (capable of firing), NOT recall. Only M1 has a scored recall gate\n" +
    "(pnpm validate:calibration). Re-run this tool after any detector change — never quote a\n" +
    "stored number.",
);
