// #448 — record that an out-of-orchestrator pass ran, by writing the durable artifact the #416
// orchestrator reads (docs/design/audit-pass-artifacts.md).
//
//   pnpm record-pass --module M1 --target <audited-dir> --pass semantic \
//       [--findings triage.json] [--summary "42 findings, 7 high"] --out <artifacts-dir>
//
// This is the universal write path for the passes that have no orchestrator seam — the LLM semantic
// scan (`/vuln-scan → /triage`), the M6 reviewed verdict, a captured vitals report, a live pen-test
// run. It stamps generatedAt from the real clock and target from --target (no hand-editing), loads
// report-schema findings from --findings if given, and writes <out>/<module>.pass.json. On the next
// `run-audit --artifacts-dir <out>`, that module derives `ran` from this artifact.
//
// Thin I/O wrapper per the repo convention — the schema/validation lives in src/audit-pass-artifact.ts.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AUDIT_MODULES, type AuditModule } from "../audit-coverage.js";
import { buildPassArtifact, writePassArtifact } from "../audit-pass-artifact.js";
import type { Finding } from "../findings.js";

const args = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

const module = flag("--module");
const target = flag("--target");
const pass = flag("--pass");
const out = flag("--out");
const summary = flag("--summary");
const findingsPath = flag("--findings");

if (!module || !target || !pass || !out) {
  console.error("usage: pnpm record-pass --module <M1..M10> --target <dir> --pass <name> --out <artifacts-dir> [--findings file.json] [--summary text]");
  process.exit(2);
}
if (!AUDIT_MODULES.includes(module as AuditModule)) {
  console.error(`--module must be one of ${AUDIT_MODULES.join(", ")}, got ${module}`);
  process.exit(2);
}

let findings: Finding[] | undefined;
if (findingsPath) {
  if (!existsSync(findingsPath)) {
    console.error(`--findings file not found: ${findingsPath}`);
    process.exit(1);
  }
  const parsed = JSON.parse(readFileSync(findingsPath, "utf8"));
  if (!Array.isArray(parsed)) {
    console.error(`--findings must be a JSON array of report-schema findings: ${findingsPath}`);
    process.exit(1);
  }
  findings = parsed as Finding[];
}

try {
  const artifact = buildPassArtifact({
    module: module as AuditModule,
    target: resolve(target),
    pass,
    generatedAt: new Date().toISOString(),
    summary,
    findings,
  });
  const path = writePassArtifact(resolve(out), artifact);
  console.error(`Recorded ${module} ${pass} pass for ${resolve(target)}${findings ? ` (${findings.length} finding(s))` : ""} → ${path}`);
} catch (err) {
  console.error(`record-pass: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
