// #448 — record that an out-of-orchestrator pass ran, by writing the durable artifact the #416
// orchestrator reads (docs/design/audit-pass-artifacts.md).
//
//   pnpm record-pass --module M1 --target <audited-dir> --pass semantic \
//       [--findings triage.json] [--summary "42 findings, 7 high"] --out <artifacts-dir>
//
// This is the universal write path for the passes that have no orchestrator seam — the LLM semantic
// scan (`/vuln-scan → /triage`), the M6 reviewed verdict, a captured vitals report, a live pen-test
// run. It stamps generatedAt from the real clock and target from --target (no hand-editing), loads
// report-schema findings from --findings if given, and writes <out>/<module>.pass.json.
//
// What the next `run-audit --artifacts-dir <out>` does with it (#1042 — every module this CLI
// accepts now has a consumer; before it, six of the ten were written and silently discarded):
//   M1/M2/M3/M6  the pass IS the module's missing tier, so the row derives `ran` from it.
//   M7           the pass IS the named Lighthouse/CWV tier, so the row stops asserting it did not
//                run and merges its findings.
//   M4/M5/M8/M9/M10  the findings are merged and the pass is named on the row, but the status is
//                NOT upgraded to `ran`: the pass covers one tier and the orchestrator has no
//                evidence about the rest (the #229 derive-don't-assert rule).
// A stale, wrong-target or malformed artifact is named on the row as rejected, never ignored.
//
// Thin I/O wrapper per the repo convention — the schema/validation lives in src/audit-pass-artifact.ts.
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { AUDIT_MODULES, type AuditModule } from "../audit-coverage.js";
import { buildPassArtifact, type PassArtifact, writePassArtifact } from "../audit-pass-artifact.js";
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
// #502: for an M1 semantic pass, record whether an M3 hotspot focus brief (scan-focus) was supplied
// to /vuln-scan. Presence of the flag ⇒ true; absence ⇒ left unrecorded (surfaced as "no focus").
const hotspotFocus = args.includes("--hotspot-focus") ? true : undefined;
// #530: for an M3 vitals pass, the worst-first top-K hotspot ranking (a JSON array of file paths).
// Surfaced by the m3 probe so cross-module enrichment (#515) fires from a captured-vitals pass too.
const hotspotsPath = flag("--hotspots");

if (!module || !target || !pass || !out) {
  console.error("usage: pnpm record-pass --module <M1..M10> --target <dir> --pass <name> --out <artifacts-dir> [--findings file.json] [--hotspots file.json] [--summary text] [--hotspot-focus]");
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

let hotspots: string[] | undefined;
if (hotspotsPath) {
  if (!existsSync(hotspotsPath)) {
    console.error(`--hotspots file not found: ${hotspotsPath}`);
    process.exit(1);
  }
  const parsed = JSON.parse(readFileSync(hotspotsPath, "utf8"));
  if (!Array.isArray(parsed) || !parsed.every((h) => typeof h === "string")) {
    console.error(`--hotspots must be a JSON array of file-path strings (the top-K hotspot ranking): ${hotspotsPath}`);
    process.exit(1);
  }
  hotspots = parsed as string[];
}

try {
  const artifact = buildPassArtifact({
    module: module as AuditModule,
    target: resolve(target),
    pass,
    generatedAt: new Date().toISOString(),
    summary,
    findings,
    hotspotFocus,
    hotspots,
  });
  const path = writePassArtifact(resolve(out), artifact);
  console.error(`Recorded ${module} ${pass} pass for ${resolve(target)}${findings ? ` (${findings.length} finding(s))` : ""} → ${path}`);
  // #1522: the slot accumulates, so say which tiers it now holds. Recording one tier used to delete
  // another's — silently, since the write said only what it had just written.
  const slot = JSON.parse(readFileSync(path, "utf8")) as PassArtifact;
  console.error(`  ${module} slot now holds: ${[slot, ...(slot.priorPasses ?? [])].map((p) => `${p.pass} (${p.generatedAt})`).join(", ")}`);
} catch (err) {
  console.error(`record-pass: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
