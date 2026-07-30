// #416 — the durable-artifact convention that lets the #229 orchestrator DERIVE `ran` for the
// passes whose real work happens outside it: M1 semantic (/vuln-scan → /triage) and live
// (detect-deeper), M2 dynamic (pentest.ts against a stood-up stack), M3 vitals (a captured report),
// and M6's reviewed verdict. Each such pass writes ONE dated results artifact at a known location;
// the probe reads it and reports `ran` ONLY when a fresh, target-matching artifact exists — else it
// keeps its honest partial/requires-live-run. This is the "derive, don't assert" rule (#229) applied
// to passes that outlive the orchestrator process: a tier flag is intent, an artifact is evidence
// (#311/#356/#351 each refused to bank `ran` off a flag for exactly this reason).

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditModule } from "./audit-coverage.js";
import type { Finding } from "./findings.js";

// The artifact a pass writes. `target` and `generatedAt` are the two fields the probe checks: the
// artifact must describe THIS engagement's target and must not be stale. `findings` (optional) lets
// a pass that produced report-schema findings (e.g. M1's triage output, M6's written verdict) feed
// them into the deliverable the same way a captured CLI does.
export interface PassArtifact {
  module: AuditModule;
  target: string; // the engagement target this pass covered — must match the audited directory
  pass: string; // which out-of-orchestrator pass wrote it: "semantic" | "live" | "dynamic" | "vitals" | "verdict"
  generatedAt: string; // ISO-8601; older than the freshness window ⇒ stale, cannot prove THIS audit ran
  summary?: string; // one-line human note surfaced in the ledger detail
  findings?: Finding[]; // report-schema findings the pass produced, if any
  // #502: for the M1 semantic pass, whether an M3 hotspot focus brief (scan-focus) was supplied to
  // /vuln-scan. undefined ⇒ not recorded (treated as "no focus" — an un-prioritized semantic pass
  // that must be surfaced, never silently assumed hotspot-focused).
  hotspotFocus?: boolean;
  // #530: for the M3 vitals pass, the worst-first top-K hotspot file ranking the captured report
  // produced. Surfaced by the m3 probe so the cross-module enrichment (#515) also fires when M3 ran
  // via a pass artifact (vitals off PATH during run-audit), not only the in-process capture path.
  hotspots?: string[];
}

// A pass older than this describes a prior state of the target, so it cannot prove the module ran
// for THIS audit. 30 days spans a normal engagement cycle; tighten per engagement if needed.
export const MAX_PASS_AGE_MS = 30 * 24 * 60 * 60 * 1000;

// The conventional filename a pass writes under the engagement's artifacts dir.
const passArtifactName = (module: AuditModule): string => `${module}.pass.json`;

type PassLookup =
  | { fresh: true; artifact: PassArtifact }
  // `reason` is set ONLY when an artifact exists but was rejected (wrong target, stale, malformed),
  // so the probe can fail loud about a rejected pass rather than silently ignoring it. Absent
  // artifact ⇒ no reason: the probe falls back to its normal not-run wording.
  | { fresh: false; reason?: string };

// The slice of the orchestrator's RunContext this lookup needs. Narrowed (#1280) so a reader
// OUTSIDE run-audit — M2's scope ledger asking whether the connected pass ran on this engagement —
// can use the same freshness/target rules without fabricating an exec/env it has no use for.
// RunContext satisfies it structurally, so every existing caller is unchanged.
interface PassArtifactSource {
  targetDir: string;
  exists: (path: string) => boolean;
  artifactsDir?: string;
  readArtifact?: (path: string) => unknown;
  now?: number;
}

// Reads the pass artifact for `module` and decides whether it is fresh evidence THIS target's pass
// ran. Reaches the filesystem only through ctx (exists/readArtifact), so it stays offline-testable.
export function findFreshPass(ctx: PassArtifactSource, module: AuditModule): PassLookup {
  if (!ctx.artifactsDir || !ctx.readArtifact) return { fresh: false };
  const path = join(ctx.artifactsDir, passArtifactName(module));
  if (!ctx.exists(path)) return { fresh: false };

  const raw = ctx.readArtifact(path) as Partial<PassArtifact> | undefined;
  if (!raw || raw.module !== module) {
    return { fresh: false, reason: `pass artifact at ${path} is missing or names a different module — cannot derive ${module} ran` };
  }
  if (raw.target !== ctx.targetDir) {
    return { fresh: false, reason: `pass artifact at ${path} covers target ${raw.target ?? "<none>"}, not the audited target ${ctx.targetDir} — not evidence THIS target's ${module} ran` };
  }
  const ts = raw.generatedAt ? Date.parse(raw.generatedAt) : NaN;
  if (Number.isNaN(ts)) {
    return { fresh: false, reason: `pass artifact at ${path} has no valid generatedAt timestamp — cannot judge freshness` };
  }
  const now = ctx.now ?? Date.now();
  const ageDays = Math.round((now - ts) / (24 * 60 * 60 * 1000));
  if (now - ts > MAX_PASS_AGE_MS) {
    return { fresh: false, reason: `pass artifact for ${module} is stale (generated ${raw.generatedAt}, ${ageDays} days ago — past the ${Math.round(MAX_PASS_AGE_MS / (24 * 60 * 60 * 1000))}-day freshness window); re-run the pass` };
  }
  return { fresh: true, artifact: raw as PassArtifact };
}

// The `ran` outcome a probe returns when a fresh pass artifact proves the out-of-orchestrator work
// happened. Carries the artifact's findings (if any) into the deliverable.
export function ranFromPass(artifact: PassArtifact, mechanicalDetail: string): { status: "ran"; detail: string; findings?: Finding[] } {
  const detail = `${mechanicalDetail} + ${artifact.pass} pass (${artifact.generatedAt}${artifact.summary ? `: ${artifact.summary}` : ""})`;
  return artifact.findings?.length ? { status: "ran", detail, findings: artifact.findings } : { status: "ran", detail };
}

// ---- The write side (#448): passes emit the artifact findFreshPass reads. ----

// Assemble a PassArtifact from parts, validating the two fields the reader gates on (a non-empty
// target and a real ISO timestamp) at construction — so a malformed artifact fails at the emitting
// pass, not silently on the next audit. generatedAt is passed in (not stamped here) so the caller
// owns the clock; the record-pass CLI stamps `new Date().toISOString()`.
export function buildPassArtifact(parts: {
  module: AuditModule;
  target: string;
  pass: string;
  generatedAt: string;
  summary?: string;
  findings?: Finding[];
  hotspotFocus?: boolean;
  hotspots?: string[];
}): PassArtifact {
  if (!parts.target.trim()) throw new Error("pass artifact needs a non-empty target (the audited directory)");
  if (!parts.pass.trim()) throw new Error("pass artifact needs a non-empty pass name (e.g. semantic, dynamic, verdict)");
  if (Number.isNaN(Date.parse(parts.generatedAt))) throw new Error(`pass artifact generatedAt is not a valid ISO-8601 timestamp: ${parts.generatedAt}`);
  return {
    module: parts.module,
    target: parts.target,
    pass: parts.pass,
    generatedAt: parts.generatedAt,
    ...(parts.summary ? { summary: parts.summary } : {}),
    ...(parts.findings?.length ? { findings: parts.findings } : {}),
    ...(parts.hotspotFocus !== undefined ? { hotspotFocus: parts.hotspotFocus } : {}),
    ...(parts.hotspots?.length ? { hotspots: parts.hotspots } : {}),
  };
}

// Write the artifact to <dir>/<module>.pass.json, creating the dir if needed. Returns the path.
// The counterpart to findFreshPass: what a pass calls so the orchestrator can later derive `ran`.
export function writePassArtifact(dir: string, artifact: PassArtifact): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, passArtifactName(artifact.module));
  writeFileSync(path, `${JSON.stringify(artifact, null, 2)}\n`);
  return path;
}
