// #416 — the durable-artifact convention that lets the #229 orchestrator DERIVE `ran` for the
// passes whose real work happens outside it: M1 semantic (/vuln-scan → /triage) and live
// (detect-deeper), M2 dynamic (pentest.ts against a stood-up stack), M3 vitals (a captured report),
// and M6's reviewed verdict. Each such pass writes ONE dated results artifact at a known location;
// the probe reads it and reports `ran` ONLY when a fresh, target-matching artifact exists — else it
// keeps its honest partial/requires-live-run. This is the "derive, don't assert" rule (#229) applied
// to passes that outlive the orchestrator process: a tier flag is intent, an artifact is evidence
// (#311/#356/#351 each refused to bank `ran` off a flag for exactly this reason).

import { join } from "node:path";
import type { AuditModule } from "./audit-coverage.js";
import type { RunContext } from "./audit-runner.js";
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

// Reads the pass artifact for `module` and decides whether it is fresh evidence THIS target's pass
// ran. Reaches the filesystem only through ctx (exists/readArtifact), so it stays offline-testable.
export function findFreshPass(ctx: RunContext, module: AuditModule): PassLookup {
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
