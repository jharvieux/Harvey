// #416 — the durable-artifact convention that lets the #229 orchestrator DERIVE `ran` for the
// passes whose real work happens outside it: M1 semantic (/vuln-scan → /triage) and live
// (detect-deeper), M2 dynamic (pentest.ts against a stood-up stack), M3 vitals (a captured report),
// and M6's reviewed verdict. Each such pass writes ONE dated results artifact at a known location;
// the probe reads it and reports `ran` ONLY when a fresh, target-matching artifact exists — else it
// keeps its honest partial/requires-live-run. This is the "derive, don't assert" rule (#229) applied
// to passes that outlive the orchestrator process: a tier flag is intent, an artifact is evidence
// (#311/#356/#351 each refused to bank `ran` off a flag for exactly this reason).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { AuditModule } from "./audit-coverage.js";
import type { Finding } from "./findings.js";

// One recorded pass. `target` and `generatedAt` are the two fields the probe checks: it must
// describe THIS engagement's target and must not be stale. `findings` (optional) lets a pass that
// produced report-schema findings (e.g. M1's triage output, M6's written verdict) feed them into the
// deliverable the same way a captured CLI does.
export interface RecordedPass {
  module: AuditModule;
  target: string; // the engagement target this pass covered — must match the audited directory
  pass: string; // which out-of-orchestrator pass wrote it: "semantic" | "live" | "connected" | "dynamic" | "vitals" | "verdict"
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

// The file at <artifacts-dir>/<module>.pass.json: the most recently recorded pass, plus the tiers
// that slot already held.
//
// #1522 — why ONE accumulating slot rather than a tier-qualified filename per pass. M1 is the module
// with several out-of-orchestrator tiers (semantic, live, connected), and they contended for one
// filename: recording the connected pass DELETED a recorded semantic pass, its findings, and the
// disclosure that named the tiers still un-run — the more diligently an engagement recorded a tier,
// the quieter its M1 row got. The alternative fix, `M1.connected.pass.json` per tier, was rejected on
// two counts: (1) `pass` is a free-form string, and every reader reaches the filesystem through a
// narrowed `exists`/`readArtifact` seam with no directory listing — so a reader would have to GUESS a
// fixed set of tier names, and a pass recorded under any other name would be written to a file nobody
// ever opens, re-creating the silent-drop #1042 closed; (2) it splits one engagement's evidence
// across N files that four separate consumers would each have to re-assemble. Accumulating keeps the
// newest pass at the top level, so every existing reader is unchanged, and no tier is ever discarded.
export interface PassArtifact extends RecordedPass {
  // Passes previously recorded in this slot for the SAME module and target, newest first. Written by
  // writePassArtifact; read through passSlotCensus, which re-checks each one's own freshness.
  priorPasses?: RecordedPass[];
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

// Every pass the slot holds, split by its OWN freshness (#1522). A superseded tier is evidence in
// exactly the same way the newest one is, and a superseded tier that has since gone stale is not
// evidence at all — but it is never dropped in silence: the probes name it on the row.
export function passSlotCensus(artifact: PassArtifact, now: number): { fresh: RecordedPass[]; stale: RecordedPass[] } {
  const { priorPasses, ...newest } = artifact;
  const all = [newest, ...(priorPasses ?? [])];
  return {
    fresh: all.filter((p) => now - Date.parse(p.generatedAt) <= MAX_PASS_AGE_MS),
    stale: all.filter((p) => !(now - Date.parse(p.generatedAt) <= MAX_PASS_AGE_MS)),
  };
}

export const passLabel = (pass: RecordedPass): string => `${pass.pass} pass (${pass.generatedAt}${pass.summary ? `: ${pass.summary}` : ""})`;

// The `ran` outcome a probe returns when a fresh pass artifact proves the out-of-orchestrator work
// happened. Carries the findings of EVERY fresh pass in the slot (#1522 — before the slot
// accumulated, a second recorded tier deleted the first one's findings on its way in) and names any
// stale tier it holds rather than passing over it.
export function ranFromPass(artifact: PassArtifact, mechanicalDetail: string, now = Date.now()): { status: "ran"; detail: string; findings?: Finding[] } {
  const { fresh, stale } = passSlotCensus(artifact, now);
  const staleNote = stale.length ? ` [also recorded, but stale and therefore NOT collected: ${stale.map(passLabel).join(", ")}]` : "";
  const detail = `${mechanicalDetail} + ${fresh.map(passLabel).join(" + ")}${staleNote}`;
  const findings = fresh.flatMap((p) => p.findings ?? []);
  return findings.length ? { status: "ran", detail, findings } : { status: "ran", detail };
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

// Fold a newly recorded pass into whatever the slot already held (#1522). The incoming pass becomes
// the top-level one (so every reader keeps seeing the most recent tier where it always was) and the
// tiers it supersedes move to priorPasses. Re-recording the SAME tier replaces that tier only — a
// re-run of the semantic pass is a correction of the semantic pass, not a second one. An existing
// artifact for a different module or a different target is not this engagement's evidence, so it is
// not carried; findFreshPass would reject it on the next audit anyway.
export function mergePassArtifact(existing: PassArtifact | undefined, incoming: PassArtifact): PassArtifact {
  if (!existing || existing.module !== incoming.module || existing.target !== incoming.target) return incoming;
  const { priorPasses, ...newest } = existing;
  const kept = [newest, ...(priorPasses ?? [])].filter((p) => p.pass !== incoming.pass);
  return kept.length ? { ...incoming, priorPasses: kept } : incoming;
}

// Write the artifact to <dir>/<module>.pass.json, creating the dir if needed. Returns the path.
// The counterpart to findFreshPass: what a pass calls so the orchestrator can later derive `ran`.
export function writePassArtifact(dir: string, artifact: PassArtifact): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, passArtifactName(artifact.module));
  let existing: PassArtifact | undefined;
  if (existsSync(path)) {
    try {
      existing = JSON.parse(readFileSync(path, "utf8")) as PassArtifact;
    } catch (err) {
      // Overwriting would discard whatever tiers this slot holds, unread. Refuse loudly instead.
      throw new Error(`${path} exists but is not valid JSON (${err instanceof Error ? err.message : String(err)}) — recording ${artifact.pass} would discard the passes it holds. Move or delete it first.`);
    }
  }
  writeFileSync(path, `${JSON.stringify(mergePassArtifact(existing, artifact), null, 2)}\n`);
  return path;
}
