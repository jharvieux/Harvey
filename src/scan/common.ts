// Shared helpers for the mechanical scan modules (secrets, dependencies, semgrep,
// supply-chain, leftover-auth, supabase-*). Keeps Finding construction consistent so
// every module fills the schema's required fields the same way.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { SourceInput } from "../detectors/common.js";
import type { Finding, PrecisionTier, Severity } from "../findings.js";

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage"]);
const SOURCE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs)$/;

// Recursive file-tree walk shared by the detectors that scan their own tree rather than the
// shared loadSources() pass. Their original reason — "loadSources() excludes plain .js" — stopped
// being true on 2026-07-25 (#1065 widened it); they keep their own walk because they run inside
// runMechanicalScan, which has no SourceInput[] to hand them. Was copy-pasted verbatim across bola-owner.ts, job-tenant-scope.ts,
// and leftover-auth.ts — extracted here so a fix/hardening lands once, not three times (#766).
export function walkSourceFiles(dir: string, root: string = dir, out: SourceInput[] = []): SourceInput[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walkSourceFiles(full, root, out);
    else if (SOURCE_EXT.test(entry)) out.push({ path: relative(root, full), text: readFileSync(full, "utf8") });
  }
  return out;
}

// A mechanical pass has no human triage step, so BFTB inputs (value/ease/safety) can't be
// judged per-finding yet — these are conservative per-severity defaults, overridable by
// callers that know more (e.g. "missing lockfile" is cheap+safe to fix regardless of severity).
const DEFAULT_BFTB: Record<Severity, { value: number; ease: number; safety: number }> = {
  Critical: { value: 5, ease: 3, safety: 4 },
  High: { value: 4, ease: 3, safety: 4 },
  Medium: { value: 3, ease: 4, safety: 4 },
  Low: { value: 2, ease: 4, safety: 5 },
  Perf: { value: 3, ease: 3, safety: 4 },
  Info: { value: 1, ease: 5, safety: 5 },
  Watch: { value: 1, ease: 3, safety: 4 },
};

interface MechanicalFindingInput {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  taxonomy: string;
  location: string;
  evidence: string;
  impact: string;
  fix: string;
  precisionTier: PrecisionTier;
  confidence?: Finding["confidence"];
  bftb?: { value: number; ease: number; safety: number };
  // #455 — CWE/OWASP identifiers, threaded through from the source (e.g. semgrep rule metadata).
  cwe?: Finding["cwe"];
  owasp?: Finding["owasp"];
  // #874 — the npm package a Dependency CVE finding is about, so the reachability pass can rank it.
  dependency?: Finding["dependency"];
}

// "high" precision-tier findings are ground-truth (verified secret, decoded service-role
// hit, exact CVE match, advisor lint, HIGH-confidence ERROR Semgrep rule) so default their
// confidence to Confirmed; "review" tier findings are heuristic and need triage.
export function mechanicalFinding(input: MechanicalFindingInput): Finding {
  return {
    id: input.id,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence ?? (input.precisionTier === "high" ? "Confirmed" : "Review"),
    category: input.category,
    taxonomy: input.taxonomy,
    location: input.location,
    status: "Open",
    evidence: input.evidence,
    impact: input.impact,
    fix: input.fix,
    ...(input.bftb ?? DEFAULT_BFTB[input.severity]),
    mechanical: true,
    precisionTier: input.precisionTier,
    ...(input.cwe ? { cwe: input.cwe } : {}),
    ...(input.owasp ? { owasp: input.owasp } : {}),
    ...(input.dependency ? { dependency: input.dependency } : {}),
  };
}
