// M7 (performance) — shapes the Supabase performance advisor's "lints" (Management API
// `GET /v1/projects/{ref}/advisors/performance`) into Finding[] (src/findings.ts) for §3b of
// the audit report. Pure transform only; src/cli/perf-scan.ts does the API call.
//
// Findings are grouped by lint rule name (one Finding per rule, count in the title) rather
// than one per row — a real engagement can surface 100+ unindexed FKs and a client needs
// "124 unindexed foreign keys, here's the migration" not 124 near-identical rows. The
// severity/value/ease/safety for the two curated DB rules below aren't guessed: they mirror
// F-04/F-05/F-07 in report-template/findings.atc.json, a real prior engagement's advisor pull
// (see docs/m7-performance.md for the mapping into the report).

import type { Finding, Severity } from "./findings.js";

type AdvisorLevel = "ERROR" | "WARN" | "INFO";

export interface AdvisorLint {
  name: string;
  title: string;
  level: AdvisorLevel;
  detail: string;
  categories?: string[];
  description?: string;
  remediation?: string;
  metadata?: { schema?: string; name?: string; type?: string };
  cache_key?: string;
}

export interface AdvisorReport {
  lints: AdvisorLint[];
}

interface LintProfile {
  taxonomy: string;
  impact: string;
  fix: string;
  severity: Severity;
  value: number;
  ease: number;
  safety: number;
  title: (count: number) => string;
}

// Curated profiles for the performance-advisor rules Harvey has actually seen and fixed on a
// real engagement, or that Supabase's advisor docs describe unambiguously enough to score
// confidently. Any other rule name falls back to a level-derived profile below — reported,
// never dropped.
const LINT_PROFILES: Record<string, LintProfile> = {
  unindexed_foreign_keys: {
    taxonomy: "Missing index",
    impact: "Sequential scans on parent UPDATE/DELETE and FK JOINs; degrades at scale.",
    fix: "Additive covering-index migration for each listed foreign key.",
    severity: "Perf",
    value: 4,
    ease: 5,
    safety: 5,
    title: (n) => `${n} unindexed foreign key${n === 1 ? "" : "s"}`,
  },
  auth_rls_initplan: {
    taxonomy: "auth_rls_initplan",
    impact: "auth.uid()/auth.role() (or other auth.* calls) evaluated per-row instead of once per query.",
    fix: "Wrap the call in (select …) — e.g. auth.uid() → (select auth.uid()) — to hoist it to a once-per-query initplan. Verify the rewritten policy is behavior-identical before shipping.",
    severity: "Perf",
    value: 4,
    ease: 4,
    safety: 4,
    title: (n) => (n === 1 ? "1 RLS policy re-evaluates auth.* per row" : `${n} RLS policies re-evaluate auth.* per row`),
  },
  unused_index: {
    taxonomy: "Index hygiene",
    impact: "Write & storage overhead for an index the query planner isn't using.",
    fix: "DROP INDEX CONCURRENTLY after confirming it doesn't back a rare-but-critical path or a UNIQUE constraint.",
    severity: "Low",
    value: 2,
    ease: 2,
    safety: 3,
    title: (n) => `${n} unused index${n === 1 ? "" : "es"}`,
  },
  multiple_permissive_policies: {
    taxonomy: "Redundant RLS policies",
    impact: "Postgres evaluates every permissive policy for the same role+action — each extra policy multiplies the per-row check cost.",
    fix: "Consolidate the permissive policies for the same role/action into one.",
    severity: "Perf",
    value: 3,
    ease: 3,
    safety: 3,
    title: (n) => `${n} table${n === 1 ? "" : "s"} with multiple permissive policies for the same role/action`,
  },
  duplicate_index: {
    taxonomy: "Redundant index",
    impact: "Identical indexes waste storage and write throughput without adding query benefit.",
    fix: "Drop the duplicate, keep one.",
    severity: "Low",
    value: 2,
    ease: 4,
    safety: 4,
    title: (n) => `${n} duplicate index${n === 1 ? "" : "es"}`,
  },
};

// Fallback for any performance lint Supabase adds that isn't curated above.
const LEVEL_FALLBACK: Record<AdvisorLevel, Severity> = { ERROR: "High", WARN: "Perf", INFO: "Low" };
const LEVEL_BFTB: Record<AdvisorLevel, { value: number; ease: number; safety: number }> = {
  ERROR: { value: 4, ease: 3, safety: 4 },
  WARN: { value: 3, ease: 3, safety: 4 },
  INFO: { value: 2, ease: 3, safety: 4 },
};

// #1083 — exported so src/scan/supabase-advisors.ts can route a PERFORMANCE-category lint (Splinter
// returns SECURITY and PERFORMANCE lints together on the local/connected tier) through the SAME
// curated impact/fix text as the hosted M7 advisor pull, instead of a second, drifting copy.
export function profileFor(lint: AdvisorLint): LintProfile {
  const curated = LINT_PROFILES[lint.name];
  if (curated) return curated;
  return {
    taxonomy: `Advisor: ${lint.name}`,
    impact: lint.description ?? `Flagged ${lint.level} by the Supabase performance advisor.`,
    fix: lint.remediation ?? "See the Supabase performance advisor remediation link for this rule.",
    severity: LEVEL_FALLBACK[lint.level],
    ...LEVEL_BFTB[lint.level],
    title: (n) => `${n} × ${lint.title || lint.name}`,
  };
}

const MAX_LISTED_TABLES = 8;

function locationFor(lints: AdvisorLint[]): string {
  const tables = [...new Set(lints.map((l) => (l.metadata?.schema && l.metadata?.name ? `${l.metadata.schema}.${l.metadata.name}` : undefined)).filter((v): v is string => Boolean(v)))];
  if (tables.length === 0) return "main DB";
  if (tables.length <= MAX_LISTED_TABLES) return tables.join(", ");
  return `${tables.slice(0, MAX_LISTED_TABLES).join(", ")}, +${tables.length - MAX_LISTED_TABLES} more`;
}

// Groups lints by rule name (see module header) and sorts groups worst-first (highest instance
// count — a rule hitting 124 tables is a bigger remediation lift than one hitting 2).
export function parseAdvisorFindings(report: AdvisorReport): Finding[] {
  const groups = new Map<string, AdvisorLint[]>();
  for (const lint of report.lints) {
    const list = groups.get(lint.name);
    if (list) list.push(lint);
    else groups.set(lint.name, [lint]);
  }

  const sorted = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);

  return sorted.map(([name, lints], i): Finding => {
    const first = lints[0];
    if (!first) throw new Error(`unreachable: empty lint group for rule "${name}"`);
    const profile = profileFor(first);
    const count = lints.length;

    return {
      id: `M7-${String(i + 1).padStart(2, "0")}`,
      title: profile.title(count),
      severity: profile.severity,
      confidence: "Confirmed",
      category: "Performance",
      taxonomy: profile.taxonomy,
      location: locationFor(lints),
      // Supabase performance-advisor lints are schema-truth (Splinter runs against the live
      // schema) — ~100% precise once connected, the same trust class as a verified secret or an
      // exact CVE match (src/findings.ts's PRECISION_TIERS comment). The corpus's "connected"
      // expectedTier (src/scan/calibration/m7.entries.ts) tracks the separate live-DB dependency.
      precisionTier: "high",
      status: "Open",
      evidence: `Supabase performance advisor: ${name}.${first.detail ? ` e.g. "${first.detail}"` : ""}`,
      impact: profile.impact,
      fix: profile.fix,
      value: profile.value,
      ease: profile.ease,
      safety: profile.safety,
    };
  });
}
