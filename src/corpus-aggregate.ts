// Corpus-level aggregation for the flagship original-research report (#726). Consumes N per-app
// engagement findings.json documents (the exact shape run-audit --findings-out emits) and derives
// ONE defensible, anonymized, corpus-level statistic plus a shareable summary — the citable number
// the GTM's marketing engine (docs/gtm/04-marketing-engine.md Input 2) and AEO play
// (docs/gtm/06-seo-aeo.md) are built on.
//
// Two disciplines are load-bearing here and both come straight from the audit doctrine:
//   1. Anonymization. The summary NEVER carries an app's identity — meta.client is dropped on the
//      way in and each app becomes an opaque ordinal ("app-01"). The published number is aggregate
//      only; responsible disclosure for any identifiable app is an operator gate, not this tool's job.
//   2. Honest denominators (the coverage guard, applied to a corpus). A module-gated stat like
//      "cross-tenant exposure" is a claim ONLY about apps whose M1 tier actually ran. An app whose
//      coverage ledger does not show M1 as "ran" is NOT evidence of absence — it is excluded from
//      that stat's denominator and counted in a caveat, never silently folded in as a clean app.

import type { CoverageRow, Finding, FindingsDocument, Severity } from "./findings.js";
import { SEVERITIES } from "./findings.js";

// Severities that make an app "materially at risk" for the headline severity stat.
const HIGH_SEVERITIES: readonly Severity[] = ["Critical", "High"];

// Default keyword predicate for the "cross-tenant / tenant-isolation data exposure" finding class,
// matched case-insensitively against a finding's taxonomy + category + title. It is a HEURISTIC and
// operator-tunable — the Finding schema carries no reliable module tag, so this keyword pass is how
// a tenant-isolation finding is recognized. The methodology doc requires the published stat's
// predicate be FIXED before the corpus is run, never chosen after seeing which wording maximizes the
// number.
const CROSS_TENANT_KEYWORDS: readonly string[] = [
  "tenant",
  "cross-tenant",
  "rls",
  "row level security",
  "row-level security",
  "isolation",
  "idor",
  "bola",
  "auto-exposed",
  "public-schema table",
  "authorization",
  "authz",
];

function emptySeverityTally(): Record<Severity, number> {
  return Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
}

function moduleRan(coverage: CoverageRow[] | undefined, module: string): boolean {
  if (!coverage) return false;
  // On a monorepo the module can appear per-instance; "ran" anywhere means the tier executed.
  return coverage.some((r) => r.module === module && r.status === "ran");
}

function matchesCrossTenant(f: Finding, keywords: readonly string[]): boolean {
  const hay = `${f.taxonomy} ${f.category} ${f.title}`.toLowerCase();
  return keywords.some((k) => hay.includes(k));
}

interface AppRecord {
  label: string; // anonymized ordinal — never the client name
  findingCount: number;
  bySeverity: Record<Severity, number>;
  distinctTaxonomies: string[];
  m1Ran: boolean;
  hasCoverageLedger: boolean;
  hasHighSeverity: boolean;
  hasCrossTenant: boolean;
}

interface CorpusStat {
  key: string;
  label: string;
  numerator: number;
  denominator: number;
  pct: number | null; // null when denominator is 0 — never divide-by-zero into a fake number
  gatedBy: string | null; // module whose "ran" status defines the denominator, or null = all apps
  headline: string;
}

interface ModuleCoverageStat {
  module: string;
  appsRan: number; // apps whose ledger shows this module status "ran"
  appsTotal: number;
}

export interface CorpusSummary {
  generatedAt: string;
  appsTotal: number;
  anonymized: true;
  severityTotals: Record<Severity, number>;
  medianFindingsPerApp: number;
  stats: CorpusStat[];
  moduleCoverage: ModuleCoverageStat[];
  topTaxonomies: { taxonomy: string; apps: number }[];
  caveats: string[];
}

interface AggregateOptions {
  crossTenantKeywords?: readonly string[];
  now?: Date; // injectable for deterministic tests
}

function median(nums: number[]): number {
  if (nums.length === 0) return 0;
  const sorted = [...nums].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1]! + sorted[mid]!) / 2 : sorted[mid]!;
}

function pct(numerator: number, denominator: number): number | null {
  if (denominator === 0) return null;
  return Math.round((numerator / denominator) * 100);
}

function summarizeApp(doc: FindingsDocument, index: number, keywords: readonly string[]): AppRecord {
  const label = `app-${String(index + 1).padStart(2, "0")}`;
  const findings = doc.findings ?? [];
  const bySeverity = emptySeverityTally();
  const taxonomies = new Set<string>();
  let hasHighSeverity = false;
  let hasCrossTenant = false;

  for (const f of findings) {
    bySeverity[f.severity] += 1;
    if (f.taxonomy) taxonomies.add(f.taxonomy);
    if (HIGH_SEVERITIES.includes(f.severity)) hasHighSeverity = true;
    if (HIGH_SEVERITIES.includes(f.severity) && matchesCrossTenant(f, keywords)) hasCrossTenant = true;
  }

  return {
    label,
    findingCount: findings.length,
    bySeverity,
    distinctTaxonomies: [...taxonomies].sort(),
    m1Ran: moduleRan(doc.coverage, "M1"),
    hasCoverageLedger: Array.isArray(doc.coverage),
    hasHighSeverity,
    hasCrossTenant,
  };
}

export function aggregateCorpus(docs: FindingsDocument[], opts: AggregateOptions = {}): CorpusSummary {
  const keywords = opts.crossTenantKeywords ?? CROSS_TENANT_KEYWORDS;
  const apps = docs.map((d, i) => summarizeApp(d, i, keywords));
  const caveats: string[] = [];

  const severityTotals = emptySeverityTally();
  for (const app of apps) for (const s of SEVERITIES) severityTotals[s] += app.bySeverity[s];

  // Coverage guard on the corpus: an app with no coverage ledger cannot be asserted to have run any
  // tier, so it is excluded from every module-gated denominator. Say so loudly — an unstated
  // exclusion reads as a clean bill of health.
  const noLedger = apps.filter((a) => !a.hasCoverageLedger);
  if (noLedger.length > 0) {
    caveats.push(
      `${noLedger.length} of ${apps.length} app(s) had no coverage ledger; excluded from module-gated ` +
        `denominators (cross-tenant stat), counted only in whole-corpus severity totals.`,
    );
  }

  const m1RanApps = apps.filter((a) => a.m1Ran);
  const crossTenantApps = m1RanApps.filter((a) => a.hasCrossTenant);
  const highSevApps = apps.filter((a) => a.hasHighSeverity);

  const stats: CorpusStat[] = [
    {
      key: "high_severity",
      label: "Apps with at least one Critical or High finding",
      numerator: highSevApps.length,
      denominator: apps.length,
      pct: pct(highSevApps.length, apps.length),
      gatedBy: null,
      headline: `${pct(highSevApps.length, apps.length) ?? 0}% of ${apps.length} public Supabase apps had at least one Critical or High severity finding.`,
    },
    {
      key: "cross_tenant_exposure",
      label: "Apps with a Critical/High cross-tenant (tenant-isolation) finding, among apps where M1 ran",
      numerator: crossTenantApps.length,
      denominator: m1RanApps.length,
      pct: pct(crossTenantApps.length, m1RanApps.length),
      gatedBy: "M1",
      headline:
        m1RanApps.length === 0
          ? "Cross-tenant exposure stat not computable: M1 did not run on any app in the corpus."
          : `${pct(crossTenantApps.length, m1RanApps.length) ?? 0}% of ${m1RanApps.length} public Supabase apps (where multi-tenant analysis ran) had a cross-tenant data-exposure finding.`,
    },
  ];

  const moduleCoverage: ModuleCoverageStat[] = Array.from({ length: 10 }, (_, i) => {
    const module = `M${i + 1}`;
    return { module, appsRan: docs.filter((d) => moduleRan(d.coverage, module)).length, appsTotal: apps.length };
  });

  const taxonomyApps = new Map<string, number>();
  for (const app of apps) for (const t of app.distinctTaxonomies) taxonomyApps.set(t, (taxonomyApps.get(t) ?? 0) + 1);
  const topTaxonomies = [...taxonomyApps.entries()]
    .map(([taxonomy, appsCount]) => ({ taxonomy, apps: appsCount }))
    .sort((a, b) => b.apps - a.apps || a.taxonomy.localeCompare(b.taxonomy))
    .slice(0, 15);

  return {
    generatedAt: (opts.now ?? new Date()).toISOString(),
    appsTotal: apps.length,
    anonymized: true,
    severityTotals,
    medianFindingsPerApp: median(apps.map((a) => a.findingCount)),
    stats,
    moduleCoverage,
    topTaxonomies,
    caveats,
  };
}

export function renderSummaryText(summary: CorpusSummary): string {
  const lines: string[] = [];
  lines.push(`# Corpus audit — aggregate summary`);
  lines.push("");
  lines.push(`Apps in corpus: ${summary.appsTotal}    Generated: ${summary.generatedAt}`);
  lines.push(`Median findings per app: ${summary.medianFindingsPerApp}`);
  lines.push("");
  lines.push(`## Headline statistics`);
  for (const s of summary.stats) {
    const frac = `${s.numerator}/${s.denominator}`;
    const gate = s.gatedBy ? ` (denominator gated by ${s.gatedBy} having run)` : "";
    lines.push(`- ${s.headline}  [${frac}${gate}]`);
  }
  lines.push("");
  lines.push(`## Severity totals across the corpus`);
  for (const s of SEVERITIES) lines.push(`- ${s}: ${summary.severityTotals[s]}`);
  lines.push("");
  lines.push(`## Module coverage across the corpus (apps where each tier ran)`);
  for (const m of summary.moduleCoverage) lines.push(`- ${m.module}: ran on ${m.appsRan}/${m.appsTotal}`);
  lines.push("");
  lines.push(`## Most prevalent finding classes (by number of apps affected)`);
  for (const t of summary.topTaxonomies) lines.push(`- ${t.apps} app(s): ${t.taxonomy}`);
  if (summary.caveats.length > 0) {
    lines.push("");
    lines.push(`## Caveats`);
    for (const c of summary.caveats) lines.push(`- ${c}`);
  }
  lines.push("");
  lines.push(
    `Anonymized aggregate only. No app is identified here. Publishing any app-specific detail is ` +
      `gated on operator-run responsible disclosure — see docs/research/flagship-supabase-audit-methodology.md.`,
  );
  return lines.join("\n");
}
