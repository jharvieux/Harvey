// #1049 — M10's data-aware severity join, the module's stated differentiator (briefs/audit-modules.md
// "What it unlocks"): a cross-tenant gap on a table holding email + DOB + passport is not the same
// finding as the same gap on a preferences table, and the report must not price them the same.
//
// tools/pii-classify.mjs already scores every classified table on the SAME Severity ladder as
// src/findings.ts (see its scoreToSeverity: "Labels match src/findings.ts's Severity enum so a
// caller can drop `severity` straight into Finding.severity") — this is that caller. It is the
// hotspot mechanism's sibling (src/hotspot-scan.ts enrichFindingsWithHotspots): ONE join applied at
// assembly time to every module's findings, not a per-module reimplementation.
//
// Two deliberate limits:
//   * It only ever RAISES a severity. A benign-looking table is never evidence that a finding is
//     less serious than its own module judged it — the data map is an escalation signal, not a
//     clearance one.
//   * The BFTB inputs (value/ease/safety) are untouched, same as the hotspot join: severity says
//     how bad, BFTB says what to do first, and double-counting the same signal in both would
//     quietly re-rank the remediation plan on one input.

import type { Finding, Severity } from "./findings.js";

// The shape tools/pii-classify.mjs's buildDataMap emits (and writes to --data-map-out), keyed by
// table name. Only the fields this join reads are declared.
export interface ClassifiedTable {
  columns: { column: string; infotype: string; category: string; confidence: string }[];
  infotypes: string[];
  categories: string[];
  severityScore: number;
  severity: Severity;
}

export type DataClassMap = Record<string, ClassifiedTable>;

// The graded security ladder. Perf/Info/Watch are a different scale entirely — escalating a
// perf finding to Critical because it names a PHI table would be a category error, so findings
// outside this ladder are matched but never re-severitied.
const LADDER: Severity[] = ["Low", "Medium", "High", "Critical"];
const rank = (s: Severity): number => LADDER.indexOf(s);

export function isDataClassMap(value: unknown): value is DataClassMap {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  return Object.values(value).every((t) => {
    const row = t as Partial<ClassifiedTable>;
    return typeof row === "object" && row !== null && Array.isArray(row.categories) && typeof row.severity === "string";
  });
}

// A finding is joined to a table only through a DB-qualified reference — `public.invoices`,
// `storage.objects`, `public.profiles.profiles_select_self` — or a location that IS the bare table
// name (the live M10/PostgREST tier's format). A bare token match anywhere in a path would escalate
// `src/notes/route.ts` off a `notes` table, so the schema qualifier is the precision gate. Both the
// location AND the title are searched because the emitters split the reference between them: the
// RLS-policy findings put `public.documents.documents_select_all` in the location, while the
// missing-RLS findings put `public.audit_logs` in the title and only the migration file in the
// location (verified against dry-run/findings.json, 2026-07-25).
function referencesTable(f: Finding, table: string): boolean {
  if (f.location === table) return true;
  const escaped = table.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_.])[A-Za-z_][A-Za-z0-9_]*\\.${escaped}(?![A-Za-z0-9_])`).test(`${f.location} ${f.title}`);
}

// M10's own classification findings ARE the data map projected into findings — their severity is
// already the table's score, so joining them to it would be circular.
const isM10Finding = (f: Finding): boolean => f.taxonomy.startsWith("M10");

// Escalates every finding whose location/title names an M10-classified table to that table's data
// severity, when the table's is higher. `dataClass` carries WHY in the finding itself — the reader
// sees which table, which categories, which infotypes, and what the severity was before — because
// a silently higher number is an assertion the client cannot check.
export function escalateFindingsByDataClass(findings: Finding[], dataMap: DataClassMap): Finding[] {
  const tables = Object.entries(dataMap);
  return findings.map((f) => {
    if (isM10Finding(f)) return f;
    // Worst table first: a finding naming two classified tables is priced by the more sensitive one.
    const matches = tables.filter(([table]) => referencesTable(f, table)).sort((a, b) => b[1].severityScore - a[1].severityScore);
    const match = matches[0];
    if (!match) return f;
    const [table, t] = match;
    const escalates = rank(f.severity) >= 0 && rank(t.severity) > rank(f.severity);
    const classes = `${t.categories.join("/")} (${t.infotypes.join(", ")})`;
    return {
      ...f,
      ...(escalates ? { severity: t.severity } : {}),
      dataClass: {
        table,
        categories: t.categories,
        infotypes: t.infotypes,
        ...(escalates ? { escalatedFrom: f.severity } : {}),
        reason: escalates
          ? `Severity raised ${f.severity} → ${t.severity}: this finding names \`${table}\`, which M10 classified as holding ${classes} — data score ${t.severityScore}.`
          : `\`${table}\` holds ${classes} (M10 data score ${t.severityScore}) — no escalation: the finding's own severity already meets or exceeds the table's data severity ${t.severity}.`,
      },
    };
  });
}

// The coverage-guard half (#1049 acceptance criterion 2). With no data map, EVERY severity in the
// report is un-escalated — and an un-escalated severity is indistinguishable from one that was
// checked against the data map and left alone. Silence there reads as "we looked and the data is
// benign", which was never measured. So the absence of the join is stated as a row of its own.
export function dataClassJoinNotAssessed(reason: string): Finding {
  return {
    id: "M10-ESCALATION-00",
    title: "Data-aware severity escalation NOT applied — no M10 data map for this run",
    severity: "Info",
    confidence: "N/A",
    category: "Data classification",
    taxonomy: "M10 — Data-aware severity escalation",
    location: "(engagement-wide)",
    status: "Open",
    evidence: `M10 produced no table→PII/PHI/PCI data map this run, so no finding in this report was weighted by the sensitivity of the data it touches. Reason: ${reason}`,
    impact:
      "Every severity here is the detecting module's own. A tenant-isolation or exposure finding on a table holding health, payment-card, or government-ID data is reported at exactly the same severity as one on a preferences table — so the remediation order in this report is not data-aware. Absence of an escalation is NOT evidence the data is benign.",
    fix: "Re-run with an M10 data map available — point the run at the schema (`--schema <migrations dir | schema.sql | schema.prisma>`) or at a live database (connected tier) so table sensitivity can weight every module's severities.",
    value: 1,
    ease: 4,
    safety: 5,
    mechanical: true,
  };
}
