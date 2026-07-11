// M10 [LLM] — PII-protection adequacy pass (#201). tools/pii-classify.mjs DETECTS PII/PHI/PCI
// columns by name+type; it doesn't judge whether they're PROTECTED. This pass takes the M10
// classification plus connected-tier exposure facts (checkExposedSchemas / checkAutoExposedTables)
// and surfaces detected-but-unprotected columns: a sensitive column reachable by the anon key
// (auto-exposed public table or exposed API schema) that isn't encrypted at rest. Columns in an
// unexposed schema, or encrypted (pgsodium/Vault), are cleared.

import type { Finding, Severity } from "./findings.js";
import { reviewFinding } from "./review-tier.js";

export interface ClassifiedColumn {
  schema: string;
  table: string;
  column: string;
  category: "PII" | "SENSITIVE_PII" | "PHI" | "PCI";
  infotype: string;
  // Encrypted at rest via pgsodium/Vault (a connected-tier fact).
  encrypted: boolean;
}

export interface ExposureFacts {
  // Schemas reachable over PostgREST beyond the internal default (from checkExposedSchemas input).
  exposedSchemas: string[];
  // "schema.table" for public tables with RLS disabled — anon-reachable (checkAutoExposedTables).
  autoExposedTables: string[];
}

function severityFor(category: ClassifiedColumn["category"]): Severity {
  return category === "PII" ? "Medium" : "High";
}

interface PiiExposure {
  column: string;
  reason: string;
  category: ClassifiedColumn["category"];
}

export function reviewPiiColumn(col: ClassifiedColumn, facts: ExposureFacts): PiiExposure | null {
  const qualified = `${col.schema}.${col.table}.${col.column}`;
  const schemaExposed = facts.exposedSchemas.map((s) => s.trim()).includes(col.schema);
  const tableExposed = facts.autoExposedTables.includes(`${col.schema}.${col.table}`);
  if ((schemaExposed || tableExposed) && !col.encrypted) {
    return {
      column: qualified,
      category: col.category,
      reason: `${col.category}/${col.infotype} column is reachable via ${tableExposed ? "an auto-exposed public table" : "an exposed API schema"} and is not encrypted at rest.`,
    };
  }
  return null;
}

export function piiProtectionFindings(columns: ClassifiedColumn[], facts: ExposureFacts): Finding[] {
  return columns
    .map((c) => reviewPiiColumn(c, facts))
    .filter((r): r is PiiExposure => r !== null)
    .map((r, i) =>
      reviewFinding({
        id: `M10-PII-${String(i + 1).padStart(2, "0")}`,
        title: `Unprotected ${r.category} column ${r.column}`,
        severity: severityFor(r.category),
        category: "Data protection",
        taxonomy: "M10 — PII/PHI/PCI protection",
        location: r.column,
        evidence: r.reason,
        question: "Is this sensitive column adequately protected — encrypted at rest, masked in the exposed view, or otherwise not readable past RLS by the anon/authenticated key?",
        impact: "A detected sensitive column reachable by the anon key with no encryption is a plaintext data-exposure path — exactly the class the M10 taxonomy expects to be protected.",
        fix: "Encrypt the column at rest (pgsodium/Vault), move it out of the exposed schema, or mask it behind an RLS-scoped view; confirm the anon/authenticated grant can't read the raw value.",
        okWhen: "The column is encrypted at rest, or not reachable by the anon/authenticated key, or masked in every exposed view/RPC.",
        notOkWhen: "The raw sensitive value is readable by the anon/authenticated key with no encryption or masking.",
      }),
    );
}
