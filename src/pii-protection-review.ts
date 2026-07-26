// M10 [LLM] — PII-protection adequacy pass (#201). tools/pii-classify.mjs DETECTS PII/PHI/PCI
// columns by name+type; it doesn't judge whether they're PROTECTED. This pass takes the M10
// classification plus connected-tier exposure facts (checkExposedSchemas / checkAutoExposedTables)
// and surfaces detected-but-unprotected columns: a sensitive column reachable by the anon key
// (auto-exposed public table or exposed API schema) that isn't encrypted at rest. Columns in an
// unexposed schema, or encrypted (pgsodium/Vault), are cleared.
//
// #1043: this is what the connected tier sells ("PII protection verified in production") and until
// that issue it had ZERO production callers — the check existed, was unit-tested, and never ran. It
// is now driven by tools/pii-classify.mjs's live tier, which gathers the ExposureFacts below from
// the same read-only connection. protectionScope() is the other half: on any tier that CANNOT
// gather them, the deliverable says protection was not verified rather than staying silent, because
// a report that shows a longer sensitive-column list and no protection verdict reads as a verdict.

import type { Finding, Severity } from "./findings.js";
import { reviewFinding } from "./review-tier.js";

export interface ClassifiedColumn {
  schema: string;
  table: string;
  column: string;
  // SECRET is the classifier's stored-credential class (tools/pii-classify.mjs CATEGORY_POINTS) —
  // scored like PHI/PCI here because a plaintext credential reachable by the anon key is the same
  // failure with a larger blast radius.
  category: "PII" | "SENSITIVE_PII" | "PHI" | "PCI" | "SECRET";
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

// #1043 — the coverage row for the protection VERDICT itself, emitted on every tier so the client
// can tell "we checked and these columns are protected" from "we never checked". Both branches are
// Info/N-A rows: they report on the check, not on a defect.
//
// The limits are stated on the assessed branch too. A protection check that names only what it
// found, and not what it could not see, is the same clean-bill-of-health failure one level up.
export function piiProtectionScope(
  scope: { assessed: false; reason: string } | { assessed: true; detail: string; columnsChecked: number; unprotected: number },
): Finding {
  if (!scope.assessed) {
    return {
      id: "M10-PROT-00",
      title: "PII protection NOT verified — no live database connection on this run",
      severity: "Info",
      confidence: "N/A",
      category: "Data protection",
      taxonomy: "M10 — PII/PHI/PCI protection",
      location: "(engagement-wide)",
      status: "Open",
      evidence: `M10 classified which columns hold PII/PHI/PCI, but made NO judgment about whether any of them is protected. Verifying protection needs facts that exist only on a live connection — per-table RLS state (pg_class.relrowsecurity), anon/authenticated SELECT grants (information_schema.role_table_grants), and encryption-at-rest (pgsodium masking rules). Reason: ${scope.reason} [MEASURED — this run gathered none of those three inputs.]`,
      impact:
        "The sensitive-column list in this report is an inventory, not a verdict. No column here has been shown to be either protected or exposed; treat every one as unverified. Falsifier: re-run `SUPABASE_DB_URL=<read-only url> pnpm pii-classify` — the connected tier gathers the three inputs above and replaces this row with a per-column verdict.",
      fix: "Run the connected tier against a read-only database connection so each classified column gets a protection verdict.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    };
  }
  return {
    id: "M10-PROT-00",
    title: `PII protection verified against the live database — ${scope.columnsChecked} classified column(s) checked, ${scope.unprotected} unprotected`,
    severity: "Info",
    confidence: "N/A",
    category: "Data protection",
    taxonomy: "M10 — PII/PHI/PCI protection",
    location: "(engagement-wide)",
    status: "Open",
    evidence: `${scope.detail} Each asserted PII/PHI/PCI/secret column was judged reachable-and-plaintext or cleared; every unprotected one is its own M10-PII-nn finding. [MEASURED — read-only catalog queries on this run.]`,
    impact:
      "What this verdict does NOT cover: application-layer encryption (invisible to a catalog read, so a column encrypted by the app reads as plaintext here); the quality of an RLS policy on a table that HAS RLS enabled (M1 judges that, not this check); schemas other than `public`; and review-flagged columns (free-text/JSON containers), which are candidates for inspection rather than asserted classifications and are not verdicted.",
    fix: "Address each M10-PII-nn finding; for a column encrypted at the application layer, record that as the answer to its review question so the next audit's baseline carries it.",
    value: 1,
    ease: 4,
    safety: 5,
    mechanical: true,
  };
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
