import { ENGAGEMENT_REQUIREMENTS_VERSION, engagementRequirement } from "./engagement-requirements.js";
import type { Finding, Severity } from "./findings.js";
import { reviewFinding } from "./review-tier.js";

export interface ClassifiedColumn {
  schema: string;
  table: string;
  column: string;
  category: "PII" | "SENSITIVE_PII" | "PHI" | "PCI" | "SECRET";
  infotype: string;
  /** A supplied protection fact; catalog configuration alone does not set this. */
  encrypted: boolean;
}

export interface ColumnReadAccess {
  schema: string;
  table: string;
  column: string;
  principals: { role: string; read: "all" | "none" | "conditional"; reason: string }[];
}

export interface ExposureFacts {
  exposedSchemas: string[];
  autoExposedTables: string[];
  /** Undefined retains the schema-only review path; an empty array is unavailable evidence. */
  columnAccess?: ColumnReadAccess[];
  apiConfigurationKnown?: boolean;
  provenance?: string;
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
  if (col.encrypted) return null;
  if (facts.apiConfigurationKnown !== false && !schemaExposed && !tableExposed) return null;
  let access: string;
  if (facts.columnAccess !== undefined) {
    const column = facts.columnAccess.find((entry) => entry.schema === col.schema && entry.table === col.table && entry.column === col.column);
    const principals = column?.principals.filter((p) => p.role === "anon" || p.role === "authenticated") ?? [];
    if (principals.length === 2 && principals.every((p) => p.read === "none")) return null;
    access = principals.length
      ? principals.map((p) => `${p.role} SELECT=${p.read} (${p.reason})`).join("; ")
      : "effective column SELECT and row-policy evidence is unavailable for the client roles";
    if (facts.apiConfigurationKnown === false) access += "; API schema configuration is unavailable, so API reachability is unverified";
    else access += "; this column belongs to an exposed API schema";
  } else {
    access = `this column belongs to ${tableExposed ? "a table identified as potentially exposed" : "an exposed API schema"}; schema/table exposure alone does not prove permission to read this column or any row`;
  }
  return {
    column: qualified,
    category: col.category,
    reason: `${col.category}/${col.infotype} is a name/type sensitivity classification. Access evidence: ${access}. Encryption and masking adequacy remain unverified; missing encryption metadata is not evidence of plaintext. Provenance: ${facts.provenance ?? "supplied exposure metadata"}.`,
  };
}

export function piiProtectionScope(
  scope: { assessed: false; reason: string } | { assessed: true; detail: string; columnsChecked: number; unprotected: number },
): Finding {
  const requirements = ["database.schema-scope", "database.catalog", "database.api-configuration", "database.authorization", "database.encryption-boundaries"].map(engagementRequirement);
  const prerequisites = `Prerequisite contract ${ENGAGEMENT_REQUIREMENTS_VERSION}. ` + requirements.map((r) => `${r.id}: ${r.limitation} Metadata needed: ${r.metadata.join("; ")}. Access needed: ${r.access.join("; ")}. Falsifier: ${r.falsifier} Next step: ${r.nextStep}`).join(" ");
  return {
    id: "M10-PROT-00",
    title: scope.assessed
      ? `PII protection review — ${scope.columnsChecked} classified column(s), ${scope.unprotected} access/protection question(s)`
      : "PII protection NOT verified — protection evidence unavailable on this run",
    severity: "Info",
    confidence: "N/A",
    category: "Data protection",
    taxonomy: "M10 — PII/PHI/PCI protection",
    location: "(engagement-wide)",
    status: "Open",
    evidence: scope.assessed
      ? `${scope.detail} Sensitivity, effective direct column access, and encryption adequacy are separate assessments. No production row values were sampled by the catalog assessment. Review-flagged free-text/JSON containers are not asserted sensitive columns. [MEASURED — read-only catalog/configuration evidence.] ${prerequisites}`
      : `Name/type classification is an inventory, not a protection verdict. Reason: ${scope.reason}. [MEASURED — protection metadata was not assessed on this run.] ${prerequisites}`,
    impact: `No finding is a claim that encryption is absent. A denied direct client SELECT path does not certify views, RPCs, application/server roles, backups, storage encryption, or key management. Prerequisite contract ${ENGAGEMENT_REQUIREMENTS_VERSION}. ${requirements.map((r) => `${r.id}: ${r.limitation} Falsifier: ${r.falsifier}`).join(" ")}`,
    fix: requirements.map((r) => `${r.id}: ${r.nextStep}`).join(" "),
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
    .map((r, i) => reviewFinding({
      id: `M10-PII-${String(i + 1).padStart(2, "0")}`,
      title: `Review ${r.category} access and protection: ${r.column}`,
      severity: severityFor(r.category),
      category: "Data protection",
      taxonomy: "M10 — PII/PHI/PCI protection",
      location: r.column,
      evidence: r.reason,
      question: "Do the supported client roles have an intended read path to this sensitive column, and what evidence covers encryption and masking along that path?",
      impact: "Sensitive information could be disclosed if the observed or unresolved read path returns raw values. Classification and incomplete protection evidence alone do not establish a vulnerability.",
      fix: "Review the exact column grants, applicable row policies, views/RPCs and source encryption boundaries using synthetic fixtures. Supply configuration and reviewed source provenance; do not infer plaintext from absent catalog metadata.",
      okWhen: "The read path is intended and appropriately restricted, or verified encryption/masking covers every relevant path.",
      notOkWhen: "A synthetic control demonstrates unintended reading of a raw sensitive value by a client role.",
    }));
}
