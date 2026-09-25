import { engagementRequirement } from "./engagement-requirements.js";

/** Non-secret intake requirements shared by source and connected audit consumers. */
interface AuditPrerequisite {
  id: string;
  modules: readonly string[];
  capability: string;
  requestedInput: string;
  accessBoundary: string;
  ifUnavailable: string;
  verification: string;
}

const requirementGroups: Record<string, readonly string[]> = {
  "dependency-metadata": ["registry.public-metadata", "registry.private-authorization"],
  "database-catalog": ["database.schema-scope", "database.catalog", "database.authorization"],
  "platform-configuration": ["database.api-configuration"],
  "application-protection": ["database.encryption-boundaries"],
};

/** Keep stable public anchors while delivering the scanner's exact prerequisite records. */
function withAssessmentRequirements(row: AuditPrerequisite): AuditPrerequisite {
  const details = requirementGroups[row.id]!.map(engagementRequirement);
  return {
    ...row,
    requestedInput: [row.requestedInput, ...details.flatMap((detail) => detail.metadata)].join(" "),
    accessBoundary: [row.accessBoundary, ...details.flatMap((detail) => detail.access)].join(" "),
    ifUnavailable: [row.ifUnavailable, ...details.map((detail) => detail.limitation)].join(" "),
    verification: [row.verification, ...details.flatMap((detail) => [detail.falsifier, detail.nextStep])].join(" "),
  };
}

export const AUDIT_PREREQUISITES = {
  version: 1,
  requirements: [
    {
      id: "dependency-metadata",
      modules: ["M1"],
      capability: "Dependency licenses, declarations and install scripts",
      requestedInput: "Lockfiles and every local/workspace package manifest, including license files; identify private or unpublished packages and their registry hosts.",
      accessBoundary: "Use local metadata first. Agree which registry metadata endpoints may be contacted. If private metadata needs authentication, use a read-only package-scoped grant through the agreed secret channel; never put a token in the intake form. Reading metadata does not authorize package installation or install-script execution.",
      ifUnavailable: "Unresolved packages keep individual outcomes: missing local metadata, private/unpublished metadata unavailable, or connectivity denied. A lookup budget is a resumable processing limit, not a request for broader access.",
      verification: "Re-run metadata coverage for the same lockfile and enumerate every package outcome; verify that the affected package now has provenance-backed metadata.",
    },
    {
      id: "database-catalog",
      modules: ["M1", "M10"],
      capability: "Schema inventory and database access controls",
      requestedInput: "Name each backend and every authorized product schema, including non-public schemas. Supply committed migrations and read-only visibility into relation, column, grant, role-membership and row-security policy metadata.",
      accessBoundary: "Confirm catalog visibility for each requested schema using an engagement-scoped read-only connection. Metadata visibility must be checked explicitly; a restricted catalog can hide relations. This requirement grants no writes, DDL, production row sampling or blanket access to application rows.",
      ifUnavailable: "Record examined and unexamined schemas, relations and columns, and disclose inaccessible grant/policy metadata. An empty visible catalog does not prove that the product has no sensitive data or exposure.",
      verification: "Compare the authorized schema inventory with the catalog results using the granted role; re-run the affected metadata checks and inspect their delivered scope disclosure.",
    },
    {
      id: "platform-configuration",
      modules: ["M1", "M7", "M10"],
      capability: "Hosted configuration, advisors and exposed schemas",
      requestedInput: "Provide the backend identifiers and approved read-only configuration evidence for exposed schemas, authentication, advisors and relevant storage or encryption controls.",
      accessBoundary: "Agree the specific configuration endpoints before access. A SQL connection alone does not grant platform configuration access. Where a provider offers no sufficiently narrow token, agree an operator-provided export or a separately reviewed grant; do not request an unrestricted token by default.",
      ifUnavailable: "Configuration-dependent controls remain unassessed with the missing input identified. Catalog inventory alone cannot establish encryption at rest or the provider configuration.",
      verification: "Re-run the named configuration check with a dated, backend-bound export or approved endpoint response and confirm the result reaches the report.",
    },
    {
      id: "application-protection",
      modules: ["M10"],
      capability: "Application encryption and sensitive-data protection",
      requestedInput: "Identify the application code and non-secret configuration governing encryption, key references and data access, plus any provider control evidence included in the agreed scope.",
      accessBoundary: "Review source and control metadata. Do not request encryption keys, plaintext customer records or production samples through intake. Any additional access requires a separately agreed scope.",
      ifUnavailable: "Keep sensitivity classification separate from a protection failure. Unverified encryption or access boundaries are disclosed as unassessed, with the missing evidence and a bounded next step.",
      verification: "Trace a named sensitive field through the supplied protection boundary and corroborate the relevant configuration; report what the evidence establishes and what remains unverified.",
    },
  ].map(withAssessmentRequirements) satisfies readonly AuditPrerequisite[],
} as const;
