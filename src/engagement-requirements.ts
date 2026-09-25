/** Non-secret intake contract shared by metadata and database assessment consumers. */
export const ENGAGEMENT_REQUIREMENTS_VERSION = "harvey-engagement-requirements/1";

interface EngagementRequirement {
  id: string;
  modules: readonly string[];
  capability: string;
  metadata: readonly string[];
  access: readonly string[];
  limitation: string;
  falsifier: string;
  nextStep: string;
}

export const ENGAGEMENT_REQUIREMENTS: readonly EngagementRequirement[] = [
  { id: "registry.public-metadata", modules: ["M1"], capability: "Public package metadata",
    metadata: ["registry origin", "package name and resolved version", "lockfile identity", "request outcome and retrieval time"],
    access: ["authorized registry metadata endpoint; respect rate limits"],
    limitation: "Unavailable package metadata is an unresolved assessment, not a healthy package.",
    falsifier: "A bounded metadata request returns the exact locked package and version with usable provenance.",
    nextStep: "Confirm the intended registry and retry only the unresolved package metadata requests." },
  { id: "registry.private-authorization", modules: ["M1"], capability: "Private package metadata",
    metadata: ["private registry origin and namespace", "package scope", "authorization availability; never its value"],
    access: ["operator-configured read-only package metadata authorization"],
    limitation: "A private, forbidden or missing package response does not establish package health or absence.",
    falsifier: "An authorized read returns metadata for the exact private package version.",
    nextStep: "Have the operator configure scoped read access locally; provide only non-secret authorization status to intake." },
  { id: "database.schema-scope", modules: ["M10"], capability: "Authorized product schema inventory",
    metadata: ["explicit product schema allowlist", "relation and column denominators", "unqueried, inaccessible and missing-schema reasons"],
    access: ["operator authorization for each selected schema", "read-only pg_namespace, pg_class, pg_attribute and pg_type metadata"],
    limitation: "Unselected or inaccessible schemas and their unknown denominators remain unassessed.",
    falsifier: "A complete catalog response accounts for every authorized schema, relation and column.",
    nextStep: "Confirm the product schema allowlist and grant catalog visibility, then rerun metadata-only classification." },
  { id: "database.catalog", modules: ["M10"], capability: "Protection catalog visibility",
    metadata: ["catalog query outcomes", "relation kinds", "extension and security-label metadata"],
    access: ["read-only visibility of catalog rows for the authorized schema allowlist"],
    limitation: "Missing or unreadable metadata is unknown protection, not absent protection.",
    falsifier: "The required catalog queries complete for every selected object with a recorded denominator.",
    nextStep: "Provide catalog-only visibility or an attributable metadata export; do not provide production row values." },
  { id: "database.api-configuration", modules: ["M10"], capability: "API schema configuration",
    metadata: ["actual API-exposed schema list", "configuration source and revision"],
    access: ["read-only effective API configuration or explicit operator-supplied configuration evidence"],
    limitation: "An API schema setting alone proves neither a column grant nor readable rows.",
    falsifier: "The effective API schema list is known and the same column/principal read path is independently assessed.",
    nextStep: "Supply the API schema configuration with provenance and compare it to effective grants and RLS." },
  { id: "database.authorization", modules: ["M10"], capability: "Effective column authorization",
    metadata: ["schema USAGE", "table and column SELECT privileges", "role inheritance and attributes", "applicable RLS policies and FORCE/owner context"],
    access: ["read-only pg_roles, pg_auth_members, pg_policy and ACL metadata"],
    limitation: "Conditional predicates, views, definer calls and unenumerated roles require separate caller-specific review.",
    falsifier: "The exact column/principal path has complete effective grants and supported policy semantics, or a bounded authorized caller test resolves it.",
    nextStep: "Review the identified predicate or call boundary using synthetic allowed/denied callers; keep production values out of intake." },
  { id: "database.encryption-boundaries", modules: ["M10"], capability: "Encryption and masking boundaries",
    metadata: ["schema-qualified encryption/masking configuration", "source file and digest for the reviewed write/read boundary", "key-management and infrastructure attestations without key material"],
    access: ["read-only encryption catalog/configuration", "authorized source checkout and attributable boundary-review records"],
    limitation: "Encryption metadata alone does not prove all writes are encrypted or that every exposed read path hides plaintext. Missing metadata proves neither absence nor adequacy.",
    falsifier: "A complete reviewed write/read boundary and its synthetic plaintext/ciphertext controls establish the stated protection for the exact column.",
    nextStep: "Review the named source/configuration boundary, key access and decrypting views/RPCs with synthetic data; request a storage/key-management attestation separately." },
];

export function engagementRequirement(id: string): EngagementRequirement {
  const row = ENGAGEMENT_REQUIREMENTS.find((entry) => entry.id === id);
  if (!row) throw new Error(`Unknown engagement requirement: ${id}`);
  return row;
}

export function renderEngagementRequirements(): string {
  return `# Engagement capability prerequisites\n\nContract: ${ENGAGEMENT_REQUIREMENTS_VERSION}. Supply metadata and authorization status only; configure credentials locally. Do not submit secrets or production row values.\n\n`
    + ENGAGEMENT_REQUIREMENTS.map((r) => `## ${r.id}: ${r.capability}\n\nModules: ${r.modules.join(", ")}.\n\nMetadata: ${r.metadata.join("; ")}.\n\nAccess: ${r.access.join("; ")}.\n\nLimit: ${r.limitation}\n\nFalsifier: ${r.falsifier}\n\nNext step: ${r.nextStep}\n`).join("\n");
}
