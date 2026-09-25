# Engagement capability prerequisites

Contract: harvey-engagement-requirements/1. Supply metadata and authorization status only; configure credentials locally. Do not submit secrets or production row values.

## registry.public-metadata: Public package metadata

Modules: M1.

Metadata: registry origin; package name and resolved version; lockfile identity; request outcome and retrieval time.

Access: authorized registry metadata endpoint; respect rate limits.

Limit: Unavailable package metadata is an unresolved assessment, not a healthy package.

Falsifier: A bounded metadata request returns the exact locked package and version with usable provenance.

Next step: Confirm the intended registry and retry only the unresolved package metadata requests.

## registry.private-authorization: Private package metadata

Modules: M1.

Metadata: private registry origin and namespace; package scope; authorization availability; never its value.

Access: operator-configured read-only package metadata authorization.

Limit: A private, forbidden or missing package response does not establish package health or absence.

Falsifier: An authorized read returns metadata for the exact private package version.

Next step: Have the operator configure scoped read access locally; provide only non-secret authorization status to intake.

## database.schema-scope: Authorized product schema inventory

Modules: M10.

Metadata: explicit product schema allowlist; relation and column denominators; unqueried, inaccessible and missing-schema reasons.

Access: operator authorization for each selected schema; read-only pg_namespace, pg_class, pg_attribute and pg_type metadata.

Limit: Unselected or inaccessible schemas and their unknown denominators remain unassessed.

Falsifier: A complete catalog response accounts for every authorized schema, relation and column.

Next step: Confirm the product schema allowlist and grant catalog visibility, then rerun metadata-only classification.

## database.catalog: Protection catalog visibility

Modules: M10.

Metadata: catalog query outcomes; relation kinds; extension and security-label metadata.

Access: read-only visibility of catalog rows for the authorized schema allowlist.

Limit: Missing or unreadable metadata is unknown protection, not absent protection.

Falsifier: The required catalog queries complete for every selected object with a recorded denominator.

Next step: Provide catalog-only visibility or an attributable metadata export; do not provide production row values.

## database.api-configuration: API schema configuration

Modules: M10.

Metadata: actual API-exposed schema list; configuration source and revision.

Access: read-only effective API configuration or explicit operator-supplied configuration evidence.

Limit: An API schema setting alone proves neither a column grant nor readable rows.

Falsifier: The effective API schema list is known and the same column/principal read path is independently assessed.

Next step: Supply the API schema configuration with provenance and compare it to effective grants and RLS.

## database.authorization: Effective column authorization

Modules: M10.

Metadata: schema USAGE; table and column SELECT privileges; role inheritance and attributes; applicable RLS policies and FORCE/owner context.

Access: read-only pg_roles, pg_auth_members, pg_policy and ACL metadata.

Limit: Conditional predicates, views, definer calls and unenumerated roles require separate caller-specific review.

Falsifier: The exact column/principal path has complete effective grants and supported policy semantics, or a bounded authorized caller test resolves it.

Next step: Review the identified predicate or call boundary using synthetic allowed/denied callers; keep production values out of intake.

## database.encryption-boundaries: Encryption and masking boundaries

Modules: M10.

Metadata: schema-qualified encryption/masking configuration; source file and digest for the reviewed write/read boundary; key-management and infrastructure attestations without key material.

Access: read-only encryption catalog/configuration; authorized source checkout and attributable boundary-review records.

Limit: Encryption metadata alone does not prove all writes are encrypted or that every exposed read path hides plaintext. Missing metadata proves neither absence nor adequacy.

Falsifier: A complete reviewed write/read boundary and its synthetic plaintext/ciphertext controls establish the stated protection for the exact column.

Next step: Review the named source/configuration boundary, key access and decrypting views/RPCs with synthetic data; request a storage/key-management attestation separately.
