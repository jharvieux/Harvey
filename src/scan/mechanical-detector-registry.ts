import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import type { Finding } from "../findings.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { NON_PRODUCT } from "../detectors/load-sources.js";
import { readEntriesSafe } from "../fs-walk.js";
import { detectAuditLogTenantFindings } from "./audit-log-tenant.js";
import { detectBolaCrossFileFindings } from "./bola-cross-file.js";
import { bolaOwnerScannedFiles, detectBolaOwnerFindings } from "./bola-owner.js";
import { detectCacheTenantScopeFindings } from "./cache-tenant-scope.js";
import { detectClientSuppliedTenantFindings } from "./client-supplied-tenant.js";
import { detectCounterRaceFindings } from "./counter-race.js";
import { detectDedupWithoutUniqueFindings, uniqueConstraints } from "./dedup-unique.js";
import { detectDrizzleTenantScopeFindings } from "./drizzle-tenant-scope.js";
import { detectEmitterUnhandledErrorFindings } from "./emitter-error.js";
import { detectEnvSchemaFindings } from "./env-schema.js";
import { detectExpressPoweredByFindings } from "./express-powered-by.js";
import { detectExpressSecurityHeaderFindings } from "./express-security-headers.js";
import { detectIdempotencyFindings } from "./idempotency.js";
import { detectJobTenantScopeFindings, jobTenantScopeScannedFiles } from "./job-tenant-scope.js";
import { classifyLeftoverAuth } from "./leftover-auth.js";
import { detectMigrationColumnDriftFindings, droppedColumns } from "./migration-column-drift.js";
import type { MechanicalScanContext } from "./mechanical-context.js";
import {
  createMechanicalProducerRecord,
  targetPathExaminedUnits,
  type MechanicalExaminedUnitIdentity,
  type MechanicalProducerRecord,
} from "./mechanical-phase-cache.js";
import { detectPgIdorFindings } from "./pg-idor.js";
import { detectPgResponseExposureFindings } from "./pg-response-exposure.js";
import { pathScopeNotAssessedRows } from "./path-scope.js";
import { detectPrismaTenantScopeFindings } from "./prisma-tenant-scope.js";
import { detectPropOvershareFindings } from "./prop-overshare.js";
import { detectRawBodyNoLimitFindings } from "./raw-body-limit.js";
import { detectSecretRotationFindings } from "./secret-rotation.js";
import { detectServiceRoleLiteralFindings } from "./service-role-literal.js";
import { detectSsrSanitizerFindings } from "./ssr-sanitizer.js";
import { detectSsrfWrapperFindings } from "./ssrf-wrapper.js";
import { detectStaleQuotaReadFindings } from "./stale-quota-read.js";
import { detectStorageTenantScopeFindings } from "./storage-tenant-scope.js";
import { detectTenantGucScopeFindings } from "./tenant-guc-scope.js";
import { detectWebhookSignatureFindings } from "./webhook-signature.js";
import type { SourceInput } from "../detectors/common.js";

export type MechanicalDetectorModule = "M1" | "M6";
type EvidenceStatus = "covered" | "structured-exception";

export interface DetectorEvidenceLink {
  status: EvidenceStatus;
  path?: string;
  detail: string;
}

export interface MechanicalDetectorDefinition {
  id: string;
  order: number;
  module: MechanicalDetectorModule;
  implementation: { file: string; exportName: string };
  findingIds: readonly string[];
  taxonomies: readonly string[];
  applicableFiles: {
    description: string;
    select: (context: MechanicalScanContext) => readonly SourceInput[];
  };
  prerequisites: readonly string[];
  fallback: string;
  positiveFixture: DetectorEvidenceLink;
  benignTwin: DetectorEvidenceLink;
  conservation: DetectorEvidenceLink;
  corpus: DetectorEvidenceLink;
  cadence: DetectorEvidenceLink;
  enabled?: (options: RegisteredDetectorOptions) => boolean;
  examinedUnits: (context: MechanicalScanContext, selected: readonly SourceInput[]) => number;
  examinedUnitIdentities: (context: MechanicalScanContext, selected: readonly SourceInput[]) => MechanicalExaminedUnitIdentity[];
  invoke: (context: MechanicalScanContext, selected: readonly SourceInput[]) => Finding[];
}

export interface RegisteredDetectorOptions {
  handrolledIndicators?: boolean;
}

export type DetectorExecutionRecord = MechanicalProducerRecord;

const sourceFiles = (context: MechanicalScanContext): readonly SourceInput[] => context.sourceFiles;
const registryEvidence = (file: string, detail: string): DetectorEvidenceLink => ({ status: "covered", path: file, detail });
const registryException = (detail: string): DetectorEvidenceLink => ({ status: "structured-exception", detail });
const registryRoot = fileURLToPath(new URL("../../", import.meta.url));

function assurance(id: string, file: string, exportName: string): Pick<MechanicalDetectorDefinition, "positiveFixture" | "benignTwin" | "conservation" | "corpus" | "cadence"> {
  const testFile = file.replace(/\.ts$/, ".test.ts");
  const fixture = existsSync(join(registryRoot, testFile)) && readFileSync(join(registryRoot, testFile), "utf8").includes(exportName)
    ? registryEvidence(testFile, `${id}: this producer-linked test directly exercises ${exportName} with positive and benign populations.`)
    : undefined;
  return {
    positiveFixture: fixture ?? registryException(`${id}: no producer-specific positive fixture has been verified for ${file}#${exportName}; generic suites are not presented as evidence.`),
    benignTwin: fixture ?? registryException(`${id}: no producer-specific benign twin has been verified for ${file}#${exportName}; absence of a generic false positive is not evidence.`),
    conservation: registryException(`${id}: no producer-specific conservation plant exists; the M1/M6 module plant conserves output but does not prove this producer can fire.`),
    corpus: registryEvidence("src/cli/corpus-drift.ts", `${id}: every selected pinned-corpus target serializes this producer's execution record, including zero-finding and not-applicable populations.`),
    cadence: registryEvidence(".github/workflows/corpus-drift.yml", `${id}: the pinned-corpus workflow executes this producer on pull requests and its scheduled cadence.`),
  };
}

function detector(input: Omit<MechanicalDetectorDefinition, "applicableFiles" | "prerequisites" | "fallback" | "positiveFixture" | "benignTwin" | "conservation" | "corpus" | "cadence" | "examinedUnits" | "examinedUnitIdentities"> & Partial<Pick<MechanicalDetectorDefinition, "applicableFiles" | "prerequisites" | "fallback" | "positiveFixture" | "benignTwin" | "conservation" | "corpus" | "cadence" | "examinedUnits" | "examinedUnitIdentities">>): MechanicalDetectorDefinition {
  const defaults = assurance(input.id, input.implementation.file, input.implementation.exportName);
  return Object.freeze({
    applicableFiles: { description: "all tracked JavaScript/TypeScript source files in the shared inventory", select: sourceFiles },
    prerequisites: Object.freeze([]),
    fallback: "An empty applicable population is recorded in the detector execution census; detector-specific scope disclosures remain findings.",
    examinedUnits: (_context: MechanicalScanContext, selected: readonly SourceInput[]) => selected.length,
    examinedUnitIdentities: (_context: MechanicalScanContext, selected: readonly SourceInput[]) => targetPathExaminedUnits(input.id, selected.map((file) => file.path)),
    ...defaults,
    ...input,
  });
}

export const MECHANICAL_DETECTORS: readonly MechanicalDetectorDefinition[] = Object.freeze([
  detector({
    id: "leftover-auth", order: 10, module: "M1",
    implementation: { file: "src/scan/leftover-auth.ts", exportName: "classifyLeftoverAuth" },
    findingIds: ["AUTH-*"],
    taxonomies: ["Leftover-auth grep", "Unauthenticated debug/admin route", "Missing rate limit on auth endpoint", "In-memory rate limiter (per-instance, resets on cold start)", "Authz decision from client-controlled input", "Client-supplied payment amount trusted by server", "Sensitive value logged to console", "Client-side authorization decision", "Host header trusted in URL construction", "Upload to storage with no size/MIME limit", "Inbound webhook with no signature verification", "Unscoped service-role UPDATE/DELETE (no WHERE)", "Middleware matcher excludes /api routes", "draftMode().enable() reachable with no secret"],
    invoke: (_context, selected) => selected.map((file) => ({ path: file.path, content: file.text })).flatMap(classifyLeftoverAuth),
  }),
  detector({ id: "counter-race", order: 20, module: "M1", implementation: { file: "src/scan/counter-race.ts", exportName: "detectCounterRaceFindings" }, findingIds: ["RACE-read-modify-write-*"], taxonomies: ["Non-atomic read-modify-write race condition"], invoke: (_context, selected) => detectCounterRaceFindings([...selected]) }),
  detector({
    id: "bola-owner", order: 30, module: "M1", implementation: { file: "src/scan/bola-owner.ts", exportName: "detectBolaOwnerFindings" }, findingIds: ["AUTH-bola-body-owner-*"], taxonomies: ["Object-level authorization gap: client-supplied owner id scopes the query"],
    applicableFiles: { description: "Pages Router API files admitted by bolaOwnerScannedFiles", select: (context) => bolaOwnerScannedFiles(context.sourceFiles) },
    invoke: (_context, selected) => detectBolaOwnerFindings([...selected]),
  }),
  detector({ id: "ssrf-wrapper", order: 40, module: "M1", implementation: { file: "src/scan/ssrf-wrapper.ts", exportName: "detectSsrfWrapperFindings" }, findingIds: ["SSRF-wrapper-*"], taxonomies: ["M1 — SSRF via an uncurated cross-file fetch wrapper"], prerequisites: ["shared import graph"], invoke: (context, selected) => detectSsrfWrapperFindings([...selected], context.importGraph) }),
  detector({ id: "pg-idor", order: 50, module: "M1", implementation: { file: "src/scan/pg-idor.ts", exportName: "detectPgIdorFindings" }, findingIds: ["SEC-PG-IDOR-*"], taxonomies: ["Object-level authorization gap: client-supplied id reaches a read-by-id repo function (pg-idor-repo-fn)"], invoke: (_context, selected) => detectPgIdorFindings([...selected]) }),
  detector({ id: "pg-response-exposure", order: 60, module: "M1", implementation: { file: "src/scan/pg-response-exposure.ts", exportName: "detectPgResponseExposureFindings" }, findingIds: ["SEC-PG-RESJSON-*"], taxonomies: ["Excessive data exposure: res.json(...)*"], invoke: (_context, selected) => detectPgResponseExposureFindings([...selected]) }),
  detector({
    id: "prisma-tenant-scope", order: 70, module: "M1", implementation: { file: "src/scan/prisma-tenant-scope.ts", exportName: "detectPrismaTenantScopeFindings" }, findingIds: ["AUTH-prisma-tenant-scope-*", "M1-WRAPPER-00"], taxonomies: ["Object-level authorization gap: Prisma query filtered by primary key with no tenant scope", "Coverage — Prisma tenant-scope not assessed (wrapper-gated)"],
    applicableFiles: { description: "shared source inventory plus the root manifest used by the wrapper gate", select: (context) => context.sourceAndRootManifest },
    invoke: (_context, selected) => detectPrismaTenantScopeFindings([...selected]),
  }),
  detector({ id: "drizzle-tenant-scope", order: 80, module: "M1", implementation: { file: "src/scan/drizzle-tenant-scope.ts", exportName: "detectDrizzleTenantScopeFindings" }, findingIds: ["AUTH-drizzle-tenant-scope-*"], taxonomies: ["Object-level authorization gap: Drizzle query filtered by primary key with no tenant scope"], invoke: (_context, selected) => detectDrizzleTenantScopeFindings([...selected]) }),
  detector({ id: "client-supplied-tenant", order: 90, module: "M1", implementation: { file: "src/scan/client-supplied-tenant.ts", exportName: "detectClientSuppliedTenantFindings" }, findingIds: ["AUTH-client-supplied-tenant-*"], taxonomies: ["Object-level authorization gap: tenant predicate populated from the request"], invoke: (_context, selected) => detectClientSuppliedTenantFindings([...selected]) }),
  detector({ id: "tenant-guc-scope", order: 100, module: "M1", implementation: { file: "src/scan/tenant-guc-scope.ts", exportName: "detectTenantGucScopeFindings" }, findingIds: ["TENANT-guc-set-not-local-*"], taxonomies: ["Tenant GUC set with SET rather than SET LOCAL, leaking across a pooled connection"], invoke: (_context, selected) => detectTenantGucScopeFindings([...selected]) }),
  detector({ id: "cache-tenant-scope", order: 110, module: "M1", implementation: { file: "src/scan/cache-tenant-scope.ts", exportName: "detectCacheTenantScopeFindings" }, findingIds: ["CACHE-key-no-tenant-*", "CACHE-SCOPE-00"], taxonomies: ["Cache key without a tenant discriminator (cross-tenant cache poisoning)", "Coverage — cache sites outside the tenant-scope heuristic's bounds"], invoke: (_context, selected) => detectCacheTenantScopeFindings([...selected]) }),
  detector({ id: "storage-tenant-scope", order: 120, module: "M1", implementation: { file: "src/scan/storage-tenant-scope.ts", exportName: "detectStorageTenantScopeFindings" }, findingIds: ["STORAGE-path-no-tenant-*"], taxonomies: ["Storage object path without a tenant prefix (cross-tenant object read/overwrite)"], invoke: (_context, selected) => detectStorageTenantScopeFindings([...selected]) }),
  detector({ id: "audit-log-tenant", order: 130, module: "M1", implementation: { file: "src/scan/audit-log-tenant.ts", exportName: "detectAuditLogTenantFindings" }, findingIds: ["AUDIT-log-no-tenant-*"], taxonomies: ["Audit log entry without a tenant discriminator"], invoke: (_context, selected) => detectAuditLogTenantFindings([...selected]) }),
  detector({ id: "webhook-signature", order: 140, module: "M1", implementation: { file: "src/scan/webhook-signature.ts", exportName: "detectWebhookSignatureFindings" }, findingIds: ["WEBHOOK-sig-encoding-*"], taxonomies: ["Webhook signature decoded with the wrong encoding"], invoke: (_context, selected) => detectWebhookSignatureFindings([...selected]) }),
  detector({
    id: "migration-column-drift", order: 150, module: "M1", implementation: { file: "src/scan/migration-column-drift.ts", exportName: "detectMigrationColumnDriftFindings" }, findingIds: ["SCHEMA-dropped-column-read-*"], taxonomies: ["App code reads a column the migrations dropped"], prerequisites: ["ordered SQL migration inventory"], fallback: "No ordered migration history means there is no historical drop/rename claim to make; the registry records the zero schema population.",
    examinedUnits: (context, selected) => selected.length + context.schemas.orderedMigrations.length,
    examinedUnitIdentities: (context, selected) => targetPathExaminedUnits("migration-column-drift", [...selected.map((file) => file.path), ...context.schemas.orderedMigrations.map((migration) => migration.file)]),
    invoke: (context, selected) => detectMigrationColumnDriftFindings([...selected], droppedColumns([...context.schemas.orderedMigrations])),
  }),
  detector({ id: "idempotency", order: 160, module: "M1", implementation: { file: "src/scan/idempotency.ts", exportName: "detectIdempotencyFindings" }, findingIds: ["RETRY-*"], taxonomies: ["Batch send stamped after dispatch instead of claimed before", "Idempotency row written before the dispatched handler", "External send without a deterministic idempotency key", "Idempotency key does not identify a stable scoped operation", "Webhook state applied without an ordering guard"], invoke: (_context, selected) => detectIdempotencyFindings([...selected]) }),
  detector({ id: "stale-quota-read", order: 170, module: "M1", implementation: { file: "src/scan/stale-quota-read.ts", exportName: "detectStaleQuotaReadFindings" }, findingIds: ["RACE-stale-quota-read-*"], taxonomies: ["Quota gate consumed across a loop without re-reading"], invoke: (_context, selected) => detectStaleQuotaReadFindings([...selected]) }),
  detector({
    id: "service-role-literal", order: 180, module: "M1", implementation: { file: "src/scan/service-role-literal.ts", exportName: "detectServiceRoleLiteralFindings" }, findingIds: ["SEC-SRL-*"], taxonomies: ["Supabase service_role key hardcoded as a JWT literal (service-role-literal)"], prerequisites: ["shared import graph", "shared path-alias inventory"],
    applicableFiles: { description: "shared source inventory plus exact tsconfig/jsconfig inputs used for import aliases", select: (context) => context.serviceRoleSources },
    invoke: (context, selected) => detectServiceRoleLiteralFindings([...selected], context.importGraph, context.pathAliases),
  }),
  detector({ id: "emitter-error", order: 190, module: "M1", implementation: { file: "src/scan/emitter-error.ts", exportName: "detectEmitterUnhandledErrorFindings" }, findingIds: ["SEC-EMITTER-ERR-*"], taxonomies: ["EventEmitter emits 'error' with no registered listener"], invoke: (_context, selected) => detectEmitterUnhandledErrorFindings([...selected]) }),
  detector({ id: "express-powered-by", order: 200, module: "M1", implementation: { file: "src/scan/express-powered-by.ts", exportName: "detectExpressPoweredByFindings" }, findingIds: ["SEC-POWERED-BY-*"], taxonomies: ["Framework version disclosed via X-Powered-By"], invoke: (_context, selected) => detectExpressPoweredByFindings([...selected]) }),
  detector({ id: "express-security-headers", order: 210, module: "M1", implementation: { file: "src/scan/express-security-headers.ts", exportName: "detectExpressSecurityHeaderFindings" }, findingIds: ["SEC-EXPRESS-HEADERS-*"], taxonomies: ["Express app sets no security response headers"], invoke: (_context, selected) => detectExpressSecurityHeaderFindings([...selected]) }),
  detector({ id: "raw-body-limit", order: 220, module: "M1", implementation: { file: "src/scan/raw-body-limit.ts", exportName: "detectRawBodyNoLimitFindings" }, findingIds: ["SEC-RAW-BODY-*"], taxonomies: ["Request body accumulated with no size limit"], invoke: (_context, selected) => detectRawBodyNoLimitFindings([...selected]) }),
  detector({ id: "ssr-sanitizer", order: 230, module: "M1", implementation: { file: "src/scan/ssr-sanitizer.ts", exportName: "detectSsrSanitizerFindings" }, findingIds: ["XSS-ssr-browser-sanitizer-*"], taxonomies: ["Browser-only sanitizer in a server-rendered component"], invoke: (_context, selected) => detectSsrSanitizerFindings([...selected]) }),
  detector({ id: "prop-overshare", order: 240, module: "M1", implementation: { file: "src/scan/prop-overshare.ts", exportName: "detectPropOvershareFindings" }, findingIds: ["REACT-prop-overshare-*"], taxonomies: ["Sensitive fields in props"], invoke: (_context, selected) => detectPropOvershareFindings([...selected]) }),
  detector({
    id: "dedup-unique", order: 250, module: "M1", implementation: { file: "src/scan/dedup-unique.ts", exportName: "detectDedupWithoutUniqueFindings" }, findingIds: ["RACE-dedup-no-unique-*"], taxonomies: ["SELECT-then-INSERT dedup with no unique constraint"], prerequisites: ["SQL migration and schema snapshot inventory"], fallback: "No declared schema means the uniqueness premise cannot be evaluated; the registry records the zero schema population.",
    examinedUnits: (context, selected) => selected.length + context.schemas.orderedMigrations.length + context.schemas.snapshots.length,
    examinedUnitIdentities: (context, selected) => targetPathExaminedUnits("dedup-unique", [...selected.map((file) => file.path), ...context.schemas.orderedMigrations.map((migration) => migration.file), ...context.schemas.snapshots.map((snapshot) => snapshot.file)]),
    invoke: (context, selected) => detectDedupWithoutUniqueFindings([...selected], uniqueConstraints([...context.schemas.orderedMigrations, ...context.schemas.snapshots])),
  }),
  detector({ id: "bola-cross-file", order: 260, module: "M1", implementation: { file: "src/scan/bola-cross-file.ts", exportName: "detectBolaCrossFileFindings" }, findingIds: ["AUTH-bola-cross-file-*"], taxonomies: ["Object-level authorization gap across a module boundary"], prerequisites: ["shared import graph"], invoke: (_context, selected) => detectBolaCrossFileFindings([...selected]) }),
  detector({
    id: "job-tenant-scope", order: 270, module: "M1", implementation: { file: "src/scan/job-tenant-scope.ts", exportName: "detectJobTenantScopeFindings" }, findingIds: ["AUTH-job-tenant-scope-*", "M1-JOBPATH-00"], taxonomies: ["Service-role query in a background-job path with no tenant predicate", "Coverage — background-job directories outside the job-tenant-scope path convention"],
    applicableFiles: { description: "background-job path files admitted by jobTenantScopeScannedFiles", select: (context) => jobTenantScopeScannedFiles(context.sourceFiles) },
    invoke: (_context, selected) => detectJobTenantScopeFindings([...selected]),
  }),
  detector({
    id: "path-scope-disclosure", order: 280, module: "M1", implementation: { file: "src/scan/path-scope.ts", exportName: "pathScopeNotAssessedRows" }, findingIds: ["M1-PATHSCOPE-*"], taxonomies: ["Coverage — *"],
    positiveFixture: registryEvidence("src/scan/path-scope.test.ts", "path-scope-disclosure: zero-population paths emit their counted disclosure controls."),
    benignTwin: registryEvidence("src/scan/path-scope.test.ts", "path-scope-disclosure: non-zero populations suppress the disclosure twin."),
    invoke: (_context, selected) => pathScopeNotAssessedRows(selected),
  }),
  detector({ id: "secret-rotation", order: 290, module: "M1", implementation: { file: "src/scan/secret-rotation.ts", exportName: "detectSecretRotationFindings" }, findingIds: ["SECRET-rotation-pair-*"], taxonomies: ["Static secret verified with no rotation-pair acceptance window"], invoke: (_context, selected) => detectSecretRotationFindings([...selected]) }),
  detector({
    id: "env-schema", order: 300, module: "M1", implementation: { file: "src/scan/env-schema.ts", exportName: "detectEnvSchemaFindings" }, findingIds: ["ENV-*"], taxonomies: ["Env var completeness — framework convention not modelled", "Env var read but not declared in env schema", "Env var declared in env schema but never read"],
    applicableFiles: { description: "all tracked JavaScript/TypeScript source files, including .mts/.cts used by config and test-runner modules", select: (context) => context.envSourceFiles },
    invoke: (context, selected) => detectEnvSchemaFindings([...selected], context.framework),
  }),
  detector({
    id: "handrolled-indicators", order: 310, module: "M6", implementation: { file: "src/detectors/handrolled.ts", exportName: "detectHandrolledFindings" }, findingIds: ["M6IND-*"],
    taxonomies: [
      "M6 — Indicator: JSON deep-equal",
      "M6 — Indicator: query-string parsing",
      "M6 — Indicator: cookie parsing",
      "M6 — Indicator: random-string id",
      "M6 — Indicator: class-string merge",
      "M6 — Indicator: raw-millisecond date math",
      "M6 — Indicator: MIME-type lookup table",
      "M6 — Indicator: currency formatting",
      "M6 — Indicator: email-shape regex",
      "M6 — Indicator: manual date formatting",
      "M6 — Indicator: query-string building",
      "M6 — Indicator: base64url conversion",
      "M6 — Indicator: cookie serialization",
      "M6 — Indicator: array-unique via filter",
      "M6 — Indicator: composite timestamp-random id",
      "M6 — Indicator: non-crypto string hash",
      "M6 — Indicator: month/day-name array",
      "M6 — Indicator: JWT decode by hand",
      "M6 — Indicator: hand-rolled ErrorBoundary",
      "M6 — Indicator: markdown-to-HTML by regex",
      "M6 — Indicator: thousands-separator regex",
      "M6 — Indicator: array flatten via reduce",
      "M6 — Indicator: random-comparator shuffle",
      "M6 — Indicator: zero-pad via slice",
      "M6 — Indicator: nested-path get via split/reduce",
      "M6 — Indicator: placeholder-template id",
      "M6 — Indicator: fetch timeout via Promise.race",
      "M6 — Indicator: env JSON parsing",
      "M6 — Indicator: Vite env coercion",
      "M6 — Indicator: storage object URL concat",
      "M6 — Indicator: clipboard via execCommand",
      "M6 — Indicator: retry/backoff loop",
      "M6 — Indicator: manual pagination offset",
    ],
    applicableFiles: { description: "product JavaScript/TypeScript plus manifests from the shared loader view", select: (context) => context.loadedSources.filter((file) => !NON_PRODUCT.test(file.path)) },
    enabled: (options) => options.handrolledIndicators === true,
    positiveFixture: registryEvidence("src/detectors/handrolled.test.ts", "handrolled-indicators: the indicator suite carries positive controls."),
    benignTwin: registryEvidence("src/detectors/handrolled.test.ts", "handrolled-indicators: the indicator suite carries benign controls."),
    invoke: (_context, selected) => detectHandrolledFindings([...selected]),
  }),
]);

function matches(pattern: string, value: string): boolean {
  return pattern.endsWith("*") ? value.startsWith(pattern.slice(0, -1)) : pattern === value;
}

function ownsFinding(definition: MechanicalDetectorDefinition, finding: Finding): boolean {
  return definition.findingIds.some((pattern) => matches(pattern, finding.id))
    && definition.taxonomies.some((pattern) => matches(pattern, finding.taxonomy));
}

function uniqueFindingOwner(finding: Finding, options: RegisteredDetectorOptions): MechanicalDetectorDefinition {
  const owners = MECHANICAL_DETECTORS.filter((definition) => (definition.enabled?.(options) ?? true) && ownsFinding(definition, finding));
  if (owners.length !== 1) {
    throw new Error(`${finding.id}: expected one registry owner, found ${owners.length} [${owners.map((owner) => owner.id).join(", ")}]`);
  }
  return owners[0]!;
}

function validateEmittedOwnership(definition: MechanicalDetectorDefinition, findings: readonly Finding[]): void {
  const badIds = findings.filter((finding) => !definition.findingIds.some((pattern) => matches(pattern, finding.id))).map((finding) => finding.id);
  const badTaxonomies = findings.filter((finding) => !definition.taxonomies.some((pattern) => matches(pattern, finding.taxonomy))).map((finding) => finding.taxonomy);
  if (badIds.length > 0 || badTaxonomies.length > 0) {
    throw new Error(`${definition.id}: emitted ownership outside registry metadata; finding ids [${[...new Set(badIds)].join(", ")}], taxonomies [${[...new Set(badTaxonomies)].join(", ")}]`);
  }
}

export function runRegisteredMechanicalDetectors(context: MechanicalScanContext, options: RegisteredDetectorOptions = {}): { findings: Finding[]; records: DetectorExecutionRecord[] } {
  return context.withAstCache(() => {
    const findings: Finding[] = [];
    const records: DetectorExecutionRecord[] = [];
    for (const definition of MECHANICAL_DETECTORS) {
      const selected = definition.applicableFiles.select(context);
      if (!(definition.enabled?.(options) ?? true)) {
        records.push(createMechanicalProducerRecord({ detector: definition.id, phase: "structural-ast", order: definition.order, module: definition.module, examinedUnitIdentities: [], findings: 0, durationMs: 0, status: "not-applicable" }));
        continue;
      }
      const unitsExamined = definition.examinedUnits(context, selected);
      const examinedUnitIdentities = definition.examinedUnitIdentities(context, selected);
      if (unitsExamined !== examinedUnitIdentities.length) throw new Error(`${definition.id}: examined-unit count ${unitsExamined} differs from exact selector receipt ${examinedUnitIdentities.length}`);
      const started = performance.now();
      const emitted = definition.invoke(context, selected);
      const durationMs = performance.now() - started;
      validateEmittedOwnership(definition, emitted);
      findings.push(...emitted);
      records.push(createMechanicalProducerRecord({ detector: definition.id, phase: "structural-ast", order: definition.order, module: definition.module, examinedUnitIdentities, findings: emitted.length, durationMs, status: unitsExamined === 0 ? "not-applicable" : "ran" }));
      context.recordDetectorRun(durationMs, selected.length);
    }
    for (const finding of findings) uniqueFindingOwner(finding, options);
    return { findings, records };
  });
}

const EXTERNALLY_OWNED_DETECTOR_EXPORTS: Readonly<Record<string, { bridgeFile: string; bridgeExport: string; runnerFile: string }>> = Object.freeze({
  detectPrismaAppPerfFindings: {
    bridgeFile: "src/scan/prisma-app-perf.ts",
    bridgeExport: "scanPrismaAppPerf",
    runnerFile: "src/cli/static-detect.ts",
  },
});

interface DiscoveredDetector {
  file: string;
  exportName: string;
}

export function discoverMechanicalDetectorExports(repoRoot: string): DiscoveredDetector[] {
  const scanDir = join(repoRoot, "src", "scan");
  const named = readEntriesSafe(scanDir).entries
    .filter((entry) => !entry.isDirectory && entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts"))
    .flatMap((entry) => {
      const text = readFileSync(entry.path, "utf8");
      return [...text.matchAll(/^export function (detect[A-Za-z0-9_]*Findings)/gm)].map((match) => ({ file: `src/scan/${entry.name}`, exportName: match[1]! }));
    })
  const declared = MECHANICAL_DETECTORS.map((definition) => ({ ...definition.implementation }));
  return [...new Map([...named, ...declared].map((implementation) => [
    `${implementation.file}#${implementation.exportName}`,
    implementation,
  ])).values()].sort((a, b) => a.exportName.localeCompare(b.exportName));
}

function literalTaxonomies(text: string): string[] {
  return [...text.matchAll(/taxonomy:\s*(["'])(.*?)\1/g)].map((match) => match[2]!);
}

function evidenceProblems(definition: MechanicalDetectorDefinition, repoRoot: string): string[] {
  const out: string[] = [];
  for (const [name, evidence] of Object.entries({ positiveFixture: definition.positiveFixture, benignTwin: definition.benignTwin, conservation: definition.conservation, corpus: definition.corpus, cadence: definition.cadence })) {
    if (evidence.detail.trim().length < 20) out.push(`${definition.id}: ${name} has no substantive status detail`);
    if (evidence.status === "covered" && (!evidence.path || !existsSync(join(repoRoot, evidence.path)))) out.push(`${definition.id}: ${name} points to missing evidence ${evidence.path ?? "(none)"}`);
    if (evidence.status === "covered" && evidence.path && existsSync(join(repoRoot, evidence.path))) {
      const proof = readFileSync(join(repoRoot, evidence.path), "utf8");
      if ((name === "positiveFixture" || name === "benignTwin") && !proof.includes(definition.implementation.exportName)) {
        out.push(`${definition.id}: ${name} does not consume ${definition.implementation.exportName}`);
      }
      if (name === "corpus" && !proof.includes("mechanicalRun.detectors")) out.push(`${definition.id}: corpus evidence does not consume the detector execution census`);
      if (name === "cadence" && !proof.includes("corpus-drift")) out.push(`${definition.id}: cadence evidence does not invoke the corpus detector lane`);
    }
    if (evidence.status === "structured-exception" && evidence.path) out.push(`${definition.id}: ${name} structured exception must explain itself instead of claiming a path`);
  }
  return out;
}

export function validateMechanicalDetectorRegistry(repoRoot: string, registry: readonly MechanicalDetectorDefinition[] = MECHANICAL_DETECTORS): string[] {
  const problems: string[] = [];
  const discovered = discoverMechanicalDetectorExports(repoRoot);
  const registeredImplementations = new Map(registry.map((definition) => [definition.implementation.exportName, definition]));
  for (const implementation of discovered) {
    if (implementation.exportName in EXTERNALLY_OWNED_DETECTOR_EXPORTS) {
      const owner = EXTERNALLY_OWNED_DETECTOR_EXPORTS[implementation.exportName]!;
      const bridge = readFileSync(join(repoRoot, owner.bridgeFile), "utf8");
      const runner = readFileSync(join(repoRoot, owner.runnerFile), "utf8");
      if (!bridge.includes(`${implementation.exportName}(`) || !new RegExp(`\\bexport function ${owner.bridgeExport}\\b`).test(bridge) || !runner.includes(`${owner.bridgeExport}(`)) {
        problems.push(`${implementation.exportName}: stale external owner ${owner.bridgeFile}#${owner.bridgeExport} -> ${owner.runnerFile}`);
      }
      continue;
    }
    if (!registeredImplementations.has(implementation.exportName)) problems.push(`${implementation.exportName}: implemented detector is not registered`);
  }
  const canonicalByImplementation = new Map(MECHANICAL_DETECTORS.map((definition) => [
    `${definition.implementation.file}#${definition.implementation.exportName}`,
    definition,
  ]));
  for (const definition of registry) {
    const implementationPath = join(repoRoot, definition.implementation.file);
    if (!existsSync(implementationPath)) {
      problems.push(`${definition.id}: stale registration points to missing ${definition.implementation.file}`);
      continue;
    }
    const source = readFileSync(implementationPath, "utf8");
    if (!new RegExp(`\\bexport (?:async )?function ${definition.implementation.exportName}\\b`).test(source)) problems.push(`${definition.id}: stale registration cannot find export ${definition.implementation.exportName}`);
    const canonical = canonicalByImplementation.get(`${definition.implementation.file}#${definition.implementation.exportName}`);
    if (canonical) {
      if (JSON.stringify(definition.findingIds) !== JSON.stringify(canonical.findingIds)) problems.push(`${definition.id}: finding-id ownership differs from the canonical implementation contract`);
      if (JSON.stringify(definition.taxonomies) !== JSON.stringify(canonical.taxonomies)) problems.push(`${definition.id}: taxonomy ownership differs from the canonical implementation contract`);
    }
    for (const taxonomy of literalTaxonomies(source)) if (!definition.taxonomies.some((pattern) => matches(pattern, taxonomy))) problems.push(`${definition.id}: unknown taxonomy ${taxonomy}`);
    if (definition.findingIds.length === 0 || definition.taxonomies.length === 0 || definition.applicableFiles.description.trim().length === 0 || definition.fallback.trim().length === 0) problems.push(`${definition.id}: required identity/applicability/fallback metadata is missing`);
    problems.push(...evidenceProblems(definition, repoRoot));
  }
  const duplicate = (values: readonly string[]): string[] => values.filter((value, index) => values.indexOf(value) !== index);
  for (const id of new Set(duplicate(registry.map((definition) => definition.id)))) problems.push(`duplicate detector id ownership: ${id}`);
  for (const owner of new Set(duplicate(registry.map((definition) => `${definition.implementation.file}#${definition.implementation.exportName}`)))) problems.push(`duplicate implementation ownership: ${owner}`);
  for (const order of new Set(duplicate(registry.map((definition) => String(definition.order))))) problems.push(`duplicate deterministic order: ${order}`);
  if (registry.some((definition, index) => index > 0 && registry[index - 1]!.order >= definition.order)) problems.push("detector registry order is not strictly increasing");
  return problems;
}
