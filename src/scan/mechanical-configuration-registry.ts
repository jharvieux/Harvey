import type { Finding } from "../findings.js";
import { checkWorkflowPermissions } from "./gha-permissions.js";
import { detectOrm, type TargetOrm } from "./framework-detect.js";
import { checkInfrastructureScope } from "./infra-scope.js";
import { checkUnanalysedLanguages } from "./language-coverage.js";
import { architectureFindings } from "./mechanical-architecture.js";
import type { MechanicalProducerRecord } from "./mechanical-phase-cache.js";
import type { MechanicalScanContext } from "./mechanical-context.js";
import { checkUnassessedSfcFiles } from "./sfc-coverage.js";
import {
  checkEdgeFunctionVerifyJwt,
  checkMigrationDefinerAnonGrant,
  checkMigrationDefinerAuthz,
  checkMigrationDynamicSqlInjection,
  checkMigrationPolicySemantics,
  checkMigrationRlsBypass,
  checkMigrationRlsCommandCoverage,
  checkMigrationRlsInitplanStatic,
  checkMigrationRlsStatic,
  checkMigrationStorageBuckets,
  checkOpenSignupConfig,
  checkUnreadSqlSurfaces,
  inferAuthMethodsFromSource,
  type TenancyOverride,
} from "./supabase-static.js";
import { checkWebExtensionManifest } from "./webext-manifest.js";
import { assertProducerTaxonomyOwnership } from "./mechanical-registry-contract.js";
import { producerAssurance, type MechanicalEngineEvidence } from "./mechanical-registry-assurance.js";

interface MechanicalEngineDefinition<Input> {
  id: string;
  order: number;
  module: "M1";
  phase: "configuration";
  implementation: { file: string; exportName: string };
  additionalImplementations?: readonly { file: string; exportName: string }[];
  taxonomies: readonly string[];
  applicableFiles: { description: string; select: (input: Input) => readonly unknown[] };
  countExaminedUnits: (input: Input, selected: readonly unknown[]) => number;
  prerequisites: readonly string[];
  fallback: string;
  positiveFixture: MechanicalEngineEvidence;
  benignTwin: MechanicalEngineEvidence;
  conservation: MechanicalEngineEvidence;
  corpus: MechanicalEngineEvidence;
  cadence: MechanicalEngineEvidence;
  enabled?: (input: Input) => boolean;
  invoke: (input: Input) => Finding[];
}

interface ConfigurationInput {
  context: MechanicalScanContext;
  scanDir: string;
  tenancyOverride?: TenancyOverride;
  orm: TargetOrm;
}

const supabaseSurface = (input: ConfigurationInput): boolean => input.orm === "supabase" || input.orm === "unknown";

const fixtureFor = (file: string): string | undefined => ({
  "src/scan/supabase-static.ts": "src/scan/supabase-static.test.ts",
  "src/scan/language-coverage.ts": "src/scan/language-coverage.test.ts",
  "src/scan/sfc-coverage.ts": "src/scan/sfc-coverage.test.ts",
  "src/scan/infra-scope.ts": "src/scan/infra-scope.test.ts",
  "src/scan/gha-permissions.ts": "src/scan/gha-permissions.test.ts",
} as Record<string, string>)[file];

function definition(input: Pick<MechanicalEngineDefinition<ConfigurationInput>, "id" | "order" | "implementation" | "taxonomies" | "applicableFiles" | "invoke"> & Partial<MechanicalEngineDefinition<ConfigurationInput>>): MechanicalEngineDefinition<ConfigurationInput> {
  return Object.freeze({
    module: "M1", phase: "configuration",
    countExaminedUnits: (_full, selected) => selected.length,
    prerequisites: Object.freeze([]),
    fallback: "An inapplicable surface emits its architecture/scope disclosure or records zero examined units at the phase level.",
    ...producerAssurance(input.id, input.implementation, fixtureFor(input.implementation.file)),
    ...input,
  } as MechanicalEngineDefinition<ConfigurationInput>);
}

const surface = (description: string, select: (input: ConfigurationInput) => readonly unknown[]): MechanicalEngineDefinition<ConfigurationInput>["applicableFiles"] => ({ description, select });
const migrations = surface("ordered Supabase migration SQL files", ({ context }) => context.schemas.orderedMigrations.filter((entry) => entry.file.startsWith("supabase/migrations/")));
const supabaseConfiguration = surface("Supabase config and edge-function files", ({ context }) => context.paths.filter((path) => path === "supabase/config.toml" || path.startsWith("supabase/functions/")));

export const CONFIGURATION_DETECTORS: readonly MechanicalEngineDefinition<ConfigurationInput>[] = Object.freeze([
  definition({ id: "architecture-router", order: 10, implementation: { file: "src/scan/mechanical-architecture.ts", exportName: "architectureFindings" }, taxonomies: ["Architecture — *"], applicableFiles: surface("root manifest and detected data-layer signatures", ({ context }) => context.sourceAndRootManifest), invoke: ({ orm }) => architectureFindings(orm) }),
  definition({ id: "migration-rls-static", order: 20, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationRlsStatic" }, taxonomies: ["Migration table without RLS (static)", "Migration disables RLS on a public table (static)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationRlsStatic(scanDir) }),
  definition({ id: "migration-rls-bypass", order: 30, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationRlsBypass" }, taxonomies: ["Role with BYPASSRLS defeats row-level security (static)", "RLS enabled without FORCE — owner bypasses policies (static)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationRlsBypass(scanDir) }),
  definition({ id: "migration-rls-command", order: 40, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationRlsCommandCoverage" }, taxonomies: ["RLS policy set grants a write with no read policy (static permission matrix)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationRlsCommandCoverage(scanDir) }),
  definition({ id: "migration-policy-semantics", order: 50, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationPolicySemantics" }, taxonomies: ["M1 — Multi-tenant security", "USING(true) read policy on an M10-classified PII table (static)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir, tenancyOverride }) => checkMigrationPolicySemantics(scanDir, tenancyOverride) }),
  definition({ id: "migration-definer-authz", order: 60, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationDefinerAuthz" }, taxonomies: ["M1 — Multi-tenant security"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationDefinerAuthz(scanDir) }),
  definition({ id: "migration-definer-anon", order: 70, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationDefinerAnonGrant" }, taxonomies: ["SECURITY DEFINER granted to anon (static)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationDefinerAnonGrant(scanDir) }),
  definition({ id: "migration-dynamic-sql", order: 80, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationDynamicSqlInjection" }, taxonomies: ["plpgsql dynamic SQL injection (static)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationDynamicSqlInjection(scanDir) }),
  definition({ id: "migration-rls-initplan", order: 90, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationRlsInitplanStatic" }, taxonomies: ["auth_rls_initplan (static)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationRlsInitplanStatic(scanDir) }),
  definition({ id: "migration-storage-buckets", order: 100, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkMigrationStorageBuckets" }, taxonomies: ["Public storage bucket declared in migration SQL (static)", "storage.objects read policy open to anon (static)"], applicableFiles: migrations, enabled: supabaseSurface, invoke: ({ scanDir }) => checkMigrationStorageBuckets(scanDir) }),
  definition({ id: "unread-sql-surfaces", order: 110, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkUnreadSqlSurfaces" }, taxonomies: ["Coverage — SQL outside the schema surfaces M1 reads"], applicableFiles: surface("all SQL files compared with supported schema surfaces", ({ context }) => context.paths.filter((path) => path.endsWith(".sql"))), enabled: supabaseSurface, invoke: ({ scanDir }) => checkUnreadSqlSurfaces(scanDir) }),
  definition({ id: "edge-function-jwt", order: 120, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkEdgeFunctionVerifyJwt" }, taxonomies: ["Edge Function verify_jwt disabled"], applicableFiles: supabaseConfiguration, enabled: supabaseSurface, invoke: ({ scanDir }) => checkEdgeFunctionVerifyJwt(scanDir) }),
  definition({ id: "open-signup-config", order: 130, implementation: { file: "src/scan/supabase-static.ts", exportName: "checkOpenSignupConfig" }, additionalImplementations: [{ file: "src/scan/supabase-static.ts", exportName: "inferAuthMethodsFromSource" }], taxonomies: ["Open signup enabled", "Email confirmation disabled"], applicableFiles: surface("Supabase auth configuration plus source auth-method signals", ({ context }) => [...context.paths.filter((path) => path === "supabase/config.toml"), ...context.sourceFiles]), enabled: supabaseSurface, invoke: ({ scanDir }) => checkOpenSignupConfig(scanDir, inferAuthMethodsFromSource(scanDir)) }),
  definition({ id: "web-extension-manifest", order: 140, implementation: { file: "src/scan/webext-manifest.ts", exportName: "checkWebExtensionManifest" }, taxonomies: ["Over-broad WebExtension permissions"], applicableFiles: surface("WebExtension manifest files", ({ context }) => context.paths.filter((path) => /(^|\/)manifest\.json$/.test(path))), invoke: ({ scanDir }) => checkWebExtensionManifest(scanDir) }),
  definition({ id: "language-coverage", order: 150, implementation: { file: "src/scan/language-coverage.ts", exportName: "checkUnanalysedLanguages" }, taxonomies: ["Coverage — non-JS/TS source not analysed for tenant isolation"], applicableFiles: surface("source-like files outside the JavaScript/TypeScript analyzer", ({ context }) => context.paths.filter((path) => /\.(py|go|rb|rs|java|kt|php|cs)$/.test(path))), invoke: ({ scanDir }) => checkUnanalysedLanguages(scanDir) }),
  definition({ id: "sfc-coverage", order: 160, implementation: { file: "src/scan/sfc-coverage.ts", exportName: "checkUnassessedSfcFiles" }, taxonomies: ["Coverage — single-file-component (.svelte/.vue/.astro) source not analysed"], applicableFiles: surface("Svelte, Vue, and Astro single-file components", ({ context }) => context.paths.filter((path) => /\.(svelte|vue|astro)$/.test(path))), invoke: ({ scanDir }) => checkUnassessedSfcFiles(scanDir) }),
  definition({ id: "infrastructure-scope", order: 170, implementation: { file: "src/scan/infra-scope.ts", exportName: "checkInfrastructureScope" }, taxonomies: ["Coverage — infrastructure/IaC out of scope"], applicableFiles: surface("Docker, Terraform, Kubernetes, Helm, and Compose files", ({ context }) => context.paths.filter((path) => /(^|\/)(Dockerfile|docker-compose[^/]*|.*\.(tf|tfvars)|Chart\.yaml|values\.ya?ml)$/.test(path) || /(^|\/)(k8s|kubernetes|helm)\//.test(path))), invoke: ({ scanDir }) => checkInfrastructureScope(scanDir) }),
  definition({ id: "workflow-permissions", order: 180, implementation: { file: "src/scan/gha-permissions.ts", exportName: "checkWorkflowPermissions" }, taxonomies: ["GitHub Actions workflow grants write-all token permissions", "GitHub Actions workflow declares no token permissions"], applicableFiles: surface("GitHub Actions workflow YAML files", ({ context }) => context.paths.filter((path) => /^\.github\/workflows\/.*\.ya?ml$/.test(path))), invoke: ({ scanDir }) => checkWorkflowPermissions(scanDir) }),
]);

export function runRegisteredConfigurationDetectors(input: Omit<ConfigurationInput, "orm">): { findings: Finding[]; records: MechanicalProducerRecord[] } {
  const full = { ...input, orm: detectOrm(input.scanDir) };
  const findings: Finding[] = [];
  const records: MechanicalProducerRecord[] = [];
  for (const detector of CONFIGURATION_DETECTORS) {
    if (!(detector.enabled?.(full) ?? true)) {
      records.push({ detector: detector.id, phase: detector.phase, order: detector.order, module: detector.module, unitsExamined: 0, findings: 0, durationMs: 0, status: "not-applicable" });
      continue;
    }
    const selected = detector.applicableFiles.select(full);
    const unitsExamined = detector.countExaminedUnits(full, selected);
    const started = performance.now();
    const emitted = detector.invoke(full);
    assertProducerTaxonomyOwnership(detector, emitted);
    findings.push(...emitted);
    records.push({ detector: detector.id, phase: detector.phase, order: detector.order, module: detector.module, unitsExamined, findings: emitted.length, durationMs: performance.now() - started, status: "ran" });
  }
  return { findings, records };
}
