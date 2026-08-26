// #1689 / #1800 — counted disclosure for every detector CLASS whose production selector can admit
// zero files because of a path convention. The original registry stopped at detector entry points
// (`bola-owner` and `job-tenant-scope`). #1800 extends the same rule one level down: a whole-tree
// detector can still leave an individual class unassessed when that class accepts only route,
// test, framework, or request-entry paths. A zero from that unread population is not a clean scan.
//
// Each owner exports its metadata and the selector its production implementation consumes. This
// module only composes those exports; it never copies a regex. `path-scope.test.ts` independently
// discovers source selectors as well as class-metadata exports, and exercises every class through
// the shipping registry and rendered document. Re-run `src/cli/path-scope-census.ts` for counts.

import type { Finding } from "../findings.js";
import type { SourceInput } from "../detectors/common.js";
import { NON_PRODUCT } from "../detectors/load-sources.js";
import type { TargetFramework } from "./framework-detect.js";
import { M5_TYPE_ESCAPE_PATH_SCOPE_CLASSES, m5TypeEscapeSources } from "../detectors/m5-type-escape.js";
import { M8_VACUOUS_ASSERTION_PATH_SCOPE_CLASSES, vacuousAssertionSourceFiles } from "../detectors/m8-vacuous-assertion.js";
import {
  APP_ROUTER_PATH_SCOPE_CLASSES,
  appRouterClientRootFiles,
  appRouterMissingServerOnlyFiles,
  appRouterPageLayoutFiles,
  appRouterResponseFiles,
  appRouterRouteOrEdgeFiles,
  appRouterRouteSegmentFiles,
  appRouterSsrJsxFiles,
} from "../detectors/app-router.js";
import {
  PERF_CODE_PATH_SCOPE_CLASSES,
  perfApplicationCodeFiles,
  perfMiddlewareFiles,
  perfRerenderCandidateFiles,
  perfSyncIoCandidateFiles,
} from "../detectors/perf-code.js";
import { TEST_INTENT_PATH_SCOPE_CLASSES, securityCriticalSourceFiles, staticTestIntentFiles } from "../detectors/test-intent.js";
import { VITEST_INTENT_PATH_SCOPE_CLASSES, vitestInSourceFiles, vitestTestFiles } from "../detectors/vitest-intent.js";
import { AUTH_GUARD_DISCOVERY_PATH_SCOPE_CLASSES, authGuardDiscoveryFiles } from "./auth-guard-discovery.js";
import { bolaOwnerScannedFiles } from "./bola-owner.js";
import { BOLA_CROSS_FILE_PATH_SCOPE_CLASSES, bolaCrossFileHandlerFiles } from "./bola-cross-file.js";
import { ENV_SCHEMA_PATH_SCOPE_CLASSES, envSchemaModuleCandidates } from "./env-schema.js";
import { IDEMPOTENCY_PATH_SCOPE_CLASSES, retryableExternalSendFiles } from "./idempotency.js";
import { jobTenantScopeScannedFiles } from "./job-tenant-scope.js";
import {
  LEFTOVER_AUTH_PATH_SCOPE_CLASSES,
  leftoverAuthRateLimitFiles,
  leftoverSensitiveRouteFiles,
  leftoverUnscopedDmlFiles,
  leftoverWebhookFiles,
} from "./leftover-auth.js";

export interface PathScopeContext {
  framework?: TargetFramework;
  /** Exact caller inventories; omitted only when the supplied in-memory fixture is the inventory. */
  identifiedSourceFiles?: readonly SourceInput[];
  sourceFiles?: readonly SourceInput[];
  envSourceFiles?: readonly SourceInput[];
}

type PathScopeInventory = "loaded-sources" | "identified-sources" | "source-files" | "env-source-files" | "product-loaded-sources";

export interface PathScopedClass {
  /** Row id emitted when this class's filter admits nothing. */
  rowId: string;
  detector: string;
  /** Stable semantic class/family identifier, normally its emitted taxonomy. */
  classId: string;
  /** Owning source export, retained by the census completeness receipt. */
  ownerFile: string;
  selectorSymbol: string;
  /** The caller's input before this class's exported selector runs. */
  inventory?: Exclude<PathScopeInventory, "loaded-sources">;
  /** What the filter admits, in the words a client reads. */
  convention: string;
  /** THE detector's own exported filter — never a copy of it. */
  select: (files: readonly SourceInput[], context: Readonly<PathScopeContext>) => SourceInput[];
  /** A framework/runner family may make the class genuinely inapplicable rather than empty. */
  applicable?: (files: readonly SourceInput[], context: Readonly<PathScopeContext>) => boolean;
  /** The class that goes unassessed when the population is empty. */
  classes: string;
}

export const ENTRY_POINT_PATH_SCOPE_CLASSES: readonly PathScopedClass[] = [
  {
    rowId: "M1-PATHSCOPE-BOLA-00",
    detector: "bola-owner",
    classId: "Request-supplied owner id trusted by an authenticated Pages Router handler",
    ownerFile: "src/scan/bola-owner.ts",
    inventory: "source-files",
    selectorSymbol: "bolaOwnerScannedFiles",
    convention: "Next.js Pages Router API routes (`pages/api/**`, excluding test/example trees)",
    select: bolaOwnerScannedFiles,
    classes: "a request-supplied owner id trusted by an authenticated Pages Router handler (BOLA)",
  },
  {
    rowId: "M1-PATHSCOPE-JOB-00",
    detector: "job-tenant-scope",
    classId: "Service-role query in a background-job path with no tenant predicate",
    ownerFile: "src/scan/job-tenant-scope.ts",
    inventory: "source-files",
    selectorSymbol: "jobTenantScopeScannedFiles",
    convention: "conventional background-job directories (`inngest/`, `jobs/`, `queues/`, `workers/`, `app/api/cron/`)",
    select: jobTenantScopeScannedFiles,
    classes: "a service-role query with no tenant predicate running outside a request context",
  },
];

interface PathScopeClassGroup {
  ownerFile: string;
  exportName: string;
  classes: readonly PathScopedClass[];
}

/** Owner registries paired with the declaration discovery in `path-scope.test.ts`. */
export const PATH_SCOPE_CLASS_GROUPS: readonly PathScopeClassGroup[] = [
  { ownerFile: "src/scan/path-scope.ts", exportName: "ENTRY_POINT_PATH_SCOPE_CLASSES", classes: ENTRY_POINT_PATH_SCOPE_CLASSES },
  { ownerFile: "src/scan/leftover-auth.ts", exportName: "LEFTOVER_AUTH_PATH_SCOPE_CLASSES", classes: LEFTOVER_AUTH_PATH_SCOPE_CLASSES },
  { ownerFile: "src/scan/env-schema.ts", exportName: "ENV_SCHEMA_PATH_SCOPE_CLASSES", classes: ENV_SCHEMA_PATH_SCOPE_CLASSES },
  { ownerFile: "src/scan/auth-guard-discovery.ts", exportName: "AUTH_GUARD_DISCOVERY_PATH_SCOPE_CLASSES", classes: AUTH_GUARD_DISCOVERY_PATH_SCOPE_CLASSES },
  { ownerFile: "src/scan/idempotency.ts", exportName: "IDEMPOTENCY_PATH_SCOPE_CLASSES", classes: IDEMPOTENCY_PATH_SCOPE_CLASSES },
  { ownerFile: "src/scan/bola-cross-file.ts", exportName: "BOLA_CROSS_FILE_PATH_SCOPE_CLASSES", classes: BOLA_CROSS_FILE_PATH_SCOPE_CLASSES },
  { ownerFile: "src/detectors/app-router.ts", exportName: "APP_ROUTER_PATH_SCOPE_CLASSES", classes: APP_ROUTER_PATH_SCOPE_CLASSES },
  { ownerFile: "src/detectors/perf-code.ts", exportName: "PERF_CODE_PATH_SCOPE_CLASSES", classes: PERF_CODE_PATH_SCOPE_CLASSES },
  { ownerFile: "src/detectors/test-intent.ts", exportName: "TEST_INTENT_PATH_SCOPE_CLASSES", classes: TEST_INTENT_PATH_SCOPE_CLASSES },
  { ownerFile: "src/detectors/vitest-intent.ts", exportName: "VITEST_INTENT_PATH_SCOPE_CLASSES", classes: VITEST_INTENT_PATH_SCOPE_CLASSES },
  { ownerFile: "src/detectors/m5-type-escape.ts", exportName: "M5_TYPE_ESCAPE_PATH_SCOPE_CLASSES", classes: M5_TYPE_ESCAPE_PATH_SCOPE_CLASSES },
  { ownerFile: "src/detectors/m8-vacuous-assertion.ts", exportName: "M8_VACUOUS_ASSERTION_PATH_SCOPE_CLASSES", classes: M8_VACUOUS_ASSERTION_PATH_SCOPE_CLASSES },
];

const EXPORTED_SELECTOR_BINDINGS = new Map<string, PathScopedClass["select"]>([
  ["src/scan/bola-owner.ts#bolaOwnerScannedFiles", bolaOwnerScannedFiles],
  ["src/scan/job-tenant-scope.ts#jobTenantScopeScannedFiles", jobTenantScopeScannedFiles],
  ["src/scan/leftover-auth.ts#leftoverSensitiveRouteFiles", leftoverSensitiveRouteFiles],
  ["src/scan/leftover-auth.ts#leftoverAuthRateLimitFiles", leftoverAuthRateLimitFiles],
  ["src/scan/leftover-auth.ts#leftoverWebhookFiles", leftoverWebhookFiles],
  ["src/scan/leftover-auth.ts#leftoverUnscopedDmlFiles", leftoverUnscopedDmlFiles],
  ["src/scan/env-schema.ts#envSchemaModuleCandidates", envSchemaModuleCandidates],
  ["src/scan/auth-guard-discovery.ts#authGuardDiscoveryFiles", authGuardDiscoveryFiles],
  ["src/scan/idempotency.ts#retryableExternalSendFiles", retryableExternalSendFiles],
  ["src/scan/bola-cross-file.ts#bolaCrossFileHandlerFiles", bolaCrossFileHandlerFiles],
  ["src/detectors/app-router.ts#appRouterClientRootFiles", appRouterClientRootFiles],
  ["src/detectors/app-router.ts#appRouterMissingServerOnlyFiles", appRouterMissingServerOnlyFiles],
  ["src/detectors/app-router.ts#appRouterPageLayoutFiles", appRouterPageLayoutFiles],
  ["src/detectors/app-router.ts#appRouterResponseFiles", appRouterResponseFiles],
  ["src/detectors/app-router.ts#appRouterRouteOrEdgeFiles", appRouterRouteOrEdgeFiles],
  ["src/detectors/app-router.ts#appRouterRouteSegmentFiles", appRouterRouteSegmentFiles],
  ["src/detectors/app-router.ts#appRouterSsrJsxFiles", appRouterSsrJsxFiles],
  ["src/detectors/perf-code.ts#perfRerenderCandidateFiles", perfRerenderCandidateFiles],
  ["src/detectors/perf-code.ts#perfApplicationCodeFiles", perfApplicationCodeFiles],
  ["src/detectors/perf-code.ts#perfMiddlewareFiles", perfMiddlewareFiles],
  ["src/detectors/perf-code.ts#perfSyncIoCandidateFiles", perfSyncIoCandidateFiles],
  ["src/detectors/test-intent.ts#staticTestIntentFiles", staticTestIntentFiles],
  ["src/detectors/test-intent.ts#securityCriticalSourceFiles", securityCriticalSourceFiles],
  ["src/detectors/vitest-intent.ts#vitestTestFiles", vitestTestFiles],
  ["src/detectors/vitest-intent.ts#vitestInSourceFiles", vitestInSourceFiles],
  ["src/detectors/m5-type-escape.ts#m5TypeEscapeSources", m5TypeEscapeSources],
  ["src/detectors/m8-vacuous-assertion.ts#vacuousAssertionSourceFiles", vacuousAssertionSourceFiles],
]);

/** Existing public name retained while its population grows from detectors to per-class rows. */
export const PATH_SCOPED_DETECTORS: readonly PathScopedClass[] = PATH_SCOPE_CLASS_GROUPS.flatMap((group) => group.classes);

for (const row of PATH_SCOPED_DETECTORS) {
  const key = `${row.ownerFile}#${row.selectorSymbol}`;
  if (EXPORTED_SELECTOR_BINDINGS.get(key) !== row.select) {
    throw new Error(`Path-scope selector binding is missing or stale: ${key}`);
  }
}

export interface PathScopeCensusRow {
  rowId: string;
  detector: string;
  classId: string;
  ownerFile: string;
  selectorSymbol: string;
  convention: string;
  inventory: PathScopeInventory;
  inputFiles: number;
  applicable: boolean;
  filesRead: number;
}

function selections(
  files: readonly SourceInput[],
  context: Readonly<PathScopeContext>,
  classes: readonly PathScopedClass[],
  invokeInapplicable = false,
): Map<PathScopedClass, { applicable: boolean; files: SourceInput[]; inputFiles: number }> {
  const inventories: Record<PathScopeInventory, readonly SourceInput[]> = {
    "loaded-sources": files,
    "identified-sources": context.identifiedSourceFiles ?? files,
    "source-files": context.sourceFiles ?? files,
    "env-source-files": context.envSourceFiles ?? files,
    "product-loaded-sources": files.filter((file) => !NON_PRODUCT.test(file.path)),
  };
  const selectorCache = new Map<PathScopeInventory, Map<PathScopedClass["select"], SourceInput[]>>();
  const out = new Map<PathScopedClass, { applicable: boolean; files: SourceInput[]; inputFiles: number }>();
  for (const entry of classes) {
    const inventory = entry.inventory ?? "loaded-sources";
    const inputs = inventories[inventory];
    const applicable = entry.applicable?.(inputs, context) ?? true;
    if (!applicable && !invokeInapplicable) {
      out.set(entry, { applicable: false, files: [], inputFiles: inputs.length });
      continue;
    }
    let cache = selectorCache.get(inventory);
    if (!cache) {
      cache = new Map();
      selectorCache.set(inventory, cache);
    }
    let selected = cache.get(entry.select);
    if (selected === undefined) {
      selected = entry.select(inputs, context);
      cache.set(entry.select, selected);
    }
    out.set(entry, { applicable, files: selected, inputFiles: inputs.length });
  }
  return out;
}

/** Per-class production-selector counts — published directly, never inferred from findings. */
export function pathScopeCensus(
  files: readonly SourceInput[],
  context: Readonly<PathScopeContext> = {},
  classes: readonly PathScopedClass[] = PATH_SCOPED_DETECTORS,
): PathScopeCensusRow[] {
  // A census is also the completeness receipt: invoke every distinct production selector at every
  // target pin even when the class is framework/runner-inapplicable, and retain applicability as a
  // separate fact. The report can therefore distinguish "selector admitted zero" from "class does
  // not apply" without silently omitting either observation.
  const selected = selections(files, context, classes, true);
  return classes.map((entry) => {
    const population = selected.get(entry)!;
    return {
      rowId: entry.rowId,
      detector: entry.detector,
      classId: entry.classId,
      ownerFile: entry.ownerFile,
      selectorSymbol: entry.selectorSymbol,
      convention: entry.convention,
      inventory: entry.inventory ?? "loaded-sources",
      inputFiles: population.inputFiles,
      applicable: population.applicable,
      filesRead: population.files.length,
    };
  });
}

/**
 * One counted not-assessed row per applicable path-gated class whose production selector admitted
 * no file. M1-EXT-00 owns whole-scan absence; an entirely empty input emits no class-specific rows.
 */
export function pathScopeNotAssessedRows(
  files: readonly SourceInput[],
  context: Readonly<PathScopeContext> = {},
  classes: readonly PathScopedClass[] = PATH_SCOPED_DETECTORS,
): Finding[] {
  if ([files, context.identifiedSourceFiles, context.sourceFiles, context.envSourceFiles]
    .every((inventory) => !inventory?.length)) return [];
  const selected = selections(files, context, classes);
  return classes
    .filter((entry) => {
      const population = selected.get(entry)!;
      return population.applicable && population.files.length === 0;
    })
    .map((row) => ({
      id: row.rowId,
      title: `Not assessed: ${row.classId} found no files in its production scope`,
      severity: "Info" as const,
      confidence: "N/A" as const,
      category: "Coverage",
      taxonomy: `Coverage — ${row.detector}/${row.classId} read zero files (its path convention matched nothing)`,
      location: "(repo-wide)",
      status: "Open" as const,
      evidence: `The ${row.detector} class \`${row.classId}\` invokes its exported production selector \`${row.selectorSymbol}\`, which admits only ${row.convention}. This target supplied ${selected.get(row)!.inputFiles} file(s) in its ${row.inventory ?? "loaded-sources"} inventory and NONE were admitted, so the class ran over an empty population. Its zero findings are a statement about scope, not about the code.`,
      impact: `This check would not have detected ${row.classes} here, wherever such code actually lives in this repo. Recorded so the absence of its findings reads as 'not assessed', not 'assessed and clean'.`,
      fix: "If this repo does hold code of that kind under a different layout, review those files by hand or move them under the convention so the check reaches them. If it holds none, this row records that the class had nothing to examine.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    }));
}
