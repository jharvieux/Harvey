// Orchestrates the mechanical scan layer: secrets, dependency/framework CVEs, Semgrep
// footguns, supply chain, leftover-auth greps. Each sub-scanner shells out to its own CLI
// tool (see that module's header comment for install instructions) or walks the filesystem
// directly; this module runs them all and merges the resulting Finding[].
//
// CLI: `pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>]`

import type { Finding } from "../findings.js";
import { runOsvScanner, type OsvScanResult } from "./dependencies.js";
import { resolveScanScope } from "./scan-scope.js";
import type { TenancyOverride } from "./supabase-static.js";
import type { DependencyMap } from "./supply-chain.js";
import {
  canonicalizeCorpusOsvInput,
  compareCorpusAdvisoryState,
  CorpusAdvisoryFindingChangeError,
  type CorpusAdvisoryComparisonReceipt,
} from "../corpus-advisory-snapshot.js";
import {
  MECHANICAL_PHASES,
  assertMechanicalCacheVerification,
  executeMechanicalPhase,
  type MechanicalPhaseCacheOptions,
  type MechanicalPhaseRecord,
  type MechanicalPhaseValue,
} from "./mechanical-phase-cache.js";
import { MechanicalScanContext, type MechanicalContextMetrics } from "./mechanical-context.js";
import { runRegisteredMechanicalDetectors, type DetectorExecutionRecord } from "./mechanical-detector-registry.js";
import { runRegisteredConfigurationDetectors } from "./mechanical-configuration-registry.js";
import { runRegisteredDependencyDetectors } from "./mechanical-dependency-registry.js";
import { runRegisteredSemgrepEngines } from "./mechanical-semgrep-registry.js";
import { runRegisteredSecretsEngines } from "./mechanical-secrets-registry.js";
import { runRegisteredNormalizationEngines } from "./mechanical-normalization-registry.js";
import { MECHANICAL_REGISTRY, type MechanicalRegistryEntry } from "./mechanical-engine-registry.js";
import type { SemgrepDiagnosticEvidence, SemgrepExecutionPlanReceipt } from "./semgrep-family-cache.js";

interface PackageJson {
  dependencies?: DependencyMap;
  devDependencies?: DependencyMap;
}

interface MechanicalScanOptions {
  dir: string;
  bundleDir?: string; // .next/static after `next build`, if available — passed to the secret scan
  // Force the built-bundle secret pass to report NOT RUN instead of auto-detecting a bundle.
  //
  // WHY (found 2026-07-26 by the dry-run-drift gate failing on a correctly-regenerated artifact):
  // resolveBundleScan probes the ORIGINAL target dir, not the git-tracked scratch copy, so it finds
  // a gitignored .next/static when the developer happens to have run a build. For a real engagement
  // that is DESIRED — client-inlined secrets live in shipped JS, which is never committed. But it
  // makes the output depend on local build state, and dry-run/findings.json is committed and
  // contractually deterministic. Same class of uncontrolled input as the live npm-registry calls,
  // and handled the same way: the dry-run harness pins it off so SEC-BUNDLE-00 always emits, which
  // is also the honest report — the dry run genuinely does not scan a bundle.
  skipBundleScan?: boolean;
  // #280 — the same tenancy declaration detect-deeper.ts accepts at the connected tier
  // (--tenant-key/--tenant-mode), so the static RLS-tenancy inference can be told the app's
  // convention instead of only inferring it from the built-in candidate list.
  tenancyOverride?: TenancyOverride;
  // #267 — also run the M6 "looks hand-rolled" indicator detectors (Info-only, non-grading).
  // Opt-in: the free-report path (quick-scan) wants them; the calibration gate and the other
  // M1-scoring callers keep the M1-only default so their answer keys stay one-question keys.
  handrolledIndicators?: boolean;
  // Make no live npm-registry request: skip checkSlopsquat entirely and pin off
  // checkLicenseCompliance's registry FALLBACK (#1213 — that check classifies from the lockfile
  // with no network, so skipping the whole tier would hide a real copyleft detection rather than a
  // nondeterministic one). Default false (real engagements always run both in full). The
  // deterministic dry-run harness (src/cli/dry-run.ts) is the one caller that opts in: its
  // committed findings.json is supposed to be reproducible across machines, and a
  // registry-reachability dependency would let it drift on an offline/blipped CI run for reasons
  // that have nothing to do with the scanner's own code.
  skipNetworkChecks?: boolean;
  // #1300 / #126 option (2): guard helper names supplied per engagement, folded into the
  // route-noauth / authed-no-role-check clearance test alongside the ones discoverAuthGuards finds
  // in the target's own source (option (1)). #126 recommended both; PR #127 shipped neither.
  authGuards?: string[];
  phaseCache?: MechanicalPhaseCacheOptions;
  advisorySnapshot?: { result: OsvScanResult; digest: string; capturedAt: string; expiresAt: string; osvScannerVersion: string };
  advisoryParitySnapshot?: { result: OsvScanResult; digest: string; capturedAt: string };
  advisoryFindingChangeDisposition?: "throw" | "record";
  onAdvisoryObservation?: (receipt: CorpusAdvisoryComparisonReceipt) => void;
  secretCandidateIdentity?: string;
}

interface MechanicalScanResult {
  findings: Finding[];
  phases: MechanicalPhaseRecord[];
  detectors: DetectorExecutionRecord[];
  context: MechanicalContextMetrics;
  semgrepDiagnostics: SemgrepDiagnosticEvidence;
  semgrepExecution?: SemgrepExecutionPlanReceipt;
  advisoryObservation?: CorpusAdvisoryComparisonReceipt;
}

export interface MechanicalProducerPhaseOwnership {
  producer: string;
  phase: MechanicalRegistryEntry["phase"];
  order: number;
  module: MechanicalRegistryEntry["module"];
  registryFile: string;
}

export interface MechanicalCorpusOwnership {
  schema: 1;
  producers: readonly MechanicalProducerPhaseOwnership[];
}

/**
 * Project the live mechanical registries into their execution ownership census.
 * The optional registry is a pure seam for discovery/negative controls; production callers use
 * MECHANICAL_REGISTRY, whose entries are themselves assembled from every live phase registry.
 */
export function discoverMechanicalCorpusOwnership(
  registry: readonly Pick<MechanicalRegistryEntry, "id" | "phase" | "order" | "module" | "registryFile">[] = MECHANICAL_REGISTRY,
): MechanicalCorpusOwnership {
  return Object.freeze({
    schema: 1,
    producers: Object.freeze(registry.map((producer) => Object.freeze({
      producer: producer.id,
      phase: producer.phase,
      order: producer.order,
      module: producer.module,
      registryFile: producer.registryFile,
    }))),
  });
}

export async function runMechanicalScanDetailed(opts: MechanicalScanOptions): Promise<MechanicalScanResult> {
  const { dir, bundleDir, tenancyOverride, handrolledIndicators, skipNetworkChecks, skipBundleScan, advisorySnapshot, advisoryParitySnapshot, secretCandidateIdentity } = opts;
  if (advisorySnapshot && !skipNetworkChecks) throw new Error("an immutable advisory snapshot requires skipNetworkChecks so live registry fallbacks cannot masquerade as deterministic input");

  // Scope the walk to what should actually be scanned (issue #101): git-tracked files only
  // when dir is a git repo (excludes .env.local, .claude/worktrees/, node_modules, .next —
  // whatever's untracked/gitignored — while keeping deliberately-committed fixtures), or a
  // hard exclude list for a non-git target (zip export). Every filesystem-walking tool below
  // gets the scoped copy; only the git-history secret pass needs the real `dir` (it clones
  // the actual .git, which the scoped copy doesn't have).
  const { scanDir, cleanup } = resolveScanScope(dir);
  let ownedContext: MechanicalScanContext | undefined;
  try {
    ownedContext = new MechanicalScanContext(scanDir);
    const context = ownedContext;
    const findings: Finding[] = [];
    const phases: MechanicalPhaseRecord[] = [];
    const allUnits = Math.max(1, context.metrics().filesPresent);
    const sourceUnits = Math.max(1, context.sourceFiles.length);
    const stablePaths = (rows: Finding[]): Finding[] => rows.map((row) => Object.fromEntries(
      Object.entries(row).map(([key, value]) => [key, typeof value === "string"
        ? value.replaceAll(`${scanDir}/`, "").replaceAll(scanDir, "(repo-wide)").replaceAll(`${dir}/`, "").replaceAll(dir, "(repo-wide)")
        : value]),
    ) as unknown as Finding);
    const runPhase = async (phase: Parameters<typeof executeMechanicalPhase>[0], execute: () => MechanicalPhaseValue | Promise<MechanicalPhaseValue>): Promise<MechanicalPhaseValue> => {
      const record = await executeMechanicalPhase(phase, opts.phaseCache, async () => {
        const value = await execute();
        return { ...value, findings: stablePaths(value.findings) };
      });
      phases.push(record);
      return record;
    };

    // Secrets — source, git history, and built bundle (auto-detected .next/static or dist/, #588).
    const secrets = await runPhase("secrets-history", () => {
      const result = runRegisteredSecretsEngines({ scanDir, originalDir: dir, bundleDir, skipBundleScan, secretCandidateIdentity, unitsExamined: allUnits, context });
      return { findings: result.findings, producers: result.records, scope: { unitsExamined: allUnits, description: secretCandidateIdentity
        ? `pinned working-tree secret candidates under identity ${secretCandidateIdentity}; provider verification belongs to the live lane`
        : "tracked source tree, pinned git history, and discovered built bundle" } };
    });
    findings.push(...secrets.findings);

    // Framework/dependency CVEs.
    const packageSource = context.sourceAndRootManifest.find((file) => file.path === "package.json");
    const pkg = packageSource ? JSON.parse(packageSource.text) as PackageJson : null;
    // #1471 — the lockfile's RESOLVED version, when there is one. Passing the manifest's range
    // floor as if it were installed made "Installed next@14.2.5" a false claim on this repo's own
    // calibration target, whose lockfile resolves the patched 14.2.35.
    const dependencyStart = Date.now();
    const observedOsv = advisorySnapshot ? { result: advisorySnapshot.result } : runOsvScanner(scanDir);
    context.recordToolResult("osv", observedOsv);
    const osv = context.toolResult<typeof observedOsv>("osv")!;
    let advisoryObservation: CorpusAdvisoryComparisonReceipt | undefined;
    if (advisoryParitySnapshot && osv.failure) {
      throw new Error(`live OSV advisory verification did not complete: ${osv.failure}`);
    }
    const parityLiveRaw = advisoryParitySnapshot && !osv.failure ? canonicalizeCorpusOsvInput(osv.result) : undefined;
    const dependencyInput = {
      context,
      scanDir,
      pkg,
      osv: parityLiveRaw ? { result: parityLiveRaw } : osv,
      skipNetworkChecks,
    };
    const earlyDependency = await runRegisteredDependencyDetectors(dependencyInput, "early");
    if (advisoryParitySnapshot && !osv.failure) {
      const liveRaw = parityLiveRaw!;
      const snapshotRaw = canonicalizeCorpusOsvInput(advisoryParitySnapshot.result);
      const snapshotDependency = await runRegisteredDependencyDetectors({
        ...dependencyInput,
        osv: { result: snapshotRaw },
      }, "early");
      advisoryObservation = compareCorpusAdvisoryState({
        liveRaw,
        snapshotRaw,
        liveFindings: earlyDependency.findingsByDetector["osv-advisories"] ?? [],
        snapshotFindings: snapshotDependency.findingsByDetector["osv-advisories"] ?? [],
      });
      opts.onAdvisoryObservation?.(advisoryObservation);
      if (advisoryObservation.status === "finding-change" && opts.advisoryFindingChangeDisposition !== "record") {
        throw new CorpusAdvisoryFindingChangeError(
          `live OSV findings differ from committed corpus snapshot ${advisoryParitySnapshot.digest} captured ${advisoryParitySnapshot.capturedAt}; scheduled freshness detected a delivered-finding change`,
          advisoryObservation,
        );
      }
    }
    const dependencyFindings = stablePaths(earlyDependency.findings);
    findings.push(...dependencyFindings);

    // Semgrep footguns + missing-CSP config check. #950 — a missing/crashing binary degrades to
    // the SEM-00 disclosure instead of an uncaught ENOENT (mirrors osv-scanner, #512).
    // #1066 — an in-repo `nosemgrep` marker still withholds its match from the finding list, but
    // the withheld matches are counted in SEM-SUPPRESS-00, and anything semgrep never analysed is
    // counted in SEM-SCOPE-00. A suppression the deliverable does not mention is one the audited
    // party made on the auditor's behalf.
    const semgrepPhase = await runPhase("semgrep", async () => {
      const result = await runRegisteredSemgrepEngines({ scanDir, context, phaseCache: opts.phaseCache, authGuards: opts.authGuards, unitsExamined: allUnits });
      return {
        findings: result.findings,
        producers: result.records,
        evidence: { semgrepDiagnostics: result.diagnostics, ...(result.executionPlan ? { semgrepExecution: result.executionPlan } : {}) },
        scope: { unitsExamined: allUnits, description: "Semgrep registry/local rules plus CSP, hosting-header, and public-directory configuration checks" },
      };
    });
    // diff above can't catch it — and paths.skipped is a distinct silence again. Named here so
    findings.push(...semgrepPhase.findings);

    // #757 (part of #756): the Supabase-specific migration/RLS/PostgREST/edge-config detectors read
    // supabase/migrations, supabase/functions, and supabase/config.toml — a Prisma/Postgres app has
    // none of that DB-level RLS surface (all tenant isolation is app-layer, assessed by the
    // ORM-agnostic pg-idor/bola-owner/pg-response-exposure/service-role-literal passes below). On a
    // Prisma app, record that tier N/A by architecture instead of running detectors that can only
    // ever find nothing — an unstated absence of RLS reads as a clean bill of health (fail loud).
    // #869 extends the same routing to every other recognised non-Supabase layer: it has no
    // supabase/ surface either, and Harvey has no detector for its query shapes, so it gets a
    // named not-assessed row rather than silence.
    const configuration = await runPhase("configuration", () => {
      const result = runRegisteredConfigurationDetectors({ context, scanDir, tenancyOverride });
      return {
        findings: result.findings,
        producers: result.records,
        scope: { unitsExamined: allUnits, description: "architecture, migration/configuration, unsupported-language, infrastructure, and workflow-permission surfaces" },
      };
    });
    findings.push(...configuration.findings);

    // premise, not the symptom: these names are not registry packages, so the registry cannot
    // #1351 — the resolved-tree half checkInstallScripts cannot see (a dependency's OWN install
    const supplyDependency = await runRegisteredDependencyDetectors(dependencyInput, "supply");
    const supplyFindings = stablePaths(supplyDependency.findings);
    dependencyFindings.push(...supplyFindings);
    findings.push(...supplyFindings);
    await runPhase("dependency-advisory", () => ({
      findings: dependencyFindings,
      producers: [...earlyDependency.records, ...supplyDependency.records],
      scope: { unitsExamined: Math.max(1, context.workspace.manifests.length), description: advisorySnapshot
        ? `lockfiles/manifests against immutable OSV snapshot ${advisorySnapshot.digest} (${advisorySnapshot.osvScannerVersion}, captured ${advisorySnapshot.capturedAt}, expires ${advisorySnapshot.expiresAt}); live registry fallbacks disabled`
        : "lockfiles, resolved dependency tree, declared manifests, current OSV advisories, and live registry-backed checks" },
    }));
    phases[phases.length - 1]!.durationMs = Date.now() - dependencyStart;

    const structural = await runPhase("structural-ast", () => {
      const registered = runRegisteredMechanicalDetectors(context, { handrolledIndicators });
      return { findings: registered.findings, producers: registered.records, scope: { unitsExamined: sourceUnits, description: "registry-owned source greps, dataflow, and structural/AST detectors over one immutable scan context" } };
    });
    findings.push(...structural.findings);
    // Normalization consumes findings only. Release the bounded raw-AST working set at the real
    // consumer boundary rather than retaining it until report assembly and target cleanup.
    context.releaseAstWorkingSet();

    // #874 — rank the Dependency CVE rows by whether the package is actually imported here. Runs
    // LAST so it sees every CVE emitter's output (curated Next.js, curated deps, OSV) in one pass.
    // Ordering + a per-row justification only: nothing here grades, and nothing sets
    // exploitabilityVerified (#213/#227 stands).
    const directDeps = new Set(Object.keys({ ...pkg?.dependencies, ...pkg?.devDependencies }));
    const normalized = await runPhase("normalization", () => {
      const result = runRegisteredNormalizationEngines({ findings, scanDir, directDeps });
      return {
        findings: result.findings,
        producers: result.records,
        scope: { unitsExamined: Math.max(1, findings.length), description: "all phase findings composed, dependency reachability ranked, and CWE metadata enriched" },
      };
    });
    const recorded = new Set(phases.map((phase) => phase.phase));
    const missing = MECHANICAL_PHASES.filter((phase) => !recorded.has(phase));
    const duplicates = phases.map((phase) => phase.phase).filter((phase, index, all) => all.indexOf(phase) !== index);
    if (missing.length > 0 || duplicates.length > 0) {
      throw new Error(`mechanical phase accounting incomplete: missing [${missing.join(", ")}], duplicated [${duplicates.join(", ")}]`);
    }
    const detectorRecords = phases.flatMap((phase) => phase.producers ?? []);
    const expectedProducers = discoverMechanicalCorpusOwnership().producers.map((producer) => `${producer.phase}:${producer.producer}`);
    const actualProducers = detectorRecords.map((producer) => `${producer.phase}:${producer.detector}`);
    const missingProducers = expectedProducers.filter((identity) => !actualProducers.includes(identity));
    const extraProducers = actualProducers.filter((identity) => !expectedProducers.includes(identity));
    const duplicateProducers = actualProducers.filter((identity, index, all) => all.indexOf(identity) !== index);
    const mismatchedFindingCounts = phases.filter((phase) => (phase.producers ?? []).reduce((sum, producer) => sum + producer.findings, 0) !== phase.findings.length)
      .map((phase) => `${phase.phase}=${(phase.producers ?? []).reduce((sum, producer) => sum + producer.findings, 0)}/${phase.findings.length}`);
    if (missingProducers.length > 0 || extraProducers.length > 0 || duplicateProducers.length > 0 || mismatchedFindingCounts.length > 0) {
      throw new Error(`mechanical producer accounting incomplete: missing [${missingProducers.join(", ")}], extra [${extraProducers.join(", ")}], duplicated [${[...new Set(duplicateProducers)].join(", ")}], finding-counts [${mismatchedFindingCounts.join(", ")}]`);
    }
    assertMechanicalCacheVerification(phases, opts.phaseCache);
    // #975 — declare each AST detector's CWE (semgrep rows already carry theirs from rule metadata).
    const semgrepDiagnostics = semgrepPhase.evidence?.semgrepDiagnostics;
    if (!semgrepDiagnostics) throw new Error("Semgrep phase did not retain complete diagnostic evidence");
    const semgrepExecution = semgrepPhase.evidence?.semgrepExecution;
    return {
      findings: normalized.findings,
      phases,
      detectors: detectorRecords,
      context: context.metrics(),
      semgrepDiagnostics,
      ...(semgrepExecution ? { semgrepExecution } : {}),
      ...(advisoryObservation ? { advisoryObservation } : {}),
    };
  } finally {
    ownedContext?.dispose();
    cleanup();
  }
}

export async function runMechanicalScan(opts: MechanicalScanOptions): Promise<Finding[]> {
  return (await runMechanicalScanDetailed(opts)).findings;
}
