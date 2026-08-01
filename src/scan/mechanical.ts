// Orchestrates the mechanical scan layer: secrets, dependency/framework CVEs, Semgrep
// footguns, supply chain, leftover-auth greps. Each sub-scanner shells out to its own CLI
// tool (see that module's header comment for install instructions) or walks the filesystem
// directly; this module runs them all and merges the resulting Finding[].
//
// CLI: `pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>]`

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { enrichFindingsCwe } from "../cwe-map.js";
import type { Finding } from "../findings.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { discoverAuthGuards } from "./auth-guard-discovery.js";
import { scanBolaOwner } from "./bola-owner.js";
import { scanSsrfWrapper } from "./ssrf-wrapper.js";
import { scanCounterRace } from "./counter-race.js";
import { scanPgIdor } from "./pg-idor.js";
import { scanPrismaTenantScope } from "./prisma-tenant-scope.js";
import { scanDrizzleTenantScope } from "./drizzle-tenant-scope.js";
import { scanClientSuppliedTenant } from "./client-supplied-tenant.js";
import { scanTenantGucScope } from "./tenant-guc-scope.js";
import { scanCacheTenantScope } from "./cache-tenant-scope.js";
import { scanStorageTenantScope } from "./storage-tenant-scope.js";
import { scanAuditLogTenant } from "./audit-log-tenant.js";
import { scanWebhookSignature } from "./webhook-signature.js";
import { scanMigrationColumnDrift } from "./migration-column-drift.js";
import { scanIdempotency } from "./idempotency.js";
import { scanStaleQuotaRead } from "./stale-quota-read.js";
import { scanPgResponseExposure } from "./pg-response-exposure.js";
import { scanSecretRotation } from "./secret-rotation.js";
import { scanSsrSanitizer } from "./ssr-sanitizer.js";
import { scanPropOvershare } from "./prop-overshare.js";
import { scanDedupWithoutUnique } from "./dedup-unique.js";
import { scanBolaCrossFile } from "./bola-cross-file.js";
import { scanServiceRoleLiteral } from "./service-role-literal.js";
import { scanEnvSchema } from "./env-schema.js";
import { scanEmitterUnhandledError } from "./emitter-error.js";
import { scanExpressPoweredBy } from "./express-powered-by.js";
import { scanExpressSecurityHeaders } from "./express-security-headers.js";
import { scanRawBodyNoLimit } from "./raw-body-limit.js";
import { annotateCveReachability, unrankedCveDisclosure } from "./dep-reachability.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs, osvUnavailableFinding, parseOsvFindings, resolvedTree, runOsvScanner } from "./dependencies.js";
import { detectOrm, ORM_LABELS, type TargetOrm } from "./framework-detect.js";
import { checkHostingConfigHeaders } from "./hosting-headers.js";
import { checkWorkflowPermissions } from "./gha-permissions.js";
import { checkInfrastructureScope } from "./infra-scope.js";
import { scanJobTenantScope } from "./job-tenant-scope.js";
import { checkUnanalysedLanguages } from "./language-coverage.js";
import { checkUnassessedSfcFiles } from "./sfc-coverage.js";
import { scanLeftoverAuth } from "./leftover-auth.js";
import { resolveScanScope } from "./scan-scope.js";
import { bundleScanSkippedFinding, resolveBundleScan, scanSecrets } from "./secrets.js";
import {
  checkMissingCsp,
  checkPublicDirSensitive,
  parseSemgrepFindings,
  partitionGuardTokenSuppressed,
  partitionMarkerSuppressed,
  runSemgrep,
  semgrepErrorFinding,
  semgrepScopeFinding,
  semgrepSuppressionFinding,
  semgrepUnavailableFinding,
} from "./semgrep.js";
import {
  checkEdgeFunctionVerifyJwt,
  checkMigrationDefinerAnonGrant,
  checkMigrationDefinerAuthz,
  checkMigrationDynamicSqlInjection,
  checkMigrationPolicySemantics,
  checkMigrationRlsInitplanStatic,
  checkMigrationRlsBypass,
  checkMigrationRlsCommandCoverage,
  checkMigrationRlsStatic,
  checkMigrationStorageBuckets,
  checkUnreadSqlSurfaces,
  checkOpenSignupConfig,
  inferAuthMethodsFromSource,
  type TenancyOverride,
} from "./supabase-static.js";
import { checkDependencyInstallScripts, checkInstallScripts, checkKnownIoc, checkLicenseCompliance, checkLockfilePresence, checkNonRegistryDependencies, checkSlopsquat, checkTyposquat, checkUnpinnedDependencies, NETWORK_SKIPPED_REASON, slopsquatCoverageFinding, supplyChainScopeFinding, type DependencyMap } from "./supply-chain.js";
import { checkWebExtensionManifest } from "./webext-manifest.js";
import { licenseScope } from "../sbom.js";
import { collectWorkspaceManifests } from "../workspaces.js";

interface PackageJson {
  dependencies?: DependencyMap;
  devDependencies?: DependencyMap;
}

function readPackageJson(dir: string): PackageJson | null {
  const path = join(dir, "package.json");
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as PackageJson;
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
}

// #757 (part of #756): the recognized-architecture record for a Prisma/Postgres target. Same
// visible-not-assessed disclosure contract as SEC-TH-GH-00/M5-00 — Info/N-A, never a defect — so
// the DB-level RLS tier's non-applicability is stated in the deliverable rather than left silent.
// It is NOT a vulnerability and NOT a partial-couldn't-run: on a Prisma app the RLS tier is N/A by
// architecture, and tenant isolation is assessed app-layer by the pg-idor/bola-owner/
// pg-response-exposure/service-role-literal passes plus the LLM semantic pass.
function prismaArchitectureNote(): Finding {
  return {
    id: "M1-ARCH-PRISMA",
    title: "DB-level RLS checks not applicable — Prisma/Postgres architecture",
    severity: "Info",
    confidence: "N/A",
    category: "Multi-tenant isolation",
    taxonomy: "Architecture — Prisma/Postgres (no DB-level RLS)",
    location: "(repo-wide)",
    status: "Open",
    evidence:
      "Target detected as a Prisma/Postgres app (schema.prisma / @prisma/client) with no Supabase project. Supabase's Postgres RLS lives in supabase/migrations and is enforced by the database; a Prisma app has none of that surface, so the migration-RLS, PostgREST-exposure, and edge-config detectors have nothing to analyze.",
    impact:
      "Not a defect. Tenant isolation in a Prisma app is entirely app-layer — enforced in query code, not by the database — so it is assessed by the app-layer M1 detectors (pg-idor, bola-owner, pg-response-exposure, service-role-literal) and the LLM semantic pass, not by the RLS detectors. This row records that the DB-level RLS tier is N/A by architecture rather than leaving its absence unstated.",
    fix: "None required. Confirm every query is tenant-scoped in application code (the app-layer M1 detectors cover this).",
    value: 1,
    ease: 5,
    safety: 5,
    mechanical: true,
  };
}

// #901: the M1 sibling of prismaArchitectureNote for Drizzle. #869 first disclosed Drizzle as
// wholly unassessed; #901 ships scanDrizzleTenantScope, so the builder-chain read/write shape
// (db.select()/update()/delete()...where(eq(t.id, …))) IS now covered. This row records the PARTIAL
// coverage: the query-builder idiom is analysed, the relational-query API (db.query.*.findFirst) and
// any raw-SQL escape hatch are not, so mechanical coverage is still incomplete (fail loud).
function drizzleArchitectureNote(): Finding {
  return {
    id: "M1-ARCH-DRIZZLE",
    title: "DB-level RLS checks not applicable — Drizzle/Postgres architecture; tenant-scope partially assessed",
    severity: "Info",
    confidence: "N/A",
    category: "Multi-tenant isolation",
    taxonomy: "Architecture — Drizzle (no DB-level RLS; builder-chain tenant-scope detector runs)",
    location: "(repo-wide)",
    status: "Open",
    evidence:
      "Target's data layer detected as Drizzle with no Supabase project — there is no DB-level RLS surface (the migration-RLS, PostgREST-exposure and edge-config detectors read supabase/migrations, supabase/config.toml and supabase/functions, none of which exist here). The Drizzle tenant-scope detector (#901, drizzle-tenant-scope) DID run: it flags a db.select()/update()/delete() chain whose .where(...) filters by the primary key alone (eq(table.id, …)) with no tenant/owner column.",
    impact:
      "Mechanical tenant-scope coverage for this target is PARTIAL, not clean: the Drizzle query-builder chain is analysed, but the relational-query API (db.query.<table>.findFirst/findMany) and any raw-SQL escape hatch are NOT — a missing tenant predicate in those shapes would not be flagged. Coverage is therefore INCOMPLETE; recorded so the absence of further findings reads as \"partially assessed\" rather than \"assessed and clean\".",
    fix: "Review tenant scoping in the relational-query API and any raw-SQL access by hand (or with the paid LLM semantic pass, which is not ORM-shape-bound): every read and write must filter on the tenant/owner column, not on the primary key alone.",
    value: 1,
    ease: 5,
    safety: 5,
    mechanical: true,
  };
}

// #869: the M1 sibling of #844/#757. M1's subject is tenant isolation. On Supabase that lives in
// RLS; on Prisma it lives in the app layer and #760 gives us a detector for the Prisma idiom; on
// Drizzle #901 gives us one for the builder-chain idiom (see drizzleArchitectureNote). On a
// Kysely/TypeORM/Sequelize/Knex/Mongoose target it ALSO lives in the app layer — and Harvey has no
// detector for those query builders' shapes, so the scan completed, reported nothing, and the
// absence read as "no tenant-scope problems found". This row states the limit instead. `orm` is a
// recognised non-Supabase, non-Prisma, non-Drizzle layer (the caller gates on that).
function unsupportedDataLayerNote(orm: Exclude<TargetOrm, "unknown" | "supabase" | "prisma" | "drizzle">): Finding {
  const label = ORM_LABELS[orm];
  // The app-layer detectors that DO run are shape-specific: Express+`pg` call sites (pg-idor,
  // pg-response-exposure), Supabase service-role clients (bola-owner, job-tenant-scope), and the
  // Prisma idiom (prisma-tenant-scope). A raw-SQL target is partly inside that set; a query-builder
  // target is entirely outside it. Say which, rather than implying uniform coverage.
  const covered =
    orm === "raw-sql"
      ? "The Express+`pg` app-layer detectors (pg-idor, pg-response-exposure) DID run and cover handlers written in that shape; queries issued from any other shape — a different HTTP framework, a hand-rolled query module — are matched by none of them."
      : `No detector matches ${label} query shapes: the app-layer M1 detectors that ran cover Express+\`pg\` call sites, Supabase service-role clients, the Prisma idiom (#760), and the Drizzle builder chain (#901) only.`;
  return {
    id: `M1-ARCH-${orm.toUpperCase()}`,
    title: `Tenant-scope checks not assessed — ${label} data layer`,
    severity: "Info",
    confidence: "N/A",
    category: "Multi-tenant isolation",
    taxonomy: `Architecture — ${label} (no DB-level RLS, no tenant-scope detector)`,
    location: "(repo-wide)",
    status: "Open",
    evidence: `Target's data layer detected as ${label} with no Supabase project. There is no DB-level RLS surface to analyse (the migration-RLS, PostgREST-exposure and edge-config detectors read supabase/migrations, supabase/config.toml and supabase/functions, none of which exist here), so tenant isolation is enforced entirely in application query code. ${covered}`,
    impact: `Mechanical tenant-scope coverage for this target is INCOMPLETE, not clean: a missing tenant predicate in a ${label} query would not be flagged by this tier. Recorded so the absence of M1 tenant-scope findings reads as "not assessed here" rather than "assessed and clean".`,
    fix: `Review tenant scoping in the ${label} data-access layer by hand (or with the paid LLM semantic pass, which is not ORM-shape-bound): every read and write must filter on the tenant/owner column, not on the primary key alone.`,
    value: 1,
    ease: 5,
    safety: 5,
    mechanical: true,
  };
}

export async function runMechanicalScan(opts: MechanicalScanOptions): Promise<Finding[]> {
  const { dir, bundleDir, tenancyOverride, handrolledIndicators, skipNetworkChecks, skipBundleScan } = opts;

  // Scope the walk to what should actually be scanned (issue #101): git-tracked files only
  // when dir is a git repo (excludes .env.local, .claude/worktrees/, node_modules, .next —
  // whatever's untracked/gitignored — while keeping deliberately-committed fixtures), or a
  // hard exclude list for a non-git target (zip export). Every filesystem-walking tool below
  // gets the scoped copy; only the git-history secret pass needs the real `dir` (it clones
  // the actual .git, which the scoped copy doesn't have).
  const { scanDir, cleanup } = resolveScanScope(dir);
  try {
    const findings: Finding[] = [];

    // Secrets — source, git history, and built bundle (auto-detected .next/static or dist/, #588).
    const bundle = skipBundleScan ? { disclosure: bundleScanSkippedFinding() } : resolveBundleScan(dir, bundleDir);
    findings.push(...scanSecrets(scanDir, dir, bundle.bundleDir));
    if (bundle.disclosure) findings.push(bundle.disclosure);

    // Framework/dependency CVEs.
    const osv = runOsvScanner(scanDir);
    findings.push(...(osv.failure ? [osvUnavailableFinding(osv.failure)] : parseOsvFindings(osv.result)));
    const pkg = readPackageJson(scanDir);
    // #1471 — the lockfile's RESOLVED version, when there is one. Passing the manifest's range
    // floor as if it were installed made "Installed next@14.2.5" a false claim on this repo's own
    // calibration target, whose lockfile resolves the patched 14.2.35.
    const resolved = resolvedTree(scanDir);
    const nextVersion = pkg?.dependencies?.next ?? pkg?.devDependencies?.next;
    if (nextVersion) findings.push(...checkNextVersionCVEs(nextVersion, "package.json", resolved));

    // Semgrep footguns + missing-CSP config check. #950 — a missing/crashing binary degrades to
    // the SEM-00 disclosure instead of an uncaught ENOENT (mirrors osv-scanner, #512).
    // #1066 — an in-repo `nosemgrep` marker still withholds its match from the finding list, but
    // the withheld matches are counted in SEM-SUPPRESS-00, and anything semgrep never analysed is
    // counted in SEM-SCOPE-00. A suppression the deliverable does not mention is one the audited
    // party made on the auditor's behalf.
    const semgrep = runSemgrep(scanDir);
    if (semgrep.failure) {
      findings.push(semgrepUnavailableFinding(semgrep.failure));
    } else {
      // #1093 — harvey-route-noauth/harvey-authed-no-role-check now match unconditionally in the
      // YAML; this re-derives their guard/role-check clause on the real matched span before
      // nosem re-derivation runs. A function the guard-token check clears was never a finding to
      // begin with (not an in-repo suppression), so it must not reach partitionMarkerSuppressed or
      // SEM-SUPPRESS-00.
      // #1300: the name lists in those two regexes are OURS; a project's house style is not.
      // Guard helpers discovered in the target's own source (option (1)) plus any supplied per
      // engagement (option (2)) clear the finding the same way a recognised name does.
      const projectGuards = [
        ...discoverAuthGuards(loadSources(scanDir).filter((f) => !NON_PRODUCT.test(f.path))),
        ...(opts.authGuards ?? []),
      ];
      const { reported: guardCleared } = partitionGuardTokenSuppressed(semgrep.result, projectGuards);
      const { reported, suppressed } = partitionMarkerSuppressed({ results: guardCleared });
      findings.push(...parseSemgrepFindings({ results: reported }));
      findings.push(...semgrepSuppressionFinding(suppressed, scanDir));
      findings.push(...semgrepScopeFinding(scanDir, semgrep.result));
      // #1077: a file semgrep errored on (syntax error) still counts as "scanned", so the SCOPE
      // diff above can't catch it — and paths.skipped is a distinct silence again. Named here so
      // neither reads as a clean file.
      findings.push(...semgrepErrorFinding(scanDir, semgrep.result));
    }
    findings.push(...checkMissingCsp(scanDir));
    findings.push(...checkHostingConfigHeaders(scanDir));
    findings.push(...checkPublicDirSensitive(scanDir));

    // #757 (part of #756): the Supabase-specific migration/RLS/PostgREST/edge-config detectors read
    // supabase/migrations, supabase/functions, and supabase/config.toml — a Prisma/Postgres app has
    // none of that DB-level RLS surface (all tenant isolation is app-layer, assessed by the
    // ORM-agnostic pg-idor/bola-owner/pg-response-exposure/service-role-literal passes below). On a
    // Prisma app, record that tier N/A by architecture instead of running detectors that can only
    // ever find nothing — an unstated absence of RLS reads as a clean bill of health (fail loud).
    // #869 extends the same routing to every other recognised non-Supabase layer: it has no
    // supabase/ surface either, and Harvey has no detector for its query shapes, so it gets a
    // named not-assessed row rather than silence.
    const orm = detectOrm(scanDir);
    if (orm === "prisma") {
      findings.push(prismaArchitectureNote());
    } else if (orm === "drizzle") {
      findings.push(drizzleArchitectureNote());
    } else if (orm !== "supabase" && orm !== "unknown") {
      findings.push(unsupportedDataLayerNote(orm));
    } else {
      findings.push(...checkMigrationRlsStatic(scanDir));
      findings.push(...checkMigrationRlsBypass(scanDir));
      findings.push(...checkMigrationRlsCommandCoverage(scanDir));
      findings.push(...checkMigrationPolicySemantics(scanDir, tenancyOverride));
      findings.push(...checkMigrationDefinerAuthz(scanDir));
      findings.push(...checkMigrationDefinerAnonGrant(scanDir));
      findings.push(...checkMigrationDynamicSqlInjection(scanDir));
      findings.push(...checkMigrationRlsInitplanStatic(scanDir));
      findings.push(...checkMigrationStorageBuckets(scanDir));
      // #1323 — the static SQL pass reads two surfaces (supabase/migrations/*.sql and a root
      // schema.sql). Any other .sql in the tree is counted and named, so a schema kept in db/ or
      // sql/ produces a disclosure row instead of an empty section that reads as clean.
      findings.push(...checkUnreadSqlSurfaces(scanDir));
      findings.push(...checkEdgeFunctionVerifyJwt(scanDir));
      // #671 — gate the email-confirmation advisor on whether email auth is actually used (source
      // heuristic): an OAuth-only app gets a conditional note, not an asserted Medium.
      findings.push(...checkOpenSignupConfig(scanDir, inferAuthMethodsFromSource(scanDir)));
    }
    findings.push(...checkWebExtensionManifest(scanDir));

    // #871 — source in languages no M1 rule can read (a Python/Go/Ruby service on the same tables
    // bypasses RLS just as effectively as a broken policy). Disclosure only, by design.
    findings.push(...checkUnanalysedLanguages(scanDir));

    // #919 — .svelte/.vue/.astro single-file components: invisible to every static/AST pass
    // (M5/M6/M7/M9 + the M1 AST detectors) AND, until now, uncounted. Same disclosure doctrine as
    // #871 immediately above. Disclosure only, by design.
    findings.push(...checkUnassessedSfcFiles(scanDir));

    // #886 — Dockerfiles/Terraform/K8s manifests are out of scope by decision, not by oversight
    // (docs/design/infrastructure-out-of-scope.md). Say so when the target has them.
    findings.push(...checkInfrastructureScope(scanDir));

    // #1212 — GITHUB_TOKEN scope. GHA is NOT covered by the infra-scope decision above: Harvey
    // already ships four registry GHA classes and a non-grading category built for them. The
    // missing-block half is an absence check, which no pattern rule can express.
    findings.push(...checkWorkflowPermissions(scanDir));

    // Supply chain. #1231/#1232 — the checks below split by what question each one asks, not by a
    // single scope: a name-match check reads the RESOLVED TREE (where the malicious or typosquatted
    // package actually arrives), a range-check reads the DECLARED MANIFESTS of every workspace
    // member (a lockfile has no ranges to read). Each split is argued at the check itself and stated
    // in the output by SUP-SCOPE-00 — a scope decision that lives only in a comment is, from the
    // deliverable's side, indistinguishable from an oversight.
    if (pkg) {
      const workspace = collectWorkspaceManifests(scanDir);
      // prod+dev only: a peer range is deliberately wide and would false-positive SUP-UNPINNED.
      const declared = workspace.manifests.flatMap((m) =>
        Object.entries({ ...m.dependencies, ...m.devDependencies }).map(([name, range]) => ({ manifest: m.label, name, range })),
      );
      const license = licenseScope(scanDir);
      // #1344: a workspace member is resolved from inside the repo, never from the registry, so a
      // registry HEAD for it returns 404 and SUP-SLOPSQUAT reads that as "hallucinated". #1231's
      // widening from the root manifest to every member is what first fed these names in, and the
      // result was 10 High "hallucinated dependency" rows on saas-lite (@kit/*) and 21 on carbon
      // (@carbon/*) — both graded F on the free tier (MEASURED 2026-07-27, #1344). Excluded on the
      // premise, not the symptom: these names are not registry packages, so the registry cannot
      // answer anything about them. Both signals are used because either alone misses cases — npm
      // and yarn-classic workspaces declare a member with a plain semver range, not `workspace:`.
      const workspaceOwnNames = new Set(workspace.manifests.map((m) => m.name).filter((n): n is string => typeof n === "string"));
      const isWorkspaceInternal = (d: { name: string; range: string }): boolean =>
        workspaceOwnNames.has(d.name) || /^(workspace|link|portal):/.test(d.range.trim());
      const workspaceInternalNames = [...new Set(declared.filter(isWorkspaceInternal).map((d) => d.name))];
      const declaredNames = [...new Set(declared.filter((d) => !isWorkspaceInternal(d)).map((d) => d.name))];
      // Root manifest first (workspace.manifests is root-first), then members, then the tree — so
      // any capped registry budget is spent on the packages the client actually chose.
      const allNames = [...new Set([...declaredNames, ...license.candidates.map((c) => c.name)])];
      const tree = { declared: new Set(declaredNames), source: license.source };

      findings.push(...checkTyposquat(allNames, tree));
      findings.push(...checkKnownIoc(allNames, "package.json", tree));
      // The curated CVE table is the OFFLINE FALLBACK for the tier osv-scanner owns. When
      // osv-scanner ran it already walked the whole lockfile, so widening this to the tree would
      // double-report its rows against a second id; when it did not, the tree is otherwise
      // unassessed for CVEs and the curated table is all there is. #1471: the DECLARED range used
      // to win over the resolved version for a name that has both — a range floor is not a version
      // match, so the resolved one now wins inside checkKnownDependencyCVEs via `resolved`.
      const curatedCveDeps: DependencyMap = {};
      if (osv.failure) for (const c of license.candidates) if (c.version) curatedCveDeps[c.name] ??= c.version;
      for (const d of declared) curatedCveDeps[d.name] = d.range;
      findings.push(...checkKnownDependencyCVEs(curatedCveDeps, "package.json", resolved));
      findings.push(...checkUnpinnedDependencies(declared));
      findings.push(...checkNonRegistryDependencies(declared));
      findings.push(...checkInstallScripts(workspace.manifests));
      // #1351 — the resolved-tree half checkInstallScripts cannot see (a dependency's OWN install
      // script, transitive ones included). Reads license.candidates below, which already carries
      // hasInstallScript when the resolved-tree source is package-lock.json.
      findings.push(...checkDependencyInstallScripts(license.candidates));
      if (skipNetworkChecks) {
        // #1067 — a deliberately skipped tier is still an unassessed tier. The committed dry-run
        // artifact has to SAY this never ran, or its silence reads as a clean verdict.
        findings.push(slopsquatCoverageFinding(declaredNames, NETWORK_SKIPPED_REASON));
      } else {
        findings.push(...(await checkSlopsquat(declaredNames)));
      }
      // #456 — license compliance (SPDX + copyleft/unknown flags). #1213: the candidate set is the
      // RESOLVED TREE, not the manifest — a copyleft package reached only transitively was
      // previously never submitted to the check — plus the manifest's optional/peer deps, which
      // are exactly where a package's platform binaries (the ATC `@img/sharp-*` case) live.
      // The classification itself is offline for a lockfile that records licenses, so unlike
      // checkSlopsquat it still runs under skipNetworkChecks; only the registry fallback is pinned
      // off, and the packages that leaves unclassified are named in SUP-LICENSE-00.
      findings.push(...(await checkLicenseCompliance(license, { skipRegistry: skipNetworkChecks })));
      findings.push(
        supplyChainScopeFinding({
          license,
          treeNames: new Set(license.candidates.map((c) => c.name)).size,
          declaredNames: declaredNames.length,
          workspaceInternalNames,
          osvRan: osv.failure === undefined,
        }),
      );
    }
    findings.push(...checkLockfilePresence(scanDir));

    // Leftover-auth greps.
    findings.push(...scanLeftoverAuth(scanDir));

    // #353 — non-atomic read-modify-write race (AST dataflow over source files, incl. plain .js).
    findings.push(...scanCounterRace(scanDir));

    // #433 — authenticated pages/api handler scoping a service-role query by a request-supplied
    // owner id (BOLA). AST dataflow, incl. plain .js.
    findings.push(...scanBolaOwner(scanDir));

    // #1325 (#570 remainder) — cross-file SSRF through a fetch wrapper whose name is NOT one of
    // harvey-ssrf-fetch's curated four (fetchRemote/fetchUrl/fetchExternal/proxyFetch). Resolves
    // the actual import + checks the callee's definition SHAPE instead of guessing by name.
    findings.push(...scanSsrfWrapper(scanDir));

    // #663 — Express + pg repo-function IDOR: an authenticated handler passes a client-supplied
    // id straight into a name-gated read-by-id repo function, no ownership comparison.
    findings.push(...scanPgIdor(scanDir));

    // #701 (#663 remainder) — Express + pg excessive data exposure: res.json(...) names a
    // curated sensitive field directly, spreads a same-function object that does, or hands
    // back a same-function "SELECT *" row untouched.
    findings.push(...scanPgResponseExposure(scanDir));

    // #760 — Prisma-idiom cross-tenant BOLA: a `prisma.<model>.<verb>({ where: { id } })` read/
    // write filtered by primary key alone, with no tenant/owner column. ORM-agnostic app-layer
    // class — a Prisma app has no RLS, so the where clause is the only isolation gate.
    findings.push(...scanPrismaTenantScope(scanDir));

    // #901 — Drizzle-idiom cross-tenant BOLA: a `db.select()/update()/delete()...where(eq(t.id, …))`
    // read/write filtered by primary key alone, with no tenant/owner column. Same app-layer class as
    // #760 for a different query builder — a Drizzle app has no RLS, so the where is the only gate.
    findings.push(...scanDrizzleTenantScope(scanDir));

    // #1194 — the OTHER half of tenant scoping, which #760/#901 structurally cannot see: the tenant
    // predicate is PRESENT and names the right column, and its VALUE comes from the request. OWASP
    // Multi-Tenant CS section 1 ("Never trust client-supplied tenant IDs").
    findings.push(...scanClientSuppliedTenant(scanDir));

    // #1195 — a tenant GUC set with SET rather than SET LOCAL / set_config(..., true): the setting
    // outlives its transaction under transaction-mode pooling, so a later request on that reused
    // connection is evaluated against the previous tenant's identifier.
    findings.push(...scanTenantGucScope(scanDir));

    // #1196 — a cache key derived from the resource id alone, with no tenant discriminator, in a
    // function that already has one in scope: the first tenant to populate the entry serves its
    // rows to every other tenant asking for the same resource id.
    findings.push(...scanCacheTenantScope(scanDir));

    // #1198 — a Supabase storage object path built from the caller-supplied filename alone, with no
    // tenant prefix or ownership check: one tenant overwrites and reads another's objects in a
    // shared bucket. Distinct from AUTH-upload-no-limit (leftover-auth.ts), which fires on the same
    // shape for an unrelated defect (no size/MIME limit).
    findings.push(...scanStorageTenantScope(scanDir));

    // #1242 — an audit entry that names the actor and a state change but no tenant: a cross-tenant
    // access cannot be reconstructed afterwards, which undercuts the sheet's own detective control.
    findings.push(...scanAuditLogTenant(scanDir));

    // #1230 / D-091 item 12 — a webhook signature decoded with an encoding the provider does not
    // use: every genuine delivery fails verification and the handler is silently inoperative.
    findings.push(...scanWebhookSignature(scanDir));

    // #1230 / D-091 item 13 — app code names a column the migration history already dropped.
    // Column names are strings inside the query chain, so tsc cannot see the break.
    findings.push(...scanMigrationColumnDrift(scanDir));

    // #1230 / D-091 items 10, 22, 24 — three retry-safety orderings: a dedup row written before
    // the handler it guards, a batch send stamped after dispatch instead of claimed before, and an
    // external send from a retryable job with no idempotency key.
    findings.push(...scanIdempotency(scanDir));

    // #1230 / D-091 item 6 — a budget/limit gate read once and then consumed across a loop of
    // operations without re-reading, so the cap is enforced against a stale value.
    findings.push(...scanStaleQuotaRead(scanDir));

    // #664 — service_role key hardcoded as a JWT literal (same-file or cross-file const) and
    // passed to createClient. Real base64 decode + role/iss claim check, incl. plain .js.
    findings.push(...scanServiceRoleLiteral(scanDir));

    // #1202 — EventEmitter emits 'error' with no same-file listener; disclosed same-file-only
    // limitation (a listener attached by an importing module is invisible to this pass).
    findings.push(...scanEmitterUnhandledError(scanDir));

    // #1204 — an Express app whose constructing module never disables X-Powered-By. Review tier,
    // and the finding itself states the two things a static pass cannot see (a disable in another
    // module, a strip at the proxy/CDN). The "use helmet" half of the same OWASP line is declined
    // by ruling — see the recorded reason in express-powered-by.ts.
    findings.push(...scanExpressPoweredBy(scanDir));

    // #1350 — the effect check that decline assumed already existed. b5-headers only reads a
    // next.config.js headers() route (MEASURED: bare Express app 0 findings, same omission in a
    // next.config.js 3), so on Express nothing checked the headers and nothing said so. Adoption is
    // still not a defect: hand-set headers clear this exactly as a header middleware does.
    findings.push(...scanExpressSecurityHeaders(scanDir));

    // #1200 — a raw `req.on("data", …)` accumulator with no byte ceiling; disclosed
    // single-handler limitation (a ceiling imposed by middleware elsewhere is invisible).
    findings.push(...scanRawBodyNoLimit(scanDir));

    // #1239 — `dompurify` (browser-only) called in a server-rendered module. Its own pass because
    // every dangerouslySetInnerHTML rule EXCLUDES an import-bound sanitizer wrap, so the semgrep
    // layer is structurally blind to it.
    findings.push(...scanSsrSanitizer(scanDir));

    // #1252 — a whole domain object handed to a component as one prop when its declared type
    // carries a sensitive field. Its own pass because it is a TYPE question: the semgrep layer does
    // not read an interface declaration, so it has no view of what is in the object being passed.
    findings.push(...scanPropOvershare(scanDir));

    // #1257 / D-091 item 25 — SELECT-then-INSERT dedup whose predicate columns carry no UNIQUE
    // constraint. Folds the migration DDL against the app-side predicate, the same shape
    // migration-column-drift.ts uses for item 13.
    findings.push(...scanDedupWithoutUnique(scanDir));

    // #1267 — the route → repository → query chain across a module boundary: the cross-file
    // complement of scanBolaOwner, which is single-file by construction. Non-overlap is structural
    // (one requires the .eq() in the handler file, the other requires it in an imported module).
    findings.push(...scanBolaCrossFile(scanDir));

    // #681 — service-role query in a background-job path (Inngest/cron/queue/worker) with no
    // tenant predicate at all. AST dataflow, incl. plain .js.
    findings.push(...scanJobTenantScope(scanDir));
    // #680 — a static secret verified with a single equality/HMAC check and no dual-secret
    // rotation window (inter-service seams only; inert when no verify site exists).
    findings.push(...scanSecretRotation(scanDir));
    // #679 — env-schema completeness: `process.env.X` reads not declared in the target's env
    // schema module (undeclared read → finding; declared-but-unread → Info). No schema, no diff.
    findings.push(...scanEnvSchema(scanDir));

    // M6 free-tier indicators (#267) — product code only; test/fixture files aren't audit
    // findings. package.json stays in the set: the class-merge dep-gate reads it.
    if (handrolledIndicators) {
      findings.push(...detectHandrolledFindings(loadSources(scanDir).filter((f) => !NON_PRODUCT.test(f.path))));
    }

    // #874 — rank the Dependency CVE rows by whether the package is actually imported here. Runs
    // LAST so it sees every CVE emitter's output (curated Next.js, curated deps, OSV) in one pass.
    // Ordering + a per-row justification only: nothing here grades, and nothing sets
    // exploitabilityVerified (#213/#227 stands).
    const directDeps = new Set(Object.keys({ ...pkg?.dependencies, ...pkg?.devDependencies }));
    const ranked = annotateCveReachability(findings, scanDir, directDeps);
    if (ranked.unranked > 0) {
      // Fail loud rather than letting unranked rows sink silently to the bottom of a sorted list.
      ranked.findings.push(unrankedCveDisclosure(ranked.unranked));
    }
    // #975 — declare each AST detector's CWE (semgrep rows already carry theirs from rule metadata).
    return enrichFindingsCwe(ranked.findings);
  } finally {
    cleanup();
  }
}
