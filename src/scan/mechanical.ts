// Orchestrates the mechanical scan layer: secrets, dependency/framework CVEs, Semgrep
// footguns, supply chain, leftover-auth greps. Each sub-scanner shells out to its own CLI
// tool (see that module's header comment for install instructions) or walks the filesystem
// directly; this module runs them all and merges the resulting Finding[].
//
// CLI: `pnpm exec tsx src/cli/scan.ts --mechanical --dir <path> [--bundle <path>]`

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "../findings.js";
import { detectHandrolledFindings } from "../detectors/handrolled.js";
import { loadSources, NON_PRODUCT } from "../detectors/load-sources.js";
import { scanBolaOwner } from "./bola-owner.js";
import { scanCounterRace } from "./counter-race.js";
import { scanPgIdor } from "./pg-idor.js";
import { scanPrismaTenantScope } from "./prisma-tenant-scope.js";
import { scanPgResponseExposure } from "./pg-response-exposure.js";
import { scanSecretRotation } from "./secret-rotation.js";
import { scanServiceRoleLiteral } from "./service-role-literal.js";
import { scanEnvSchema } from "./env-schema.js";
import { checkKnownDependencyCVEs, checkNextVersionCVEs, osvUnavailableFinding, parseOsvFindings, type OsvScanResult } from "./dependencies.js";
import { detectOrm, ORM_LABELS, type TargetOrm } from "./framework-detect.js";
import { checkHostingConfigHeaders } from "./hosting-headers.js";
import { scanJobTenantScope } from "./job-tenant-scope.js";
import { checkUnanalysedLanguages } from "./language-coverage.js";
import { scanLeftoverAuth } from "./leftover-auth.js";
import { resolveScanScope } from "./scan-scope.js";
import { resolveBundleScan, scanSecrets } from "./secrets.js";
import { checkMissingCsp, checkPublicDirSensitive, parseSemgrepFindings, runSemgrep } from "./semgrep.js";
import {
  checkEdgeFunctionVerifyJwt,
  checkMigrationDefinerAnonGrant,
  checkMigrationDefinerAuthz,
  checkMigrationDynamicSqlInjection,
  checkMigrationPolicySemantics,
  checkMigrationRlsInitplanStatic,
  checkMigrationRlsStatic,
  checkOpenSignupConfig,
  inferAuthMethodsFromSource,
  type TenancyOverride,
} from "./supabase-static.js";
import { checkInstallScripts, checkKnownIoc, checkLicenseCompliance, checkLockfilePresence, checkNonRegistryDependencies, checkSlopsquat, checkTyposquat, checkUnpinnedDependencies, type DependencyMap } from "./supply-chain.js";
import { checkWebExtensionManifest } from "./webext-manifest.js";

interface PackageJson {
  dependencies?: DependencyMap;
  devDependencies?: DependencyMap;
  scripts?: Record<string, string>;
}

function readPackageJson(dir: string): PackageJson | null {
  const path = join(dir, "package.json");
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as PackageJson;
}

const LOCKFILES = ["pnpm-lock.yaml", "package-lock.json", "yarn.lock"];

function runOsvScanner(dir: string): { result: OsvScanResult; failure?: string } {
  const lockfile = LOCKFILES.find((f) => existsSync(join(dir, f)));
  // No lockfile is a target property, not a tool failure — checkLockfilePresence discloses it.
  if (!lockfile) return { result: {} };
  let out: string;
  try {
    out = execFileSync("osv-scanner", ["--format", "json", "--lockfile", join(dir, lockfile)], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024 * 64,
    });
  } catch (err) {
    // osv-scanner exits 1 when it finds vulnerabilities — stdout still has the report.
    const e = err as { stdout?: string; code?: string; message?: string };
    if (typeof e.stdout === "string" && e.stdout.length > 0) out = e.stdout;
    // #512: a failure with no report (binary missing, crash) must not silently cost the
    // engagement its CVE pass — surface the reason so the caller emits the disclosure finding.
    else return { result: {}, failure: e.code === "ENOENT" ? "osv-scanner not found on PATH" : (e.message ?? "osv-scanner failed with no output") };
  }
  return { result: out.trim() ? (JSON.parse(out) as OsvScanResult) : {} };
}

interface MechanicalScanOptions {
  dir: string;
  bundleDir?: string; // .next/static after `next build`, if available — passed to the secret scan
  // #280 — the same tenancy declaration detect-deeper.ts accepts at the connected tier
  // (--tenant-key/--tenant-mode), so the static RLS-tenancy inference can be told the app's
  // convention instead of only inferring it from the built-in candidate list.
  tenancyOverride?: TenancyOverride;
  // #267 — also run the M6 "looks hand-rolled" indicator detectors (Info-only, non-grading).
  // Opt-in: the free-report path (quick-scan) wants them; the calibration gate and the other
  // M1-scoring callers keep the M1-only default so their answer keys stay one-question keys.
  handrolledIndicators?: boolean;
  // Skip checkLicenseCompliance/checkSlopsquat — the only two live npm-registry calls in this
  // scan. Default false (real engagements always run both). The deterministic dry-run harness
  // (src/cli/dry-run.ts) is the one caller that opts in: its committed findings.json is supposed
  // to be reproducible across machines, and a registry-reachability dependency would let it drift
  // on an offline/blipped CI run for reasons that have nothing to do with the scanner's own code.
  skipNetworkChecks?: boolean;
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

// #869: the M1 sibling of #844/#757. M1's subject is tenant isolation. On Supabase that lives in
// RLS; on Prisma it lives in the app layer and #760 gives us a detector for the Prisma idiom. On a
// Drizzle/Kysely/TypeORM/Sequelize/Knex/Mongoose target it ALSO lives in the app layer — and Harvey
// has no detector for those query builders' shapes, so the scan completed, reported nothing, and
// the absence read as "no tenant-scope problems found". This row states the limit instead.
// `orm` is a recognised non-Supabase, non-Prisma layer (the caller gates on that).
function unsupportedDataLayerNote(orm: Exclude<TargetOrm, "unknown" | "supabase" | "prisma">): Finding {
  const label = ORM_LABELS[orm];
  // The app-layer detectors that DO run are shape-specific: Express+`pg` call sites (pg-idor,
  // pg-response-exposure), Supabase service-role clients (bola-owner, job-tenant-scope), and the
  // Prisma idiom (prisma-tenant-scope). A raw-SQL target is partly inside that set; a query-builder
  // target is entirely outside it. Say which, rather than implying uniform coverage.
  const covered =
    orm === "raw-sql"
      ? "The Express+`pg` app-layer detectors (pg-idor, pg-response-exposure) DID run and cover handlers written in that shape; queries issued from any other shape — a different HTTP framework, a hand-rolled query module — are matched by none of them."
      : `No detector matches ${label} query shapes: the app-layer M1 detectors that ran cover Express+\`pg\` call sites, Supabase service-role clients, and the Prisma idiom (#760) only.`;
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
  const { dir, bundleDir, tenancyOverride, handrolledIndicators, skipNetworkChecks } = opts;

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
    const bundle = resolveBundleScan(dir, bundleDir);
    findings.push(...scanSecrets(scanDir, dir, bundle.bundleDir));
    if (bundle.disclosure) findings.push(bundle.disclosure);

    // Framework/dependency CVEs.
    const osv = runOsvScanner(scanDir);
    findings.push(...(osv.failure ? [osvUnavailableFinding(osv.failure)] : parseOsvFindings(osv.result)));
    const pkg = readPackageJson(scanDir);
    const nextVersion = pkg?.dependencies?.next ?? pkg?.devDependencies?.next;
    if (nextVersion) findings.push(...checkNextVersionCVEs(nextVersion.replace(/^[\^~]/, "")));

    // Semgrep footguns + missing-CSP config check.
    findings.push(...parseSemgrepFindings(runSemgrep(scanDir)));
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
    } else if (orm !== "supabase" && orm !== "unknown") {
      findings.push(unsupportedDataLayerNote(orm));
    } else {
      findings.push(...checkMigrationRlsStatic(scanDir));
      findings.push(...checkMigrationPolicySemantics(scanDir, tenancyOverride));
      findings.push(...checkMigrationDefinerAuthz(scanDir));
      findings.push(...checkMigrationDefinerAnonGrant(scanDir));
      findings.push(...checkMigrationDynamicSqlInjection(scanDir));
      findings.push(...checkMigrationRlsInitplanStatic(scanDir));
      findings.push(...checkEdgeFunctionVerifyJwt(scanDir));
      // #671 — gate the email-confirmation advisor on whether email auth is actually used (source
      // heuristic): an OAuth-only app gets a conditional note, not an asserted Medium.
      findings.push(...checkOpenSignupConfig(scanDir, inferAuthMethodsFromSource(scanDir)));
    }
    findings.push(...checkWebExtensionManifest(scanDir));

    // #871 — source in languages no M1 rule can read (a Python/Go/Ruby service on the same tables
    // bypasses RLS just as effectively as a broken policy). Disclosure only, by design.
    findings.push(...checkUnanalysedLanguages(scanDir));

    // Supply chain.
    if (pkg) {
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      findings.push(...checkTyposquat(Object.keys(allDeps)));
      findings.push(...checkKnownIoc(Object.keys(allDeps)));
      findings.push(...checkKnownDependencyCVEs(allDeps));
      findings.push(...checkUnpinnedDependencies(allDeps));
      findings.push(...checkNonRegistryDependencies(allDeps));
      findings.push(...checkInstallScripts(pkg.scripts ?? {}));
      if (!skipNetworkChecks) {
        findings.push(...(await checkSlopsquat(Object.keys(allDeps))));
        // #456 — license compliance (SPDX + copyleft/unknown flags).
        findings.push(...(await checkLicenseCompliance(allDeps)));
      }
    }
    findings.push(...checkLockfilePresence(scanDir));

    // Leftover-auth greps.
    findings.push(...scanLeftoverAuth(scanDir));

    // #353 — non-atomic read-modify-write race (AST dataflow over source files, incl. plain .js).
    findings.push(...scanCounterRace(scanDir));

    // #433 — authenticated pages/api handler scoping a service-role query by a request-supplied
    // owner id (BOLA). AST dataflow, incl. plain .js.
    findings.push(...scanBolaOwner(scanDir));

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

    // #664 — service_role key hardcoded as a JWT literal (same-file or cross-file const) and
    // passed to createClient. Real base64 decode + role/iss claim check, incl. plain .js.
    findings.push(...scanServiceRoleLiteral(scanDir));

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

    return findings;
  } finally {
    cleanup();
  }
}
