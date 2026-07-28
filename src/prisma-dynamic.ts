// #759 (part of #756) — the Prisma/Postgres M2 dynamic path. A Prisma app has NO PostgREST and NO
// DB-level RLS, so the Supabase cross-tenant PostgREST matrix (src/dynamic-validate.ts) DOES NOT
// APPLY: tenant isolation is entirely app-layer and is testable ONLY through the app's HTTP routes.
// This module is the routed, testable core — assess → stand up plain Postgres → `prisma migrate` →
// seed two tenants → drive the app-route probes — with the RLS matrix recorded NOT-APPLICABLE (an
// honest disclosure, never a silent skip). The live Docker/prisma/build execution is behind the
// injected PrismaStandUpRunner seam (src/pentest/prisma-standup.ts) so the decision logic runs
// offline. Routing between this and the Supabase path is by detectOrm (src/scan/framework-detect.ts).

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readNamesSafe } from "./fs-walk.js";
import { buildPassArtifact, writePassArtifact } from "./audit-pass-artifact.js";
import type { Coverage, DynamicValidationResult, StandUpResult } from "./dynamic-validate.js";
import type { Finding } from "./findings.js";
import { mechanicalFinding } from "./scan/common.js";
import { buildScopeLedger } from "./pentest/scope-ledger.js";

// The facts about a Prisma repo that decide whether — and how — we stand it up for M2.
export interface PrismaLayout {
  schemaPath: string | null; // path to schema.prisma, or null if none found (⇒ not a stand-up-able Prisma target)
  migrationsDir: string | null; // the prisma/migrations dir when it holds ≥1 committed migration.sql
  scripts: Record<string, string>; // package.json scripts (build/start let us boot the app to probe its routes)
}

// schema.prisma conventionally lives at prisma/schema.prisma or the repo root; probed in that order.
const PRISMA_SCHEMA_CANDIDATES = ["prisma/schema.prisma", "schema.prisma"];

// A prisma/migrations dir "has migrations" when at least one child dir carries a migration.sql — the
// signal that `prisma migrate deploy` (versioned migrations) is the right apply command rather than
// `prisma db push` (schema-only, no migration history).
export function hasCommittedMigrations(migrationsDir: string): boolean {
  let children: string[];
  try {
    children = readNamesSafe(migrationsDir);
  } catch {
    return false;
  }
  return children.some((c) => existsSync(join(migrationsDir, c, "migration.sql")));
}

export function readPrismaLayout(targetDir: string): PrismaLayout {
  let scripts: Record<string, string> = {};
  const pkgPath = join(targetDir, "package.json");
  if (existsSync(pkgPath)) {
    try {
      scripts = (JSON.parse(readFileSync(pkgPath, "utf8")) as { scripts?: Record<string, string> }).scripts ?? {};
    } catch { /* malformed package.json — no scripts */ }
  }
  const schemaPath = PRISMA_SCHEMA_CANDIDATES.map((rel) => join(targetDir, rel)).find(existsSync) ?? null;
  let migrationsDir: string | null = null;
  if (schemaPath) {
    const candidate = join(dirname(schemaPath), "migrations");
    if (existsSync(candidate) && hasCommittedMigrations(candidate)) migrationsDir = candidate;
  }
  return { schemaPath, migrationsDir, scripts };
}

// How to reproduce the schema on the fresh Postgres: `prisma migrate deploy` when versioned
// migrations are committed (the faithful, ordered apply — and a set that won't apply is an M2
// finding), else `prisma db push` straight from schema.prisma (a migration-less Prisma app). Returned
// as argv (after `prisma`) so the live runner just prepends its `npx prisma` invocation.
export function selectPrismaMigrateCommand(layout: PrismaLayout): string[] {
  return layout.migrationsDir ? ["migrate", "deploy"] : ["db", "push", "--skip-generate"];
}

// #1163 — the resolved prisma CLI major version, parsed from `prisma --version` ("prisma : 7.9.0").
// Null when the line is absent (an unexpected --version format ⇒ treat as pre-v7, the unchanged path).
export function prismaCliMajor(versionOutput: string): number | null {
  const m = versionOutput.match(/^\s*prisma\s*:\s*(\d+)\.\d+\.\d+/im);
  return m ? Number(m[1]) : null;
}

// #1163 — Prisma 7 rejects a `url = env(...)`/`directUrl = ...` line in schema.prisma (error P1012),
// wanting the connection URL out of the schema. Strip those assignment lines so an existing
// Prisma-5/6-style schema validates under a v7 CLI. Only datasource assignments carry `<key> = …`;
// model fields never do, so the blanket line match is safe.
export function stripSchemaDatasourceUrl(schema: string): string {
  return schema.replace(/^[ \t]*(?:url|directUrl)[ \t]*=.*$/gim, "");
}

// #1163 — the minimal Prisma-7 config that supplies the datasource URL out-of-schema from the env var
// Harvey already sets (DATABASE_URL → its own Postgres container). A plain object (no `prisma/config`
// import) so the config loads before the target's deps are installed. Covers both `db push` and
// `migrate deploy` (which, unlike push, has no --url flag under v7).
export function prismaV7ConfigSource(schemaPath: string): string {
  return `export default { schema: ${JSON.stringify(schemaPath)}, datasource: { url: process.env.DATABASE_URL } };\n`;
}

// #1163 — rewrite the apply argv for a v7+ CLI: drop --skip-generate (removed in v7) and point the CLI
// at the synthesized config (which carries the stripped schema path + the out-of-schema URL).
export function prismaV7ApplyArgs(migrateCommand: string[], configPath: string): string[] {
  return [...migrateCommand.filter((a) => a !== "--skip-generate"), "--config", configPath];
}

interface PrismaStandUpVerdict {
  canStandUp: boolean; // can we stand up the DB at all? false ⇒ no schema.prisma, nothing to provision
  coverage: Coverage; // full = DB + app-route probes; none = DB stood up but no runnable app to probe (Prisma has no PostgREST fallback)
  reason: string;
  limitations: string[];
}

// The RLS-matrix disclosure that MUST accompany every Prisma M2 verdict: the Supabase cross-tenant
// PostgREST/RLS matrix is not-applicable by architecture, not skipped. Stated so an absent matrix
// never reads as an unproven gap (the coverage guard: fail loud, say it in the output).
export const RLS_NOT_APPLICABLE =
  "PostgREST/RLS cross-tenant matrix: NOT APPLICABLE — this is a Prisma/Postgres app with no PostgREST layer and no DB-level RLS. Tenant isolation is entirely app-layer, so it is tested through the app's HTTP routes (cross-tenant BOLA/IDOR + missing-auth), not the DB.";

// Can we stand this Prisma target up, and how fully? The app is the ONLY tenancy surface (no
// PostgREST), so "no runnable app" means the DB reproduces but there is nothing to probe dynamically
// — recorded honestly, never rounded up to a clean pass.
export function assessPrismaStandUp(layout: PrismaLayout): PrismaStandUpVerdict {
  if (!layout.schemaPath) {
    return {
      canStandUp: false,
      coverage: "none",
      reason: `no schema.prisma found (probed ${PRISMA_SCHEMA_CANDIDATES.join(", ")}) — nothing to provision on a local Postgres`,
      limitations: [],
    };
  }
  const limitations = [RLS_NOT_APPLICABLE];
  if (!layout.migrationsDir) {
    limitations.push("no prisma/migrations dir — reproducing the schema via `prisma db push` from schema.prisma (no versioned migration history to replay)");
  }
  const canRunApp = Boolean(layout.scripts.dev || layout.scripts.build || layout.scripts.start);
  if (!canRunApp) {
    limitations.push("no dev/build/start script — the app can't be booted, and a Prisma app has no PostgREST layer to fall back to, so no dynamic tenancy surface can be probed (the schema still reproduces on the local Postgres)");
  }
  return {
    canStandUp: true,
    coverage: canRunApp ? "full" : "none",
    reason: canRunApp
      ? "stand-up-able: local Postgres + `prisma migrate` + boot the app and drive its routes"
      : "the schema reproduces on a local Postgres, but the app is not runnable — no app-route surface to probe (and Prisma has no PostgREST fallback)",
    limitations,
  };
}

// The Prisma-app live-execution seam. The real runner (createPrismaLiveStandUp) runs a Docker
// Postgres, applies the schema via `prisma migrate`, seeds two tenants, boots the app, and drives the
// app-route probes; a test injects a fake. Mirrors the Supabase StandUpRunner but with no PostgREST
// explore step — the app routes are the whole surface.
export interface PrismaStandUpRunner {
  standUpDb: () => StandUpResult; // docker Postgres + prisma migrate + seed two tenants
  runApp: (targetDir: string) => { ok: boolean; output: string }; // build + boot; DATABASE_URL → the local Postgres
  pentest: (coverage: Coverage) => { ok: boolean; findings: Finding[]; output: string }; // app-route probes (RLS matrix N/A)
}

// A Prisma schema that won't reproduce on a fresh Postgres is a real M2 finding (the app is not
// reproducibly provisionable), captured with the failure — never swallowed as an environment gap.
function prismaMigrateFinding(targetDir: string, output: string): Finding {
  return mechanicalFinding({
    id: "M2-PRISMA-MIGRATE",
    title: "Prisma schema does not apply cleanly to a fresh Postgres database",
    severity: "Medium",
    category: "Dynamic pen-test (M2)",
    taxonomy: "M2 — Provisioning / reproducibility",
    location: targetDir,
    evidence: `Applying the Prisma schema (\`prisma migrate deploy\`/\`db push\`) to a fresh Postgres failed:\n${output.slice(0, 500)}`,
    impact: "The schema is not reproducibly provisionable from its own migrations, so a from-scratch environment (CI, a new engineer, disaster recovery, or this pen-test) cannot be stood up. It also blocks dynamic app-route probing.",
    fix: "Make `prisma migrate deploy` (or `prisma db push`) apply cleanly to an empty database — resolve failed/ordering migrations, missing extensions, or environment-specific objects.",
    precisionTier: "high",
  });
}

// Orchestrate one Prisma target: assess → stand up Postgres + `prisma migrate` + seed → (boot app) →
// app-route probes → emit M2.pass.json. A step that can't complete returns a reasoned failure and
// writes NO artifact (a target we couldn't probe must never read as a clean `ran`) — EXCEPT a
// schema-apply failure, which IS an M2 finding and so DOES emit an artifact carrying it.
export function runPrismaDynamicValidation(opts: {
  targetDir: string;
  layout: PrismaLayout;
  artifactsDir: string;
  now: () => string; // injected clock (ISO string) so the result is deterministic under test
  runner: PrismaStandUpRunner;
}): DynamicValidationResult {
  const { targetDir, layout, artifactsDir, now, runner } = opts;

  const verdict = assessPrismaStandUp(layout);
  const base = { target: targetDir, standUp: false, findings: [] as Finding[], artifactPath: null as string | null, notes: [] as string[] };
  if (!verdict.canStandUp) {
    return { ...base, coverage: "none", reason: `could not stand up ${targetDir}: ${verdict.reason}`, limitations: verdict.limitations };
  }

  const db = runner.standUpDb();
  if (!db.ok) {
    if (db.migrationApplyFailed) {
      const finding = prismaMigrateFinding(targetDir, db.output);
      const artifact = buildPassArtifact({
        module: "M2", target: targetDir, pass: "dynamic", generatedAt: now(),
        summary: "Prisma schema did not apply cleanly to a fresh Postgres — recorded as an M2 finding",
        findings: [finding],
      });
      return {
        ...base, coverage: "none", findings: [finding], artifactPath: writePassArtifact(artifactsDir, artifact),
        reason: `Prisma schema failed to apply (recorded as an M2 finding, not skipped): ${db.output}`,
        limitations: verdict.limitations,
      };
    }
    if (db.seedApplyFailed) {
      return { ...base, coverage: "none", reason: `Harvey's two-tenant seed failed to apply (a harness/seed issue, not a client schema defect): ${db.output}`, limitations: verdict.limitations };
    }
    return { ...base, coverage: "none", reason: `Postgres stand-up failed for ${targetDir}: ${db.output}`, limitations: verdict.limitations };
  }

  let coverage = verdict.coverage;
  const limitations = [...verdict.limitations];
  const notes: string[] = [db.output];
  for (const s of db.seedSkips ?? []) {
    limitations.push(`seed: table "${s.table}" was SKIPPED — its INSERT violated ${s.constraint || "a constraint"} (${s.reason}); a generic two-tenant seed can't satisfy this table's bespoke invariant`);
  }

  if (coverage === "full") {
    const app = runner.runApp(targetDir);
    if (!app.ok) {
      // No PostgREST fallback on a Prisma app — a failed boot means no dynamic surface probed. Honest.
      coverage = "none";
      limitations.push(`the app failed to boot (${app.output}) — a Prisma app has no PostgREST layer to probe instead, so no dynamic app-route probing ran; the schema DID reproduce on the local Postgres`);
    } else {
      notes.push(app.output);
    }
  }

  const pt = runner.pentest(coverage);
  if (!pt.ok) {
    return { ...base, coverage, reason: `app-route pen-test failed against the local stack: ${pt.output}`, limitations, notes };
  }
  notes.push(pt.output);
  const findings = [...pt.findings];

  // Evidence = we actually probed the app routes (coverage full), or we produced a finding. A DB that
  // stood up but whose app never booted probed nothing dynamically — recorded honestly, no artifact.
  // Judged on the PROBE's findings, before the scope disclosure is added: a disclosure is not evidence.
  const producedEvidence = coverage === "full" || findings.length > 0;
  const notProbedReason = limitations[limitations.length - 1];

  // #875 — same scope disclosure as the Supabase path: the app-route probes ran against a Postgres
  // container built from the committed Prisma schema, not the deployed database. Only on a run that
  // produced evidence — a run that probed nothing has no verdict to be mis-read as production-clean.
  if (producedEvidence) {
    const scope = buildScopeLedger({
      targetDir,
      stack: "a Harvey-owned local Postgres container",
      sources: [layout.schemaPath, layout.migrationsDir].filter((s): s is string => Boolean(s)),
      revision: db.revision ?? null,
      coverage,
      rows: db.scopeRows ?? [],
    });
    findings.push(scope.finding);
    limitations.push(...scope.limitations);
  }

  let artifactPath: string | null = null;
  if (producedEvidence) {
    const artifact = buildPassArtifact({
      module: "M2", target: targetDir, pass: "dynamic", generatedAt: now(),
      summary: `Prisma dynamic validation (${coverage} coverage; RLS matrix not-applicable, app-route probing is the tenancy surface); ${findings.length} finding(s)`,
      findings,
    });
    artifactPath = writePassArtifact(artifactsDir, artifact);
  }
  return {
    target: targetDir, standUp: true, coverage,
    reason: coverage === "full"
      ? `Prisma dynamic validation ran (app-route probing; RLS matrix not-applicable)`
      : `Prisma DB stood up but no app-route surface was probed — ${notProbedReason}`,
    limitations, notes, artifactPath, findings,
  };
}
