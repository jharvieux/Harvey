// #450 — dynamic validation harness CLI: assess whether a public repo can be stood up locally for
// M2, and (with --execute) stand it up, pen-test it, and emit the M2 pass artifact (#448).
//
//   pnpm dynamic-validate <target-dir | repo-url> [--pin <commit>] [--out <artifacts-dir>] [--execute]
//
// Default is ASSESS-ONLY: clone (if a URL) + report a go/no-go verdict with its coverage and any
// limitations — useful for triaging which public repos are dynamic-validation candidates at all.
// --execute runs the AUTONOMOUS live pipeline (createLiveStandUp: supabase start → apply the client
// migrations → create two auth users → seed two tenants → live PostgREST cross-tenant matrix → app
// build) and, on success, writes <out>/M2.pass.json. No operator step — Harvey provisions its own
// stack (#159/#161). It needs Docker + the Supabase CLI on PATH; without them each step returns a
// reasoned failure and NO artifact is written (never a silent clean run). The stack is always torn
// down (supabase stop) in a finally.
//
// The decision logic and emission are the tested pure functions in src/dynamic-validate.ts; this
// wrapper is the untested I/O per the repo convention.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { cloneAtPin } from "../scan/corpus-clone.js";
import {
  assessStandUpAbility,
  detectClientSecuritySuite,
  readRepoLayout,
  runMultiProjectDynamicValidation,
  splitLayoutByProject,
} from "../dynamic-validate.js";
import { createLiveStandUp } from "../pentest/live-standup.js";
import { detectOrm } from "../scan/framework-detect.js";
import { assessPrismaStandUp, readPrismaLayout, runPrismaDynamicValidation, selectPrismaMigrateCommand } from "../prisma-dynamic.js";
import { createPrismaLiveStandUp } from "../pentest/prisma-standup.js";

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

if (!targetArg) {
  console.error("usage: pnpm dynamic-validate <target-dir | repo-url> [--pin <commit>] [--out <artifacts-dir>] [--execute]");
  process.exit(2);
}

const isUrl = /^(https?:\/\/|git@)/.test(targetArg);
const targetDir = isUrl ? mkdtempSync(join(tmpdir(), "harvey-dynval-clone-")) : resolve(targetArg);
if (isUrl) {
  const pin = flag("--pin");
  if (!pin) {
    console.error("cloning a repo URL requires --pin <commit> (validation runs against a fixed commit)");
    process.exit(2);
  }
  cloneAtPin(targetArg, pin, targetDir);
}

// #759 — route by ORM. A Prisma/Postgres app has no PostgREST/RLS surface, so the Supabase
// migrations/PostgREST path does not apply: stand up plain Postgres + `prisma migrate` + drive the
// app's HTTP routes (the only tenancy gate). Supabase (and `unknown`) take the unchanged path below.
if (detectOrm(targetDir) === "prisma") {
  const prismaLayout = readPrismaLayout(targetDir);
  const prismaVerdict = assessPrismaStandUp(prismaLayout);
  console.log(`Dynamic-validation assessment (Prisma path) — ${targetDir}`);
  console.log(`  verdict:  ${prismaVerdict.canStandUp ? "GO" : "NO-GO"} (${prismaVerdict.coverage})`);
  console.log(`  reason:   ${prismaVerdict.reason}`);
  for (const l of prismaVerdict.limitations) console.log(`  limitation: ${l}`);
  if (!prismaVerdict.canStandUp) process.exit(1);

  if (!args.includes("--execute")) {
    console.log("\nassess-only (pass --execute to stand up + probe). Live pipeline needs Docker + the target's prisma.");
    process.exit(0);
  }
  const prismaOut = flag("--out");
  if (!prismaOut) {
    console.error("--execute requires --out <artifacts-dir> to write M2.pass.json");
    process.exit(2);
  }
  const migrateCommand = selectPrismaMigrateCommand(prismaLayout);
  console.log(`  apply: \`prisma ${migrateCommand.join(" ")}\` against a Harvey-owned plain Postgres container`);
  const { runner, container, port, customAuth, stop } = createPrismaLiveStandUp({
    targetDir,
    layout: prismaLayout,
    migrateCommand,
    safeScope: { allowDestructive: true, allowNonLocal: false },
  });
  console.log(`  isolation: container ${container} on host port ${port} (teardown scoped to this container only)`);
  console.log(`  app auth: ${customAuth.reason}`);
  let prismaResult;
  try {
    prismaResult = runPrismaDynamicValidation({ targetDir, layout: prismaLayout, artifactsDir: resolve(prismaOut), now: () => new Date().toISOString(), runner });
  } finally {
    stop();
  }
  console.log(`\n${prismaResult.reason}`);
  for (const l of prismaResult.limitations) console.log(`  limitation: ${l}`);
  for (const n of prismaResult.notes) console.log(`  note: ${n}`);
  console.log(`  findings: ${prismaResult.findings.length}`);
  if (prismaResult.artifactPath) {
    console.log(`M2 pass artifact → ${prismaResult.artifactPath} (run-audit --artifacts-dir ${resolve(prismaOut)} now derives M2 ran)`);
    process.exit(0);
  }
  console.error("no M2 artifact written — the target could not be validated dynamically (see reason above)");
  process.exit(1);
}

const layout = readRepoLayout(targetDir);
const verdict = assessStandUpAbility(layout);
console.log(`Dynamic-validation assessment — ${targetDir}`);
console.log(`  verdict:  ${verdict.canStandUp ? "GO" : "NO-GO"} (${verdict.coverage})`);
console.log(`  reason:   ${verdict.reason}`);
for (const l of verdict.limitations) console.log(`  limitation: ${l}`);

if (!verdict.canStandUp) process.exit(1);

if (!args.includes("--execute")) {
  console.log("\nassess-only (pass --execute to stand up + pen-test). Live pipeline needs Docker + the Supabase CLI.");
  process.exit(0);
}

const out = flag("--out");
if (!out) {
  console.error("--execute requires --out <artifacts-dir> to write M2.pass.json");
  process.exit(2);
}

// #610 — a monorepo ships >1 Supabase project (apps/*/supabase/migrations). Stand up + probe EACH in
// turn, each on its own isolated stack (project-id/ports), and roll the per-DB outcomes into one M2
// deliverable. A single-project target is exactly one project here.
const projects = splitLayoutByProject(targetDir, layout);
if (projects.length > 1) {
  console.log(`  monorepo: ${projects.length} Supabase project(s) — standing up + probing each in turn: ${projects.map((p) => p.label).join(", ")}`);
}

// The real autonomous live runner: supabase start → apply client migrations → create two auth users
// → apply the generic two-tenant seed → run the live PostgREST matrix. --allow-destructive is safe
// here: every probe hits the disposable local seed inside the stand-up boundary. One per project, on
// its own project-id/ports; the orchestrator tears each stack down before the next binds its ports.
const result = runMultiProjectDynamicValidation({
  targetDir,
  layout,
  artifactsDir: resolve(out),
  now: () => new Date().toISOString(),
  makeProject: (project, plan) => {
    const tag = projects.length > 1 ? `[${project.label}] ` : "";
    console.log(`  ${tag}seed: two ${plan.seed.dataModel === "user" ? "users" : "tenants"} (${plan.seed.dataModel} model) across ${plan.seed.scopedTables.length} scoped table(s)${plan.tables ? ` (HARVEY_TABLES=${plan.tables})` : ""}`);
    for (const w of plan.seed.warnings) console.log(`  ${tag}seed-warning: ${w}`);
    const clientSuite = detectClientSecuritySuite(project.appDir);
    if (clientSuite.present) console.log(`  ${tag}client suite (bonus): ${clientSuite.detail}`);
    const { runner, workdir, projectId, ports, customAuth, stop } = createLiveStandUp({
      plan,
      safeScope: { allowDestructive: true, allowNonLocal: false },
    });
    console.log(`  ${tag}live stand-up workdir: ${workdir}`);
    console.log(`  ${tag}isolation: project-id ${projectId} on ports api=${ports.api} db=${ports.db} (#604 — teardown scoped to this project only)`);
    console.log(`  ${tag}app auth: ${customAuth.reason}`);
    return { runner, clientSuite, stop };
  },
});

console.log(`\n${result.reason}`);
for (const l of result.limitations) console.log(`  limitation: ${l}`);
for (const n of result.notes) console.log(`  note: ${n}`);
console.log(`  findings: ${result.findings.length}`);
if (result.artifactPath) {
  console.log(`M2 pass artifact → ${result.artifactPath} (run-audit --artifacts-dir ${resolve(out)} now derives M2 ran)`);
} else {
  console.error("no M2 artifact written — the target could not be validated dynamically (see reason above)");
  process.exitCode = 1;
}
