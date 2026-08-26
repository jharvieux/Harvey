// #1689 / #1800 — discovery completeness, paired per-class path populations, real structural-scan
// delivery, and a conservation falsifier for every path-scoped class.

import { execFile, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { buildHtml } from "../../report-template/render.mjs";
import { esc } from "../../report-template/sections.mjs";
import { assembleEngagementDocument } from "../audit-report.js";
import { conservationLedger } from "../conservation-ledger.js";
import type { ReportMeta } from "../findings.js";
import { readEntriesSafe } from "../fs-walk.js";
import type { SourceInput } from "../detectors/common.js";
import { MechanicalScanContext } from "./mechanical-context.js";
import { runRegisteredMechanicalDetectors } from "./mechanical-detector-registry.js";
import { detectBolaOwnerFindings } from "./bola-owner.js";
import { detectJobTenantScopeFindings } from "./job-tenant-scope.js";
import { detectM5TypeEscapeFindings } from "../detectors/m5-type-escape.js";
import { detectM8VacuousAssertionFindings } from "../detectors/m8-vacuous-assertion.js";
import {
  ENTRY_POINT_PATH_SCOPE_CLASSES,
  PATH_SCOPE_CLASS_GROUPS,
  PATH_SCOPED_DETECTORS,
  pathScopeCensus,
  pathScopeNotAssessedRows,
  type PathScopeContext,
  type PathScopedClass,
} from "./path-scope.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const elsewhere: SourceInput = { path: "src/lib/orders.ts", text: "export const x = 1;\n" };
const pagesApi: SourceInput = { path: "pages/api/invoice.js", text: "export default function handler(req, res) { res.end(); }\n" };
const jobFile: SourceInput = { path: "src/inngest/import.ts", text: "export const run = async () => {};\n" };

interface SelectorControl {
  populated: SourceInput[];
  zero: SourceInput[];
  context?: PathScopeContext;
}

const source = (path: string, text = "export const value = 1;\n"): SourceInput => ({ path, text });
const plain = source("src/lib/plain.ts");
const appClient = source("app/dashboard/client.tsx", '"use client";\nexport function Client() { return <div />; }\n');
const appPage = source("app/dashboard/page.tsx", "export default function Page() { return <main />; }\n");
const appRoute = source("app/api/orders/route.ts", "export async function GET() { return Response.json({ ok: true }); }\n");
const vitestManifest = source("package.json", '{"devDependencies":{"vitest":"3.2.6"}}\n');
const compilerConfig = source(".babelrc", '{"plugins":["babel-plugin-react-compiler"]}\n');

const controls: Record<string, SelectorControl> = {
  "src/scan/bola-owner.ts#bolaOwnerScannedFiles": {
    populated: [pagesApi],
    zero: [plain],
  },
  "src/scan/job-tenant-scope.ts#jobTenantScopeScannedFiles": {
    populated: [source("src/jobs/import.ts")],
    zero: [plain],
  },
  "src/scan/leftover-auth.ts#leftoverSensitiveRouteFiles": {
    populated: [source("app/admin/route.ts")],
    zero: [plain],
  },
  "src/scan/leftover-auth.ts#leftoverAuthRateLimitFiles": {
    populated: [source("app/login/route.ts")],
    zero: [plain],
  },
  "src/scan/leftover-auth.ts#leftoverWebhookFiles": {
    populated: [source("app/api/webhook/route.ts")],
    zero: [plain],
  },
  "src/scan/leftover-auth.ts#leftoverUnscopedDmlFiles": {
    populated: [appRoute],
    zero: [plain],
  },
  "src/scan/env-schema.ts#envSchemaModuleCandidates": {
    populated: [source("src/env.ts")],
    zero: [plain],
  },
  "src/scan/auth-guard-discovery.ts#authGuardDiscoveryFiles": {
    populated: [source("src/lib/auth.ts")],
    zero: [appRoute],
  },
  "src/scan/idempotency.ts#retryableExternalSendFiles": {
    populated: [source("src/jobs/send.ts")],
    zero: [plain],
  },
  "src/scan/bola-cross-file.ts#bolaCrossFileHandlerFiles": {
    populated: [appRoute],
    zero: [plain],
  },
  "src/detectors/app-router.ts#appRouterClientRootFiles": {
    populated: [appClient],
    zero: [plain],
    context: { framework: "next" },
  },
  "src/detectors/app-router.ts#appRouterMissingServerOnlyFiles": {
    populated: [appClient, source("src/server/data.ts")],
    zero: [plain],
    context: { framework: "next" },
  },
  "src/detectors/app-router.ts#appRouterPageLayoutFiles": {
    populated: [appPage],
    zero: [plain],
    context: { framework: "next" },
  },
  "src/detectors/app-router.ts#appRouterResponseFiles": {
    populated: [appRoute],
    zero: [plain],
    context: { framework: "next" },
  },
  "src/detectors/app-router.ts#appRouterRouteOrEdgeFiles": {
    populated: [appRoute],
    zero: [plain],
    context: { framework: "next" },
  },
  "src/detectors/app-router.ts#appRouterRouteSegmentFiles": {
    populated: [appPage],
    zero: [plain],
    context: { framework: "next" },
  },
  "src/detectors/app-router.ts#appRouterSsrJsxFiles": {
    populated: [appPage],
    zero: [plain],
    context: { framework: "next" },
  },
  "src/detectors/perf-code.ts#perfRerenderCandidateFiles": {
    populated: [compilerConfig, source("src/components/card.tsx", "export function Card() { return <div />; }\n")],
    zero: [compilerConfig, source("src/emails/message.tsx", 'import { Html } from "@react-email/components";\nexport const Message = () => <Html />;\n')],
  },
  "src/detectors/perf-code.ts#perfApplicationCodeFiles": {
    populated: [source("src/services/orders.ts")],
    zero: [source("scripts/generate.ts")],
  },
  "src/detectors/perf-code.ts#perfMiddlewareFiles": {
    populated: [source("middleware.ts")],
    zero: [plain],
  },
  "src/detectors/perf-code.ts#perfSyncIoCandidateFiles": {
    populated: [appRoute],
    zero: [source("scripts/generate.ts")],
  },
  "src/detectors/test-intent.ts#staticTestIntentFiles": {
    populated: [source("src/orders.test.ts")],
    zero: [plain],
  },
  "src/detectors/test-intent.ts#securityCriticalSourceFiles": {
    populated: [source("src/auth.ts")],
    zero: [plain],
  },
  "src/detectors/vitest-intent.ts#vitestTestFiles": {
    populated: [vitestManifest, source("src/orders.test.ts")],
    zero: [vitestManifest, plain],
  },
  "src/detectors/vitest-intent.ts#vitestInSourceFiles": {
    populated: [vitestManifest, plain],
    zero: [vitestManifest, source("src/orders.test.ts")],
  },
  "src/detectors/m5-type-escape.ts#m5TypeEscapeSources": {
    populated: [source("src/types.ts")],
    zero: [source("src/types.d.ts")],
  },
  "src/detectors/m8-vacuous-assertion.ts#vacuousAssertionSourceFiles": {
    populated: [source("src/orders.test.ts")],
    zero: [plain],
  },
};

function keyFor(row: PathScopedClass): string {
  return `${row.ownerFile}#${row.selectorSymbol}`;
}

function sourceFilesUnder(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readEntriesSafe(dir).entries) {
    if (entry.isDirectory) out.push(...sourceFilesUnder(entry.path));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts")) out.push(entry.path);
  }
  return out;
}

function discoveredClassGroups(): { ownerFile: string; exportName: string }[] {
  const out: { ownerFile: string; exportName: string }[] = [];
  for (const base of [join(REPO_ROOT, "src", "scan"), join(REPO_ROOT, "src", "detectors")]) {
    for (const file of sourceFilesUnder(base)) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/export const ([A-Z][A-Z0-9_]*_PATH_SCOPE_CLASSES)\b/g)) {
        out.push({ ownerFile: relative(REPO_ROOT, file), exportName: match[1]! });
      }
    }
  }
  return out.sort((a, b) => `${a.ownerFile}#${a.exportName}`.localeCompare(`${b.ownerFile}#${b.exportName}`));
}

// Discover exported SourceInput[] selector declarations independently of class metadata.
// Classify only a direct shared SOURCE_FILE predicate as language-only.
function discoverSourceSelectors(ownerFile: string, text: string): string[] {
  const sf = ts.createSourceFile(ownerFile, text, ts.ScriptTarget.Latest, true);
  const selectors: string[] = [];
  for (const node of sf.statements) {
    if (!ts.isFunctionDeclaration(node) || !node.name || !node.body) continue;
    if (!node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) continue;
    if (node.type?.getText(sf).replace(/\s/g, "") !== "SourceInput[]") continue;
    const parameter = node.parameters[0];
    if (!parameter?.type?.getText(sf).includes("SourceInput")) continue;
    const statement = node.body.statements.length === 1 ? node.body.statements[0] : undefined;
    const returned = statement && ts.isReturnStatement(statement) ? statement.expression : undefined;
    const callback = returned && ts.isCallExpression(returned) ? returned.arguments[0] : undefined;
    const predicate = callback && ts.isArrowFunction(callback) ? callback.body : undefined;
    const filter = returned && ts.isCallExpression(returned) && ts.isPropertyAccessExpression(returned.expression)
      && returned.expression.name.text === "filter" && returned.expression.expression.getText(sf) === parameter.name.getText(sf);
    const languageImport = sf.statements.some((entry) => ts.isImportDeclaration(entry)
      && ts.isStringLiteral(entry.moduleSpecifier) && entry.moduleSpecifier.text.endsWith("/load-sources.js")
      && entry.importClause?.namedBindings && ts.isNamedImports(entry.importClause.namedBindings)
      && entry.importClause.namedBindings.elements.some((binding) => binding.name.text === "SOURCE_FILE" && !binding.propertyName));
    const languageOnly = filter && languageImport && callback && ts.isArrowFunction(callback)
      && callback.parameters.length === 1 && predicate && ts.isCallExpression(predicate)
      && predicate.expression.getText(sf) === "SOURCE_FILE.test" && predicate.arguments.length === 1
      && predicate.arguments[0]!.getText(sf) === `${callback.parameters[0]!.name.getText(sf)}.path`;
    if (!languageOnly) selectors.push(`${ownerFile}#${node.name.text}`);
  }
  return selectors;
}

function withProductionContext<T>(files: readonly SourceInput[], framework: PathScopeContext["framework"], read: (context: MechanicalScanContext) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "harvey-path-scope-delivery-"));
  let context: MechanicalScanContext | undefined;
  try {
    for (const file of files) {
      mkdirSync(dirname(join(dir, file.path)), { recursive: true });
      writeFileSync(join(dir, file.path), file.text);
    }
    if (framework === "next") writeFileSync(join(dir, "package.json"), '{"dependencies":{"next":"15.0.0"}}\n');
    context = new MechanicalScanContext(dir);
    return read(context);
  } finally {
    context?.dispose();
    rmSync(dir, { recursive: true, force: true });
  }
}

const reportMeta: ReportMeta = {
  client: "path-scope control",
  subtitle: "delivery control",
  date: "2026-08-15",
  commit: "test",
  auditor: "Harvey",
  confidential: true,
  overallHealth: 100,
  tenantIsolation: "not relevant",
  authModel: "not relevant",
  headline: "delivery control",
  scope: "fixture",
  methodology: "mechanical registry",
  outOfScope: "none",
};

describe("#1689 entry-point path-scoped detector disclosure", () => {
  it("emits one row per entry detector that read zero files", () => {
    const rows = pathScopeNotAssessedRows([elsewhere], {}, ENTRY_POINT_PATH_SCOPE_CLASSES);
    expect(rows.map((row) => row.id).sort()).toEqual(["M1-PATHSCOPE-BOLA-00", "M1-PATHSCOPE-JOB-00"]);
    expect(rows.every((row) => row.confidence === "N/A" && row.category === "Coverage")).toBe(true);
    expect(rows.find((row) => row.id === "M1-PATHSCOPE-BOLA-00")?.evidence).toContain("pages/api/**");
    expect(rows.find((row) => row.id === "M1-PATHSCOPE-JOB-00")?.evidence).toContain("workers/");
  });

  it("suppresses the row when the detector has a real population", () => {
    expect(pathScopeNotAssessedRows([elsewhere, pagesApi], {}, ENTRY_POINT_PATH_SCOPE_CLASSES).map((row) => row.id)).toEqual([
      "M1-PATHSCOPE-JOB-00",
    ]);
    expect(pathScopeNotAssessedRows([elsewhere, jobFile], {}, ENTRY_POINT_PATH_SCOPE_CLASSES).map((row) => row.id)).toEqual([
      "M1-PATHSCOPE-BOLA-00",
    ]);
    expect(pathScopeNotAssessedRows([elsewhere, pagesApi, jobFile], {}, ENTRY_POINT_PATH_SCOPE_CLASSES)).toEqual([]);
  });

  it("stays silent when the target has no source files — M1-EXT-00 owns that case", () => {
    expect(pathScopeNotAssessedRows([])).toEqual([]);
  });

  it("counts the files each entry detector actually reads", () => {
    expect(pathScopeCensus([elsewhere, pagesApi, jobFile], {}, ENTRY_POINT_PATH_SCOPE_CLASSES)).toEqual([
      expect.objectContaining({ detector: "bola-owner", filesRead: 1 }),
      expect.objectContaining({ detector: "job-tenant-scope", filesRead: 1 }),
    ]);
    expect(pathScopeCensus([elsewhere], {}, ENTRY_POINT_PATH_SCOPE_CLASSES).every((row) => row.filesRead === 0)).toBe(true);
  });

  it("keeps the entry census predicate identical to the detector's production scope", () => {
    const bolaPlant: SourceInput = {
      path: "pages/api/billing/invoice.js",
      text: [
        'import { admin } from "../../../lib/supabaseAdmin";',
        'import { getServerSession } from "next-auth";',
        "export default async function handler(req, res) {",
        "  const session = await getServerSession(req);",
        '  if (!session) return res.status(401).json({ error: "unauthorized" });',
        '  const { data } = await admin.from("invoices").select("*").eq("tenant_id", req.body.tenantId);',
        "  res.status(200).json({ invoice: data });",
        "}",
      ].join("\n"),
    };
    const bola = PATH_SCOPED_DETECTORS.find((row) => row.detector === "bola-owner")!;
    expect(bola.select([bolaPlant], {}).length).toBe(1);
    expect(detectBolaOwnerFindings([bolaPlant]).length).toBeGreaterThan(0);
    expect(bola.select([elsewhere], {}).length).toBe(0);
    expect(detectBolaOwnerFindings([{ ...bolaPlant, path: "src/lib/billing.js" }])).toEqual([]);

    const job = PATH_SCOPED_DETECTORS.find((row) => row.detector === "job-tenant-scope")!;
    expect(job.select([jobFile], {}).length).toBe(1);
    expect(job.select([elsewhere], {}).length).toBe(0);
    const classRows = (files: SourceInput[]): number =>
      detectJobTenantScopeFindings(files).filter((finding) => finding.id !== "M1-JOBPATH-00").length;
    expect(classRows([{ ...jobFile, path: "src/lib/import.ts" }])).toBe(0);
  });
});

describe("#1800 discovery-backed path-scoped class registry", () => {
  it("discovers every owner export and rejects an unregistered class group", () => {
    const registered = PATH_SCOPE_CLASS_GROUPS.map(({ ownerFile, exportName }) => ({ ownerFile, exportName })).sort((a, b) =>
      `${a.ownerFile}#${a.exportName}`.localeCompare(`${b.ownerFile}#${b.exportName}`),
    );
    expect(registered).toEqual(discoveredClassGroups());
  });

  it("discovers production source selectors even when their owner declares no class metadata", () => {
    const discovered = ["scan", "detectors"].flatMap((dir) => sourceFilesUnder(join(REPO_ROOT, "src", dir)))
      .flatMap((file) => discoverSourceSelectors(relative(REPO_ROOT, file), readFileSync(file, "utf8")));
    const registered = new Set(PATH_SCOPED_DETECTORS.map(keyFor));
    expect(discovered.filter((selector) => !registered.has(selector))).toEqual([]);
    expect(discovered).toContain("src/detectors/m5-type-escape.ts#m5TypeEscapeSources");
    expect(discovered).toContain("src/detectors/m8-vacuous-assertion.ts#vacuousAssertionSourceFiles");
    const undeclared = discoverSourceSelectors("src/detectors/new-class.ts", `
      export function newClassFiles(files: readonly SourceInput[]): SourceInput[] {
        return files.filter(file => /routes/.test(file.path));
      }
    `);
    expect(undeclared.filter((selector) => !registered.has(selector))).toEqual(["src/detectors/new-class.ts#newClassFiles"]);
  });

  it("has unique row/class identities and selector metadata declared by the owning module", () => {
    expect(new Set(PATH_SCOPED_DETECTORS.map((row) => row.rowId)).size).toBe(PATH_SCOPED_DETECTORS.length);
    expect(new Set(PATH_SCOPED_DETECTORS.map((row) => `${row.detector}\u0000${row.classId}`)).size).toBe(PATH_SCOPED_DETECTORS.length);
    for (const row of PATH_SCOPED_DETECTORS) {
      expect(row.rowId).toMatch(/^M1-PATHSCOPE-[A-Z0-9-]+-00$/);
      expect(row.detector).not.toBe("");
      expect(row.classId).not.toBe("");
      expect(row.convention).not.toBe("");
      expect(row.classes).not.toBe("");
      expect(typeof row.select).toBe("function");
      const owner = readFileSync(join(REPO_ROOT, row.ownerFile), "utf8");
      expect(owner).toMatch(new RegExp(`export (?:function|const) ${row.selectorSymbol}\\b`));
    }
  });

  it("has a populated and zero control for every distinct production selector", () => {
    expect(Object.keys(controls).sort()).toEqual([...new Set(PATH_SCOPED_DETECTORS.map(keyFor))].sort());
    for (const row of PATH_SCOPED_DETECTORS) {
      const control = controls[keyFor(row)]!;
      const context = control.context ?? {};
      expect(row.applicable?.(control.populated, context) ?? true, `${row.rowId} populated applicability`).toBe(true);
      expect(row.applicable?.(control.zero, context) ?? true, `${row.rowId} zero applicability`).toBe(true);

      expect(row.select(control.populated, context).length, `${row.rowId} populated selector`).toBeGreaterThan(0);
      expect(pathScopeNotAssessedRows(control.populated, context, [row]), `${row.rowId} populated disclosure`).toEqual([]);
      expect(pathScopeCensus(control.populated, context, [row])[0]).toMatchObject({
        rowId: row.rowId,
        applicable: true,
        filesRead: expect.any(Number),
      });

      expect(row.select(control.zero, context), `${row.rowId} zero selector`).toEqual([]);
      expect(pathScopeNotAssessedRows(control.zero, context, [row]).map((finding) => finding.id), `${row.rowId} zero disclosure`).toEqual([
        row.rowId,
      ]);
      expect(pathScopeCensus(control.zero, context, [row])).toEqual([
        expect.objectContaining({ rowId: row.rowId, applicable: true, filesRead: 0 }),
      ]);
    }
  });

  it("invokes selectors in the census but emits no row for a genuinely inapplicable class", () => {
    const row = PATH_SCOPED_DETECTORS.find((entry) => entry.rowId === "M1-PATHSCOPE-M8-VITEST-UNRESTORED-SPY-00")!;
    const files = [source("src/orders.test.ts")];
    expect(row.select(files, {})).toHaveLength(1);
    expect(row.applicable?.(files, {})).toBe(false);
    expect(pathScopeCensus(files, {}, [row])).toEqual([
      expect.objectContaining({ rowId: row.rowId, applicable: false, filesRead: 1 }),
    ]);
    expect(pathScopeNotAssessedRows(files, {}, [row])).toEqual([]);
  });

  it("fails in the intended direction when any populated class selector is bypassed", () => {
    for (const row of PATH_SCOPED_DETECTORS) {
      const control = controls[keyFor(row)]!;
      const context = control.context ?? {};
      expect(pathScopeNotAssessedRows(control.populated, context, [row])).toEqual([]);
      const bypassed: PathScopedClass = { ...row, select: () => [] };
      expect(pathScopeNotAssessedRows(control.populated, context, [bypassed]).map((finding) => finding.id)).toEqual([row.rowId]);
    }
  });

  it("delivers every class through the shipping registry and assembly, and conserves each dropped row", () => {
    for (const entry of PATH_SCOPED_DETECTORS) {
      const control = controls[keyFor(entry)]!;
      withProductionContext(control.zero, control.context?.framework, (context) => {
        const produced = runRegisteredMechanicalDetectors(context).findings;
        const row = produced.find((finding) => finding.id === entry.rowId);
        expect(row, entry.rowId).toBeDefined();
        const document = assembleEngagementDocument(
          [{ module: "M1", status: "ran" }],
          { connected: false, dynamic: false, llm: false },
          produced, reportMeta, undefined, {},
        );
        expect(document.findings, entry.rowId).toContainEqual(row);
        const html = buildHtml(document);
        expect(html, entry.rowId).toContain(esc(entry.rowId));
        expect(html, `${entry.rowId} rendered reason`).toContain(esc(row!.evidence));
        expect(conservationLedger(produced, document.findings, { M1: produced }).ok, entry.rowId).toBe(true);
        const dropped = document.findings.filter((finding) => finding.id !== entry.rowId);
        const broken = conservationLedger(produced, dropped, { M1: produced });
        expect(broken.ok, entry.rowId).toBe(false);
        expect(broken.unaccounted, entry.rowId).toBe(1);
      });
      withProductionContext(control.populated, control.context?.framework, (context) => {
        const produced = runRegisteredMechanicalDetectors(context).findings;
        expect(produced.some((finding) => finding.id === entry.rowId), `${entry.rowId} populated production input`).toBe(false);
      });
    }
  });

  it("uses the actual M5 and M8 path predicates, including Python-only production inventories", () => {
    const typeSource = 'const first = input as any;\nconst second = input as unknown as string;\n// @ts-ignore\nconst third: string = 1;\n';
    expect(detectM5TypeEscapeFindings([source("src/types.ts", typeSource)])).toHaveLength(3);
    expect(detectM5TypeEscapeFindings([source("src/types.d.ts", typeSource)])).toEqual([]);
    expect(detectM5TypeEscapeFindings([source("src/types.stories.ts", typeSource)])).toEqual([]);
    const assertion = 'test("value", () => expect(true).toBe(true));\n';
    expect(detectM8VacuousAssertionFindings([source("src/example.test.ts", assertion)])).toHaveLength(1);
    expect(detectM8VacuousAssertionFindings([source("src/example.ts", assertion)])).toEqual([]);
    const rowId = "M1-PATHSCOPE-M8-VACUOUS-ASSERTION-00";
    for (const [path, present] of [["test_example.py", false], ["example.py", true]] as const) {
      withProductionContext([source(path, "def test_example():\n    assert True\n")], undefined, (context) => {
        expect(context.loadedSources).toEqual([]);
        const produced = runRegisteredMechanicalDetectors(context).findings;
        expect(produced.some((finding) => finding.id === rowId)).toBe(present);
        const census = pathScopeCensus(context.loadedSources, { identifiedSourceFiles: context.identifiedSourceFiles });
        expect(census.find((row) => row.rowId === rowId)).toMatchObject({
          inventory: "identified-sources", inputFiles: 1, filesRead: present ? 0 : 1,
        });
      });
    }
  });

  it("preserves the class rows in the standalone static CLI and suppresses populated Python tests", async () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-path-scope-static-"));
    try {
      const target = join(dir, "target");
      mkdirSync(target);
      writeFileSync(join(target, "types.d.ts"), "declare const value: unknown;\n");
      const out = join(dir, "findings.json");
      const run = () => promisify(execFile)(process.execPath, ["--import", "tsx", join(REPO_ROOT, "src/cli/static-detect.ts"), target, "--out", out], {
        cwd: REPO_ROOT, timeout: 20_000, maxBuffer: 1024 * 1024,
      });
      await run();
      const empty = JSON.parse(readFileSync(out, "utf8")) as { id: string }[];
      const expected = PATH_SCOPED_DETECTORS.filter((entry) => ["m5-type-escape", "m8-vacuous-assertion"].includes(entry.detector));
      for (const entry of expected) expect(empty.some((finding) => finding.id === entry.rowId), entry.rowId).toBe(true);
      writeFileSync(join(target, "test_example.py"), "def test_example():\n    assert True\n");
      await run();
      const populated = JSON.parse(readFileSync(out, "utf8")) as { id: string }[];
      expect(populated.some((finding) => finding.id === "M1-PATHSCOPE-M8-VACUOUS-ASSERTION-00")).toBe(false);
      expect(populated.some((finding) => finding.id.startsWith("M8VAC-"))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("runs the disclosure over the current loadedSources surface, including .mts/.cts", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-path-scope-loaded-sources-"));
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "plain.mts"), "export const plain = true;\n");
    const context = new MechanicalScanContext(dir);
    try {
      expect(context.sourceFiles).toEqual([]);
      expect(context.loadedSources.map((file) => file.path)).toEqual(["src/plain.mts"]);
      const findings = runRegisteredMechanicalDetectors(context).findings;
      expect(findings.some((finding) => finding.id === "M1-PATHSCOPE-ENV-SCHEMA-00")).toBe(true);
    } finally {
      context.dispose();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("keeps the census CLI fail-loud flag exit at 2 before any clone is attempted", () => {
    const cli = join(REPO_ROOT, "src", "cli", "path-scope-census.ts");
    const result = spawnSync(process.execPath, ["--import", "tsx", cli, "--unknown-path-scope-flag"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 20_000,
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("Unrecognized flag: --unknown-path-scope-flag");
  });
});
