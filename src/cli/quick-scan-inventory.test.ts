import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CLI, MECHANICAL_BINARIES_PRESENT, createQuickScanTestHarness } from "./quick-scan-test-support.js";

const { dirs, run, cleanup } = createQuickScanTestHarness();
afterEach(cleanup);

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("quick-scan CLI — unresolved product inventory (#2132)", () => {
  it("inherits root stores and output directories for a direct workspace target", async () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-quick-workspace-inventory-"));
    dirs.push(root);
    const app = join(root, "apps/web");
    const write = (base: string, path: string, text: string) => {
      const full = join(base, path);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, text);
    };
    write(root, "package.json", JSON.stringify({ name: "root", private: true, packageManager: "pnpm@9.0.0", workspaces: ["apps/*"] }));
    write(root, "pnpm-workspace.yaml", "packages:\n  - apps/*\n");
    write(root, ".npmrc", "store-dir=apps/web/package-cache\n");
    write(root, "tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "apps/web/compiled" } }));
    write(app, "package.json", JSON.stringify({ name: "web", private: true }));
    for (const path of ["src/index.ts", "src/live.ts", "src/app/reports/authored.ts", "src/app/dist/authored.ts"]) {
      write(app, path, "export const authored = true;\n");
    }
    for (const path of [".pnpm-store/v3/pkg/dead.ts", "package-cache/v3/pkg/dead.ts", "compiled/dead.ts"]) {
      write(app, path, "export const generated = true;\n");
    }

    const out = join(app, "quick.json");
    await run([CLI, "--dir", app, "--json", "--out", out]);
    const report = JSON.parse(readFileSync(out, "utf8")) as {
      size: { files: number; excludedFiles: number };
      scorecard: { dimensions: Array<{ module: string; measure?: string }> };
    };
    expect(report.size).toMatchObject({ files: 4, excludedFiles: 3 });
    expect(report.scorecard.dimensions.find((row) => row.module === "M8")?.measure).toContain("across 5 source file(s)");
  }, 120000);

  it.each(["json", "text"])("keeps the full authored population but does not grade M4 through an unresolved Vite output (%s)", async (format) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quick-unresolved-inventory-"));
    dirs.push(repo);
    const write = (path: string, text: string) => {
      const full = join(repo, path);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, text);
    };
    const cloned = [
      "export function summarizeOrder(order: { items: { price: number; qty: number }[]; tax: number }) {",
      "  let subtotal = 0;",
      "  for (const item of order.items) subtotal += item.price * item.qty;",
      "  const taxAmount = subtotal * order.tax;",
      "  return { subtotal, taxAmount, total: subtotal + taxAmount };",
      "}",
      "",
    ].join("\n");
    write("package.json", JSON.stringify({ name: "dynamic-vite-output", private: true }));
    write("vite.config.ts", "const output = 'compiled'; export default { build: { outDir: output } };\n");
    write("compiled/a.ts", cloned);
    write("dist/authored.ts", cloned);
    write("src/one.ts", cloned);
    write("src/two.ts", cloned);
    if (format === "json") {
      const out = join(repo, "quick.json");
  
      await run([CLI, "--dir", repo, "--json", "--out", out]);
      const report = JSON.parse(readFileSync(out, "utf8")) as {
        size: { files: number };
        scorecard: { dimensions: Array<{ module: string; status: string; reason?: string }> };
      };
      expect(report.size.files).toBe(5);
      expect(report.scorecard.dimensions.find((row) => row.module === "M4")).toMatchObject({
        status: "not-assessed",
        reason: expect.stringContaining("vite.config.ts: configuration output paths are unresolved"),
      });

    } else {
      const renderedOut = join(repo, "quick.txt");
      await run([CLI, "--dir", repo, "--out", renderedOut]);
      const rendered = readFileSync(renderedOut, "utf8");
      expect(rendered).toContain("M4   Duplication — NOT ASSESSED by this scan");
      expect(rendered).toContain("Product-source configuration is unresolved");
      expect(rendered).toContain("Vite build.outDir is not a static string");
    }
  }, 120000);

  it.each(["json", "text"])("does not grade a configured whole-output workspace with zero inspected product source (%s)", async (format) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-quick-whole-output-"));
    dirs.push(root);
    const app = join(root, "apps/web");
    const write = (base: string, path: string, text: string) => {
      const full = join(base, path);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, text);
    };
    write(root, "package.json", JSON.stringify({ private: true, workspaces: ["apps/*"] }));
    write(root, "tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "apps" } }));
    write(app, "package.json", JSON.stringify({ name: "generated", private: true }));
    for (const path of ["auth-one.ts", "auth-two.ts", "plain-one.ts", "plain-two.ts"]) {
      write(app, path, `export const ${path.replace(/\W/g, "_")} = true;\n`);
    }

    if (format === "json") {
      const jsonOut = join(root, "quick.json");
      const sarifOut = join(root, "quick.sarif");
      await run([CLI, "--dir", app, "--json", "--out", jsonOut, "--sarif-out", sarifOut]);
      const report = JSON.parse(readFileSync(jsonOut, "utf8")) as {
        grade?: string;
        score?: number;
        gradeScope: string;
        riskDisclosure: string;
        size: { files: number; excludedFiles: number };
        scorecard: { grade?: string; score?: number; dimensions: Array<{ module: string; status: string; reason?: string }> };
      };
      expect(report.size).toMatchObject({ files: 0, excludedFiles: 4 });
      expect(report.grade).toBeUndefined();
      expect(report.score).toBeUndefined();
      expect(report.gradeScope).toContain("NOT ASSESSED");
      expect(report.riskDisclosure).toContain("No M1 hygiene grade was assigned");
      expect(report.riskDisclosure).not.toContain("This grade covers");
      expect(report.scorecard.grade).toBeUndefined();
      expect(report.scorecard.score).toBeUndefined();
      expect(report.scorecard.dimensions.find((row) => row.module === "M4")).toMatchObject({
        status: "not-assessed",
        reason: expect.stringMatching(/All 4 discovered JS\/TS source file.*\. \(TypeScript compiler output declared by tsconfig\.json\)/),
      });
      const sarif = JSON.parse(readFileSync(sarifOut, "utf8")) as { runs: Array<{ properties: { harveyCoverageAbsent: string } }> };
      expect(sarif.runs[0]?.properties.harveyCoverageAbsent).toContain("M1 product-source hygiene was not assessed");
      expect(sarif.runs[0]?.properties.harveyCoverageAbsent).toContain("TypeScript compiler output declared by tsconfig.json");
      expect(sarif.runs[0]?.properties.harveyCoverageAbsent).not.toContain("also graded");

    } else {
      const textOut = join(root, "quick.txt");
      await run([CLI, "--dir", app, "--out", textOut]);
      const rendered = readFileSync(textOut, "utf8");
      expect(rendered).toContain("Codebase Health NOT ASSESSED");
      expect(rendered).toContain("M4   Duplication — NOT ASSESSED by this scan");
      expect(rendered).toContain("TypeScript compiler output declared by tsconfig.json");
      expect(rendered).not.toContain("M4   Duplication — A");
      expect(rendered).not.toContain("M1 security & multi-tenant isolation — Hygiene Grade A");
    }
  }, 120000);

  it.each(["json", "text"])("reports a producer-backed Python M5 assessment beside an excluded JS/TS population (%s)", async (format) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quick-polyglot-assessment-"));
    dirs.push(repo);
    const write = (path: string, text: string) => {
      const full = join(repo, path);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, text);
    };
    write("package.json", JSON.stringify({ name: "polyglot-assessment", private: true }));
    write("tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "compiled" } }));
    write("compiled/output.ts", "export const generated = true;\n");
    write("worker.py", "def work():\n    try:\n        run()\n    except Exception:\n        pass\n");

    if (format === "json") {
      const jsonOut = join(repo, "quick.json");
      const sarifOut = join(repo, "quick.sarif");
      await run([CLI, "--dir", repo, "--json", "--out", jsonOut, "--sarif-out", sarifOut]);
      const report = JSON.parse(readFileSync(jsonOut, "utf8")) as {
        scorecard: { dimensions: Array<{ module: string; status: string; grade?: string; count?: number; scope: string }> };
      };
      expect(report.scorecard.dimensions.find((row) => row.module === "M5")).toMatchObject({
        status: "indicator-only",
        count: 1,
        scope: expect.stringMatching(/examined 1 authored product source file.*No JS\/TS product source was inspected/),
      });
      for (const module of ["M4", "M6", "M7", "M8", "M9"]) {
        expect(report.scorecard.dimensions.find((row) => row.module === module)?.status).toBe("not-assessed");
      }
      const sarif = JSON.parse(readFileSync(sarifOut, "utf8")) as {
        runs: Array<{ properties: { harveyCoverageAbsent: string }; results: Array<{ ruleId: string; message: { text: string } }> }>;
      };
      const exported = sarif.runs[0]!;
      const scope = exported.properties.harveyCoverageAbsent;
      expect(exported.results.map((result) => result.ruleId)).toEqual(expect.arrayContaining([
        "M5 — Python empty/pass exception handler",
        "M5 — Source coverage partial: python",
        "M5 — Hardcoded deployment source coverage not-assessed",
        "M6 — Source coverage not-assessed: python",
      ]));
      expect(exported.results.find((result) => result.ruleId === "M5 — Source coverage partial: python")?.message.text).toContain("All 1 python file(s) were examined");
      expect(scope).toContain("also includes raw mechanical findings for M5, M6");
      expect(scope).toContain("including any partial or not-assessed coverage disclosures emitted with those findings");
      expect(scope).toContain("No assessed scorecard dimension is absent from this SARIF's module findings");
      expect(scope).not.toContain("M1 mechanical results only");
      expect(scope).not.toContain("graded M5; produced a High data-exposure rating for M10; those results are in the report");

    } else {
      const textOut = join(repo, "quick.txt");
      await run([CLI, "--dir", repo, "--out", textOut]);
      const rendered = readFileSync(textOut, "utf8");
      expect(rendered).toContain("M5   Dead code & slop — indicators only — not graded");
      expect(rendered).toContain("No JS/TS product source was inspected");
    }
  }, 120000);

  it("retains Python's zero-finding assessment and coverage disclosure in the real SARIF export", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quick-python-zero-"));
    dirs.push(repo);
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "python-zero", private: true }));
    writeFileSync(join(repo, "worker.py"), "def work():\n    try:\n        run()\n    except Exception as error:\n        log(error)\n");

    const jsonOut = join(repo, "quick.json");
    const sarifOut = join(repo, "quick.sarif");
    await run([CLI, "--dir", repo, "--json", "--out", jsonOut, "--sarif-out", sarifOut]);
    const report = JSON.parse(readFileSync(jsonOut, "utf8")) as {
      scorecard: { dimensions: Array<{ module: string; status: string; count?: number }> };
    };
    const sarif = JSON.parse(readFileSync(sarifOut, "utf8")) as {
      runs: Array<{ properties: { harveyCoverageAbsent: string }; results: Array<{ ruleId: string; message: { text: string } }> }>;
    };
    const exported = sarif.runs[0]!;
    expect(report.scorecard.dimensions.find((row) => row.module === "M5")).toMatchObject({ status: "indicator-only", count: 0 });
    expect(exported.results.map((result) => result.ruleId)).not.toContain("M5 — Python empty/pass exception handler");
    expect(exported.results.find((result) => result.ruleId === "M5 — Source coverage partial: python")?.message.text).toContain("All 1 python file(s) were examined");
    expect(exported.properties.harveyCoverageAbsent).toContain("also includes raw mechanical findings for M5, M6");
    expect(exported.properties.harveyCoverageAbsent).not.toContain("graded M5; those dimensions are scorecard-only");
  }, 120000);

  it("distinguishes a configuration-only scorecard dimension from serialized findings", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quick-config-only-"));
    dirs.push(repo);
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "config-only", private: true }));
    writeFileSync(join(repo, "next.config.js"), "export default { poweredByHeader: true };\n");
    mkdirSync(join(repo, "supabase", "migrations"), { recursive: true });
    writeFileSync(join(repo, "supabase", "migrations", "0001_profiles.sql"), "create table profiles (email text);\n");

    const jsonOut = join(repo, "quick.json");
    const sarifOut = join(repo, "quick.sarif");
    await run([CLI, "--dir", repo, "--json", "--out", jsonOut, "--sarif-out", sarifOut]);
    const report = JSON.parse(readFileSync(jsonOut, "utf8")) as {
      scorecard: { dimensions: Array<{ module: string; status: string; band?: string }> };
    };
    const sarif = JSON.parse(readFileSync(sarifOut, "utf8")) as { runs: Array<{ properties: { harveyCoverageAbsent: string }; results: Array<{ ruleId: string }> }> };
    const exported = sarif.runs[0]!;
    expect(report.scorecard.dimensions.find((row) => row.module === "M10")).toMatchObject({ status: "risk-band" });
    expect(exported.results.some((result) => /^M10 —/.test(result.ruleId))).toBe(false);
    expect(exported.properties.harveyCoverageAbsent).toContain("data-exposure rating for M10; those dimensions are scorecard-only because this SARIF contains no matching module finding");
    expect(exported.properties.harveyCoverageAbsent).not.toContain("M1 mechanical results only");
  }, 120000);
});
