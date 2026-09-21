// #933: quick-scan runs the mechanical scan over a scratch copy of the target
// (src/scan/scan-scope.ts's resolveScanScope, #101), so every raw finding location carries that
// run's mkdtemp `harvey-scan-scope-*` prefix. quick-scan is the client-facing FREE report — a
// per-run/per-machine scratch path in front of every location is unreadable and reads as a leaked
// internal path. relativizeScanScope (#285) already existed and already handled this for the SARIF
// export (#910); this proves it's also applied at quick-scan's own render/output boundary, for
// --out/console, --findings-out, and --json alike, not just SARIF.

import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { HealthScorecard } from "../health-scorecard.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "quick-scan.ts");
const CALIBRATION = join(REPO_ROOT, "targets", "calibration");

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const SCRATCH_PREFIX = /harvey-scan-scope-/;

// These two tests drive the REAL mechanical scan (src/scan/mechanical.ts) as a child process, so
// they need semgrep/trufflehog/gitleaks actually installed — same requirement mechanical.test.ts
// documents (it mocks those sub-scanners specifically because pnpm verify's own convention is
// deterministic-offline, matching the CI `verify` job which — per .github/workflows/ci.yml —
// deliberately does not install them, unlike the separate `dry-run` job). Skip with a named
// reason rather than a silent pass: this is the existing offline-suite convention, not a new one.
function hasBinary(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
const MECHANICAL_BINARIES_PRESENT = ["semgrep", "trufflehog", "gitleaks"].every(hasBinary);

// #1134: awaited spawn, not execFileSync. execFileSync blocks the vitest worker's event loop for the
// call's duration, and a blocked worker cannot service the birpc ack for a task update it already
// sent — vitest hardcodes a 60s window for that ack (see vitest.config.ts's HEAVY_CLI_TESTS comment,
// and #1120/#1133 which found run-audit.test.ts's beforeAll actually over that line). MEASURED
// 2026-07-26 each call here takes ~10s on this hardware, comfortably under the 60s ceiling either
// way, but the standing constraint is "no single blocking window may approach 60s" for every heavy
// CLI test — awaiting a spawned child leaves the loop free regardless of how slow the call gets.
function run(args: string[]): Promise<{ stdout: string }> {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, ["--import", "tsx", ...args], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "ignore"] });
    let stdout = "";
    // setEncoding, never `stdout += <Buffer>` (#1759): string-concatenating a Buffer decodes THAT
    // CHUNK in isolation, so a multi-byte character straddling a chunk boundary decodes to U+FFFD.
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (stdout += d));
    child.on("error", rej);
    child.on("close", (code) => (code === 0 ? res({ stdout }) : rej(new Error(`quick-scan ${args.join(" ")} exited ${code}`))));
  });
}

describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("quick-scan CLI — no scratch-scope path leaks into client-facing output (#933)", () => {
  // Drives the real mechanical scan (semgrep/trufflehog/gitleaks/osv-scanner) as a child process,
  // so vitest's 5s default is far too short. 30s was too short too: #1125 is this file blowing that
  // budget under full-suite parallel load while passing in isolation, reproduced by two sweep
  // executors on unrelated branches. #1120 moved the file into the serialized heavy-CLI run
  // (vitest.config.ts), where MEASURED 2026-07-26 both tests take ~11s each on a load-25 10-core
  // machine — but that measurement is this hardware, and this describe block has never once
  // executed on a CI runner (the `verify` job installs none of these binaries). 120s so the budget
  // is not the thing that discovers unfamiliar hardware; the assertion is about path leakage, and
  // nothing about it gets weaker with more headroom.
  it("does not leak the harvey-scan-scope-* mkdtemp prefix into the rendered report", async () => {
    const { stdout } = await run([CLI, "--dir", CALIBRATION]);
    expect(stdout).toMatch(/verified hygiene issue/); // sanity: the calibration fixture DOES produce findings
    expect(stdout).not.toMatch(SCRATCH_PREFIX);
  }, 120000);

  it("does not leak the scratch prefix into --findings-out (the raw mechanical Finding[])", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "harvey-quick-scan-test-"));
    dirs.push(outDir);
    const findingsOutPath = join(outDir, "findings.json");
    await run([CLI, "--dir", CALIBRATION, "--findings-out", findingsOutPath, "--out", join(outDir, "report.txt")]);
    const findings = JSON.parse(readFileSync(findingsOutPath, "utf8")) as { location: string }[];
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => SCRATCH_PREFIX.test(f.location))).toBe(false);
  }, 120000);
});

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

  it("keeps the full authored population but does not grade M4 through an unresolved Vite output", async () => {
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
    const renderedOut = join(repo, "quick.txt");
    await run([CLI, "--dir", repo, "--out", renderedOut]);
    const rendered = readFileSync(renderedOut, "utf8");
    expect(rendered).toContain("M4   Duplication — NOT ASSESSED by this scan");
    expect(rendered).toContain("Product-source configuration is unresolved");
    expect(rendered).toContain("Vite build.outDir is not a static string");
  }, 120000);

  it("does not grade a configured whole-output workspace with zero inspected product source", async () => {
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

    const textOut = join(root, "quick.txt");
    await run([CLI, "--dir", app, "--out", textOut]);
    const rendered = readFileSync(textOut, "utf8");
    expect(rendered).toContain("Codebase Health NOT ASSESSED");
    expect(rendered).toContain("M4   Duplication — NOT ASSESSED by this scan");
    expect(rendered).toContain("TypeScript compiler output declared by tsconfig.json");
    expect(rendered).not.toContain("M4   Duplication — A");
    expect(rendered).not.toContain("M1 security & multi-tenant isolation — Hygiene Grade A");
  }, 120000);

  it("reports a producer-backed Python M5 assessment beside an excluded JS/TS population", async () => {
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

    const jsonOut = join(repo, "quick.json");
    const sarifOut = join(repo, "quick.sarif");
    await run([CLI, "--dir", repo, "--json", "--out", jsonOut, "--sarif-out", sarifOut]);
    const report = JSON.parse(readFileSync(jsonOut, "utf8")) as {
      scorecard: { dimensions: Array<{ module: string; status: string; grade?: string; count?: number; scope: string }> };
    };
    expect(report.scorecard.dimensions.find((row) => row.module === "M5")).toMatchObject({
      status: "graded",
      grade: "F",
      count: 1,
      scope: expect.stringMatching(/examined 1 authored source file.*No JS\/TS product source was inspected/),
    });
    for (const module of ["M4", "M6", "M7", "M8", "M9"]) {
      expect(report.scorecard.dimensions.find((row) => row.module === module)?.status).toBe("not-assessed");
    }
    const sarif = JSON.parse(readFileSync(sarifOut, "utf8")) as { runs: Array<{ properties: { harveyCoverageAbsent: string } }> };
    expect(sarif.runs[0]?.properties.harveyCoverageAbsent).toContain("graded M5");
    expect(sarif.runs[0]?.properties.harveyCoverageAbsent).not.toContain("M4, M5, M6");

    const textOut = join(repo, "quick.txt");
    await run([CLI, "--dir", repo, "--out", textOut]);
    const rendered = readFileSync(textOut, "utf8");
    expect(rendered).toContain("M5   Dead code & slop — F");
    expect(rendered).toContain("No JS/TS product source was inspected");
  }, 120000);
});


// #1237(a) — the loop-copy allowlist sanitizer, driven through the REAL semgrep run rather than a
// recorded fixture, because what it has to prove is the sanitizer's behaviour and a recording
// does not. It lives here rather than in the calibration entries alone for a measured reason:
// `validate-calibration` scores all three rows correctly, but at the time this landed that gate
// printed a review-tier miss as a tracked NON-FATAL gap and still exited 0. MEASURED 2026-07-31 —
// with the sanitizer's identifier constraint deleted, both adversarial positives went silent, both
// rows read FAIL, and the gate still printed GATE PASS and exited 0. #1628 closed that hole the
// same day: a review-tier miss is a GATE FAIL now, so the corpus rows would bite on their own. This
// block stays because it is not the same test — it drives the sanitizer through a real semgrep run
// and asserts WHICH fixtures it spares, which a recall count leaves unsaid.
describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("harvey-jsx-prop-spread-injection: the loop-copy allowlist (#1237)", () => {
  const FIXTURES = join(CALIBRATION, "src", "owasp-react");

  async function propSpreadHits(): Promise<string[]> {
    const outDir = mkdtempSync(join(tmpdir(), "harvey-propspread-test-"));
    dirs.push(outDir);
    const findingsOutPath = join(outDir, "findings.json");
    await run([CLI, "--dir", CALIBRATION, "--findings-out", findingsOutPath, "--out", join(outDir, "report.txt")]);
    const findings = JSON.parse(readFileSync(findingsOutPath, "utf8")) as { taxonomy: string; location: string }[];
    return findings
      .filter((f) => f.taxonomy.includes("prop-spread-injection"))
      .map((f) => f.location.split("/").pop() ?? f.location);
  }

  it("clears the named-allowlist loop and still fires on both shapes that spoof it", async () => {
    const hit = await propSpreadHits();
    // Sanity: the rule ran at all. Without this the three assertions below all pass on an empty set.
    expect(hit.some((l) => l.startsWith("prop-spread-injection.tsx"))).toBe(true);
    expect(FIXTURES).toBeTruthy();

    // The fix: `for (const k of ALLOWED_PROPS) if (k in raw) safe[k] = raw[k]` is the sheet's own
    // remedy written imperatively, and the rule was reporting it at High.
    expect(hit.some((l) => l.startsWith("prop-spread-loop-allowlist.tsx"))).toBe(false);

    // The two shapes a looser version of that sanitizer would clear silently. Neither is a
    // hypothetical: dropping the `$ALLOW` identifier constraint makes both of these go dark.
    expect(hit.some((l) => l.startsWith("prop-spread-loop-own-keys.tsx"))).toBe(true);
    expect(hit.some((l) => l.startsWith("prop-spread-loop-tainted-list.tsx"))).toBe(true);
  }, 120000);
});


describe.skipIf(!MECHANICAL_BINARIES_PRESENT)("M9 workspace assessment at quick-scan output (#2074)", () => {
  it.each(["unsupported-only", "native-astro-only", "mixed-clean", "mixed-defects"])("preserves assessment and disclosure in both formats for %s", async (shape) => {
    const target = mkdtempSync(join(tmpdir(), "harvey-m9-workspace-"));
    dirs.push(target);
    mkdirSync(join(target, "apps/site/src"), { recursive: true });
    writeFileSync(join(target, "package.json"), JSON.stringify({ name: "m9-scope-fixture", private: true, workspaces: ["apps/*"] }));
    for (const config of ["next.config.js", "next.config.mjs", "next.config.cjs", "next.config.ts", "babel.config.js", "babel.config.mjs", "babel.config.cjs"]) {
      writeFileSync(join(target, config), "export default {};");
    }
    writeFileSync(join(target, "apps/site/package.json"), JSON.stringify({ name: "site", dependencies: { astro: "5.0.0" } }));
    writeFileSync(join(target, "apps/site/src", shape === "native-astro-only" ? "page.astro" : "main.ts"), shape === "native-astro-only" ? "<h1>Site</h1>" : "export const site = 1;");
    if (shape.startsWith("mixed")) {
      mkdirSync(join(target, "apps/api/app"), { recursive: true });
      writeFileSync(join(target, "apps/api/package.json"), JSON.stringify({ name: "api", dependencies: { next: "14.0.0" } }));
      for (let i = 0; i < (shape === "mixed-defects" ? 6 : 1); i += 1) {
        mkdirSync(join(target, `apps/api/app/p${i}`), { recursive: true });
        writeFileSync(join(target, `apps/api/app/p${i}/page.tsx`), shape === "mixed-defects"
          ? "export default function Page() { return <div>{window.innerWidth}</div>; }"
          : "export default function Page() { return null; }");
      }
    }
    const jsonRun = await run([CLI, "--dir", target, "--json"]);
    const textRun = await run([CLI, "--dir", target]);
    const scorecard = (JSON.parse(jsonRun.stdout) as { scorecard: HealthScorecard }).scorecard;
    const m9 = scorecard.dimensions.find((d) => d.module === "M9")!;
    const m9Line = textRun.stdout.split("\n").find((line) => line.includes("M9") && line.includes("Framework-boundary correctness"))!;
    for (const text of [JSON.stringify(m9), textRun.stdout]) {
      expect(text).toContain("Astro");
      expect(text).toContain("apps/site");
    }
    if (shape.startsWith("mixed")) {
      expect(m9.status).toBe("graded");
      expect(m9.count).toBe(shape === "mixed-defects" ? 6 : 0);
      expect(m9.notAssessedRows).toBe(1);
      expect(m9.reason).toContain("was not analysed");
      expect(m9Line).toMatch(/[A-F] \(\d+\/100\)/);
      if (shape === "mixed-clean") expect(m9.score).toBe(100);
    } else {
      expect(m9.status).toBe("not-assessed");
      expect(m9.grade).toBeUndefined();
      expect(m9.score).toBeUndefined();
      expect(scorecard.gradedModules).not.toContain("M9");
      expect(m9Line).toContain("NOT ASSESSED");
      expect(m9Line).not.toMatch(/[A-F] \(\d+\/100\)/);
      const graded = scorecard.dimensions.filter((d) => d.status === "graded" && d.module !== "M9");
      expect(scorecard.score).toBe(Math.round(graded.reduce((sum, d) => sum + d.score!, 0) / graded.length));
    }
  }, 120000);
});
