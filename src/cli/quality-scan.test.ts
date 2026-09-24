// #544: jscpd (M4 duplication) runs WHOLE-REPO, not per-workspace. #519 had swept it into knip's
// per-workspace change, which on a monorepo structurally cannot see a block copy-pasted ACROSS
// workspaces — the most valuable duplication signal in a monorepo — and also silently dropped every
// workspace the shared discoverTargets glob can't expand (a `packages/**` double-star, #548). This
// drives the real CLI against a synthetic two-workspace monorepo whose only clone spans apps/web and
// a `packages/**` package: under per-workspace jscpd M4 sees nothing; under whole-repo it must find
// the cross-workspace pair. A regression back to per-workspace jscpd fails this test.

import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { digestObservedPaths, readCorpusScannerScope } from "../corpus-scanner-scope.js";
import { AUDIT_RUNNERS } from "../audit-runners.js";
import { createQualityScanTestHarness } from "./quality-scan-test-support.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "quality-scan.ts");

const harness = createQualityScanTestHarness();
const { dirs, run: spawnCli } = harness;
afterEach(() => harness.cleanup());

// A block long/token-dense enough to clear jscpd's default min-lines/min-tokens gate, so an
// identical copy in two workspaces is reported as one cross-file clone.
const CLONED_BLOCK = `export function summarizeOrder(order: { items: { price: number; qty: number }[]; tax: number }) {
  let subtotal = 0;
  for (const item of order.items) {
    subtotal += item.price * item.qty;
  }
  const taxAmount = subtotal * order.tax;
  const total = subtotal + taxAmount;
  return {
    subtotal: Math.round(subtotal * 100) / 100,
    taxAmount: Math.round(taxAmount * 100) / 100,
    total: Math.round(total * 100) / 100,
    itemCount: order.items.reduce((n, i) => n + i.qty, 0),
  };
}
`;

function monorepoFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-cli-"));
  dirs.push(repo);
  writeFileSync(join(repo, "pnpm-workspace.yaml"), "packages:\n  - apps/*\n  - packages/**\n");
  writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "fixture-root", private: true }));
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  };
  write("apps/web/package.json", JSON.stringify({ name: "web" }));
  write("apps/web/src/order.ts", CLONED_BLOCK);
  // packages/** — the double-star workspace discoverTargets doesn't even enumerate (#548); a
  // whole-repo jscpd walks it regardless of the workspace glob, a per-workspace one never sees it.
  write("packages/billing/package.json", JSON.stringify({ name: "@kit/billing" }));
  write("packages/billing/src/order.ts", CLONED_BLOCK);
  return repo;
}


async function runCli(repo: string, args: string[] = [], input?: string | null): Promise<Finding[]> {
  const outPath = join(repo, "quality-out.json");
  await spawnCli("node_modules/.bin/tsx", [CLI, repo, ...args, "--out", outPath], REPO_ROOT, input);
  return JSON.parse(readFileSync(outPath, "utf8")) as Finding[];
}

describe("quality-scan CLI — native duplication failures remain visible (#2102)", () => {
  it.each(["valid", "tiny", "missing", "malformed", "nonzero", "timeout"] as const)("delivers the %s adapter outcome and cleans the actual output directory", async (mode) => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-quality-jscpd-failure-"));
    dirs.push(fixture);
    const repo = join(fixture, "target");
    mkdirSync(repo);
    writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "duplication-failure-control", private: true }));
    writeFileSync(join(repo, "a.ts"), "export const a = 1;\n");
    if (mode !== "tiny") writeFileSync(join(repo, "b.ts"), "export const b = 2;\n");
    const capture = join(fixture, "output-path.txt");
    const executable = join(fixture, "jscpd.cjs");
    writeFileSync(executable, `#!/usr/bin/env node
const fs=require('node:fs');const path=require('node:path');const args=process.argv.slice(2);
const out=args[args.indexOf('--output')+1];fs.writeFileSync(${JSON.stringify(capture)},out);
const mode=${JSON.stringify(mode)};
if(mode==='valid')fs.writeFileSync(path.join(out,'jscpd-report.json'),JSON.stringify({statistics:{total:{percentage:0,duplicatedLines:0,lines:2}},duplicates:[]}));
if(mode==='malformed')fs.writeFileSync(path.join(out,'jscpd-report.json'),'{broken JSON');
if(mode==='nonzero'){process.stderr.write('jscpd native failure canary');process.exitCode=7;}
if(mode==='timeout')setInterval(()=>{},1000);
`);
    chmodSync(executable, 0o755);
    const preload = join(fixture, "native-jscpd.cjs");
    // Substitute only the external executable; the shipping adapter, catch, receipt and findings
    // assembly all execute unchanged. The fake child still receives the adapter's real argv/cwd.
    writeFileSync(preload, `const cp=require('node:child_process');const {syncBuiltinESMExports}=require('node:module');
const original=cp.execFileSync;cp.execFileSync=function(file,args,options){return original.call(this,String(file).endsWith('/jscpd')?${JSON.stringify(executable)}:file,args,options);};syncBuiltinESMExports();`);
    const output = join(fixture, "findings.json");
    const receipt = join(fixture, "scope.json");
    const stderr = await spawnCli(process.execPath, ["--require", preload, "--import", "tsx", CLI, repo,
      "--timeout", mode === "timeout" ? "0.5" : "5", "--out", output, "--scope-out", receipt], REPO_ROOT);
    const actualOutput = readFileSync(capture, "utf8");
    dirs.push(actualOutput);
    expect(existsSync(actualOutput)).toBe(false);
    const findings = JSON.parse(readFileSync(output, "utf8")) as Finding[];
    const scope = readCorpusScannerScope(receipt, "quality-scan");
    const gap = findings.find((finding) => finding.id === "M4-99");
    if (mode === "valid" || mode === "tiny") {
      expect(gap).toBeUndefined();
      expect(scope.observation).toMatchObject({ jscpd: { status: "completed" } });
    } else {
      const diagnostic = mode === "nonzero" ? "jscpd native failure canary"
        : mode === "timeout" ? "did not complete within 0.5s (timed out)"
          : mode === "missing" ? "no report" : "JSON";
      expect(gap).toMatchObject({ taxonomy: "M4 — Duplication", evidence: expect.stringContaining(diagnostic) });
      expect(stderr).toContain(diagnostic);
      expect(scope.observation).toMatchObject({ jscpd: { status: "incomplete" } });
      expect(gap?.impact).toContain("not a finding of zero duplication");
    }
  }, 30_000);
});

describe("quality-scan CLI — jscpd runs whole-repo so cross-workspace clones are detected (#544)", () => {
  // 30s: drives the real CLI end-to-end (jscpd whole-repo + per-workspace knip on the now-enumerated
  // packages/** workspace, #548) as a child process — well over vitest's 5s default under load.
  it("finds a clone spanning apps/web and a packages/** workspace", async () => {
    const findings = await runCli(monorepoFixture());
    const crossWorkspace = findings.filter(
      (f) => f.taxonomy.startsWith("M4 —") && f.location.includes("apps/web") && f.location.includes("packages/billing"),
    );
    expect(crossWorkspace.length).toBeGreaterThan(0);
  }, 30000);

  // #580: this target has NO vite markers and a healthy (mostly-used) file set — the disclosure
  // must stay silent on a target that never asked the question, matching "a normal Vite target
  // with the plugin active is unaffected" from a non-Vite target's side too.
  it("does not raise the M5-99 entry-uncertain disclosure on a normal, non-Vite target", async () => {
    const findings = await runCli(monorepoFixture());
    expect(findings.find((f) => f.id === "M5-99")).toBeUndefined();
  }, 30000);
});

describe("quality-scan CLI — context-aware product inventory (#2132)", () => {
  it.each(["empty", "config-only", "external-only", "positive"] as const)("delivers the requested %s source receipt and its assessment disposition", async (shape) => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-quality-zero-receipt-"));
    dirs.push(fixture);
    const repo = join(fixture, "target");
    mkdirSync(repo);
    if (shape !== "empty") {
      writeFileSync(join(repo, "package.json"), JSON.stringify({ name: "zero-quality-fixture", private: true }));
      writeFileSync(join(repo, "tsconfig.json"), JSON.stringify({ compilerOptions: { noEmit: true } }));
    }
    if (shape === "external-only") {
      mkdirSync(join(fixture, "outside"));
      writeFileSync(join(fixture, "outside", "hidden.ts"), CLONED_BLOCK);
      symlinkSync(join(fixture, "outside"), join(repo, "external-src"), "dir");
    } else if (shape === "positive") {
      writeFileSync(join(repo, "authored.ts"), CLONED_BLOCK);
    }
    const scopePath = join(fixture, "scope.json");
    const outPath = join(fixture, "findings.json");
    const stderr = await spawnCli("node_modules/.bin/tsx", [CLI, repo, "--degraded-knip-reason", "Explicit source-only receipt control without target dependency installation.", "--scope-out", scopePath, "--out", outPath], REPO_ROOT);
    const findings = JSON.parse(readFileSync(outPath, "utf8")) as Finding[];
    const receipt = readCorpusScannerScope(scopePath, "quality-scan");
    if (receipt.observation.scanner !== "quality-scan") throw new Error("expected quality receipt");
    if (shape === "positive") {
      expect(receipt.unitsExamined).toBe(1);
      expect(receipt.observation.productSources.pathsDigest).toBe(digestObservedPaths(["authored.ts"]));
      expect(receipt.observation.zeroSourceDisposition).toBeUndefined();
      expect(findings.some((finding) => finding.id === "M4-99" || finding.id === "M5-00")).toBe(false);
    } else {
      expect(receipt.unitsExamined).toBe(0);
      expect(receipt.observation).toMatchObject({
        productSources: { count: 0, pathsDigest: digestObservedPaths([]) },
        jscpd: { status: shape === "external-only" ? "incomplete" : "completed", comparedLines: 0 },
        zeroSourceDisposition: {
          status: "not-assessed", reason: expect.stringContaining("no eligible"),
          provenance: expect.stringContaining("0 admitted files"), falsifier: expect.stringContaining("invalidates"),
        },
      });
      for (const id of ["M4-99", "M5-00"]) {
        const gap = findings.find((finding) => finding.id === id);
        expect(gap).toBeDefined();
        expect(gap!.evidence).toContain(shape === "external-only" ? "external-src" : shape === "empty" && id === "M5-00" ? "Unable to find package.json" : "no eligible");
      }
      if (shape === "external-only") {
        expect(receipt.observation.zeroSourceDisposition!.reason).toContain("external-src");
        const assessment = AUDIT_RUNNERS.find((runner) => runner.module === "M4")!.run({
          targetDir: repo, env: { connected: false, dynamic: false, llm: false }, exists: existsSync,
          exec: () => ({ ok: true, output: readFileSync(outPath, "utf8"), stderr }),
        });
        expect(assessment).toMatchObject({
          kind: "not-assessed", reason: expect.stringContaining(findings.find((finding) => finding.id === "M4-99")!.evidence),
          provenance: "MEASURED", falsifier: expect.stringContaining("quality-scan"),
        });
        expect(assessment).not.toHaveProperty("unitsExamined");
      }
    }
  }, 30_000);

  it.each(["imported", "cross-config", "noEmit JavaScript"])("reports authored dead code through %s compiler provenance", async (mode) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-compiler-cli-"));
    dirs.push(repo);
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    const authoredPath = mode === "noEmit JavaScript" ? "src/outside.js" : "src/authored.ts";
    write("package.json", JSON.stringify({ name: "compiler-fixture", private: true }));
    write("knip.json", JSON.stringify({ entry: ["outside.ts"], project: ["**/*.{ts,js}"] }));
    write("outside.ts", mode === "cross-config" ? "export const outside = true;\n" : `import { used } from './${authoredPath.replace(/\.ts$/, ".js")}';\nconsole.log(used);\n`);
    write(authoredPath, "export const used = true;\nexport function unusedAuthoredFunction() { return 'authored'; }\n");
    write("tsconfig.build.json", JSON.stringify({
      compilerOptions: { target: "ES2022", module: "ESNext", rootDir: ".", outDir: "src", ...(mode === "noEmit JavaScript" ? { noEmit: true, allowJs: true } : {}) },
      files: ["outside.ts"],
    }));
    if (mode === "cross-config") write("tsconfig.check.json", JSON.stringify({ compilerOptions: { noEmit: true }, files: [authoredPath] }));
    if (mode !== "noEmit JavaScript") write("src/outside.js", "export function generatedArtifact() { return 'generated'; }\n");

    const findings = await runCli(repo);
    expect(findings).toContainEqual(expect.objectContaining({
      taxonomy: "M5 — Slop / dead code",
      location: expect.stringContaining(authoredPath),
      title: expect.stringContaining("Unused"),
    }));
    if (mode !== "noEmit JavaScript") {
      expect(findings.filter((finding) => finding.location.includes("src/outside.js"))).toEqual([]);
      expect(findings).toContainEqual(expect.objectContaining({
        id: "M4-SCOPE-00", evidence: expect.stringMatching(/`src\/outside\.js`: 1 file.*TypeScript compiler output/),
      }));
    }
  }, 30000);

  it("excludes a pnpm store clone, retains a real reports-route clone, and discloses the exact store population", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-store-cli-"));
    dirs.push(repo);
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "store-fixture", private: true, packageManager: "pnpm@9.0.0" }));
    write("src/app/api/reports/one/route.ts", CLONED_BLOCK);
    write("src/app/api/reports/two/route.ts", CLONED_BLOCK);
    write(".pnpm-store/v3/a/index.ts", CLONED_BLOCK);
    write(".pnpm-store/v3/b/index.ts", CLONED_BLOCK);
    const findings = await runCli(repo);
    const productClone = findings.find((finding) => finding.taxonomy.startsWith("M4 —") && finding.location.includes("reports/one") && finding.location.includes("reports/two"));
    expect(productClone).toBeDefined();
    expect(findings.some((finding) => finding.location.includes(".pnpm-store"))).toBe(false);
    const scope = findings.find((finding) => finding.id === "M4-SCOPE-00");
    expect(scope?.evidence).toContain("**/.pnpm-store/**");
    expect(scope?.evidence).toContain("2 files");
  }, 30000);

  it("excludes a proven inactive install overlay but still scans authored code named patches", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-overlay-cli-"));
    dirs.push(repo);
    const scopePath = join(repo, "quality-scope.json");
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "overlay-fixture", private: true }));
    write("optional/install.sh", [
      '#!/usr/bin/env bash',
      'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
      'ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"',
      'OVERLAY_DIR="$SCRIPT_DIR/overlay"',
      'BACKUP_DIR="$ROOT_DIR/.optional-backup"',
      'cp "$ROOT_DIR/live/one.ts" "$BACKUP_DIR/live/one.ts"',
      'cp "$ROOT_DIR/live/two.ts" "$BACKUP_DIR/live/two.ts"',
      'cp "$OVERLAY_DIR/live/one.ts" "$ROOT_DIR/live/one.ts"',
      'cp "$OVERLAY_DIR/live/two.ts" "$ROOT_DIR/live/two.ts"',
      'cp "$ROOT_DIR/patches/authored-one.ts" "$BACKUP_DIR/authored-one.ts"',
      'cp "$ROOT_DIR/patches/authored-two.ts" "$BACKUP_DIR/authored-two.ts"',
      'cp "$ROOT_DIR/patches/authored-one.ts" "$ROOT_DIR/patches/authored-one.ts"',
      'cp "$ROOT_DIR/patches/authored-two.ts" "$ROOT_DIR/patches/authored-two.ts"',
      'cp "$ROOT_DIR/patches/cross-one.ts" "$BACKUP_DIR/cross-one.ts"',
      'cp "$ROOT_DIR/patches/cross-two.ts" "$BACKUP_DIR/cross-two.ts"',
      'cp "$ROOT_DIR/patches/cross-one.ts" "$ROOT_DIR/patches/cross-two.ts"',
      'cp "$ROOT_DIR/patches/cross-two.ts" "$ROOT_DIR/patches/cross-one.ts"',
      '',
    ].join("\n"));
    write("optional/overlay/live/one.ts", CLONED_BLOCK);
    write("optional/overlay/live/two.ts", CLONED_BLOCK);
    write("live/one.ts", "export const liveOne = true;\n");
    write("live/two.ts", "export const liveTwo = false;\n");
    write("patches/authored-one.ts", CLONED_BLOCK);
    write("patches/authored-two.ts", CLONED_BLOCK);
    write("patches/cross-one.ts", "export const crossOne = true;\n");
    write("patches/cross-two.ts", "export const crossTwo = false;\n");

    const findings = await runCli(repo, ["--scope-out", scopePath]);
    expect(findings.filter((finding) => finding.location.includes("optional/overlay"))).toEqual([]);
    expect(findings).toContainEqual(expect.objectContaining({
      taxonomy: "M4 — Duplication",
      location: expect.stringMatching(/patches\/authored-one\.ts.*patches\/authored-two\.ts|patches\/authored-two\.ts.*patches\/authored-one\.ts/),
    }));
    for (const path of ["patches/cross-one.ts", "patches/cross-two.ts"]) {
      expect(findings).toContainEqual(expect.objectContaining({ taxonomy: "M5 — Slop / dead code", location: path }));
    }
    expect(findings).toContainEqual(expect.objectContaining({
      id: "M4-SCOPE-00",
      evidence: expect.stringMatching(/`optional\/overlay\/\*\*`: 2 files.*optional\/install\.sh/),
    }));
    const scope = JSON.parse(readFileSync(scopePath, "utf8")) as {
      unitsExamined: number;
      observation: { productSources: { count: number } };
    };
    expect(scope.unitsExamined).toBe(6);
    expect(scope.observation.productSources.count).toBe(6);
  }, 30000);

  function compilerLiveOverlayFixture(): string {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-live-overlay-"));
    dirs.push(repo);
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "live-overlay-fixture", private: true }));
    write("tsconfig.json", JSON.stringify({ compilerOptions: { noEmit: true }, files: ["outside.ts"] }));
    write("knip.json", JSON.stringify({ entry: ["outside.ts"], project: ["**/*.ts"] }));
    write("outside.ts", "import { one } from './optional/overlay/live/one.js';\nimport { two } from './optional/overlay/live/two.js';\nconsole.log(one(), two());\n");
    write("optional/install.sh", [
      'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
      'ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"',
      'OVERLAY_DIR="$SCRIPT_DIR/overlay"',
      'BACKUP_DIR="$ROOT_DIR/.optional-backup"',
      ...["one", "two", "three"].map((name) => `cp "$ROOT_DIR/live/${name}.ts" "$BACKUP_DIR/live/${name}.ts"`),
      ...["one", "two", "three"].map((name) => `cp "$OVERLAY_DIR/live/${name}.ts" "$ROOT_DIR/live/${name}.ts"`),
    ].join("\n"));
    for (const name of ["one", "two", "three"]) {
      write(`live/${name}.ts`, `export const original${name} = true;\n`);
      write(`optional/overlay/live/${name}.ts`, `${CLONED_BLOCK}\nexport function ${name}() { throw new Error("Not implemented"); }\n`);
    }
    return repo;
  }

  it("reports compiler-live overlay duplication findings through the quality CLI", async () => {
    const repo = compilerLiveOverlayFixture();
    const findings = await runCli(repo);
    expect(findings).toContainEqual(expect.objectContaining({
      taxonomy: "M4 — Duplication", location: expect.stringMatching(/optional\/overlay\/live\/one\.ts.*optional\/overlay\/live\/two\.ts|optional\/overlay\/live\/two\.ts.*optional\/overlay\/live\/one\.ts/),
    }));
    expect(findings.some((finding) => finding.location.includes("optional/overlay/live/three.ts"))).toBe(false);
  }, 30000);

  it("reports compiler-live overlay dead-code findings through the quick-scan CLI", async () => {
    const repo = compilerLiveOverlayFixture();
    const quickPath = join(repo, "quick-out.json");
    await spawnCli(process.execPath, ["--import", "tsx", join(REPO_ROOT, "src/cli/quick-scan.ts"), "--dir", repo, "--json", "--out", quickPath], REPO_ROOT, undefined, { timeoutMs: 110_000 });
    const quick = JSON.parse(readFileSync(quickPath, "utf8")) as { scorecard: { dimensions: Array<{ module: string; count?: number }> } };
    expect(quick.scorecard.dimensions.find((dimension) => dimension.module === "M5")).toMatchObject({ count: 2 });
  }, 120000);

  it("preserves executable Knip config imports and exclusions while disclosing unverified selection", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-executable-knip-"));
    dirs.push(repo);
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "executable-knip", private: true, packageManager: "pnpm@9.0.0" }));
    write("src/index.ts", "export const live = true;\n");
    write("src/authored-ignore/dead.ts", "export const intentionallyIgnored = true;\n");
    write("src/cache/.pnpm-store/v3/pkg/unused.ts", "export const dependencyArtifact = true;\n");
    write("knip-provider.ts", 'import { writeFileSync } from "node:fs"; writeFileSync("provider-consumed", "yes");\n');
    write("knip.config.ts", 'import "./knip-provider.ts"; const project = ["src/**/*.ts"]; export default () => ({ entry: ["src/index.ts"], project, ignore: "src/authored-ignore/**" });\n');
    const receiptPath = join(repo, "scope.json");
    const findings = await runCli(repo, ["--scope-out", receiptPath]);
    expect(readFileSync(join(repo, "provider-consumed"), "utf8")).toBe("yes");
    expect(findings.some((finding) => finding.location.includes(".pnpm-store"))).toBe(false);
    expect(findings.some((finding) => finding.location.includes("authored-ignore"))).toBe(false);
    expect(findings.some((finding) => finding.id === "M5-98")).toBe(false);
    expect(findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("configuration could not be inspected");
    expect(readCorpusScannerScope(receiptPath, "quality-scan").observation).toMatchObject({
      knip: { completed: [], incomplete: ["(repo root)"], populations: [
        { scope: "(repo root)", status: "incomplete", configuration: "root-workspace-config", reason: expect.stringContaining("could not be inspected") },
      ] },
    });
  }, 30000);

  it("retains root-declared stores and generated output for root and direct workspace entry points", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-workspace-inventory-"));
    dirs.push(repo);
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "root", private: true, packageManager: "pnpm@9.0.0", workspaces: ["apps/*"] }));
    write("pnpm-workspace.yaml", "packages:\n  - apps/*\n");
    write(".npmrc", "store-dir=apps/web/package-cache\n");
    write("tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "apps/web/compiled" } }));
    write("apps/web/package.json", JSON.stringify({ name: "web", private: true }));
    write("apps/web/knip.json", JSON.stringify({ entry: ["src/index.ts"], project: ["**/*.ts"] }));
    write("apps/web/src/index.ts", 'import { live } from "./live.js"; console.log(live);\n');
    write("apps/web/src/live.ts", "export const live = true;\n");
    write("apps/web/src/app/reports/dead.ts", "export const authoredReport = true;\n");
    write("apps/web/src/app/dist/dead.ts", "export const authoredDist = true;\n");
    write("apps/web/.pnpm-store/v3/pkg/dead.ts", "export const dependencyArtifact = true;\n");
    write("apps/web/package-cache/v3/pkg/dead.ts", "export const cachedArtifact = true;\n");
    write("apps/web/compiled/dead.ts", "export const generatedArtifact = true;\n");

    const findings = await runCli(repo);
    for (const excluded of [".pnpm-store", "package-cache", "compiled/dead.ts"]) {
      expect(findings.some((finding) => finding.location.includes(excluded)), excluded).toBe(false);
    }
    for (const authored of ["src/app/reports/dead.ts", "src/app/dist/dead.ts"]) {
      expect(findings).toContainEqual(expect.objectContaining({ taxonomy: "M5 — Slop / dead code", location: `apps/web/${authored}` }));
    }
    const scope = findings.find((finding) => finding.id === "M4-SCOPE-00");
    expect(scope?.evidence).toContain("apps/web/package-cache/**");
    expect(scope?.evidence).toContain("apps/web/compiled/**");

    const directFindings = await runCli(join(repo, "apps/web"));
    for (const excluded of [".pnpm-store", "package-cache", "compiled/dead.ts"]) {
      expect(directFindings.filter((finding) => finding.taxonomy === "M5 — Slop / dead code" && finding.location.includes(excluded)), `direct ${excluded}`).toEqual([]);
    }
    for (const authored of ["src/app/reports/dead.ts", "src/app/dist/dead.ts"]) {
      expect(directFindings).toContainEqual(expect.objectContaining({ taxonomy: "M5 — Slop / dead code", location: authored }));
    }
    const directScope = directFindings.find((finding) => finding.id === "M4-SCOPE-00");
    expect(directScope?.evidence).toContain("`**/.pnpm-store/**`: 1 file");
    expect(directScope?.evidence).toContain("`package-cache/**`: 1 file");
    expect(directScope?.evidence).toContain("`compiled/**`: 1 file");
  }, 30000);

  it("inherits a root output boundary through a brace-declared direct workspace scan", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-brace-workspace-"));
    dirs.push(repo);
    const app = join(repo, "packages/app");
    const scopePath = join(repo, "quality-scope.json");
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "root", private: true, workspaces: ["packages/{app,lib}"] }));
    write("tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "packages/app/generated" } }));
    write("packages/app/package.json", JSON.stringify({ name: "app", private: true }));
    write("packages/app/knip.json", JSON.stringify({ entry: ["src/live.ts"], project: ["**/*.ts"] }));
    write("packages/app/src/live.ts", "export const live = true;\n");
    write("packages/app/src/dead.ts", "export const dead = true;\n");
    write("packages/app/generated/dead.ts", "export const generated = true;\n");
    write("packages/lib/package.json", JSON.stringify({ name: "lib", private: true }));

    const findings = await runCli(app, ["--scope-out", scopePath]);
    expect(findings).toContainEqual(expect.objectContaining({ taxonomy: "M5 — Slop / dead code", location: "src/dead.ts" }));
    expect(findings.some((finding) => finding.location.includes("generated/dead.ts"))).toBe(false);
    expect(findings).toContainEqual(expect.objectContaining({
      id: "M4-SCOPE-00",
      evidence: expect.stringMatching(/`generated\/\*\*`: 1 file.*TypeScript compiler output declared by tsconfig\.json/),
    }));
    const scope = JSON.parse(readFileSync(scopePath, "utf8")) as { unitsExamined: number; observation: { productSources: { count: number } } };
    expect(scope.unitsExamined).toBe(2);
    expect(scope.observation.productSources.count).toBe(2);
  }, 30000);

  it("keeps findings and a conserved receipt when a Vite output boundary is unresolved", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-unresolved-vite-"));
    dirs.push(repo);
    const scopePath = join(repo, "quality-scope.json");
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "dynamic-vite", private: true }));
    write("knip.json", JSON.stringify({ entry: ["src/live.ts"], project: ["src/**/*.ts"] }));
    write("src/live.ts", "export const live = true;\n");
    write("src/dead.ts", "export const dead = true;\n");
    write("vite.config.ts", "const outDir = process.env.OUT_DIR; export default { build: { outDir } };\n");

    const findings = await runCli(repo, ["--scope-out", scopePath]);
    expect(findings).toContainEqual(expect.objectContaining({ taxonomy: "M5 — Slop / dead code", location: "src/dead.ts" }));
    expect(findings).toContainEqual(expect.objectContaining({
      id: "M5-00",
      evidence: expect.stringContaining("vite.config.ts"),
    }));
    const scope = JSON.parse(readFileSync(scopePath, "utf8")) as {
      observation: { knip: { discovered: string[]; completed: string[]; incomplete: string[] } };
    };
    expect(scope.observation.knip).toMatchObject({
      discovered: ["(repo root)"],
      completed: [],
      reduced: [],
      incomplete: ["(repo root)"],
      populations: [{ scope: "(repo root)", productSources: 3, status: "incomplete", reason: expect.stringContaining("vite.config.ts") }],
    });
  }, 30000);

  it("does not scan workspace members removed by a negated package-manager glob", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-negated-workspace-"));
    dirs.push(repo);
    const scopePath = join(repo, "quality-scope.json");
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "root", private: true }));
    write("pnpm-workspace.yaml", "packages:\n  - packages/*\n  - '!packages/{scratch,temp}'\n");
    for (const name of ["app", "scratch", "temp"]) {
      write(`packages/${name}/package.json`, JSON.stringify({ name, private: true }));
      write(`packages/${name}/knip.json`, JSON.stringify({ entry: ["src/live.ts"], project: ["src/**/*.ts"] }));
      write(`packages/${name}/src/live.ts`, "export const live = true;\n");
      write(`packages/${name}/src/dead.ts`, "export const dead = true;\n");
    }

    const findings = await runCli(repo, ["--scope-out", scopePath]);
    expect(findings).toContainEqual(expect.objectContaining({ location: "packages/app/src/dead.ts" }));
    expect(findings.some((finding) => /packages\/(?:scratch|temp)\//.test(finding.location))).toBe(false);
    const scope = JSON.parse(readFileSync(scopePath, "utf8")) as {
      observation: { knip: { discovered: string[]; completed: string[]; incomplete: string[] } };
    };
    expect(scope.observation.knip).toMatchObject({
      discovered: ["packages/app", "packages/scratch", "packages/temp"],
      completed: ["packages/app"],
      reduced: [],
      incomplete: ["packages/scratch", "packages/temp"],
      populations: [
        { scope: "packages/app", productSources: 2, status: "completed" },
        { scope: "packages/scratch", productSources: 2, status: "incomplete", reason: expect.stringContaining("negative-workspace-glob") },
        { scope: "packages/temp", productSources: 2, status: "incomplete", reason: expect.stringContaining("negative-workspace-glob") },
      ],
    });
    expect(findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("packages/scratch");
  }, 30000);

  it("excludes an entire generated workspace from every M4 source consumer", async () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-quality-whole-workspace-"));
    dirs.push(root);
    const app = join(root, "apps/web");
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    };
    write("package.json", JSON.stringify({ private: true, workspaces: ["apps/*"] }));
    write("tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "apps" } }));
    write("apps/web/package.json", JSON.stringify({ name: "generated", private: true }));
    write("apps/web/auth-one.ts", CLONED_BLOCK.replace("summarizeOrder", "requireTenantOne"));
    write("apps/web/auth-two.ts", CLONED_BLOCK.replace("summarizeOrder", "requireTenantTwo").replace("itemCount", "rowCount"));
    write("apps/web/plain-one.ts", CLONED_BLOCK.replace("summarizeOrder", "buildOne"));
    write("apps/web/plain-two.ts", CLONED_BLOCK.replace("summarizeOrder", "buildTwo").replace("itemCount", "rowCount"));

    for (const args of [[], ["--whole-repo-diverged"]]) {
      rmSync(join(app, "quality-out.json"), { force: true });
      const scopePath = join(root, "generated-scope.json");
      const findings = await runCli(app, [...args, "--scope-out", scopePath]);
      expect(findings.some((finding) => finding.id.startsWith("M4-DIV"))).toBe(false);
      expect(findings.find((finding) => finding.id === "M4-99")?.evidence).toContain("no eligible");
      expect(readCorpusScannerScope(scopePath, "quality-scan")).toMatchObject({
        unitsExamined: 0,
        observation: { zeroSourceDisposition: { status: "not-assessed" } },
      });
      expect(findings.some((finding) => finding.id === "M4-97")).toBe(false);
      expect(findings.filter((finding) => finding.taxonomy === "M5 — Slop / dead code")).toEqual([
        expect.objectContaining({ id: "M5-00", evidence: expect.stringContaining("no eligible") }),
      ]);
      expect(findings).toContainEqual(expect.objectContaining({
        id: "M4-SCOPE-00",
        evidence: expect.stringMatching(/`\*\*\/\*`: 5 files.*TypeScript compiler output declared by tsconfig\.json/),
      }));
    }
  }, 30000);

  it("retains outer exclusions through a nested workspace owner", async () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-quality-nested-workspace-"));
    dirs.push(root);
    const workspace = join(root, "apps/web");
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(root, rel)), { recursive: true });
      writeFileSync(join(root, rel), text);
    };
    write("package.json", JSON.stringify({ private: true, workspaces: ["apps/*"] }));
    write("tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "apps/web/packages/leaf" } }));
    write("apps/web/package.json", JSON.stringify({ name: "web", private: true, workspaces: ["packages/*"] }));
    write("apps/web/packages/leaf/package.json", JSON.stringify({ name: "leaf", private: true }));
    write("apps/web/packages/leaf/knip.json", JSON.stringify({ entry: ["index.ts"], project: ["**/*.ts"] }));
    write("apps/web/packages/leaf/unused.ts", "export const generated = true;\n");
    write("apps/web/packages/authored/package.json", JSON.stringify({ name: "authored", private: true }));
    write("apps/web/packages/authored/knip.json", JSON.stringify({ entry: ["index.ts"], project: ["**/*.ts"] }));
    write("apps/web/packages/authored/unused.ts", "export const authored = true;\n");

    const findings = await runCli(workspace);
    expect(findings.some((finding) => finding.location.includes("packages/leaf/unused.ts"))).toBe(false);
    expect(findings).toContainEqual(expect.objectContaining({ taxonomy: "M5 — Slop / dead code", location: "packages/authored/unused.ts" }));
    expect(findings).toContainEqual(expect.objectContaining({ id: "M4-SCOPE-00", evidence: expect.stringContaining("`packages/leaf/**`: 3 files") }));
  }, 30000);

  it("discloses an existing malformed jscpd config instead of replacing it", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-malformed-jscpd-"));
    dirs.push(repo);
    const write = (rel: string, text: string) => {
      mkdirSync(dirname(join(repo, rel)), { recursive: true });
      writeFileSync(join(repo, rel), text);
    };
    write("package.json", JSON.stringify({ name: "malformed-jscpd", private: true }));
    write(".jscpd.json", '{"ignore": [ BROKEN }\n');
    write("src/one.ts", CLONED_BLOCK);
    write("src/two.ts", CLONED_BLOCK);

    const findings = await runCli(repo);
    expect(findings).toContainEqual(expect.objectContaining({
      id: "M4-99",
      evidence: expect.stringMatching(/Invalid \.jscpd\.json/),
    }));
    expect(findings.some((finding) => finding.id === "M4-01")).toBe(false);

    write(".jscpd.json", JSON.stringify({ ignore: "src/one.ts" }));
    const invalidShapeFindings = await runCli(repo);
    expect(invalidShapeFindings).toContainEqual(expect.objectContaining({
      id: "M4-99",
      evidence: expect.stringMatching(/Invalid jscpd ignore configuration/),
    }));
  }, 30000);
});

// #580: MEASURED against a real knip run (2026-07-18) — a Vite target where `vite` is declared in
// no dependency at all (the issue's "vite not in deps" cause) leaves knip unable to activate its
// Vite plugin. It falls back to default index.*-only entry resolution: main.ts and its one real
// import stay "used", but vite.config.ts and every other file in src/utils/ come back unused (5 of
// the 7 scanned .ts files, 71%) even though the real Vite entry graph (index.html -> main.ts ->
// utils/a.ts) only leaves 4 of them (utils/b-e) genuinely dead. Regenerating this fixture and
// re-running `knip --reporter json` directly is how the #580 disclosure logic's numbers were
// grounded, not guessed.
function misresolvedViteFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-vite-cli-"));
  dirs.push(repo);
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  };
  write("package.json", JSON.stringify({ name: "vite-fixture", private: true, version: "0.0.0" }));
  write("vite.config.ts", "export default {};\n");
  write("index.html", '<!doctype html>\n<html>\n  <body>\n    <script type="module" src="/src/main.ts"></script>\n  </body>\n</html>\n');
  write("src/main.ts", 'import { helperA } from "./utils/a";\nconsole.log(helperA());\n');
  write("src/utils/a.ts", "export function helperA() {\n  return \"a\";\n}\n");
  for (const n of ["b", "c", "d", "e"]) {
    write(`src/utils/${n}.ts`, `export function helper${n.toUpperCase()}() {\n  return "${n}";\n}\n`);
  }
  return repo;
}

// #693/AoP#566: Harvey merges knip's `ignoreExportsUsedInFile: { interface, type }` into the scan
// so a component Props/option type used only within its own file (exported by convention) isn't
// over-reported, while a type exported and referenced nowhere still surfaces. Pins the injection
// end-to-end through the CLI; the mechanism itself was verified directly against knip 5.88.1.
function exportedTypesFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-types-cli-"));
  dirs.push(repo);
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  };
  write("package.json", JSON.stringify({ name: "types-fixture", private: true, version: "0.0.0", type: "module" }));
  write("src/index.ts", 'import { Widget } from "./widget.js";\nexport function main() {\n  return Widget({ label: "x" });\n}\n');
  write(
    "src/widget.ts",
    // WidgetProps: exported, used only in-file → must be suppressed by the injected config.
    // OrphanType: exported, referenced nowhere → must still surface (review-tier, not dead-code delete).
    "export interface WidgetProps {\n  label: string;\n}\nexport interface OrphanType {\n  gone: boolean;\n}\nexport function Widget(props: WidgetProps) {\n  return props.label;\n}\n",
  );
  return repo;
}

describe("quality-scan CLI — M5 injects knip ignoreExportsUsedInFile so exported-by-convention types aren't over-reported (#693/AoP#566)", () => {
  it("suppresses a Props type used only in-file but still reports a truly-unreferenced exported type", async () => {
    const findings = await runCli(exportedTypesFixture());
    const typeFinding = findings.find((f) => f.title.includes("Exported-but-unreferenced type"));
    expect(typeFinding).toBeDefined();
    expect(typeFinding?.evidence).toContain("OrphanType");
    expect(typeFinding?.evidence).not.toContain("WidgetProps");
    // and it stays the de-escalated review tier from #693, never confirmed dead code
    expect(typeFinding?.confidence).toBe("Review");
  }, 30000);
});

describe("quality-scan CLI — M5 discloses uncertain knip entry resolution on a mis-resolved Vite target (#580)", () => {
  it("raises M5-99 when vite.config.ts/index.html are present but `vite` isn't resolvable", async () => {
    const findings = await runCli(misresolvedViteFixture());
    const disclosure = findings.find((f) => f.id === "M5-99");
    expect(disclosure).toBeDefined();
    expect(disclosure?.taxonomy).toContain("M5");
    expect(disclosure?.evidence).toContain("isn't resolvable");
  }, 30000);
});

// #696: a config-less scan target gives knip no way to infer non-app entry points (test files above
// all), so it floods the unused-files list with test-only-imported libs. Harvey generates a knip
// config (test/script/load-test globs + framework entries) for a config-less scope, so those files
// resolve — but because the entry graph is INFERRED, the residual unused-FILE findings drop to
// review tier.
const write = (repo: string, rel: string, text: string) => {
  mkdirSync(dirname(join(repo, rel)), { recursive: true });
  writeFileSync(join(repo, rel), text);
};

function configlessNextFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-next-cli-"));
  dirs.push(repo);
  // `next` dep → detectTargetFramework === "next"; ships NO knip config, so Harvey infers entries.
  write(repo, "package.json", JSON.stringify({ name: "next-fixture", private: true, version: "0.0.0", type: "module", dependencies: { next: "14.2.0" } }));
  write(repo, "app/page.tsx", 'import { used } from "../lib/used.js";\nexport default function Page() {\n  return used;\n}\n');
  write(repo, "lib/used.ts", 'export const used = "u";\n');
  // Reachable ONLY through a test file — knip would flag it dead without the generated test-glob
  // entry. Its survival is the proof the test-glob lever works.
  write(repo, "lib/testonly.ts", 'export const testHelper = "t";\n');
  write(repo, "lib/testonly.test.ts", 'import { testHelper } from "./testonly.js";\nconsole.log(testHelper);\n');
  // Genuinely dead: no entry (inferred or otherwise) reaches it — must still surface.
  write(repo, "lib/dead.ts", 'export const dead = "d";\n');
  return repo;
}

describe("quality-scan CLI — M5 generates a knip config for a config-less scope so entries resolve (#696)", () => {
  it("does not flag a test-only-imported lib (test globs make the test an entry), still flags a genuinely-dead lib as review-tier", async () => {
    const findings = await runCli(configlessNextFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // test-only-imported file rescued by the generated test glob
    expect(unusedFile("lib/testonly.ts")).toBeUndefined();
    // page-imported file rescued by the generated app-router entry glob
    expect(unusedFile("lib/used.ts")).toBeUndefined();

    // genuinely-dead file still surfaces — but at review tier, since the entry graph was inferred
    const dead = unusedFile("lib/dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Review");
    expect(dead?.precisionTier).toBe("review");
    expect(dead?.impact).toContain("Harvey-inferred entry points");
  }, 30000);
});

function configlessViteFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-vite696-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({ name: "vite696", private: true, version: "0.0.0", type: "module" }));
  write(repo, "vite.config.ts", "export default {};\n");
  write(repo, "index.html", '<!doctype html>\n<html>\n  <body>\n    <script type="module" src="/src/main.ts"></script>\n  </body>\n</html>\n');
  write(repo, "src/main.ts", 'import { used } from "./used.js";\nconsole.log(used);\n');
  write(repo, "src/used.ts", 'export const used = "u";\n');
  write(repo, "src/dead.ts", 'export const dead = "d";\n');
  return repo;
}

describe("quality-scan CLI — M5 resolves Vite entries (index.html/main/vite.config) from a generated config (#696)", () => {
  it("rescues vite.config.ts and main-reachable files, still flags a dead file at review tier", async () => {
    const findings = await runCli(configlessViteFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // index.html/main entry declared by the generated Vite globs keeps main.ts + its import used;
    // vite.config.ts is declared an entry so it is no longer over-reported.
    expect(unusedFile("vite.config.ts")).toBeUndefined();
    expect(unusedFile("src/main.ts")).toBeUndefined();
    expect(unusedFile("src/used.ts")).toBeUndefined();

    const dead = unusedFile("src/dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Review");
  }, 30000);
});

function ownKnipConfigFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-ownknip-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({
    name: "ownknip",
    private: true,
    version: "0.0.0",
    type: "module",
    packageManager: "pnpm@9.0.0",
    knip: { ignore: "src/package-ignored/**" },
  }));
  // The target's OWN knip config names a NON-standard entry Harvey's inferred globs would never
  // declare. If Harvey overrode entries, custom-entry.ts (and reachable.ts) would show unused.
  write(repo, "knip.json", JSON.stringify({ entry: ["custom-entry.ts"] }));
  write(repo, "custom-entry.ts", 'import { thing } from "./reachable.js";\nconsole.log(thing);\n');
  // LocalProps: exported, used only in-file → proves the #695 ignoreExportsUsedInFile merge STILL
  // happens even though entries are the target's own.
  write(repo, "reachable.ts", "export interface LocalProps {\n  x: number;\n}\nexport const thing: LocalProps = { x: 1 };\n");
  write(repo, "dead.ts", 'export const dead = "d";\n');
  write(repo, "src/package-ignored/dead.ts", 'export const packageIgnored = "ignored";\n');
  write(repo, "src/cache/.pnpm-store/v3/pkg/dead.ts", 'export const dependencyArtifact = "ignored";\n');
  return repo;
}

describe("quality-scan CLI — M5 never overrides a target's own knip entry config (#696), only merges ignoreExportsUsedInFile (#695)", () => {
  it("respects the target's entries (its config governs) and keeps its file findings Confirmed", async () => {
    const findings = await runCli(ownKnipConfigFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // reachable via the TARGET's own custom entry — proves Harvey did not override entries.
    expect(unusedFile("reachable.ts")).toBeUndefined();
    expect(findings.some((finding) => finding.location.includes("package-ignored"))).toBe(false);
    expect(findings.some((finding) => finding.location.includes(".pnpm-store"))).toBe(false);

    // dead file surfaces at Confirmed tier — the target supplied its own entry graph, so its file
    // findings are NOT the review-tier inferred kind.
    const dead = unusedFile("dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Confirmed");
    expect(dead?.precisionTier).toBe("high");

    // the #695 merge still applies: an interface exported and used only in-file is not over-reported.
    const typeFinding = findings.find((f) => f.title.includes("Exported-but-unreferenced type") && f.evidence.includes("LocalProps"));
    expect(typeFinding).toBeUndefined();
  }, 30000);
});

describe("quality-scan CLI — root Knip workspace configuration (#2151)", () => {
  const memberConfig = { entry: ["src/live.ts"], project: ["src/**/*.ts"], ignore: ["src/ignored.ts"] };
  const writeMember = (repo: string, member: string): void => {
    write(repo, `${member}/package.json`, JSON.stringify({ name: member.replaceAll("/", "-"), private: true }));
    for (const name of ["live", "dead", "ignored"]) {
      write(repo, `${member}/src/${name}.ts`, `export const ${name} = true;\n`);
    }
  };

  it("projects one root compiler inventory across real member Knip children", async () => {
    const fixture = mkdtempSync(join(tmpdir(), "harvey-quality-knip-inventory-cost-"));
    dirs.push(fixture);
    const repo = join(fixture, "target");
    const members = ["packages/one", "packages/three", "packages/two"];
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["packages/*"] }));
    write(repo, "tsconfig.json", JSON.stringify({
      compilerOptions: { outDir: "packages/one/root-generated", skipLibCheck: true }, include: ["root/**/*.ts"],
    }));
    write(repo, "root/sentinel.ts", CLONED_BLOCK);
    write(repo, "packages/one/root-generated/artifact.ts", CLONED_BLOCK);
    for (const member of members) {
      write(repo, `${member}/package.json`, JSON.stringify({ name: member.replaceAll("/", "-"), private: true }));
      write(repo, `${member}/tsconfig.json`, JSON.stringify({ compilerOptions: { skipLibCheck: true }, include: ["src/**/*.ts"] }));
      write(repo, `${member}/src/index.ts`, "export const entry = true;\n");
      write(repo, `${member}/src/dead.ts`, CLONED_BLOCK);
    }
    write(repo, "packages/one/knip.json", JSON.stringify({ entry: ["src/index.ts"], project: ["**/*.ts"] }));
    const tracePath = join(fixture, "children.jsonl");
    const preloadPath = join(fixture, "observe.cjs");
    // Observe the shipping parent and real children without replacing their results. Reading the
    // root-only compiler input before every child is the expensive whole-graph rebuild, regardless
    // of machine speed or how long the child's own analysis takes.
    writeFileSync(preloadPath, [
      'const fs = require("node:fs");',
      'const cp = require("node:child_process");',
      'const { syncBuiltinESMExports } = require("node:module");',
      `const sentinel = ${JSON.stringify(join(repo, "root/sentinel.ts"))};`,
      `const trace = ${JSON.stringify(tracePath)};`,
      "const read = fs.readFileSync;",
      "const exec = cp.execFileSync;",
      "let rootReads = 0;",
      "fs.readFileSync = function(path, ...args) {",
      "  if (path === sentinel) rootReads++;",
      "  return read.call(this, path, ...args);",
      "};",
      "cp.execFileSync = function(bin, args, options) {",
      '  fs.appendFileSync(trace, JSON.stringify({ bin, args, cwd: options.cwd, rootReads }) + "\\n");',
      "  return exec.call(this, bin, args, options);",
      "};",
      "syncBuiltinESMExports();",
    ].join("\n"));
    const scopePath = join(fixture, "scope.json");
    const outPath = join(fixture, "findings.json");
    await spawnCli(process.execPath, ["--require", preloadPath, "--import", "tsx", CLI, repo, "--scope-out", scopePath, "--out", outPath], REPO_ROOT);
    const calls = readFileSync(tracePath, "utf8").trim().split("\n").map((line) => JSON.parse(line) as {
      bin: string; args: string[]; cwd: string; rootReads: number;
    }).filter((call) => call.bin.endsWith("/knip"));
    expect(calls.map((call) => call.cwd)).toEqual(members.map((member) => join(repo, member)));
    expect(calls.map((call) => call.args)).toEqual(members.map(() => ["-c", ".knip.harvey.json", "--reporter", "json", "--no-exit-code"]));
    expect(calls.map((call) => call.rootReads)).toEqual(members.map(() => 1));
    const findings = JSON.parse(readFileSync(outPath, "utf8")) as Finding[];
    expect(findings.filter((finding) => finding.title.startsWith("Unused file")).map((finding) => finding.location).sort())
      .toEqual(members.map((member) => `${member}/src/dead.ts`));
    expect(findings.some((finding) => finding.location.includes("root-generated/artifact.ts"))).toBe(false);
    expect(findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("root or undeclared product source");
    expect(readCorpusScannerScope(scopePath, "quality-scan").observation).toMatchObject({
      productSources: { count: 7 },
      knip: { completed: members, incomplete: ["(repo root)"], populations: [
        { scope: "(repo root)", productSources: 1, status: "incomplete" },
        { scope: "packages/one", productSources: 2, status: "completed", configuration: "local-config" },
        { scope: "packages/three", productSources: 2, status: "completed", configuration: "harvey-inferred" },
        { scope: "packages/two", productSources: 2, status: "completed", configuration: "harvey-inferred" },
      ] },
    });
  }, 30_000);

  it.each([
    { configName: "knip.json", manifest: "package.json" },
    { configName: "knip.jsonc", manifest: "pnpm-workspace.yaml" },
    { configName: "package.json#knip", manifest: "package.json" },
  ])("preserves global $configName settings on $manifest workspaces without explicit Knip workspace keys", async ({ configName, manifest }) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-implicit-knip-workspaces-"));
    dirs.push(repo);
    const config = { entry: ["src/root-live.ts"], project: ["src/**/*.ts"], ignore: ["apps/web/src/ignored.ts"] };
    write(repo, "package.json", JSON.stringify({ name: "root", private: true,
      ...(manifest === "package.json" ? { workspaces: ["apps/*"] } : {}),
      ...(configName === "package.json#knip" ? { knip: config } : {}),
    }));
    if (manifest === "pnpm-workspace.yaml") write(repo, manifest, "packages:\n  - apps/*\n");
    if (configName !== "package.json#knip") {
      write(repo, configName, `${configName.endsWith("jsonc") ? "// package-manager workspaces supply the graph\n" : ""}${JSON.stringify(config)}\n`);
    }
    writeMember(repo, "apps/web");
    write(repo, "apps/web/src/index.ts", 'import { live } from "./live.js";\nconsole.log(live);\n');
    write(repo, "src/root-live.ts", "export const live = true;\n");
    write(repo, "src/root-dead.ts", "export const dead = true;\n");
    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    expect(direct.files.sort()).toEqual(["apps/web/src/dead.ts", "src/root-dead.ts"]);

    for (const target of ["", "apps/web"]) {
      const receiptPath = join(repo, "scope.json");
      const findings = await runCli(join(repo, target), ["--scope-out", receiptPath]);
      const receipt = readCorpusScannerScope(receiptPath, "quality-scan");
      if (receipt.observation.scanner !== "quality-scan") throw new Error("expected quality-scan receipt");
      const expectedCount = target ? 4 : 6;
      expect(receipt.observation.productSources.count).toBe(expectedCount);
      expect(receipt.observation.knip.populations.reduce((sum, population) => sum + population.productSources, 0)).toBe(expectedCount);
      const prefix = target ? `${target}/` : "";
      const unused = findings.filter((finding) => finding.title.startsWith("Unused file"));
      expect(unused.map((finding) => finding.location).sort())
        .toEqual(direct.files.filter((file) => file.startsWith(prefix)).map((file) => file.slice(prefix.length)).sort());
      expect(unused.every((finding) => finding.confidence === "Confirmed")).toBe(true);
      expect(findings.some((finding) => finding.id === "M5-00" || finding.id === "M5-98")).toBe(false);
      expect(receipt.observation.knip).toMatchObject({
        discovered: target ? ["(repo root)"] : ["(repo root)", "apps/web"],
        completed: target ? ["(repo root)"] : ["(repo root)", "apps/web"], incomplete: [],
        populations: target
          ? [{ scope: "(repo root)", productSources: 4, status: "completed", configuration: "root-workspace-config" }]
          : [
              { scope: "(repo root)", productSources: 2, status: "completed", configuration: "root-workspace-config" },
              { scope: "apps/web", productSources: 4, status: "completed", configuration: "root-workspace-config" },
            ],
      });
    }
  }, 30_000);

  it.each(["directory", "file"])("stops unknown ancestor selection at a separate repository .git %s", async (gitKind) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-knip-repository-boundary-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "outer", private: true }));
    const project = "targets/calibration";
    write(repo, "knip.js", `module.exports = () => {
      require("node:fs").writeFileSync(require("node:path").join(__dirname, "ancestor-executed"), "yes");
      return ${JSON.stringify({ workspaces: { [`${project}/apps/web`]: memberConfig } })};
    };\n`);
    write(repo, `${project}/package.json`, JSON.stringify({ name: "separate", private: true, workspaces: ["apps/web"] }));
    if (gitKind === "directory") write(repo, `${project}/.git/config`, "[core]\n");
    else write(repo, `${project}/.git`, "gitdir: ../separate-worktree-metadata\n");
    writeMember(repo, `${project}/apps/web`);
    write(repo, `${project}/apps/web/knip.json`, JSON.stringify(memberConfig));

    for (const target of [project, `${project}/apps/web`]) {
      const receiptPath = join(repo, "scope.json");
      const findings = await runCli(join(repo, target), ["--scope-out", receiptPath]);
      expect(existsSync(join(repo, "ancestor-executed"))).toBe(false);
      expect(findings.filter((finding) => finding.title.startsWith("Unused file")).map((finding) => finding.location))
        .toEqual([target === project ? "apps/web/src/dead.ts" : "src/dead.ts"]);
      expect(findings.some((finding) => finding.id === "M5-00" || finding.id === "M5-98")).toBe(false);
      expect(readCorpusScannerScope(receiptPath, "quality-scan").observation).toMatchObject({
        productSources: { count: 3 }, knip: { incomplete: [], populations: [
          { scope: target === project ? "apps/web" : "(repo root)", productSources: 3, status: "completed", configuration: "local-config" },
        ] },
      });
    }
  }, 30_000);

  it.each(["package.json", "pnpm-workspace.yaml"])("preserves ancestor negative workspace selection from %s on subtree scans", async (manifest) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-ancestor-negative-knip-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true,
      ...(manifest === "package.json" ? { workspaces: ["apps/*", "!apps/ignored"] } : {}),
    }));
    if (manifest === "pnpm-workspace.yaml") write(repo, manifest, "packages:\n  - apps/*\n  - '!apps/ignored'\n");
    write(repo, "knip.json", JSON.stringify({ workspaces: { "apps/*": memberConfig } }));
    for (const member of ["apps/kept", "apps/ignored"]) writeMember(repo, member);
    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    expect(direct.files).toEqual(["apps/kept/src/dead.ts"]);

    for (const target of ["", "apps/ignored", "apps/ignored/src"]) {
      const receiptPath = join(repo, "scope.json");
      const findings = await runCli(join(repo, target), ["--scope-out", receiptPath]);
      expect(findings.filter((finding) => finding.title.startsWith("Unused file")).map((finding) => finding.location))
        .toEqual(target ? [] : direct.files);
      expect(findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("negative-workspace-glob");
      const receipt = readCorpusScannerScope(receiptPath, "quality-scan");
      if (receipt.observation.scanner !== "quality-scan") throw new Error("expected quality-scan receipt");
      const expectedCount = target ? 3 : 6;
      expect(receipt.observation.productSources.count).toBe(expectedCount);
      expect(receipt.observation.knip.populations.reduce((sum, population) => sum + population.productSources, 0)).toBe(expectedCount);
      expect(receipt.observation.knip.incomplete).toEqual([target ? "(repo root)" : "apps/ignored"]);
      expect(receipt.observation.knip.populations).toContainEqual(expect.objectContaining({
        scope: target ? "(repo root)" : "apps/ignored", productSources: 3, status: "incomplete",
        reason: expect.stringContaining("negative-workspace-glob"),
      }));
    }
  }, 30_000);

  it.each([false, true])("projects Knip-only descendant populations onto a direct parent (ignored: %s)", async (ignored) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-knip-only-descendant-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/web"] }));
    write(repo, "knip.json", JSON.stringify({
      workspaces: { "apps/web": memberConfig, "apps/web/tools/worker": memberConfig },
      ...(ignored ? { ignoreWorkspaces: ["apps/web/tools/worker"] } : {}),
    }));
    for (const member of ["apps/web", "apps/web/tools/worker"]) writeMember(repo, member);
    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    expect(direct.files.sort()).toEqual(ignored ? ["apps/web/src/dead.ts"] : ["apps/web/src/dead.ts", "apps/web/tools/worker/src/dead.ts"]);

    for (const target of ["", "apps/web", "apps/web/tools/worker"]) {
      const receiptPath = join(repo, "scope.json");
      const findings = await runCli(join(repo, target), ["--scope-out", receiptPath]);
      const prefix = target ? `${target}/` : "";
      expect(findings.filter((finding) => finding.title.startsWith("Unused file")).map((finding) => finding.location).sort())
        .toEqual(direct.files.filter((file) => file.startsWith(prefix)).map((file) => file.slice(prefix.length)).sort());
      expect(findings.some((finding) => finding.id === "M5-00")).toBe(ignored);
      const receipt = readCorpusScannerScope(receiptPath, "quality-scan");
      if (receipt.observation.scanner !== "quality-scan") throw new Error("expected quality-scan receipt");
      const workerScope = target === "apps/web/tools/worker" ? "(repo root)" : target ? "tools/worker" : "apps/web/tools/worker";
      const expectedCount = target === "apps/web/tools/worker" ? 3 : 6;
      expect(receipt.observation.productSources.count).toBe(expectedCount);
      expect(receipt.observation.knip.populations.reduce((sum, population) => sum + population.productSources, 0)).toBe(expectedCount);
      expect(receipt.observation.knip.incomplete).toEqual(ignored ? [workerScope] : []);
      expect(receipt.observation.knip.populations).toContainEqual(expect.objectContaining({
        scope: workerScope, productSources: 3, status: ignored ? "incomplete" : "completed", configuration: "root-workspace-config",
        ...(ignored ? { reason: expect.stringContaining("ignoreWorkspaces includes apps/web/tools/worker") } : {}),
      }));
    }
  }, 30_000);

  it.each([
    { packageWorkspaces: false, expression: "function" },
    { packageWorkspaces: true, expression: "function" },
    { packageWorkspaces: false, expression: "literal mutation" },
    { packageWorkspaces: true, expression: "literal mutation" },
  ])("retains one executable ancestor graph with unverified Knip-only membership ($expression, package workspaces: $packageWorkspaces)", async ({ packageWorkspaces, expression }) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-dynamic-knip-only-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true,
      ...(packageWorkspaces ? { workspaces: ["apps/web"] } : {}),
    }));
    const config = { workspaces: { "apps/web": memberConfig, "tools/worker": memberConfig }, ignoreWorkspaces: ["tools/worker"] };
    write(repo, "knip.js", expression === "function" ? `module.exports = () => {
      require("node:fs").appendFileSync(require("node:path").join(__dirname, "executions.txt"), "executed\\n");
      return ${JSON.stringify(config)};
    };\n` : `module.exports = {};
      require("node:fs").appendFileSync(require("node:path").join(__dirname, "executions.txt"), "executed\\n");
      Object.assign(module.exports, ${JSON.stringify(config)});\n`);
    for (const member of ["apps/web", "tools/worker"]) writeMember(repo, member);
    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    expect(direct.files).toEqual(["apps/web/src/dead.ts"]);

    for (const target of ["", "apps/web", "tools", "tools/worker"]) {
      const receiptPath = join(repo, "scope.json");
      rmSync(join(repo, "executions.txt"));
      const findings = await runCli(join(repo, target), ["--scope-out", receiptPath]);
      const prefix = target ? `${target}/` : "";
      expect(findings.filter((finding) => finding.title.startsWith("Unused file")).map((finding) => finding.location).sort())
        .toEqual(direct.files.filter((file) => file.startsWith(prefix)).map((file) => file.slice(prefix.length)).sort());
      expect(findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("configuration could not be inspected");
      expect(findings.some((finding) => finding.id === "M5-98")).toBe(false);
      expect(readFileSync(join(repo, "executions.txt"), "utf8")).toBe("executed\n");
      const receipt = readCorpusScannerScope(receiptPath, "quality-scan");
      if (receipt.observation.scanner !== "quality-scan") throw new Error("expected quality-scan receipt");
      const expectedCount = target ? 3 : 7;
      expect(receipt.observation.productSources.count).toBe(expectedCount);
      expect(receipt.observation.knip.populations.reduce((sum, population) => sum + population.productSources, 0)).toBe(expectedCount);
      expect(receipt.observation.knip.completed).toEqual([]);
      expect(receipt.observation.knip.populations.every((population) => population.status === "incomplete"
        && population.reason?.includes("could not be inspected") && population.configuration === "root-workspace-config")).toBe(true);
    }
  }, 30_000);

  it("matches direct root Knip and preserves member settings from both entry points", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-root-knip-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"] }));
    write(repo, "knip.json", JSON.stringify({ workspaces: { "apps/web": {
      entry: ["src/live.ts"], project: ["src/**/*.ts"], ignore: ["src/intentionally-ignored.ts"],
    } } }));
    write(repo, "apps/web/package.json", JSON.stringify({ name: "web", private: true }));
    write(repo, "apps/web/src/live.ts", "export const live = true;\n");
    write(repo, "apps/web/src/dead.ts", "export const dead = true;\n");
    write(repo, "apps/web/src/intentionally-ignored.ts", "export const ignored = true;\n");
    write(repo, "src/root-dead.ts", "export const rootDead = true;\n");

    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    const receiptPath = join(repo, "root-scope.json");
    const findings = await runCli(repo, ["--scope-out", receiptPath]);
    const receipt = readCorpusScannerScope(receiptPath, "quality-scan");
    if (receipt.observation.scanner !== "quality-scan") throw new Error("expected quality-scan receipt");
    expect(receipt.observation.productSources.count).toBe(4);
    expect(receipt.observation.knip.populations.reduce((sum, population) => sum + population.productSources, 0)).toBe(4);
    const unused = findings.filter((finding) => finding.taxonomy === "M5 — Slop / dead code" && finding.title.startsWith("Unused file"));
    expect(unused.map((finding) => finding.location).sort()).toEqual(direct.files.sort());
    expect(unused.map((finding) => finding.location).sort()).toEqual(["apps/web/src/dead.ts", "src/root-dead.ts"]);
    expect(unused.every((finding) => finding.confidence === "Confirmed")).toBe(true);
    expect(findings.some((finding) => finding.id === "M5-00" || finding.id === "M5-98")).toBe(false);
    expect(receipt.observation).toMatchObject({
      productSources: { count: 4 },
      knip: {
        discovered: ["(repo root)", "apps/web"], completed: ["(repo root)", "apps/web"], incomplete: [],
        populations: [
          { scope: "(repo root)", productSources: 1, status: "completed", configuration: "root-workspace-config" },
          { scope: "apps/web", productSources: 3, status: "completed", configuration: "root-workspace-config" },
        ],
      },
    });

    const member = join(repo, "apps/web");
    const memberReceiptPath = join(repo, "member-scope.json");
    const memberFindings = await runCli(member, ["--scope-out", memberReceiptPath]);
    expect(memberFindings.filter((finding) => finding.taxonomy === "M5 — Slop / dead code" && finding.title.startsWith("Unused file"))
      .map((finding) => finding.location)).toEqual(["src/dead.ts"]);
    expect(readCorpusScannerScope(memberReceiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 3 },
      knip: { discovered: ["(repo root)"], completed: ["(repo root)"], populations: [
        { scope: "(repo root)", productSources: 3, status: "completed", configuration: "root-workspace-config" },
      ] },
    });
  }, 30_000);

  it("discloses a member omitted by root Knip ignoreWorkspaces from both entry points", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-ignored-root-knip-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"] }));
    write(repo, "knip.json", JSON.stringify({
      workspaces: { "apps/*": { entry: ["src/live.ts"], project: ["src/**/*.ts"] } },
      ignoreWorkspaces: ["apps/{web,api}"],
    }));
    for (const name of ["web", "other"]) {
      write(repo, `apps/${name}/package.json`, JSON.stringify({ name, private: true }));
      write(repo, `apps/${name}/src/live.ts`, "export const live = true;\n");
      write(repo, `apps/${name}/src/dead.ts`, "export const dead = true;\n");
    }
    write(repo, "src/root-dead.ts", "export const rootDead = true;\n");

    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    const rootReceiptPath = join(repo, "root-scope.json");
    const rootFindings = await runCli(repo, ["--scope-out", rootReceiptPath]);
    expect(rootFindings.filter((finding) => finding.title.startsWith("Unused file"))
      .map((finding) => finding.location).sort()).toEqual(direct.files.sort());
    expect(rootFindings.find((finding) => finding.id === "M5-00")?.evidence).toContain("ignoreWorkspaces includes apps/web");
    expect(readCorpusScannerScope(rootReceiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 5 },
      knip: {
        discovered: ["(repo root)", "apps/other", "apps/web"],
        completed: ["(repo root)", "apps/other"], incomplete: ["apps/web"],
        populations: [
          { scope: "(repo root)", productSources: 1, status: "completed" },
          { scope: "apps/other", productSources: 2, status: "completed" },
          { scope: "apps/web", productSources: 2, status: "incomplete", configuration: "root-workspace-config", reason: expect.stringContaining("ignoreWorkspaces includes apps/web") },
        ],
      },
    });

    const memberReceiptPath = join(repo, "member-scope.json");
    const memberFindings = await runCli(join(repo, "apps/web"), ["--scope-out", memberReceiptPath]);
    expect(memberFindings.some((finding) => finding.title.startsWith("Unused file"))).toBe(false);
    expect(memberFindings.find((finding) => finding.id === "M5-00")?.evidence).toContain("ignoreWorkspaces includes apps/web");
    expect(readCorpusScannerScope(memberReceiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 2 }, knip: {
        discovered: ["(repo root)"], completed: [], incomplete: ["(repo root)"],
        populations: [{ scope: "(repo root)", productSources: 2, status: "incomplete", reason: expect.stringContaining("ignoreWorkspaces includes apps/web") }],
      },
    });
  }, 30_000);

  it.each(["function", "literal mutation", "provider wrapper"])("keeps %s root workspace selection unverified in both receipts", async (expression) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-executable-root-knip-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"] }));
    const config = { workspaces: { "apps/web": { entry: ["src/live.ts"], project: ["src/**/*.ts"] } } };
    const mutation = 'require("node:fs").appendFileSync(require("node:path").join(__dirname, "executions.txt"), "executed\\n");';
    write(repo, "knip.js", expression === "function"
      ? `module.exports = () => { ${mutation} return ${JSON.stringify({ ...config, ignoreWorkspaces: ["apps/web"] })}; };\n`
      : expression === "literal mutation"
      ? `module.exports = ${JSON.stringify(config)}; ${mutation} module.exports.ignoreWorkspaces = ['apps/web'];\n`
      : `module.exports = require('./provider.js').defineConfig(${JSON.stringify(config)});\n`);
    if (expression === "provider wrapper") write(repo, "provider.js", `exports.defineConfig = (config) => {
      ${mutation}
      return { ...config, ignoreWorkspaces: ['apps/web'] };
    };\n`);
    write(repo, "apps/web/package.json", JSON.stringify({ name: "web", private: true }));
    write(repo, "apps/web/src/live.ts", "export const live = true;\n");
    write(repo, "apps/web/src/dead.ts", "export const dead = true;\n");
    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    expect(direct.files).toEqual([]);
    expect(readFileSync(join(repo, "executions.txt"), "utf8")).toBe("executed\n");
    rmSync(join(repo, "executions.txt"));
    const rootReceiptPath = join(repo, "root-scope.json");
    const rootFindings = await runCli(repo, ["--scope-out", rootReceiptPath]);
    expect(readFileSync(join(repo, "executions.txt"), "utf8")).toBe("executed\n");
    expect(rootFindings.some((finding) => finding.title.startsWith("Unused file"))).toBe(false);
    expect(rootFindings.find((finding) => finding.id === "M5-00")?.evidence).toContain("configuration could not be inspected");
    expect(readCorpusScannerScope(rootReceiptPath, "quality-scan").observation).toMatchObject({
      knip: { incomplete: ["(repo root)", "apps/web"], populations: [
        { scope: "(repo root)", status: "incomplete", reason: expect.stringContaining("could not be inspected") },
        { scope: "apps/web", productSources: 2, status: "incomplete", reason: expect.stringContaining("could not be inspected") },
      ] },
    });
    rmSync(join(repo, "executions.txt"));
    const memberReceiptPath = join(repo, "member-scope.json");
    const memberFindings = await runCli(join(repo, "apps/web"), ["--scope-out", memberReceiptPath]);
    expect(readFileSync(join(repo, "executions.txt"), "utf8")).toBe("executed\n");
    expect(memberFindings.some((finding) => finding.title.startsWith("Unused file"))).toBe(false);
    expect(memberFindings.find((finding) => finding.id === "M5-00")?.evidence).toContain("configuration could not be inspected");
    expect(readCorpusScannerScope(memberReceiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 2 }, knip: { incomplete: ["(repo root)"], populations: [
        { scope: "(repo root)", productSources: 2, status: "incomplete", reason: expect.stringContaining("could not be inspected") },
      ] },
    });
  }, 30_000);

  it("uses one ancestor Knip graph for a direct member and its declared nested member", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-nested-root-knip-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/*", "apps/web/packages/*"] }));
    write(repo, "knip.json", JSON.stringify({ workspaces: {
      "apps/web": { entry: ["src/live.ts"], project: ["src/**/*.ts"] },
      "apps/web/packages/leaf": { entry: ["src/live.ts"], project: ["src/**/*.ts"] },
    } }));
    write(repo, "apps/web/package.json", JSON.stringify({ name: "web", private: true, workspaces: ["packages/*"] }));
    write(repo, "apps/web/src/live.ts", "export const live = true;\n");
    write(repo, "apps/web/src/dead.ts", "export const dead = true;\n");
    write(repo, "apps/web/packages/leaf/package.json", JSON.stringify({ name: "leaf", private: true }));
    write(repo, "apps/web/packages/leaf/src/live.ts", "export const live = true;\n");
    write(repo, "apps/web/packages/leaf/src/dead.ts", "export const dead = true;\n");
    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    const receiptPath = join(repo, "member-scope.json");
    const findings = await runCli(join(repo, "apps/web"), ["--scope-out", receiptPath]);
    expect(findings.filter((finding) => finding.title.startsWith("Unused file"))
      .map((finding) => finding.location).sort())
      .toEqual(direct.files.filter((file) => file.startsWith("apps/web/"))
        .map((file) => file.slice("apps/web/".length)).sort());
    expect(findings.filter((finding) => finding.title.startsWith("Unused file"))
      .map((finding) => finding.location).sort()).toEqual(["packages/leaf/src/dead.ts", "src/dead.ts"]);
    expect(findings.some((finding) => finding.id === "M5-00" || finding.id === "M5-98")).toBe(false);
    expect(readCorpusScannerScope(receiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 4 }, knip: {
        discovered: ["(repo root)", "packages/leaf"], completed: ["(repo root)", "packages/leaf"], incomplete: [],
        populations: [
          { scope: "(repo root)", productSources: 2, status: "completed", configuration: "root-workspace-config" },
          { scope: "packages/leaf", productSources: 2, status: "completed", configuration: "root-workspace-config" },
        ],
      },
    });
  }, 30_000);

  it("counts Knip-only configured workspaces and honors them on direct member scans", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-knip-only-workspace-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/web"] }));
    const memberConfig = { entry: ["src/live.ts"], project: ["src/**/*.ts"], ignore: ["src/ignored.ts"] };
    write(repo, "knip.json", JSON.stringify({ workspaces: { "apps/web": memberConfig, "tools/worker": memberConfig } }));
    for (const scope of ["apps/web", "tools/worker"]) {
      write(repo, `${scope}/package.json`, JSON.stringify({ name: scope.replace("/", "-"), private: true }));
      write(repo, `${scope}/src/live.ts`, "export const live = true;\n");
      write(repo, `${scope}/src/dead.ts`, "export const dead = true;\n");
      write(repo, `${scope}/src/ignored.ts`, "export const ignored = true;\n");
    }

    const direct = JSON.parse(execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
      ["--reporter", "json", "--no-exit-code"], { cwd: repo, encoding: "utf8" })) as { files: string[] };
    const rootReceiptPath = join(repo, "root-scope.json");
    const rootFindings = await runCli(repo, ["--scope-out", rootReceiptPath]);
    expect(rootFindings.filter((finding) => finding.title.startsWith("Unused file"))
      .map((finding) => finding.location).sort()).toEqual(direct.files.sort());
    expect(readCorpusScannerScope(rootReceiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 6 }, knip: {
        discovered: ["(repo root)", "apps/web", "tools/worker"], completed: ["(repo root)", "apps/web", "tools/worker"], incomplete: [],
        populations: [
          { scope: "(repo root)", productSources: 0, status: "completed", configuration: "root-workspace-config" },
          { scope: "apps/web", productSources: 3, status: "completed", configuration: "root-workspace-config" },
          { scope: "tools/worker", productSources: 3, status: "completed", configuration: "root-workspace-config" },
        ],
      },
    });

    const memberReceiptPath = join(repo, "member-scope.json");
    const memberFindings = await runCli(join(repo, "tools/worker"), ["--scope-out", memberReceiptPath]);
    expect(memberFindings.filter((finding) => finding.title.startsWith("Unused file"))
      .map((finding) => finding.location)).toEqual(["src/dead.ts"]);
    expect(readCorpusScannerScope(memberReceiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 3 }, knip: {
        discovered: ["(repo root)"], completed: ["(repo root)"], incomplete: [],
        populations: [{ scope: "(repo root)", productSources: 3, status: "completed", configuration: "root-workspace-config" }],
      },
    });
  }, 30_000);

  it("discloses root sources left outside member-local Knip runs", async () => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-local-knip-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"] }));
    write(repo, "apps/web/package.json", JSON.stringify({ name: "web", private: true }));
    write(repo, "apps/web/knip.json", JSON.stringify({ entry: ["src/live.ts"], project: ["src/**/*.ts"], ignore: ["src/ignored.ts"] }));
    write(repo, "apps/web/src/live.ts", "export const live = true;\n");
    write(repo, "apps/web/src/dead.ts", "export const dead = true;\n");
    write(repo, "apps/web/src/ignored.ts", "export const ignored = true;\n");
    write(repo, "src/root-dead.ts", "export const rootDead = true;\n");

    const receiptPath = join(repo, "scope.json");
    const findings = await runCli(repo, ["--scope-out", receiptPath]);
    expect(findings.filter((finding) => finding.taxonomy === "M5 — Slop / dead code" && finding.title.startsWith("Unused file"))
      .map((finding) => finding.location)).toEqual(["apps/web/src/dead.ts"]);
    expect(findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("root or undeclared product source");
    expect(readCorpusScannerScope(receiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 4 },
      knip: {
        discovered: ["(repo root)", "apps/web"], completed: ["apps/web"], incomplete: ["(repo root)"],
        populations: [
          { scope: "(repo root)", productSources: 1, status: "incomplete", configuration: "none", reason: expect.stringContaining("root or undeclared product source") },
          { scope: "apps/web", productSources: 3, status: "completed", configuration: "local-config" },
        ],
      },
    });
  }, 30_000);
});

// #810: the "NEEDS target npm install" prereq. This fixture ships a vite.config.ts that imports an
// uninstalled plugin (@vitejs/plugin-react) — exactly what a target with no node_modules looks like:
// knip aborts trying to LOAD that plugin config (MEASURED against knip 5.88.1: exit 2, no JSON).
// Before #810 M5 produced only the M5-00 "did not complete" gap (zero findings). Now it re-runs with
// every knip plugin disabled + inferred entries and surfaces the dead file at review tier, disclosing
// the reduced mode as M5-98. A regression that drops the retry produces M5-00 and no dead-code finding.
function noNodeModulesViteFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-noinstall-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({ name: "noinstall", private: true, version: "0.0.0", type: "module", packageManager: "pnpm@9.0.0", devDependencies: { vite: "^5.0.0", "@vitejs/plugin-react": "^4.0.0" } }));
  // Imports an uninstalled plugin → knip can't load this config without the target's node_modules.
  write(repo, "vite.config.cjs", 'require("node:fs").writeFileSync("target-provider-consumed", "yes");\nrequire("@vitejs/plugin-react");\nmodule.exports = {};\n');
  write(repo, "index.html", '<!doctype html>\n<html>\n  <body>\n    <script type="module" src="/src/main.ts"></script>\n  </body>\n</html>\n');
  write(repo, "src/main.ts", 'import { used } from "./used.js";\nconsole.log(used);\n');
  write(repo, "src/used.ts", 'export const used = "u";\n');
  write(repo, "src/dead.ts", 'export const dead = "d";\n');
  write(repo, "src/cache/.pnpm-store/v3/pkg/dead.ts", 'export const dependencyArtifact = "ignored";\n');
  return repo;
}

function noNodeModulesReactRouterFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-react-router-degraded-cli-"));
  dirs.push(repo);
  write(
    repo,
    "package.json",
    JSON.stringify({
      name: "react-router-degraded",
      private: true,
      version: "0.0.0",
      type: "module",
      dependencies: { "@react-router/node": "^7.0.0", "react-router": "^7.0.0" },
      devDependencies: { "@react-router/dev": "^7.0.0", vite: "^6.0.0" },
    }),
  );
  // A rejected partial install must not execute either provider-bearing config. The static
  // app/routes.ts contract entry imports the actual route module, preserving source-evidenced
  // reachability without blessing every helper nested anywhere below app/routes/ as an entry.
  write(
    repo,
    "react-router.config.js",
    'require("node:fs").writeFileSync("target-provider-consumed", "yes");\nrequire("missing-react-router-provider");\nmodule.exports = {};\n',
  );
  write(repo, "app/routes.ts", 'import Dashboard from "./routes/dashboard.js";\nexport default [Dashboard];\n');
  write(repo, "app/routes/dashboard.tsx", 'import { live } from "../components/live.js";\nexport default function Dashboard() { return live; }\n');
  write(repo, "app/routes/api/lib/dead-helper.ts", 'export const deadNestedRouteHelper = "dead";\n');
  write(repo, "app/components/live.ts", 'export const live = "reachable";\nexport const sourceLocalDeadExport = "dead";\n');
  write(repo, "app/components/dead.ts", 'export const genuinelyDead = "dead";\n');
  return repo;
}

function degradedWorkspaceResolverFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-workspace-resolver-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({ name: "resolver-boundary-root", private: true, workspaces: ["apps/*", "packages/*"] }));
  write(
    repo,
    "apps/web/package.json",
    JSON.stringify({
      name: "@fixture/web",
      private: true,
      type: "module",
      dependencies: { "@react-router/node": "^7.0.0", "react-router": "^7.0.0" },
      devDependencies: { "@react-router/dev": "^7.0.0" },
    }),
  );
  write(repo, "packages/contracts/package.json", JSON.stringify({ name: "@fixture/contracts", private: true, main: "index.js", types: "index.d.ts" }));
  write(repo, "packages/contracts/index.js", 'exports.runtimeValue = "live";\n');
  write(repo, "packages/contracts/index.d.ts", 'export interface Contract { value: string }\nexport declare const runtimeValue: string;\n');
  // Model a rejected partial materialization: source imports can resolve, but the scanner must not
  // execute the target's provider-bearing config. The app intentionally omits @fixture/contracts
  // from its own manifest to make Knip emit the three unlisted-import shapes below.
  write(repo, "apps/web/node_modules/@fixture/contracts/package.json", JSON.stringify({ name: "@fixture/contracts", main: "index.js", types: "index.d.ts" }));
  write(repo, "apps/web/node_modules/@fixture/contracts/index.js", 'exports.runtimeValue = "live";\n');
  write(repo, "apps/web/node_modules/@fixture/contracts/index.d.ts", 'export interface Contract { value: string }\nexport declare const runtimeValue: string;\n');
  write(
    repo,
    "apps/web/react-router.config.cjs",
    'require("node:fs").writeFileSync("target-provider-consumed", "yes");\nconst contracts = require("@fixture/contracts");\nmodule.exports = { contracts };\n',
  );
  write(repo, "apps/web/app/runtime.ts", 'import { runtimeValue } from "@fixture/contracts";\nexport const live = runtimeValue;\n');
  write(repo, "apps/web/app/routes/dashboard.ts", 'import { live } from "../runtime.js";\nexport default live;\n');
  write(repo, "apps/web/app/routes/types.ts", 'import type { Contract } from "@fixture/contracts";\nexport default {} satisfies Contract;\n');
  write(repo, "apps/web/app/routes.ts", 'import Dashboard from "./routes/dashboard.js";\nimport Types from "./routes/types.js";\nexport default [Dashboard, Types];\n');
  return repo;
}

describe("quality-scan CLI — M5 runs without the target's node_modules via a plugins-disabled retry (#810)", () => {
  it.each(["forced", "retry"])("isolates %s source-only scans from package Knip plugin and exclusion overrides", async (mode) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-degraded-package-knip-"));
    dirs.push(repo);
    write(repo, "package.json", JSON.stringify({ name: "source-only-root", private: true,
      workspaces: ["apps/*", "!apps/negative"],
      knip: {
        entry: ["absent-entry.ts"], project: ["absent-project/**/*.ts"],
        ignore: ["**"], ignoreFiles: ["**"], ignoreIssues: { "**": ["files"] },
        exclude: ["files"], rules: { files: "off" }, ignoreWorkspaces: ["apps/ignored"], vite: {},
        workspaces: { ".": { vite: {} }, "apps/web": { vite: {} }, "tools/worker": { vite: {} } },
      },
    }));
    write(repo, "vite.config.cjs", 'require("node:fs").appendFileSync("root-provider-consumed", "executed\\n"); throw new Error("root provider deliberately unavailable"); module.exports = {};\n');
    write(repo, "root-dead.ts", "export const rootDead = true;\n");
    for (const member of ["apps/web", "apps/ignored", "apps/negative", "tools/worker"]) {
      write(repo, `${member}/package.json`, JSON.stringify({ name: member.replaceAll("/", "-"), private: true }));
      write(repo, `${member}/src/index.ts`, "export const entry = true;\n");
      write(repo, `${member}/src/dead.ts`, "export const dead = true;\n");
      write(repo, `${member}/vite.config.cjs`, `require("node:fs").appendFileSync(${JSON.stringify(join(repo, "member-provider-consumed"))}, "executed\\n"); module.exports = {};\n`);
    }
    let initialProviderExecutions: string | undefined;
    if (mode === "retry") {
      // Knip's loader can evaluate a throwing module more than once within its first attempt.
      // Establish that actual failed-attempt count, then prove Harvey's retry adds no executions.
      expect(() => execFileSync(join(REPO_ROOT, "node_modules/.bin/knip"),
        ["--reporter", "json", "--no-exit-code"], { cwd: repo, stdio: "pipe" }))
        .toThrow("root provider deliberately unavailable");
      initialProviderExecutions = readFileSync(join(repo, "root-provider-consumed"), "utf8");
      rmSync(join(repo, "root-provider-consumed"));
    }
    const scopePath = join(repo, "scope.json");
    const findings = await runCli(repo, ["--scope-out", scopePath,
      ...(mode === "forced" ? ["--degraded-knip-reason", "Dependency preparation rejected the target tree."] : []),
    ]);
    expect(existsSync(join(repo, "member-provider-consumed"))).toBe(false);
    expect(existsSync(join(repo, "root-provider-consumed"))).toBe(mode === "retry");
    if (mode === "retry") expect(readFileSync(join(repo, "root-provider-consumed"), "utf8")).toBe(initialProviderExecutions);
    const expectedDead = ["apps/ignored/src/dead.ts", "apps/web/src/dead.ts", "root-dead.ts", "tools/worker/src/dead.ts"];
    expect(findings.filter((finding) => finding.title.startsWith("Unused file")).map((finding) => finding.location).sort()).toEqual(expectedDead);
    expect(findings.filter((finding) => expectedDead.includes(finding.location)).every((finding) => finding.confidence === "Review")).toBe(true);
    expect(findings.find((finding) => finding.id === "M5-98")?.evidence)
      .toContain(mode === "forced" ? "Dependency preparation rejected" : "root provider deliberately unavailable");
    expect(findings.find((finding) => finding.id === "M5-00")?.evidence).toContain("negative-workspace-glob");
    expect(readCorpusScannerScope(scopePath, "quality-scan").observation).toMatchObject({
      productSources: { count: 14 },
      knip: { completed: ["(repo root)", "apps/ignored", "apps/web", "tools/worker"], incomplete: ["apps/negative"], populations: [
        { scope: "(repo root)", productSources: 2, status: "reduced", configuration: "harvey-inferred" },
        { scope: "apps/ignored", productSources: 3, status: "reduced", configuration: "harvey-inferred" },
        { scope: "apps/negative", productSources: 3, status: "incomplete", reason: expect.stringContaining("negative-workspace-glob") },
        { scope: "apps/web", productSources: 3, status: "reduced", configuration: "harvey-inferred" },
        { scope: "tools/worker", productSources: 3, status: "reduced", configuration: "harvey-inferred" },
      ] },
    });
  }, 30_000);

  it.each(["growth", "replacement"] as const)("discloses retry source population %s after refreshing framework inventory", async (change) => {
    const repo = mkdtempSync(join(tmpdir(), "harvey-quality-retry-fresh-"));
    const observer = mkdtempSync(join(tmpdir(), "harvey-quality-retry-observer-"));
    dirs.push(repo, observer);
    write(repo, "package.json", JSON.stringify({ name: "retry-fresh", private: true, type: "module" }));
    write(repo, "tsconfig.json", JSON.stringify({ compilerOptions: { outDir: "generated" }, files: ["main.ts"] }));
    write(repo, "main.ts", "export const main = true;\n");
    write(repo, "generated/client.ts", "export const mode = import.meta.env.MODE;\n");
    write(repo, "index.html", '<script type="module" src="/ui/start.ts"></script>\n');
    write(repo, "ui/start.ts", "export const start = true;\n");
    const retryCompilerOptions = change === "growth" ? { noEmit: true } : { outDir: "ui" };
    write(repo, "knip.config.ts", `import { writeFileSync } from "node:fs";
export default () => {
  writeFileSync("tsconfig.json", JSON.stringify({ compilerOptions: ${JSON.stringify(retryCompilerOptions)}, files: ["main.ts"] }));
  throw new Error("fixture changes compiler scope before failing");
};\n`);
    const observedConfig = join(observer, "retry-config.json");
    const preload = join(observer, "observe.cjs");
    writeFileSync(preload, `const cp = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const original = cp.execFileSync;
cp.execFileSync = function (file, args, options) {
  const config = args && args[args.indexOf("-c") + 1];
  if (path.basename(file) === "knip" && config && config.endsWith(".json")) {
    fs.writeFileSync(${JSON.stringify(observedConfig)}, fs.readFileSync(path.resolve(options.cwd, config)));
  }
  return original.apply(this, arguments);
};
require("node:module").syncBuiltinESMExports();\n`);
    const output = join(repo, "quality-out.json");
    const receiptPath = join(repo, "scope.json");
    await spawnCli(process.execPath, ["--require", preload, "--import", "tsx", CLI, repo, "--out", output, "--scope-out", receiptPath], REPO_ROOT);
    const config = JSON.parse(readFileSync(observedConfig, "utf8")) as { entry: string[]; vite: boolean };
    expect(config.entry).toContain("index.html");
    expect(config.vite).toBe(false);
    const findings = JSON.parse(readFileSync(output, "utf8")) as Finding[];
    const initialPaths = ["knip.config.ts", "main.ts", "ui/start.ts"];
    const retryPaths = ["knip.config.ts", "main.ts", "generated/client.ts", ...(change === "growth" ? ["ui/start.ts"] : [])];
    const initialDigest = digestObservedPaths(initialPaths);
    const retryDigest = digestObservedPaths(retryPaths);
    const reason = findings.find((finding) => finding.id === "M5-00")?.evidence;
    expect(reason).toContain(`initial 3 file(s), paths SHA-256 ${initialDigest}`);
    expect(reason).toContain(`retry ${retryPaths.length} file(s), paths SHA-256 ${retryDigest}`);
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-98" }));
    expect(findings).toContainEqual(expect.objectContaining({ location: "generated/client.ts", confidence: "Review", precisionTier: "review" }));
    expect(readCorpusScannerScope(receiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: 3, pathsDigest: initialDigest },
      knip: { completed: [], reduced: [], incomplete: ["(repo root)"], populations: [
        { scope: "(repo root)", productSources: 3, pathsDigest: initialDigest, status: "incomplete", configuration: "harvey-inferred",
          reason: expect.stringContaining(`retry ${retryPaths.length} file(s), paths SHA-256 ${retryDigest}`) },
      ] },
    });
    const stableFindings = await runCli(repo, ["--scope-out", receiptPath]);
    expect(stableFindings.find((finding) => finding.id === "M5-00")).toBeUndefined();
    expect(stableFindings).toContainEqual(expect.objectContaining({ location: "generated/client.ts", confidence: "Review", precisionTier: "review" }));
    expect(readCorpusScannerScope(receiptPath, "quality-scan").observation).toMatchObject({
      productSources: { count: retryPaths.length, pathsDigest: retryDigest },
      knip: { completed: ["(repo root)"], reduced: ["(repo root)"], incomplete: [], populations: [
        { scope: "(repo root)", productSources: retryPaths.length, pathsDigest: retryDigest, status: "reduced", configuration: "harvey-inferred" },
      ] },
    });
  }, 30000);

  it("produces dead-code findings on a no-node_modules target and discloses the reduced tier as M5-98, not the M5-00 gap", async () => {
    const findings = await runCli(noNodeModulesViteFixture());
    const unusedFile = (name: string) => findings.find((f) => f.taxonomy.startsWith("M5 —") && f.title.startsWith("Unused") && f.location.endsWith(name));

    // The dead file is surfaced even though knip could not load the target's config — at review tier
    // (entries were inferred by the degraded retry, same contingency as #696).
    const dead = unusedFile("src/dead.ts");
    expect(dead).toBeDefined();
    expect(dead?.confidence).toBe("Review");
    expect(dead?.precisionTier).toBe("review");

    // main-reachable file is NOT flagged — the inferred Vite/index.html entry globs still resolve it.
    expect(unusedFile("src/used.ts")).toBeUndefined();

    // reduced-mode disclosure present; the "did not complete" gap is NOT (it DID complete via retry).
    const reduced = findings.find((f) => f.id === "M5-98");
    expect(reduced).toBeDefined();
    expect(reduced?.taxonomy).toContain("M5");
    expect(reduced?.fix).toContain("dependencies");
    expect(findings.find((f) => f.id === "M5-00")).toBeUndefined();
    expect(findings.some((finding) => finding.location.includes(".pnpm-store"))).toBe(false);
  }, 30000);

  it("starts directly in the source-only tier when dependency preparation rejected the installed tree", async () => {
    const repo = noNodeModulesViteFixture();
    const findings = await runCli(repo, ["--degraded-knip-reason", "dependency preparation incomplete: clean install failed"], "canary-quality-unrequested-stdin");
    expect(existsSync(join(repo, "target-provider-consumed"))).toBe(false);
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-01", location: expect.stringMatching(/src\/dead\.ts$/), confidence: "Review" }));
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: expect.stringContaining("dependency preparation incomplete") }));
    expect(findings.find((finding) => finding.id === "M5-98")?.evidence).not.toContain("canary-quality-unrequested-stdin");
    expect(findings.find((finding) => finding.id === "M5-00")).toBeUndefined();
    expect(findings.some((finding) => finding.location.includes(".pnpm-store"))).toBe(false);
  }, 30000);

  it("preserves an explicit stdin reason byte-for-byte in M5-98 without executing the target provider (#1778)", async () => {
    const repo = noNodeModulesViteFixture();
    const reason = "  dependency preparation incomplete: canary-quality-\u00e9\ud83d\udea6\"'\\\nsecond line\n";
    const findings = await runCli(repo, ["--degraded-knip-reason-stdin", "--degraded-knip-unresolved-dependency-surface"], reason);
    expect(existsSync(join(repo, "target-provider-consumed"))).toBe(false);
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-98", evidence: `knip could not load the target's own config, so it re-ran with all plugins disabled and Harvey-inferred entry points: (repo root): ${reason}` }));
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-01", location: expect.stringMatching(/src\/dead\.ts$/), confidence: "Review" }));
    expect(findings.find((finding) => finding.id === "M5-00")).toBeUndefined();
  }, 30000);

  it.each([
    { args: ["--degraded-knip-reason-stdin"], input: "", diagnostic: "--degraded-knip-reason-stdin requires a non-empty reason" },
    { args: ["--degraded-knip-reason-stdin"], input: " \t\n", diagnostic: "--degraded-knip-reason-stdin requires a non-empty reason" },
    { args: ["--degraded-knip-reason-stdin", "--degraded-knip-reason", "canary-quality-conflict"], input: null, diagnostic: "choose only one degraded Knip reason source" },
    { args: ["--degraded-knip-unresolved-dependency-surface"], input: "canary-quality-unrequested", diagnostic: "--degraded-knip-unresolved-dependency-surface requires --degraded-knip-reason or --degraded-knip-reason-stdin" },
  ])("rejects invalid reason sources before scanning: $args / $input (#1778)", async ({ args, input, diagnostic }) => {
    const repo = noNodeModulesViteFixture();
    await expect(runCli(repo, args, input)).rejects.toMatchObject({ exitCode: 2, stderr: `${diagnostic}\n` });
    expect(existsSync(join(repo, "quality-out.json"))).toBe(false);
    expect(existsSync(join(repo, "target-provider-consumed"))).toBe(false);
  }, 30000);

  it("checks usage before reading a requested stdin reason (#1778)", async () => {
    await expect(spawnCli("node_modules/.bin/tsx", [CLI, "--degraded-knip-reason-stdin"], REPO_ROOT, null)).rejects.toMatchObject({ exitCode: 2, stderr: expect.stringMatching(/^usage: /) });
  }, 30000);

  it("reconstructs framework-contract route entries without executing rejected React Router config", async () => {
    const repo = noNodeModulesReactRouterFixture();
    const findings = await runCli(repo, ["--degraded-knip-reason", "dependency preparation incomplete: clean install failed"]);
    const unusedFile = (name: string) => findings.find(
      (finding) => finding.taxonomy.startsWith("M5 —") && /^Unused (?:security-relevant )?file:/.test(finding.title) && finding.location.endsWith(name),
    );

    expect(existsSync(join(repo, "target-provider-consumed"))).toBe(false);
    expect(unusedFile("app/routes/dashboard.tsx")).toBeUndefined();
    expect(unusedFile("app/routes/api/lib/dead-helper.ts")).toMatchObject({ severity: "Low", confidence: "Review", precisionTier: "review" });
    expect(unusedFile("app/components/live.ts")).toBeUndefined();
    expect(unusedFile("app/components/dead.ts")).toMatchObject({ severity: "Low", confidence: "Review", precisionTier: "review" });
    expect(findings).toContainEqual(expect.objectContaining({
      title: "Unused exports in app/components/live.ts",
      severity: "Low",
      confidence: "Confirmed",
      evidence: expect.stringContaining("sourceLocalDeadExport"),
    }));
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-98" }));
    expect(findings.some((finding) => finding.id === "M5-00")).toBe(false);
  }, 30000);

  it("separates workspace resolver-contingent config/type imports from reliable runtime imports", async () => {
    const repo = degradedWorkspaceResolverFixture();
    const findings = await runCli(repo, ["--degraded-knip-reason", "dependency preparation incomplete: clean install failed"]);
    const unlisted = (location: string) => findings.find(
      (finding) => finding.title.startsWith("Unlisted import") && finding.location === location,
    );

    expect(existsSync(join(repo, "apps/web/target-provider-consumed"))).toBe(false);
    expect(unlisted("apps/web/react-router.config.cjs")).toMatchObject({ severity: "Info", confidence: "Review", precisionTier: "review" });
    expect(unlisted("apps/web/app/routes/types.ts")).toMatchObject({ severity: "Info", confidence: "Review", precisionTier: "review" });
    expect(unlisted("apps/web/app/runtime.ts")).toMatchObject({ severity: "Medium", confidence: "Confirmed", precisionTier: "high" });
    expect(findings).toContainEqual(expect.objectContaining({ id: "M5-98" }));
    expect(findings.some((finding) => finding.id === "M5-00")).toBe(false);
  }, 30000);
});

// #948 (remainder of #931): jscpd resolves its `.jscpd.json` auto-discovery AND, separately, its
// own CWD's `.gitignore` (a second, less-anchored .gitignore reader in jscpd's own CLI package,
// distinct from the one @jscpd/finder uses for the scanned directory itself) relative to
// `process.cwd()` of the CHILD PROCESS — not the target directory passed on the command line.
// Confirmed by instrumenting jscpd 4.2.5 directly: a multi-segment `.gitignore` entry read from an
// unrelated CWD gets converted into an ANY-DEPTH glob that can accidentally match a directory name
// inside a wholly unrelated scanned tree, silently emptying jscpd's file list — exactly the
// "some absolute paths" cwd-dependence #931 measured on documenso. This engineers a deterministic
// collision (rather than relying on a real repo's real path to coincidentally collide) and proves
// quality-scan's own jscpd invocation is no longer cwd-dependent: pinning `cwd: dir` in runJscpd
// (src/cli/quality-scan.ts) makes the child read the TARGET's own .gitignore/.jscpd.json
// regardless of where quality-scan itself happens to be launched from.
function poisonCwdFixture(): { poisonCwd: string; target: string } {
  const poisonCwd = mkdtempSync(join(tmpdir(), "harvey-quality-poison-cwd-"));
  dirs.push(poisonCwd);
  execFileSync("git", ["init", "-q"], { cwd: poisonCwd });
  // A multi-segment, non-rooted .gitignore entry — jscpd's CWD-based reader (src/init/ignore.ts)
  // has no concept of a scan-relative baseDir, so it converts this into a bare "**/zzz/dup/**"
  // any-depth glob instead of anchoring it to poisonCwd, unlike @jscpd/finder's own (correct)
  // per-scanDir gitignore collector.
  writeFileSync(join(poisonCwd, ".gitignore"), "zzz/dup\n");

  const target = mkdtempSync(join(tmpdir(), "harvey-quality-poison-target-"));
  dirs.push(target);
  execFileSync("git", ["init", "-q"], { cwd: target });
  writeFileSync(join(target, "package.json"), JSON.stringify({ name: "poison-target-fixture", private: true }));
  // Every comparable source file lives under zzz/dup/ — if the poisoned CWD's any-depth glob
  // leaks into this scan, it excludes the target's ENTIRE file list, not just a subset.
  write(target, "zzz/dup/a.ts", CLONED_BLOCK);
  write(target, "zzz/dup/b.ts", CLONED_BLOCK);
  return { poisonCwd, target };
}

async function runCliFromCwd(cwd: string, repo: string): Promise<Finding[]> {
  const outPath = join(repo, "quality-out.json");
  // Absolute tsx path: `cwd` here is the whole point under test (an unrelated directory), so a
  // repo-relative "node_modules/.bin/tsx" (which every other helper in this file can use because
  // THEY pin cwd: REPO_ROOT) would not resolve.
  await spawnCli(join(REPO_ROOT, "node_modules", ".bin", "tsx"), [CLI, repo, "--out", outPath], cwd);
  return JSON.parse(readFileSync(outPath, "utf8")) as Finding[];
}

describe("quality-scan CLI — jscpd is not poisoned by an unrelated CWD's .gitignore/.jscpd.json (#948)", () => {
  it("finds the real cross-file clone even when launched from a CWD whose own .gitignore would (if leaked) exclude the whole target", async () => {
    const { poisonCwd, target } = poisonCwdFixture();
    const findings = await runCliFromCwd(poisonCwd, target);

    const clone = findings.filter((f) => f.taxonomy.startsWith("M4 —") && f.location.includes("zzz/dup/a.ts") && f.location.includes("zzz/dup/b.ts"));
    expect(clone.length).toBeGreaterThan(0);
    // The coverage-gap disclosure (jscpd wrote no report / analysed nothing) must NOT fire —
    // that's the exact symptom this test guards against regressing to.
    expect(findings.find((f) => f.id === "M4-99")).toBeUndefined();
  }, 30000);
});

// #1050: briefs/audit-modules.md names unused DEPENDENCIES as part of M5's dead-code output. knip
// reports them; Harvey's KnipIssue type had no field for them, so they were dropped at the type
// boundary and M5 under-reported with no disclosure — an absence that reads as a clean result.
// MEASURED against knip 5.88.1 (2026-07-25): the JSON reporter puts them on the package.json issue
// entry as `dependencies` / `devDependencies`, each [{ name, line, col, pos }]. This drives the real
// CLI so the field names stay pinned to what knip actually emits, not to what an issue claimed.
function unusedDependencyFixture(): string {
  const repo = mkdtempSync(join(tmpdir(), "harvey-quality-unuseddep-cli-"));
  dirs.push(repo);
  write(repo, "package.json", JSON.stringify({
    name: "unuseddep", private: true, version: "0.0.0", type: "module",
    dependencies: { "left-pad": "^1.3.0" },
    devDependencies: { rimraf: "^5.0.0" },
  }));
  write(repo, "src/index.ts", 'export const go = () => "used";\n');
  return repo;
}

describe("quality-scan CLI — M5 reports unused dependencies (#1050)", () => {
  it("surfaces a declared-but-never-imported runtime dependency and devDependency as M5 findings", async () => {
    const findings = await runCli(unusedDependencyFixture());
    const deps = findings.find((f) => f.title === "Unused dependencies declared in package.json");
    const devDeps = findings.find((f) => f.title === "Unused devDependencies declared in package.json");

    expect(deps?.evidence).toContain("left-pad");
    expect(deps?.taxonomy).toBe("M5 — Slop / dead code");
    // A runtime dependency nobody imports still ships into the installed tree — supply-chain
    // surface, which is why it is not filed as pure tidiness.
    expect(deps?.impact).toContain("supply-chain surface");
    expect(devDeps?.evidence).toContain("rimraf");
  }, 30000);
});
