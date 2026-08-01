// Periodic schema-drift check for the CAPTURED external-tool fixtures beyond osv-scanner — the
// #1130 remainder: lighthouse, vitals, trufflehog (unverified + git-history), jscpd, knip, Stryker,
// plus semgrep and gitleaks (#1266 — FIXTURE-INVENTORY.md claimed these two already had a drift
// check; they did not, because #1165 recaptured them 24 minutes before #1170 landed this family and
// neither was registered here). Companion to src/cli/osv-fixture-drift.ts; the pure per-tool
// contracts + their negative controls live in src/scan/fixture-drift-contracts.ts (under
// `pnpm verify`), this runs the binaries.
//
// For the selected --tool it: (1) asserts the installed tool is the pinned version the committed
// fixture was captured from; (2) re-checks the COMMITTED fixture against its own contract (so a
// hand-edit is caught here too); (3) re-runs the pinned tool against a reproducible seed and asserts
// the FRESH output still satisfies the contract the parser depends on (the fields it reads exist with
// the right SHAPE — the #1063 invariant). A byte diff is not usable: tool CONTENT churns run-to-run.
//
// Like osv-fixture-drift / dry-run-drift, this needs the mechanical binaries so it is NOT part of
// `pnpm verify`; the contract logic and its negative controls are. Wired into the conservation.yml
// cadence, which already installs the toolchain.
//
//   pnpm exec tsx src/cli/fixture-drift.ts --tool <jscpd|knip|trufflehog|vitals|stryker|lighthouse>
//   pnpm <tool>-fixture-drift
//
// --fixture <path> overrides the committed fixture path (the negative control points it at a
// perturbed copy to prove the check fails loud).

import "./sync-stdio.js";
import { execFileSync, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import { fileURLToPath } from "node:url";

import { JSCPD_IGNORE_GLOBS, type JscpdReport, type KnipReport } from "../quality-scan.js";
import type { TruffleHogResult } from "../scan/secrets.js";
import type { VitalsReport } from "../hotspot-scan.js";
import type { StrykerReport } from "../mutation-scan.js";
import type { LighthouseResult } from "../lighthouse.js";
import { buildGitHistoryFixture, runTruffleHogGitJson } from "../scan/git-history-secret-gate.js";
import {
  JSCPD_PINNED_VERSION,
  KNIP_PINNED_VERSION,
  TRUFFLEHOG_PINNED_VERSION,
  VITALS_PINNED_VERSION,
  STRYKER_PINNED_VERSION,
  LIGHTHOUSE_PINNED_VERSION,
  SEMGREP_PINNED_VERSION,
  GITLEAKS_PINNED_VERSION,
  checkJscpdContract,
  checkKnipContract,
  checkTruffleHogContract,
  checkStrykerContract,
  checkLighthouseContract,
  checkSemgrepFixtureContract,
  checkGitleaksFixtureContract,
  VITALS_DRIFT_CONTRACT,
  type GitScopeSanity,
  type SemgrepContractOutput,
  classifyFreshRun,
  renderDriftVerdict,
  type GitleaksContractResult,
} from "../scan/fixture-drift-contracts.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function fail(tool: string, message: string): never {
  console.error(`✗ ${tool}-fixture-drift: ${message}`);
  process.exit(1);
}

interface DriftOptions<T> {
  tool: string;
  pinnedVersion: string;
  installedVersion: string;
  fixturePaths: string[]; // relative to repoRoot; overridable via --fixture
  parse: (raw: string) => T;
  contract: (parsed: T) => string[];
  rerun: () => Promise<{ parsed: T; summary: string }>;
  // Checked ONLY against the fresh rerun, before the standard contract check. A returned reason
  // means a KNOWN, detectable non-drift failure mode (#1206) — reported as NOT RUN (exit 0) instead
  // of the generic contract-violation FAIL, so a disclosed flake doesn't get misread as a schema
  // drift or spam the alert-issue tracker for something already tracked.
  notRunIf?: (parsed: T) => string | undefined;
}

async function runDrift<T>(o: DriftOptions<T>): Promise<never> {
  if (o.installedVersion !== o.pinnedVersion) {
    fail(
      o.tool,
      `installed ${o.tool} is ${o.installedVersion}, the committed fixture was captured from ${o.pinnedVersion}. ` +
        `A drift check on a different version cannot vouch for the fixture — re-verify the committed fixture and this parser against ${o.installedVersion} ` +
        `(update its PROVENANCE.md and the pinned version), or pin ${o.pinnedVersion}.`,
    );
  }

  const overridden = arg("--fixture");
  const fixturePaths = overridden ? [overridden] : o.fixturePaths.map((p) => join(repoRoot, p));
  for (const fp of fixturePaths) {
    const committed = o.parse(readFileSync(fp, "utf8"));
    const violations = o.contract(committed);
    if (violations.length > 0) {
      fail(o.tool, `the COMMITTED fixture ${relative(repoRoot, fp)} violates its own schema contract (a hand-edit?):\n  - ${violations.join("\n  - ")}`);
    }
  }

  const { parsed, summary } = await o.rerun();
  // `o` whole, not `o.contract, o.notRunIf` spread out: dropping the classifier from the call is
  // then a change to the OPTIONS OBJECT, which VITALS_DRIFT_CONTRACT's test sees (#1416.4).
  const verdict = classifyFreshRun(o, parsed);
  // The verdict → message/exit mapping is `renderDriftVerdict` (#1727) — a pure function tested in
  // fixture-drift-contracts.test.ts. Only the print/exit below stays unguarded here.
  const outcome = renderDriftVerdict(o.tool, o.installedVersion, verdict, summary);
  (outcome.stream === "log" ? console.log : console.error)(outcome.message);
  process.exit(outcome.exitCode);
}

function requireBinary(tool: string, resolver: () => string): string {
  try {
    return resolver();
  } catch (err) {
    const e = err as { code?: string; message?: string };
    if (e.code === "ENOENT") {
      fail(tool, `${tool} is not available — this drift check requires it (the conservation.yml job installs the toolchain).`);
    }
    fail(tool, e.message ?? `${tool} version check failed`);
  }
}

// --- jscpd (FIXTURE-INVENTORY row 11) ----------------------------------------
// Re-runs the local jscpd against targets/calibration/dup (committed, the same corpus runJscpdLive
// exercises) — not the fixture's own capture corpus, which is not committed; disclosed. Same
// invocation as quality-scan.test.ts's runJscpdLive.
async function jscpdDrift(): Promise<never> {
  const bin = join(repoRoot, "node_modules", ".bin", "jscpd");
  const version = requireBinary("jscpd", () => execFileSync(bin, ["--version"], { encoding: "utf8" }).trim());
  return runDrift<JscpdReport>({
    tool: "jscpd",
    pinnedVersion: JSCPD_PINNED_VERSION,
    installedVersion: version,
    fixturePaths: ["src/scan/__fixtures__/jscpd/jscpd-4.2.5-report.json"],
    parse: (raw) => JSON.parse(raw) as JscpdReport,
    contract: checkJscpdContract,
    rerun: async () => {
      const dupDir = join(repoRoot, "targets", "calibration", "dup");
      const outDir = mkdtempSync(join(tmpdir(), "harvey-jscpd-drift-"));
      try {
        execFileSync(
          bin,
          [dupDir, "--reporters", "json", "--output", outDir, "--threshold", "100", "--absolute", "--silent", "--noTips", "--no-gitignore", "--ignore", JSCPD_IGNORE_GLOBS.join(",")],
          { stdio: ["ignore", "ignore", "pipe"] },
        );
        const report = JSON.parse(readFileSync(join(outDir, "jscpd-report.json"), "utf8")) as JscpdReport;
        for (const dup of report.duplicates) {
          dup.firstFile.name = relative(dupDir, resolve(dup.firstFile.name));
          dup.secondFile.name = relative(dupDir, resolve(dup.secondFile.name));
        }
        return { parsed: report, summary: `jscpd ${version} over targets/calibration/dup — ${report.duplicates.length} duplicate(s)` };
      } finally {
        rmSync(outDir, { recursive: true, force: true });
      }
    },
  });
}

// --- knip (FIXTURE-INVENTORY row 12) -----------------------------------------
// Re-runs the local knip against a throwaway mini-project rebuilt to match the fixture's PROVENANCE:
// one dead file + one file with an unused value export and an unused type export.
function buildKnipSeed(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "harvey-knip-drift-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "knip-drift-seed", version: "0.0.0", type: "module" }, null, 2) + "\n");
  writeFileSync(join(dir, "knip.json"), JSON.stringify({ entry: ["src/index.ts"], project: ["src/**/*.ts"] }, null, 2) + "\n");
  writeFileSync(join(dir, "tsconfig.json"), JSON.stringify({ compilerOptions: { module: "esnext", moduleResolution: "bundler", strict: true, noEmit: true }, include: ["src"] }, null, 2) + "\n");
  mkdirSync(join(dir, "src"));
  writeFileSync(join(dir, "src", "index.ts"), `import { usedHelper } from "./clean.js";\nimport { usedByMixed } from "./mixed.js";\nexport const main = () => usedHelper() + usedByMixed();\n`);
  writeFileSync(join(dir, "src", "clean.ts"), `export const usedHelper = (): number => 1;\n`);
  writeFileSync(join(dir, "src", "mixed.ts"), `export const usedByMixed = (): number => 2;\nexport const neverImported = (): number => 3;\nexport type UnusedType = { a: number };\n`);
  writeFileSync(join(dir, "src", "dead.ts"), `export const orphan = (): number => 4;\n`);
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

async function knipDrift(): Promise<never> {
  const bin = join(repoRoot, "node_modules", ".bin", "knip");
  const version = requireBinary("knip", () => execFileSync(bin, ["--version"], { encoding: "utf8" }).trim());
  return runDrift<KnipReport>({
    tool: "knip",
    pinnedVersion: KNIP_PINNED_VERSION,
    installedVersion: version,
    fixturePaths: ["src/scan/__fixtures__/knip/knip-5.88.1-report.json"],
    parse: (raw) => JSON.parse(raw) as KnipReport,
    contract: checkKnipContract,
    rerun: async () => {
      const { dir, cleanup } = buildKnipSeed();
      try {
        const out = execFileSync(bin, ["--reporter", "json", "--no-exit-code"], { cwd: dir, encoding: "utf8", maxBuffer: 1024 * 1024 * 16 });
        const report = JSON.parse(out) as KnipReport;
        return { parsed: report, summary: `knip ${version} over a rebuilt dead-code seed — ${report.files.length} dead file(s), ${report.issues.length} issue record(s)` };
      } finally {
        cleanup();
      }
    },
  });
}

// --- trufflehog (FIXTURE-INVENTORY rows 8 + 10) ------------------------------
// One re-run covers both captured fixtures: same tool, same command, same-shaped throwaway repo
// (buildGitHistoryFixture) — a fake PAT committed then git-rm'd, recovered by walking history.
async function trufflehogDrift(): Promise<never> {
  const version = requireBinary("trufflehog", () => {
    const r = spawnSync("trufflehog", ["--version"], { encoding: "utf8" });
    if (r.error) throw r.error;
    const m = `${r.stderr}${r.stdout}`.match(/trufflehog\s+(\d+\.\d+\.\d+)/);
    if (!m) throw new Error(`could not parse a version from: ${JSON.stringify((r.stderr || r.stdout).trim())}`);
    return m[1]!;
  });
  return runDrift<TruffleHogResult[]>({
    tool: "trufflehog",
    pinnedVersion: TRUFFLEHOG_PINNED_VERSION,
    installedVersion: version,
    fixturePaths: [
      "src/scan/__fixtures__/trufflehog/trufflehog-3.96.0-git-unverified.json",
      "src/scan/__fixtures__/trufflehog-git-history/trufflehog-3.96.0-git-history.json",
    ],
    parse: (raw) => JSON.parse(raw) as TruffleHogResult[],
    contract: checkTruffleHogContract,
    rerun: async () => {
      const { dir, cleanup } = buildGitHistoryFixture();
      try {
        // #1757 site 2. The old shape accepted a crashed run's partial stdout and diffed it against
        // the committed contract, so an incomplete run reported either a false SCHEMA DRIFT alarm —
        // sending the responder after an upstream release that never happened — or, if the prefix
        // happened to satisfy the contract, a silent pass. An incomplete run is now DID NOT RUN,
        // named as such and distinct from both.
        const run = runTruffleHogGitJson(dir);
        if (run.failure !== undefined) {
          fail("trufflehog", `the fresh run DID NOT RUN to completion (${run.failure}) — this is not schema drift, and its partial output was not diffed against the committed fixture.`);
        }
        const results = run.records as TruffleHogResult[];
        return { parsed: results, summary: `trufflehog ${version} over a git-history secret seed — ${results.length} record(s)` };
      } finally {
        cleanup();
      }
    },
  });
}

// --- vitals (FIXTURE-INVENTORY row 6) ----------------------------------------
// Re-runs the committed re-capture seed (seed.py) which builds the M3 corpus repo + provenance DB and
// runs the pinned vitals against it. seed.py asserts the pinned version internally.
function resolveVitals(): { bin: string; prefixArgs: string[] } | undefined {
  const onPath = spawnSync("vitals_cli.py", ["version"], { encoding: "utf8" });
  if (!onPath.error && /Vitals v/.test(onPath.stdout)) return { bin: "vitals_cli.py", prefixArgs: [] };
  const cacheDir = resolve(homedir(), ".claude/plugins/cache/vitals");
  if (existsSync(cacheDir)) {
    for (const v of readNamesSafe(cacheDir)) {
      const script = resolve(cacheDir, v, "vitals/scripts/vitals_cli.py");
      if (existsSync(script)) return { bin: "python3", prefixArgs: [script] };
    }
  }
  const marketplace = resolve(homedir(), ".claude/plugins/marketplaces/vitals/scripts/vitals_cli.py");
  if (existsSync(marketplace)) return { bin: "python3", prefixArgs: [marketplace] };
  return undefined;
}

async function vitalsDrift(): Promise<never> {
  const resolved = resolveVitals();
  if (!resolved) fail("vitals", "vitals_cli.py is not available on PATH or in ~/.claude/plugins — this drift check requires the vitals plugin (the conservation.yml job installs it).");
  const out = execFileSync(resolved.bin, [...resolved.prefixArgs, "version"], { encoding: "utf8" });
  const version = out.match(/v?(\d+\.\d+\.\d+)/)?.[1] ?? out.trim();
  return runDrift<VitalsReport & { _gitScopeSanity?: GitScopeSanity }>({
    tool: "vitals",
    pinnedVersion: VITALS_PINNED_VERSION,
    installedVersion: version,
    ...VITALS_DRIFT_CONTRACT,
    rerun: async () => {
      const seed = join(repoRoot, "src/__fixtures__/vitals-recapture/seed.py");
      const outFile = join(mkdtempSync(join(tmpdir(), "harvey-vitals-drift-")), "vitals-report.json");
      try {
        try {
          // stderr INHERITED so the seed's diagnostics stream into the job log as they happen;
          // stdout PIPED so nothing it writes there is discarded. seed.py routes everything —
          // including its `sys.exit(msg)` failures — to stderr today, so the pipe is usually empty;
          // it exists because "the harness discarded the evidence" is the half of #1206 that made
          // the other half undiagnosable, and `stdio: ignore` is how that happens silently.
          execFileSync("python3", [seed, "--out", outFile], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
        } catch (err) {
          // What the bare throw added was a Node stack plus `stdout: null, stderr: null` on the
          // error object — which reads as "python3 itself blew up", and #1206 was filed on exactly
          // that misreading. Point at the real output instead, and replay any captured stdout.
          const captured = String((err as { stdout?: string }).stdout ?? "").trim();
          fail(
            "vitals",
            `the re-capture seed ${relative(repoRoot, seed)} exited non-zero — ITS OWN STDERR IS IMMEDIATELY ABOVE THIS LINE and is the evidence to read. (${(err as Error).message})` +
              (captured ? `\n--- seed stdout ---\n${captured}` : "\n(the seed wrote nothing to stdout; everything it says goes to stderr)"),
          );
        }
        const parsed = JSON.parse(readFileSync(outFile, "utf8")) as VitalsReport & { _note?: string; _gitScopeSanity?: GitScopeSanity };
        delete parsed._note;
        return { parsed, summary: `vitals ${version} over the seeded M3 corpus — ${parsed.hotspots.length} hotspot(s), ${parsed.knowledge_risk.length} truck-factor row(s), ${parsed.coupling.length} coupling edge(s)` };
      } finally {
        rmSync(outFile, { force: true });
      }
    },
  });
}

// --- Stryker (FIXTURE-INVENTORY row 13) --------------------------------------
// Re-runs `npx stryker run` against targets/calibration/test-quality/ (committed — the same target
// the fixtures were captured from), installing that target's own isolated dep tree first if needed.
async function strykerDrift(): Promise<never> {
  const targetDir = join(repoRoot, "targets", "calibration", "test-quality");
  if (!existsSync(join(targetDir, "node_modules"))) {
    execFileSync("npm", ["ci"], { cwd: targetDir, stdio: ["ignore", "inherit", "inherit"] });
  }
  const corePkg = join(targetDir, "node_modules", "@stryker-mutator", "core", "package.json");
  const version = existsSync(corePkg) ? (JSON.parse(readFileSync(corePkg, "utf8")) as { version: string }).version : "(not installed)";
  return runDrift<StrykerReport>({
    tool: "stryker",
    pinnedVersion: STRYKER_PINNED_VERSION,
    installedVersion: version,
    fixturePaths: ["src/scan/__fixtures__/stryker/stryker-9.6.1-m8-calibration.json"],
    parse: (raw) => JSON.parse(raw) as StrykerReport,
    contract: checkStrykerContract,
    rerun: async () => {
      execFileSync("npx", ["stryker", "run"], { cwd: targetDir, stdio: ["ignore", "inherit", "inherit"] });
      const report = JSON.parse(readFileSync(join(targetDir, "reports", "mutation", "mutation.json"), "utf8")) as StrykerReport;
      const mutants = Object.values(report.files).reduce((n, f) => n + f.mutants.length, 0);
      return { parsed: report, summary: `stryker ${version} over targets/calibration/test-quality — ${Object.keys(report.files).length} file(s), ${mutants} mutant(s)` };
    },
  });
}

// --- lighthouse (FIXTURE-INVENTORY row 5) ------------------------------------
// Re-runs lighthouse-node against a locally-served static page via chrome-launcher, headless,
// onlyCategories: ["performance"] — the same invocation src/cli/lighthouse-scan.ts uses. The served
// page's actual performance is irrelevant: this checks the LHR SHAPE, not its values.
async function lighthouseDrift(): Promise<never> {
  const pkg = join(repoRoot, "node_modules", "lighthouse", "package.json");
  if (!existsSync(pkg)) fail("lighthouse", "the lighthouse node dependency is not installed — run pnpm install.");
  const version = (JSON.parse(readFileSync(pkg, "utf8")) as { version: string }).version;
  const { launch } = await import("chrome-launcher");
  const runLighthouse = (await import("lighthouse")).default;
  return runDrift<LighthouseResult>({
    tool: "lighthouse",
    pinnedVersion: LIGHTHOUSE_PINNED_VERSION,
    installedVersion: version,
    fixturePaths: ["src/__fixtures__/lighthouse-report.json"],
    parse: (raw) => {
      const parsed = JSON.parse(raw) as LighthouseResult & { _note?: string };
      delete parsed._note;
      return parsed;
    },
    contract: checkLighthouseContract,
    rerun: async () => {
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>drift</title></head><body><h1>Harvey lighthouse drift seed</h1><p>${"content ".repeat(80)}</p></body></html>`;
      const server = createServer((_req, res) => {
        res.setHeader("content-type", "text/html; charset=utf-8");
        res.end(html);
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
      const port = (server.address() as AddressInfo).port;
      const chrome = await launch({ chromeFlags: ["--headless=new", "--no-sandbox", "--disable-gpu"] });
      try {
        const runner = await runLighthouse(`http://127.0.0.1:${port}/`, { port: chrome.port, output: "json", logLevel: "error", onlyCategories: ["performance"] });
        const lhr = runner!.lhr as unknown as LighthouseResult;
        const score = lhr.categories?.performance?.score;
        return { parsed: lhr, summary: `lighthouse ${version} over a served static page — performance score ${typeof score === "number" ? score.toFixed(2) : String(score)}` };
      } finally {
        await chrome.kill();
        server.close();
      }
    },
  });
}

// --- semgrep (FIXTURE-INVENTORY row 7, #1266) --------------------------------
// Re-runs the committed corpus builder — the exact reproducible recipe
// __fixtures__/semgrep/PROVENANCE.md documents — against a fresh throwaway per-rule seed, and
// asserts the FRESH output still satisfies the schema contract the committed fixture and
// parseSemgrepFindings depend on.
async function semgrepDrift(): Promise<never> {
  const version = requireBinary("semgrep", () => execFileSync("semgrep", ["--version"], { encoding: "utf8" }).trim());
  const builder = join(repoRoot, "src/scan/__fixtures__/semgrep/build-corpus.mjs");
  return runDrift<SemgrepContractOutput>({
    tool: "semgrep",
    pinnedVersion: SEMGREP_PINNED_VERSION,
    installedVersion: version,
    fixturePaths: ["src/scan/__fixtures__/semgrep/semgrep-1.164.0-corpus.json"],
    parse: (raw) => JSON.parse(raw) as SemgrepContractOutput,
    contract: checkSemgrepFixtureContract,
    rerun: async () => {
      const out = execFileSync("node", [builder], { encoding: "utf8", maxBuffer: 1024 * 1024 * 128 });
      const parsed = JSON.parse(out) as SemgrepContractOutput;
      return { parsed, summary: `semgrep ${version} over a rebuilt per-rule seed — ${parsed.results?.length ?? 0} result(s)` };
    },
  });
}

// --- gitleaks (FIXTURE-INVENTORY row 9, #1266) -------------------------------
// Re-runs the committed corpus builder (__fixtures__/gitleaks/PROVENANCE.md's recipe) against a
// fresh throwaway planted-secret seed, and asserts the FRESH output still satisfies the schema
// contract — including the #210 demo-key co-location — the committed fixture and
// parseGitleaksFindings depend on.
async function gitleaksDrift(): Promise<never> {
  const version = requireBinary("gitleaks", () => execFileSync("gitleaks", ["version"], { encoding: "utf8" }).trim());
  const builder = join(repoRoot, "src/scan/__fixtures__/gitleaks/build-corpus.mjs");
  return runDrift<GitleaksContractResult[]>({
    tool: "gitleaks",
    pinnedVersion: GITLEAKS_PINNED_VERSION,
    installedVersion: version,
    fixturePaths: ["src/scan/__fixtures__/gitleaks/gitleaks-8.30.1-corpus.json"],
    parse: (raw) => JSON.parse(raw) as GitleaksContractResult[],
    contract: checkGitleaksFixtureContract,
    rerun: async () => {
      const out = execFileSync("node", [builder], { encoding: "utf8", maxBuffer: 1024 * 1024 * 64 });
      const parsed = JSON.parse(out) as GitleaksContractResult[];
      return { parsed, summary: `gitleaks ${version} over a rebuilt planted-secret seed — ${parsed.length} record(s)` };
    },
  });
}

const RUNNERS: Record<string, () => Promise<never>> = {
  jscpd: jscpdDrift,
  knip: knipDrift,
  trufflehog: trufflehogDrift,
  vitals: vitalsDrift,
  stryker: strykerDrift,
  lighthouse: lighthouseDrift,
  semgrep: semgrepDrift,
  gitleaks: gitleaksDrift,
};

const tool = arg("--tool");
if (!tool || !(tool in RUNNERS)) {
  console.error(`usage: pnpm exec tsx src/cli/fixture-drift.ts --tool <${Object.keys(RUNNERS).join("|")}> [--fixture <path>]`);
  process.exit(2);
}

await RUNNERS[tool]!();
