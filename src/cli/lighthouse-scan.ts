// M7 [L] tier (#387) — runs Lighthouse against a LOCAL build of the target and shapes the Core
// Web Vitals metrics into Finding[] via src/lighthouse.ts's parseLighthouseFindings. Operator
// decision (#387): run locally — Harvey builds and serves the target itself (`npm run build` +
// `npm run start`) and points Lighthouse at that local server, NOT a client staging URL. Pass
// `--url <base>` to skip build/serve and audit an already-running instance instead.
//
//   pnpm lighthouse-scan <target-dir> [--route /path]... [--port 3000] [--out findings.lh.json]
//   pnpm lighthouse-scan --url http://localhost:3000 --route / --route /dashboard --out …
//
// Browser: chrome-launcher (per #387). It auto-detects a system Chrome; to reuse the Playwright
// chromium the repo already installs for report-template, set LIGHTHOUSE_CHROME_PATH — this CLI
// fills it from `chromium.executablePath()` when the env var is unset and Playwright's browser is
// present, so no separate Chrome install is required.
//
// Fail-loud (CLAUDE.md coverage doctrine): if the target can't be built, served, or driven, the
// CWV tier is UNMEASURED — this writes lighthouseUnavailableFinding(reason) with the reason and
// exits 0, the same "record the gap, don't silently skip" contract as M5-00/M8-00. It never
// pretends a run happened. Untested thin I/O wrapper per the repo convention; the parse/threshold/
// degrade logic it calls is unit-tested in src/lighthouse.test.ts.

import { spawn, spawnSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { launch } from "chrome-launcher";
import runLighthouse from "lighthouse";
import type { Finding } from "../findings.js";
import { lighthouseUnavailableFinding, parseLighthouseFindings, type LighthousePageResult, type LighthouseResult } from "../lighthouse.js";

// Value-flags consume the next token; --route repeats. Anything left over is the target dir.
const VALUE_FLAGS = new Set(["--url", "--out", "--port", "--route"]);
const rawArgs = process.argv.slice(2);
const flags: Record<string, string> = {};
const routes: string[] = [];
const positionals: string[] = [];
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i]!;
  if (VALUE_FLAGS.has(a)) {
    const val = rawArgs[++i];
    if (val === undefined) break;
    if (a === "--route") routes.push(val);
    else flags[a] = val;
  } else if (!a.startsWith("--")) {
    positionals.push(a);
  }
}
const baseUrl = flags["--url"];
const targetArg = positionals[0];
const outPath = flags["--out"];
const port = flags["--port"] ? Number(flags["--port"]) : 3000;
if (routes.length === 0) routes.push("/");

if (!baseUrl && !targetArg) {
  console.error("usage: pnpm lighthouse-scan <target-dir> [--route /path]... [--port 3000] [--out file]  (or --url <base>)");
  process.exit(2);
}

function emit(findings: Finding[]): void {
  const json = `${JSON.stringify(findings, null, 2)}\n`;
  if (outPath) {
    writeFileSync(outPath, json);
    console.error(`wrote ${findings.length} findings to ${outPath}`);
  } else {
    console.log(json);
  }
}

// Points chrome-launcher at a browser. Prefer an explicit override; otherwise reuse the Playwright
// chromium the repo already installs (report-template/render.mjs) so no second browser is needed.
async function resolveChromePath(): Promise<string | undefined> {
  if (process.env.LIGHTHOUSE_CHROME_PATH) return process.env.LIGHTHOUSE_CHROME_PATH;
  try {
    const { chromium } = await import("playwright");
    const path = chromium.executablePath();
    return path || undefined;
  } catch {
    return undefined; // let chrome-launcher find a system Chrome
  }
}

async function waitForServer(url: string, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.status < 500) return true;
    } catch {
      // not up yet
    }
    await sleep(500);
  }
  return false;
}

// Resolves a running base URL to audit: either the caller-supplied --url, or a local server this
// CLI builds and starts. Returns a cleanup to tear down anything it spun up. Throws (with a
// human reason) when the target can't be built or served — the caller turns that into the
// fail-loud disclosure finding.
async function resolveTarget(): Promise<{ base: string; cleanup: () => void }> {
  if (baseUrl) return { base: baseUrl.replace(/\/$/, ""), cleanup: () => {} };

  const targetDir = resolve(targetArg!);
  console.error(`building target (npm run build) in ${targetDir} …`);
  const build = spawnSync("npm", ["run", "build"], { cwd: targetDir, stdio: "inherit" });
  if (build.status !== 0) throw new Error(`\`npm run build\` in ${targetDir} exited ${build.status ?? "with a signal"} — no servable build to audit`);

  console.error(`starting target (npm run start -- -p ${port}) …`);
  const server = spawn("npm", ["run", "start", "--", "-p", String(port)], { cwd: targetDir, stdio: "inherit" });
  const base = `http://localhost:${port}`;
  const cleanup = () => {
    if (!server.killed) server.kill("SIGTERM");
  };
  server.on("error", (e) => console.error(`server process error: ${e.message}`));

  if (!(await waitForServer(base, 60_000))) {
    cleanup();
    throw new Error(`target server at ${base} did not become ready within 60s (check its \`start\` script and that port ${port} is free)`);
  }
  return { base, cleanup };
}

async function auditRoute(base: string, route: string, chromePort: number): Promise<LighthousePageResult> {
  const url = `${base}${route.startsWith("/") ? route : `/${route}`}`;
  const runnerResult = await runLighthouse(url, { port: chromePort, output: "json", logLevel: "error", onlyCategories: ["performance"] });
  if (!runnerResult) throw new Error(`Lighthouse returned no result for ${url}`);
  return { route, result: runnerResult.lhr as unknown as LighthouseResult };
}

async function main(): Promise<void> {
  let cleanup = () => {};
  try {
    const target = await resolveTarget();
    cleanup = target.cleanup;

    const chromePath = await resolveChromePath();
    const chrome = await launch({ chromeFlags: ["--headless=new", "--no-sandbox"], chromePath });
    try {
      const pages: LighthousePageResult[] = [];
      for (const route of routes) {
        console.error(`lighthouse: auditing ${target.base}${route} …`);
        pages.push(await auditRoute(target.base, route, chrome.port));
      }
      const findings = parseLighthouseFindings(pages);
      console.error(`M7 Lighthouse: ${pages.length} page(s) audited -> ${findings.length} finding(s)`);
      emit(findings);
    } finally {
      await chrome.kill();
    }
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    console.error(`Lighthouse tier could not run — recording a coverage disclosure: ${reason}`);
    emit([lighthouseUnavailableFinding(reason)]);
  } finally {
    cleanup();
  }
}

await main();
