// M7 [L] tier (#387) — runs Lighthouse against a LOCAL build of the target and shapes the Core
// Web Vitals metrics into Finding[] via src/lighthouse.ts's parseLighthouseFindings. Operator
// decision (#387): run locally — Harvey builds and serves the target itself (`npm run build` +
// `npm run start`) and points Lighthouse at that local server, NOT a client staging URL. Pass
// `--url <base>` to skip build/serve and audit an already-running instance instead.
//
//   pnpm lighthouse-scan <target-dir> [--route /path]... [--port 3000] [--out findings.lh.json]
//   pnpm lighthouse-scan --url http://localhost:3000 --route / --route /dashboard --out …
//
// Browser: chrome-launcher (per #387). It PREFERS a system Chrome (chrome-launcher auto-detects
// one) and only falls back to the Playwright chromium the repo installs for report-template when no
// system Chrome exists — because that Playwright build ("Chrome for Testing") fails Lighthouse with
// NO_FCP ("the page did not paint any content"), verified live in #488. LIGHTHOUSE_CHROME_PATH
// overrides both. A run that still measures nothing (NO_FCP on the fallback) is surfaced as the
// fail-loud M7L-00 disclosure, never a silent clean.
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
import { lighthouseRunErrorReason, lighthouseUnavailableFinding, parseLighthouseFindings, type LighthousePageResult, type LighthouseResult } from "../lighthouse.js";

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

async function playwrightChromePath(): Promise<string | undefined> {
  try {
    const { chromium } = await import("playwright");
    return chromium.executablePath() || undefined;
  } catch {
    return undefined;
  }
}

// Launches Chrome for Lighthouse. Prefer a system Chrome (chrome-launcher auto-detects it); only
// fall back to the Playwright chromium the repo installs when no system Chrome exists — that
// "Chrome for Testing" build fails Lighthouse with NO_FCP (#488), so it is a last resort, not the
// default. LIGHTHOUSE_CHROME_PATH overrides both.
async function launchChrome() {
  const chromeFlags = ["--headless=new", "--no-sandbox"];
  const override = process.env.LIGHTHOUSE_CHROME_PATH;
  if (override) return launch({ chromeFlags, chromePath: override });
  try {
    return await launch({ chromeFlags });
  } catch (systemErr) {
    const fallback = await playwrightChromePath();
    if (!fallback) throw systemErr;
    console.error(`no system Chrome found; falling back to Playwright chromium at ${fallback} — it may fail with NO_FCP (#488)`);
    return launch({ chromeFlags, chromePath: fallback });
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
  const lhr = runnerResult.lhr as unknown as LighthouseResult;
  // A run that errored (e.g. NO_FCP) or produced no score measured nothing; parseLighthouseFindings
  // would read its absent metrics as a clean pass. Surface it so the caller records the disclosure.
  const errReason = lighthouseRunErrorReason(lhr);
  if (errReason) throw new Error(`Lighthouse could not measure ${url}: ${errReason}`);
  return { route, result: lhr };
}

async function main(): Promise<void> {
  let cleanup = () => {};
  try {
    const target = await resolveTarget();
    cleanup = target.cleanup;

    const chrome = await launchChrome();
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
