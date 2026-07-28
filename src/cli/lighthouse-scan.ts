// M7 [L] tier (#387) — runs Lighthouse against a LOCAL build of the target and shapes the Core
// Web Vitals metrics into Finding[] via src/lighthouse.ts's parseLighthouseFindings. Operator
// decision (#387): run locally — Harvey builds and serves the target itself (`npm run build` +
// `npm run start`) and points Lighthouse at that local server, NOT a client staging URL. Pass
// `--url <base>` to skip build/serve and audit an already-running instance instead.
//
//   pnpm lighthouse-scan <target-dir> [--route /path]... [--port 3000] [--out findings.lh.json]
//   pnpm lighthouse-scan --url http://localhost:3000 --route / --route /dashboard --out …
//
// Browser resolution (#387, #488, #556, #818), in order:
//   1. LIGHTHOUSE_CHROME_PATH — an explicit override, always wins.
//   2. The Playwright chromium this repo already installs for report-template (#818) — tried
//      FIRST: it needs no system install and no network, so CWV is not gated on either. Skip via
//      LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM=1 (operator/test seam to force steps 3/4). It is a
//      Chrome-for-Testing build, just an older pinned one that reproduced Lighthouse's NO_FCP
//      ("the page did not paint any content") live pre-#818 (#488, re-confirmed #556); the
//      `--disable-gpu --disable-dev-shm-usage` flags below target that failure mode directly
//      (a small /dev/shm is a documented cause of a headless-Chrome renderer crash reading as
//      NO_FCP) but this has NOT been re-proven live since (no network-isolated sandbox with a
//      browser to test against — see docs/design/m7-chrome-provisioning.md for the last live
//      proof, which predates this reordering).
//   3. A system Chrome — chrome-launcher auto-detects one (skip via LIGHTHOUSE_SKIP_SYSTEM_CHROME=1,
//      an operator/test seam to force step 4 on a machine that does have one).
//   4. A PROVISIONED Chrome-for-Testing build (#556) — last resort, since it needs network:
//      `npm install --prefix <cache> @puppeteer/browsers` (runtime, --no-save; never a package.json
//      dependency) then `browsers install chrome@stable`, cached under
//      ~/.cache/harvey/chrome-for-testing so repeat runs skip the download. See
//      docs/design/m7-chrome-provisioning.md.
// A run that still measures nothing (NO_FCP on every reachable candidate) is surfaced as the
// fail-loud M7L-00 disclosure, never a silent clean. A chrome that LAUNCHES but yields NO_FCP (or
// any other Lighthouse runtimeError) on the first route is treated the same as a launch failure —
// killed, and the resolution order falls through to the next candidate (#841) — by verifying each
// auto-resolved candidate against that first route as part of selecting it, not just checking that
// it launched. An explicit LIGHTHOUSE_CHROME_PATH override is exempt: it "always wins" (no
// fallthrough), so a soft failure there still propagates as-is.
//
// chrome-launcher spawns Chrome as a raw child_process; a bad path (e.g. a stale
// LIGHTHOUSE_CHROME_PATH) makes Node emit an unhandled 'error' event on that child process, which
// crashes the whole CLI before main()'s try/catch ever sees it (#556). safeLaunch() wraps every
// launch() call with a scoped `uncaughtException` handler so that failure degrades through the same
// M7L-00 disclosure as every other unmeasurable case, instead of an uncaught exit.
//
// Fail-loud (CLAUDE.md coverage doctrine): if the target can't be built, served, or driven, the
// CWV tier is UNMEASURED — this writes lighthouseUnavailableFinding(reason) with the reason and
// exits 0, the same "record the gap, don't silently skip" contract as M5-00/M8-00. It never
// pretends a run happened. The build/serve/parse path is an untested thin I/O wrapper per the repo
// convention (the parse/threshold/degrade logic it calls is unit-tested in src/lighthouse.test.ts);
// the browser-resolution error routing (#556) IS tested as a child process — see
// lighthouse-scan.test.ts.

import { spawn, spawnSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import { existsSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { Browser, detectBrowserPlatform, install as installBrowser, resolveBuildId } from "@puppeteer/browsers";
import { launch, type LaunchedChrome, type Options as LaunchOptions } from "chrome-launcher";
import runLighthouse from "lighthouse";
import type { Finding } from "../findings.js";
import { lighthouseRunErrorReason, lighthouseScopeDisclosureFinding, lighthouseUnavailableFinding, parseLighthouseFindings, serveCommand, type LighthousePageResult, type LighthouseResult } from "../lighthouse.js";
import { tryChromeCandidates, type ChromeCandidate } from "../lighthouse-chrome-candidates.js";
import { detectTargetFramework } from "../scan/framework-detect.js";

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

// #818 test/operator seam: prints the resolved browser-candidate order (see the header comment)
// and exits WITHOUT ever launching a browser — the fastest, network-free way to prove the
// fallback ordering is wired as intended, mirroring the LIGHTHOUSE_SKIP_* seams below.
if (process.env.LIGHTHOUSE_PRINT_CHROME_ORDER) {
  const order: string[] = process.env.LIGHTHOUSE_CHROME_PATH ? ["override"] : [];
  if (!order.length) {
    if (!process.env.LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM) order.push("bundled-playwright");
    if (!process.env.LIGHTHOUSE_SKIP_SYSTEM_CHROME) order.push("system");
    order.push("provisioned");
  }
  console.log(order.join(","));
  process.exit(0);
}

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

function chromeCacheDir(): string {
  return process.env.HARVEY_CHROME_CACHE_DIR || join(homedir(), ".cache", "harvey", "chrome-for-testing");
}

// Provisions a Lighthouse-compatible Chrome (#556) through `@puppeteer/browsers`, a LOCKFILE-PINNED
// devDependency of this repo (#1324). Until 2026-07-28 it shelled out to `npm install --prefix
// <cache> --no-save @puppeteer/browsers` at RUN TIME, and the recorded reason was that
// `package.json` is a supervised path for this repo. It never was — the operator ruled on
// 2026-07-27 and the file itself, checked as it stood the day #556 was worked, never listed it. The
// cost that false constraint bought was concrete and this step is where it lands hardest: an
// unpinned `latest` resolve, with no lockfile and no recorded integrity hash, fetched and EXECUTED
// during a scan, on a client's machine. A pinned devDependency is pnpm-integrity-checked at our
// install time instead. It also retires the parsing of the CLI's stdout for an executable path.
//
// What this does NOT remove is the network: `install()` still downloads ~150 MB of Chrome-for-
// Testing from Google's CDN the first time. That is the step's whole purpose, and it stays the LAST
// resort in the resolution order for exactly that reason. Cached under chromeCacheDir()/browsers —
// the same directory the CLI wrote to, so a machine that already provisioned keeps its cache — and
// `install()` is idempotent, so this is cheap to call on every run.
//
// Returns undefined (never throws) on any failure — the caller falls back to the next resolution
// step rather than treating a failed provision as fatal.
async function provisionChrome(): Promise<string | undefined> {
  const cacheDir = join(chromeCacheDir(), "browsers");
  try {
    const platform = detectBrowserPlatform();
    if (!platform) {
      console.error(`chrome-for-testing provisioning: @puppeteer/browsers does not recognise this platform`);
      return undefined;
    }
    const buildId = await resolveBuildId(Browser.CHROME, platform, "stable");
    console.error(`provisioning a Lighthouse-compatible Chrome (chrome-for-testing ${buildId}) into ${cacheDir} …`);
    const installed = await installBrowser({ browser: Browser.CHROME, buildId, cacheDir, platform });
    return existsSync(installed.executablePath) ? installed.executablePath : undefined;
  } catch (err) {
    console.error(`chrome-for-testing provisioning failed: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}

// chrome-launcher's launch() spawns Chrome as a raw child_process; when that spawn itself fails
// (e.g. ENOENT on a bad chromePath), Node emits an unhandled 'error' event on the ChildProcess
// EventEmitter, which chrome-launcher never listens for — Node then throws it as an uncaughtException
// that bypasses every promise .catch() in between, including main()'s try/catch (#556, observed live:
// a bad LIGHTHOUSE_CHROME_PATH exits the whole CLI with ENOENT instead of degrading to M7L-00).
// This wraps a launch() attempt with a SCOPED, single-use uncaughtException handler so that failure
// surfaces as an ordinary rejected promise instead — the listener is removed as soon as launch()
// settles either way, so it never swallows an unrelated error from later in the run.
function safeLaunch(opts: LaunchOptions): Promise<LaunchedChrome> {
  return new Promise((resolvePromise, reject) => {
    let settled = false;
    const onUncaught = (err: unknown) => {
      if (settled) return;
      settled = true;
      process.removeListener("uncaughtException", onUncaught);
      reject(err instanceof Error ? err : new Error(String(err)));
    };
    process.once("uncaughtException", onUncaught);
    launch(opts).then(
      (chrome) => {
        if (settled) return;
        settled = true;
        process.removeListener("uncaughtException", onUncaught);
        resolvePromise(chrome);
      },
      (err: unknown) => {
        if (settled) return;
        settled = true;
        process.removeListener("uncaughtException", onUncaught);
        reject(err instanceof Error ? err : new Error(String(err)));
      },
    );
  });
}

// Launches Chrome for Lighthouse and verifies it against `probeRoute` — see the browser-resolution
// order in the header comment and #841 on why verification is part of candidate selection, not a
// separate step. Returns the already-audited first page alongside the chrome so main() doesn't pay
// for a second Lighthouse run against the same route.
async function launchChrome(probeBase: string, probeRoute: string): Promise<{ chrome: LaunchedChrome; firstPage: LighthousePageResult }> {
  // #818: --disable-dev-shm-usage avoids the renderer crashing on the small /dev/shm typical of
  // sandboxed/containerized hosts (a documented root cause of headless Chrome's "page did not
  // paint any content" / NO_FCP, independent of which chromePath below produces the crash);
  // --disable-gpu is the standard headless-on-a-host-with-no-GPU companion flag. Applied to every
  // candidate, not just the bundled one, since any of them can hit the same failure mode.
  const chromeFlags = ["--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"];
  const override = process.env.LIGHTHOUSE_CHROME_PATH;
  if (override) {
    // An explicit override "always wins" (see header comment) — no fallthrough on a soft failure
    // here, only on the earlier ENOENT-style launch failure (#556, still handled by safeLaunch).
    const chrome = await safeLaunch({ chromeFlags, chromePath: override });
    return { chrome, firstPage: await auditRoute(probeBase, probeRoute, chrome.port) };
  }

  // #841: a candidate that launches but can't measure `probeRoute` (NO_FCP or any other Lighthouse
  // runtimeError) is no more usable than one that failed to launch — kill it and re-throw so
  // tryChromeCandidates (src/lighthouse-chrome-candidates.ts) falls through to the next candidate
  // exactly like it already does for a thrown safeLaunch.
  async function attempt(chromePath: string | undefined): Promise<{ chrome: LaunchedChrome; firstPage: LighthousePageResult }> {
    const chrome = await safeLaunch({ chromeFlags, chromePath });
    try {
      return { chrome, firstPage: await auditRoute(probeBase, probeRoute, chrome.port) };
    } catch (err) {
      await chrome.kill();
      throw err;
    }
  }

  const candidates: ChromeCandidate<{ chrome: LaunchedChrome; firstPage: LighthousePageResult }>[] = [];

  // #818: try the Playwright chromium this repo already vendors FIRST — it needs no system
  // install and no network, so CWV is not gated on either. Skippable via
  // LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM=1 (an operator/test seam to force the steps below on a
  // machine that does have this candidate, mirroring LIGHTHOUSE_SKIP_SYSTEM_CHROME).
  if (!process.env.LIGHTHOUSE_SKIP_BUNDLED_CHROMIUM) {
    const bundled = await playwrightChromePath();
    if (bundled) candidates.push({ label: "bundled-playwright", attempt: () => attempt(bundled) });
  }

  if (!process.env.LIGHTHOUSE_SKIP_SYSTEM_CHROME) {
    candidates.push({ label: "system", attempt: () => attempt(undefined) });
  }

  // Network-dependent provisioning is the last resort now — every earlier candidate is either
  // already on disk (bundled) or already installed (system), so this is the only step that can
  // fail purely because the host has no network access. Resolved lazily (inside attempt(), not
  // here) so it's only ever invoked when reached — an earlier candidate succeeding must not pay
  // for a provisioning check.
  candidates.push({
    label: "provisioned",
    attempt: async () => {
      const provisioned = await provisionChrome();
      if (!provisioned) throw new Error("no Chrome could be provisioned");
      return attempt(provisioned);
    },
  });

  return tryChromeCandidates(candidates);
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

  // Vite has no `start` script — its build is served by `vite preview --port` (#577).
  const framework = detectTargetFramework(targetDir);
  const serve = serveCommand(framework, port);
  console.error(`starting target (${serve.label}) [framework: ${framework}] …`);
  const server = spawn("npm", serve.args, { cwd: targetDir, stdio: "inherit" });
  const base = `http://localhost:${port}`;
  const cleanup = () => {
    if (!server.killed) server.kill("SIGTERM");
  };
  server.on("error", (e) => console.error(`server process error: ${e.message}`));

  if (!(await waitForServer(base, 60_000))) {
    cleanup();
    throw new Error(`target server at ${base} did not become ready within 60s (check its \`${framework === "vite" ? "preview" : "start"}\` script and that port ${port} is free)`);
  }
  return { base, cleanup };
}

async function auditRoute(base: string, route: string, chromePort: number): Promise<LighthousePageResult> {
  const url = `${base}${route.startsWith("/") ? route : `/${route}`}`;
  console.error(`lighthouse: auditing ${url} …`);
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

    const { chrome, firstPage } = await launchChrome(target.base, routes[0]!);
    try {
      const pages: LighthousePageResult[] = [firstPage];
      for (const route of routes.slice(1)) {
        pages.push(await auditRoute(target.base, route, chrome.port));
      }
      // #1074: onlyCategories: ["performance"] below means a11y/best-practices/SEO never ran —
      // appended unconditionally whenever this tier actually produced a result, so the gap is
      // disclosed rather than silent.
      const findings = [...parseLighthouseFindings(pages), lighthouseScopeDisclosureFinding()];
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
// Explicit exit (repo convention, e.g. mutation-scan.ts/dynamic-validate.ts): chrome-launcher can
// leave an orphaned connection-poll timer running after a launch failure already settled via
// safeLaunch's uncaughtException route (#556) — without this the process lingers on that timer
// instead of exiting once work is actually done.
process.exit(0);
