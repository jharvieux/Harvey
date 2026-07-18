# M7 Lighthouse — Chrome provisioning + error routing (#556)

Follow-up to `docs/design/m7-lighthouse-validation.md` (#488), which left two carried-forward gaps:
a Playwright-only machine can't measure CWV, and a bad `LIGHTHOUSE_CHROME_PATH` crashes the CLI
instead of degrading through the M7L-00 disclosure. Both are closed here.

## Part 1 — provisioning a Lighthouse-compatible Chrome

### The constraint

`package.json`/`pnpm-lock.yaml` are supervised (never a runtime dependency for this). `@puppeteer
/browsers` (the standard tool for fetching a pinned Chrome-for-Testing build) can't be added there.

### The approach: runtime install, not a repo dependency

`src/cli/lighthouse-scan.ts`'s `provisionChrome()` shells out to `npm install --prefix <cache>
--no-save @puppeteer/browsers` **at run time**, only when reached (no system Chrome, or
`LIGHTHOUSE_SKIP_SYSTEM_CHROME=1`) — it never touches this repo's own `node_modules` or lockfile.
The installed CLI then runs `browsers install chrome@stable --path <cache>/browsers`, which
downloads Google's official "Chrome-for-Testing" build (distinct from the Playwright chromium
below) and prints `<id>@<version> <path-to-executable>`; `provisionChrome()` parses that path and
hands it to `chrome-launcher` as `chromePath`.

Cache location: `~/.cache/harvey/chrome-for-testing` (override: `HARVEY_CHROME_CACHE_DIR`, used by
the e2e proof below to avoid touching the real machine cache). Both the CLI install and the browser
download are idempotent — `browsers install` skips re-downloading a revision already present at
`--path` — so a warm cache costs one `existsSync` check plus one fast `browsers install` call
(~1–2s observed) instead of a fresh ~15s provision.

### Why not the Playwright chromium already in the repo?

It's already there (installed for `report-template`'s PDF rendering) and was the pre-#488 default.
It is *also* technically a "Chrome-for-Testing" build, just an older pinned revision — and it
reproduces Lighthouse's `NO_FCP` live (re-confirmed below), so it stays a last-resort fallback only,
never the provisioning target.

### Browser resolution order (final)

1. `LIGHTHOUSE_CHROME_PATH` — explicit override, always wins.
2. System Chrome (`chrome-launcher` auto-detect). Skippable via `LIGHTHOUSE_SKIP_SYSTEM_CHROME=1` —
   the seam used to prove step 3 on a machine that *does* have a system Chrome, without uninstalling
   it.
3. **Provisioned Chrome-for-Testing** (new, #556) — `provisionChrome()` above.
4. Playwright chromium — last resort; a run that still NO_FCPs here degrades to M7L-00 (unchanged
   from #488), never a silent clean.

### Live proof (2026-07-18)

Environment has a system Chrome, so the "no system Chrome" path was forced via
`LIGHTHOUSE_SKIP_SYSTEM_CHROME=1` + a fresh `HARVEY_CHROME_CACHE_DIR` (per the task's instruction to
simulate absence via config, not uninstall anything) — a real, minimal static page (`<h1>Hello
Lighthouse</h1>…`) served on `localhost`, audited via the actual CLI:

```
$ LIGHTHOUSE_SKIP_SYSTEM_CHROME=1 HARVEY_CHROME_CACHE_DIR=<fresh dir> \
    pnpm exec tsx src/cli/lighthouse-scan.ts --url http://localhost:8931 --out findings.json
no system Chrome found; provisioning the @puppeteer/browsers CLI into <cache> (one-time) …
provisioning a Lighthouse-compatible Chrome (chrome-for-testing) into <cache>/browsers …
lighthouse: auditing http://localhost:8931/ …
M7 Lighthouse: 1 page(s) audited -> 0 finding(s)
```

Zero findings here means the page passed every Core Web Vitals threshold — not an error — confirmed
by driving `chrome-launcher` + `lighthouse` directly against the provisioned binary
(`Google Chrome for Testing 151.0.7922.34`) and reading the raw LHR: `runtimeError: undefined`,
`performance score: 0.91`, `FCP: 627ms`, `LCP: 752ms`, `TBT: 0ms`, `CLS: 0`. A second run against the
same page via the Playwright chromium bundled in this repo (`Google Chrome for Testing 149.0.7827.55`
— an older Chrome-for-Testing revision) reproduced `NO_FCP` live, confirming #488's finding still
holds and that the provisioned build is the fix, not the fallback.

A second CLI invocation against the same warm cache completed in ~8s (vs. the ~15s cold provision),
confirming the cache is actually being hit.

### What this does not do

`run-audit` still does not invoke the Lighthouse tier itself (unchanged scope from #488 — see
`docs/design/portability-cold-target.md`, not edited here). Provisioning only fixes *whether a
Lighthouse-compatible Chrome exists*, not the orchestrator wiring.

## Part 2 — routing chrome-launcher's async 'error' event

### Root cause

`chrome-launcher`'s `Launcher.spawnProcess()` spawns Chrome with plain `child_process.spawn()` and
never attaches an `'error'` listener to the resulting `ChildProcess`. When the spawn itself fails
(e.g. `ENOENT` on a bad `chromePath`), Node emits `'error'` on that `ChildProcess` asynchronously —
an unlistened `'error'` event is a special case in Node's `EventEmitter` contract: it gets thrown as
an `uncaughtException`, bypassing every `.catch()` in the promise chain in between, including
`main()`'s `try`/`catch`. Reproduced directly against `chrome-launcher@1.2.1`:

```
$ node -e "import('chrome-launcher').then(({launch}) => launch({chromePath:'/nonexistent/bad'}))"
node:events:487
      throw er; // Unhandled 'error' event
Error: spawn /nonexistent/bad-chrome-binary ENOENT
...
Node.js v24.15.0   # process exits 1, not the M7L-00 disclosure
```

### Fix

`safeLaunch()` wraps every `chrome-launcher.launch()` call with a scoped, single-use
`process.once('uncaughtException', …)` listener: if `launch()` settles normally the listener is
removed and never fires; if Node promotes the child process's `'error'` event to an
`uncaughtException` first, the listener converts it into an ordinary rejected promise instead,
which `launchChrome()`'s existing fallback chain and `main()`'s `try`/`catch` already handle —
producing the same M7L-00 disclosure as every other unmeasurable case (`NO_FCP`, no build script,
port in use, etc.), not an uncaught exit.

### A secondary effect worth recording

`chrome-launcher`'s `waitUntilReady()` polls the DevTools port for up to `maxConnectionRetries ×
connectionPollInterval` (defaults 50 × 500ms = 25s) *inside* the same `launch()` call that failed to
spawn. `safeLaunch()`'s `uncaughtException` route settles quickly (sub-second), but that internal
poll loop is orphaned — it keeps running (and keeps the event loop alive) for up to the full 25s
even after the CLI has already recorded the M7L-00 finding. The CLI now calls `process.exit(0)`
after `main()` completes (matching the existing convention in `mutation-scan.ts` /
`dynamic-validate.ts`) so a bad-chrome-path run exits in ~1–2s instead of lingering ~25–28s on that
orphaned timer. Measured before/after via the child-process test in `lighthouse-scan.test.ts`:
27.8s → 1.8s.

### Test

`src/cli/lighthouse-scan.test.ts` runs the CLI as a real child process (mirroring the `pentest
--mode=coverage` child-process test, #352) with `LIGHTHOUSE_CHROME_PATH` pointed at a nonexistent
binary and `--url` (so no build/serve is needed — `launchChrome()` is reached directly): asserts the
process exits 0 and the emitted findings file contains exactly one `M7L-00` finding whose evidence
names the ENOENT/bad path, not a crash.
