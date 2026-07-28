// The interactive fix CLI, driven as a real child process (#1272/#1277). The library-level tests in
// src/fix/interactive.test.ts prove ingestFixDiff and stop at that boundary, and a round-trip that is
// only proven in the library leaves the flag parsing itself unguarded (CLAUDE.md, #1407). So these run
// `src/cli/fix-interactive.ts` end to end over a PLANTED calibration class and assert on exit codes:
//
//   • emit → a spec file, exit 0
//   • ingest a genuine fix → GREEN, exit 0, and the delivered artifact carries the escalation walk
//   • ingest a cosmetic diff → REJECTED, exit 1 (the gate is watched FAILING, not merely passing)
//   • ingest a fix that breaks the client's own test suite → REJECTED, exit 1 (#1272's live defect)
//   • ingest three ordered attempts → the §5 ladder really walks cheap → standard (#922)
//   • ingest two failing attempts → DOWNGRADE, and tiersUsed names only tiers that were attempted
//
// Every child process is spawned ASYNCHRONOUSLY: the file must not hold a vitest worker's event loop,
// which is the #1120/#1133 failure mode that put seven other CLI files in the heavy job.

import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { capturePatch, disposeCorpus, materialize, readCalibration, type MaterializedCorpus } from "../fix/materialize-calibration.js";

const execFileAsync = promisify(execFile);
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = "src/cli/fix-interactive.ts";
const M5_FILE = "app/api/ar-cors-reflected-safe/route.ts";
const TIMEOUT_MS = 60_000;

const dropParam = (src: string) => src.replace("export async function GET(request: Request) {", "export async function GET() {");
const cosmetic = (src: string) => src.replace("export async function GET(request: Request) {", "export async function GET(request: Request) { // touched");

// A corpus that is a real client repo: the planted class plus a package.json whose `test` script is
// genuinely executed. `contract` asserts the unused parameter is still there, so the correct fix
// breaks it — the "satisfies the scanner, breaks the app" case.
function clientCorpus(suite: "ok" | "contract"): MaterializedCorpus {
  const test =
    suite === "ok"
      ? "console.log('client suite ok');\n"
      : `const src = require("node:fs").readFileSync(${JSON.stringify(M5_FILE)}, "utf8");\n` +
        `if (!src.includes("request: Request")) { console.error("client contract broken by the fix"); process.exit(1); }\n`;
  return materialize({
    [M5_FILE]: readCalibration(M5_FILE),
    "package.json": `${JSON.stringify({ name: "client", private: true, scripts: { test: "node client-test.js" } }, null, 2)}\n`,
    "client-test.js": test,
    // No lockfile: detectRunner falls back to npm, which runs a script without an install.
  });
}

function engagement(corpus: MaterializedCorpus): string {
  const dir = join(corpus.dir, ".harvey");
  mkdirSync(dir, { recursive: true });
  const finding = {
    id: "CAL-UNUSED-PARAM", title: "Unused parameter", severity: "Low", confidence: "Confirmed",
    category: "Maintainability", taxonomy: "M5 — Unused parameter", location: `${M5_FILE}:8`,
    status: "Open", evidence: "GET(request: Request) never reads request", impact: "dead surface",
    fix: "drop the unused parameter", value: 3, ease: 5, safety: 5,
  };
  writeFileSync(
    join(dir, "findings.json"),
    JSON.stringify({
      meta: {
        client: "cal", subtitle: "s", date: "2026-07-28", commit: corpus.commit, auditor: "a",
        confidential: false, overallHealth: 7, tenantIsolation: "n/a", authModel: "n/a",
        headline: "n/a", scope: "n/a", methodology: "n/a", outOfScope: "n/a",
      },
      findings: [finding],
    }),
  );
  writeFileSync(
    join(dir, "manifest.json"),
    JSON.stringify({
      client: "cal", baselineCommit: corpus.commit, approvedFindingIds: ["CAL-UNUSED-PARAM"],
      enabledCategories: ["Maintainability"], allowlist: ["app/**"], operator: "t",
    }),
  );
  return dir;
}

function diffFile(corpus: MaterializedCorpus, name: string, fixed: string): string {
  const path = join(corpus.dir, ".harvey", name);
  writeFileSync(path, capturePatch(corpus, M5_FILE, fixed));
  return path;
}

async function cli(args: string[]): Promise<{ code: number; out: string }> {
  try {
    const { stdout, stderr } = await execFileAsync("node_modules/.bin/tsx", [CLI, ...args], { cwd: REPO_ROOT, encoding: "utf8" });
    return { code: 0, out: `${stdout}${stderr}` };
  } catch (e) {
    const err = e as { code: number; stdout: string; stderr: string };
    return { code: err.code, out: `${err.stdout}${err.stderr}` };
  }
}

const ingestArgs = (c: MaterializedCorpus, cfg: string, diffs: string[]) => [
  join(cfg, "findings.json"), join(cfg, "manifest.json"),
  "--target", c.dir, "--finding", "CAL-UNUSED-PARAM",
  ...diffs.flatMap((d) => ["--apply-diff", d]),
  "--out", join(cfg, "out"),
];

describe("fix-interactive CLI — the planted M5 class through the real emit → diff → ingest loop", () => {
  it("emit writes the spec and exits 0; a genuine fix then reaches GREEN and exits 0", async () => {
    const c = clientCorpus("ok");
    try {
      const cfg = engagement(c);
      const emitted = await cli([
        join(cfg, "findings.json"), join(cfg, "manifest.json"),
        "--target", c.dir, "--finding", "CAL-UNUSED-PARAM", "--interactive", "--out", join(cfg, "out"),
      ]);
      expect(emitted.code).toBe(0);
      expect(emitted.out).toContain("CAL-UNUSED-PARAM.fix-prompt.md");

      const good = diffFile(c, "good.diff", dropParam(readCalibration(M5_FILE)));
      const green = await cli(ingestArgs(c, cfg, [good]));
      expect(green.code).toBe(0);
      expect(green.out).toContain("✓ GREEN");
      expect(green.out).toContain("client check: pass  npm run test"); // the §2.1 half really ran
      expect(green.out).toContain("tiers used: cheap");
    } finally {
      disposeCorpus(c);
    }
  }, TIMEOUT_MS);

  it("a cosmetic diff is REJECTED with exit 1 — the gate is watched failing, not only passing", async () => {
    const c = clientCorpus("ok");
    try {
      const cfg = engagement(c);
      const bad = diffFile(c, "noop.diff", cosmetic(readCalibration(M5_FILE)));
      const red = await cli(ingestArgs(c, cfg, [bad]));
      expect(red.code).toBe(1);
      expect(red.out).toContain("✗ REJECTED");
      expect(red.out).toContain("still fires");
      expect(red.out).not.toContain("GREEN");
    } finally {
      disposeCorpus(c);
    }
  }, TIMEOUT_MS);

  it("a fix that silences the detector but BREAKS the client's suite is REJECTED with exit 1 (#1272)", async () => {
    const c = clientCorpus("contract");
    try {
      const cfg = engagement(c);
      const good = diffFile(c, "good.diff", dropParam(readCalibration(M5_FILE)));
      const red = await cli(ingestArgs(c, cfg, [good]));
      expect(red.out).toContain("after=clean"); // the detector IS satisfied
      expect(red.out).toContain("client check: FAIL (exit 1)");
      expect(red.code).toBe(1);
      expect(red.out).toContain("the client's own checks FAIL");
    } finally {
      disposeCorpus(c);
    }
  }, TIMEOUT_MS);
});

describe("fix-interactive CLI — the §5 escalation ladder actually walks (#922/#1272)", () => {
  it("two failed attempts exhaust the cheap tier and the third runs at standard, and tiersUsed says so", async () => {
    const c = clientCorpus("ok");
    try {
      const cfg = engagement(c);
      const src = readCalibration(M5_FILE);
      const a1 = diffFile(c, "a1.diff", cosmetic(src));
      const a2 = diffFile(c, "a2.diff", src.replace("export async function GET(request: Request) {", "export async function GET(request: Request) { // second try"));
      const a3 = diffFile(c, "a3.diff", dropParam(src));

      const r = await cli(ingestArgs(c, cfg, [a1, a2, a3]));
      expect(r.code).toBe(0);
      expect(r.out).toContain('attempt 1 @ tier "cheap"');
      expect(r.out).toContain('attempt 2 @ tier "cheap"'); // MAX_ATTEMPTS_PER_TIER = 2
      expect(r.out).toContain('attempt 3 @ tier "standard"'); // …then it escalates
      expect(r.out).toContain("✓ GREEN");
      expect(r.out).toContain("tiers used: cheap → standard");
    } finally {
      disposeCorpus(c);
    }
  }, TIMEOUT_MS);

  it("attempts that ran out DOWNGRADE, and tiersUsed names only the tier that was actually attempted", async () => {
    // The ladder would escalate to standard, but no third diff exists. Recording "standard" here
    // would be a tier nobody attempted — the false-record defect this wiring exists to remove.
    const c = clientCorpus("ok");
    try {
      const cfg = engagement(c);
      const src = readCalibration(M5_FILE);
      const a1 = diffFile(c, "a1.diff", cosmetic(src));
      const a2 = diffFile(c, "a2.diff", src.replace("export async function GET(request: Request) {", "export async function GET(request: Request) { // second try"));

      const r = await cli(ingestArgs(c, cfg, [a1, a2]));
      expect(r.code).toBe(1);
      expect(r.out).toContain("DOWNGRADE to recommend-only");
      expect(r.out).toContain("no further attempt was supplied");
      expect(r.out).toContain("Tiers actually attempted: cheap.");
      expect(r.out).not.toContain("standard");
    } finally {
      disposeCorpus(c);
    }
  }, TIMEOUT_MS);
});
