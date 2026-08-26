// #1546 criterion 3: fix-verify's CLI WIRING, driven as a child process.
//
// `writebackGate` is unit-tested four ways in src/cli/fix-verify.test.ts, and that file says so
// explicitly — it tests the free function "rather than spawning src/cli/fix-verify.ts as a child
// process". The consequence its own acceptance verifier found: reverting `isAdditionalRescan`, the
// `--paid` parse and the write-back branch order in src/cli/fix-verify.ts leaves the WHOLE suite
// green. The paid-rescan boundary is a commercial gate, so "the predicate is correct" is not the
// claim that matters — "the CLI applies it" is.
//
// This is the #1407 shape (library proof, unguarded flag parsing) at a fourth site, so it is fixed
// the same way: spawn the real entry point and assert on what a client would see.
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { GateReport } from "../fix/gate.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const dir = mkdtempSync(join(tmpdir(), "harvey-fix-verify-cli-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const target = join(dir, "client-checkout");
const findingsPath = join(dir, "findings.json");
const priorPath = join(dir, "prior.json");
const aliasFindingsPath = join(dir, "alias-findings.json");

// An M5 "Unused parameter" finding whose detector needs no external binary, so this test is
// hermetic. In the target below the parameter IS used, so the detector does not fire and the row
// classifies `resolved` — which, against a prior run that had it `persistent`, is exactly the
// newly-resolved transition planWriteback turns into an actionable ticket close. Without an
// actionable action the gate is a no-op and could not distinguish paid from unpaid.
const FINDING = {
  id: "F-01",
  title: "Unused parameter",
  severity: "Low",
  confidence: "Confirmed",
  category: "Slop / dead code",
  taxonomy: "M5 — Unused parameter",
  location: "app/api/x/route.ts:1",
  status: "Open",
  evidence: "the `request` parameter is never read",
  impact: "dead surface area",
  fix: "drop the parameter",
  precisionTier: "high",
  value: 3,
  ease: 3,
  safety: 3,
};

function runCli(args: string[]): Promise<{ out: string; code: number }> {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn("node", ["--import", "tsx", join(REPO_ROOT, "src/cli/fix-verify.ts"), ...args], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => (stdout += chunk));
    child.stderr.on("data", (chunk: string) => (stderr += chunk));
    child.once("error", rejectRun);
    child.once("close", (code) => resolveRun({ out: `${stdout}${stderr}`, code: code ?? 1 }));
  });
}

beforeAll(() => {
  mkdirSync(join(target, "app/api/x"), { recursive: true });
  writeFileSync(join(target, "app/api/x/route.ts"), "export async function GET(request: Request) {\n  return new Response(request.url);\n}\n");

  const meta = {
    client: "Acme", subtitle: "Fix verification", date: "2026-07-31", commit: "abc1234", auditor: "Harvey",
    confidential: true, overallHealth: 8, tenantIsolation: "n/a", authModel: "n/a", headline: "n/a",
    scope: "n/a", methodology: "n/a", outOfScope: "n/a",
  };
  writeFileSync(findingsPath, JSON.stringify({ meta, findings: [FINDING] }));
  symlinkSync("app/api/x/route.ts", join(target, "route-alias.ts"));
  writeFileSync(aliasFindingsPath, JSON.stringify({ meta, findings: [
    { ...FINDING, id: "F-REL", location: "app/api/x/route.ts:1" },
    { ...FINDING, id: "F-ABS", location: `${join(target, "app/api/x/route.ts")}:1` },
    { ...FINDING, id: "F-LINK", location: "route-alias.ts:1" },
  ] }));

  const prior: GateReport = {
    engagement: "harvey",
    targetDir: target,
    commit: "unknown (target is not a git checkout)",
    generatedAt: "2026-07-30T00:00:00Z",
    results: [
      {
        findingId: FINDING.id,
        identity: `${FINDING.taxonomy}::route.ts`,
        marker: "harvey:F-01",
        title: FINDING.title,
        taxonomy: FINDING.taxonomy,
        location: FINDING.location,
        status: "persistent",
        detail: "still firing",
      },
    ],
    counts: { resolved: 0, persistent: 1, regressed: 0, unverifiable: 0 },
  };
  writeFileSync(priorPath, JSON.stringify(prior));
});

// REVERTED the three wiring lines in src/cli/fix-verify.ts (`const isAdditionalRescan = prior !==
// undefined` → `false`, `const paid = args.includes("--paid")` → `true`, and the `!gate.allowed`
// branch moved below the dry-run branch): this file went RED, exit 1, on the withheld-without-paid
// assertion. Restored: green. src/cli/fix-verify.test.ts's four writebackGate unit tests passed in
// BOTH states — that is the gap this file closes.
describe("fix-verify CLI applies the paid-rescan gate it parses (#1546)", () => {
  it("WITHOUT --paid, an additional rescan still emits the full diagnostic report but withholds write-back", async () => {
    const { out } = await runCli([findingsPath, "--target", target, "--prior", priorPath, "--out", join(dir, "unpaid.json")]);

    // The diagnostic half is NOT the chargeable half and must be delivered in full — withholding it
    // would be a shakedown, which is the posture #824/#1357 both refuse.
    expect(out).toContain("Fix-verification gate");
    expect(out).toContain("resolved 1");
    // The chargeable half is withheld, and DISCLOSED rather than silently skipped.
    expect(out).toContain("ADDITIONAL rescan");
    expect(out).toContain("paid add-on");
    expect(out).not.toContain("[dry-run] ticket write-back plan");
    // The report file is still written — a withheld write-back never costs the client the report.
    const report = JSON.parse(readFileSync(join(dir, "unpaid.json"), "utf8")) as GateReport;
    expect(report.counts.resolved).toBe(1);
  });

  it("WITH --paid, the same run unlocks the write-back plan", async () => {
    const { out } = await runCli([findingsPath, "--target", target, "--prior", priorPath, "--paid", "--out", join(dir, "paid.json")]);
    expect(out).toContain("[dry-run] ticket write-back plan");
    expect(out).toContain("close  ticket of F-01");
    expect(out).not.toContain("ADDITIONAL rescan");
  });

  it("WITHOUT --prior — the one rescan the base engagement includes — write-back is not withheld", async () => {
    const { out } = await runCli([findingsPath, "--target", target, "--out", join(dir, "first.json")]);
    expect(out).toContain("[dry-run] ticket write-back plan");
    expect(out).not.toContain("ADDITIONAL rescan");
  });

  // #1546 criterion 4. The main guard decides whether the CLI does anything at all; if it ever
  // mismatches, `fix-verify` exits 0 having done nothing, which is the quietest possible failure —
  // a client is told their rescan ran. Asserting the process produced OUTPUT is what makes a silent
  // no-op fail. (Verified by replacing the guard's condition with `false`: exit 0, empty stdout,
  // this test red on the length assertion.)
  it("the main guard actually fires — a silent exit-0 no-op is a failure, not a pass", async () => {
    const { out, code } = await runCli([findingsPath, "--target", target, "--out", join(dir, "guard.json")]);
    expect(code).toBe(0);
    expect(out.length).toBeGreaterThan(0);
    expect(out).toContain("Fix-verification gate");
  });

  it("uses the target root to collapse relative, absolute, and symlink finding identities", async () => {
    const reportPath = join(dir, "alias-report.json");
    const { out, code } = await runCli([aliasFindingsPath, "--target", target, "--out", reportPath]);
    const report = JSON.parse(readFileSync(reportPath, "utf8")) as GateReport;

    expect(code).toBe(0);
    expect(out).toContain("3 delivered finding(s) re-verified");
    expect(new Set(report.results.map((result) => result.identity))).toHaveLength(1);
    expect(new Set(report.results.map((result) => result.marker))).toHaveLength(1);
  });
});
