// #450 — dynamic validation harness CLI: assess whether a public repo can be stood up locally for
// M2, and (with --execute) stand it up, pen-test it, and emit the M2 pass artifact (#448).
//
//   pnpm dynamic-validate <target-dir | repo-url> [--pin <commit>] [--out <artifacts-dir>] [--execute]
//
// Default is ASSESS-ONLY: clone (if a URL) + report a go/no-go verdict with its coverage and any
// limitations — useful for triaging which public repos are dynamic-validation candidates at all.
// --execute runs the live pipeline (supabase start → migrations → app build → pentest.ts) via a thin
// shell-out runner and, on success, writes <out>/M2.pass.json. The live steps need Docker + the
// Supabase CLI and are operator-run — the same live-stack work tracked in #159/#161; without those
// tools each step returns a reasoned failure and NO artifact is written (never a silent clean run).
//
// The decision logic and emission are the tested pure functions in src/dynamic-validate.ts; this
// wrapper is the untested I/O per the repo convention.
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { cloneAtPin } from "../scan/corpus-clone.js";
import { assessStandUpAbility, readRepoLayout, runDynamicValidation, type StandUpRunner } from "../dynamic-validate.js";

const args = process.argv.slice(2);
const targetArg = args.find((a) => !a.startsWith("--"));
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

if (!targetArg) {
  console.error("usage: pnpm dynamic-validate <target-dir | repo-url> [--pin <commit>] [--out <artifacts-dir>] [--execute]");
  process.exit(2);
}

const isUrl = /^(https?:\/\/|git@)/.test(targetArg);
const targetDir = isUrl ? mkdtempSync(join(tmpdir(), "harvey-dynval-clone-")) : resolve(targetArg);
if (isUrl) {
  const pin = flag("--pin");
  if (!pin) {
    console.error("cloning a repo URL requires --pin <commit> (validation runs against a fixed commit)");
    process.exit(2);
  }
  cloneAtPin(targetArg, pin, targetDir);
}

const layout = readRepoLayout(targetDir);
const verdict = assessStandUpAbility(layout);
console.log(`Dynamic-validation assessment — ${targetDir}`);
console.log(`  verdict:  ${verdict.canStandUp ? "GO" : "NO-GO"} (${verdict.coverage})`);
console.log(`  reason:   ${verdict.reason}`);
for (const l of verdict.limitations) console.log(`  limitation: ${l}`);

if (!verdict.canStandUp) process.exit(1);

if (!args.includes("--execute")) {
  console.log("\nassess-only (pass --execute to stand up + pen-test). Live pipeline needs Docker + the Supabase CLI.");
  process.exit(0);
}

const out = flag("--out");
if (!out) {
  console.error("--execute requires --out <artifacts-dir> to write M2.pass.json");
  process.exit(2);
}

// Thin shell-out runner. Each step reports ok/output; a missing tool is a reasoned failure the
// orchestration turns into "could not stand up", never a silent pass.
const sh = (cmd: string, cmdArgs: string[], cwd: string): { ok: boolean; output: string } => {
  try {
    return { ok: true, output: execFileSync(cmd, cmdArgs, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (err) {
    const e = err as { stderr?: string; stdout?: string; message?: string };
    return { ok: false, output: (e.stderr || e.stdout || e.message || "").slice(0, 300) };
  }
};

const runner: StandUpRunner = {
  standUpDb: (dir) => {
    const start = sh("supabase", ["start"], dir);
    if (!start.ok) return start;
    return sh("supabase", ["db", "reset"], dir); // applies migrations + supabase/seed.sql
  },
  runApp: (dir) => sh("npm", ["run", "build"], dir),
  pentest: (dir) => {
    const r = sh("pnpm", ["exec", "tsx", "src/cli/pentest.ts", "--target", dir], process.cwd());
    if (!r.ok) return { ok: false, findings: [], output: r.output };
    try {
      const parsed = JSON.parse(r.output) as { findings?: unknown };
      return { ok: true, findings: Array.isArray(parsed.findings) ? (parsed.findings as never[]) : [], output: r.output };
    } catch {
      return { ok: false, findings: [], output: `pentest produced no parseable findings: ${r.output.slice(0, 200)}` };
    }
  },
};

const result = runDynamicValidation({ targetDir, layout, artifactsDir: resolve(out), now: () => new Date().toISOString(), runner });
console.log(`\n${result.reason}`);
for (const l of result.limitations) console.log(`  limitation: ${l}`);
if (result.artifactPath) {
  console.log(`M2 pass artifact → ${result.artifactPath} (run-audit --artifacts-dir ${resolve(out)} now derives M2 ran)`);
} else {
  console.error("no M2 artifact written — the target could not be validated dynamically (see reason above)");
  process.exit(1);
}
