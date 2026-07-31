// #1025 — an executable guard on the CI tier router in `.github/workflows/ci.yml`.
//
// The router decides whether `build` (which runs `pnpm verify`) and `heavy-cli` run at all. A
// mis-route is expensive in both directions: too narrow and a code PR merges unverified; too wide
// and every prose PR pays 20 minutes. PR #1031 deleted `src/ci-docs-tier.test.ts` — correctly, it
// guarded per-file exceptions that no longer exist and had become vacuous — but nothing replaced it,
// so from 2026-07-26 the router's behaviour had no test and (per #1025's reopen) no observation
// either.
//
// This does NOT re-derive the routing rules in TypeScript. It EXTRACTS the router's own bash out of
// the workflow and runs it, so the thing under test is the shipped shell and not a paraphrase of it.
// A paraphrase would have to be kept in step with the YAML, and two lists kept in step is the exact
// failure #1562/#1581 record one subsystem over.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const CI_YML = fileURLToPath(new URL("../.github/workflows/ci.yml", import.meta.url));

/**
 * The router's classification loop, lifted verbatim from the `filter` step: from the `code=false`
 * initialiser through the two `$GITHUB_OUTPUT` writes. The `git diff` that produces `$files` is
 * deliberately NOT included — this test supplies the change set instead, which is the only way to
 * exercise arms no PR in the repo's history has hit.
 *
 * Fails loud rather than silently testing an empty string: a refactor that renames the variables or
 * restructures the step must break this test, not quietly reduce it to a tautology.
 */
function routerScript(yaml: string = readFileSync(CI_YML, "utf8")): string {
  const start = yaml.indexOf("\n          code=false\n");
  const end = yaml.indexOf('echo "workflows=$workflows" >> "$GITHUB_OUTPUT"');
  if (start === -1 || end === -1) {
    throw new Error(`could not find the tier router's classification loop in ${CI_YML} — it was renamed or restructured, and this guard is no longer reading the shipped code`);
  }
  const body = yaml.slice(start, yaml.indexOf("\n", end));
  if (!body.includes("case \"$f\" in") || !body.includes("SESSION.md")) {
    throw new Error("the extracted span is not the router's case statement — refusing to assert against it");
  }
  return body;
}

function route(files: string[]): { code: boolean; workflows: boolean } {
  const dir = mkdtempSync(join(tmpdir(), "harvey-tier-router-"));
  const outFile = join(dir, "github_output");
  try {
    // `bash`, not `sh`: GitHub's default shell for a `run:` block on ubuntu-latest is bash, and the
    // router uses a `<<<` here-string, which is a bashism. Running it under sh would fail for a
    // reason the real job never hits.
    const script = `set -eu\n: > "$GITHUB_OUTPUT"\nfiles=$(cat)\n${routerScript()}\n`;
    execFileSync("bash", ["-c", script], { input: files.join("\n"), env: { ...process.env, GITHUB_OUTPUT: outFile }, encoding: "utf8" });
    const out = readFileSync(outFile, "utf8");
    return { code: /^code=true$/m.test(out), workflows: /^workflows=true$/m.test(out) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("the CI tier router (#1025)", () => {
  it("skips build for a prose-only docs PR — the tier's whole point", () => {
    expect(route(["docs/design/free-tier-recall-measurement.md"])).toEqual({ code: false, workflows: false });
    expect(route(["SESSION.md"])).toEqual({ code: false, workflows: false });
    expect(route(["docs/tier1-runbook.md", "docs/runbooks/README.md", "SESSION.md"])).toEqual({ code: false, workflows: false });
  });

  // `docs/*.md` is a `case` pattern, not a glob: `*` matches `/` here. The tier would silently
  // narrow to top-level docs only if anyone "corrected" it to `docs/**/*.md`, and every nested doc
  // would then start paying a full verify.
  it("treats a NESTED docs path as prose too", () => {
    expect(route(["docs/gtm/03-pricing-packaging.md"]).code).toBe(false);
  });

  it("runs the full verify for a briefs/** PR — briefs are tool input the scanners read at runtime", () => {
    expect(route(["briefs/anti-patterns.md"])).toEqual({ code: true, workflows: false });
    expect(route(["briefs/fp-rules.txt"]).code).toBe(true);
  });

  it("runs the full verify for code, targets and manifests", () => {
    for (const f of ["src/findings.ts", "targets/calibration/app/page.tsx", "package.json", "dry-run/findings.json"]) {
      expect(route([f]), f).toEqual({ code: true, workflows: false });
    }
  });

  it("routes a workflow-only PR to actionlint and not to build", () => {
    expect(route([".github/workflows/ci.yml"])).toEqual({ code: false, workflows: true });
  });

  // A composite action is NOT under .github/workflows/, so it falls to the catch-all and runs the
  // full verify. That is the safe direction and worth pinning: the six alert paths all call into
  // .github/actions/alert-issue, and routing it to actionlint alone would test none of it.
  it("does not treat everything under .github/ as a workflow", () => {
    expect(route([".github/actions/alert-issue/action.yml"])).toEqual({ code: true, workflows: false });
    expect(route([".github/alert-paths.json"]).code).toBe(true);
  });

  it("takes the widest tier when a change set mixes them — one prose file cannot exempt a code PR", () => {
    expect(route(["docs/design/x.md", "src/findings.ts"])).toEqual({ code: true, workflows: false });
    expect(route(["docs/design/x.md", ".github/workflows/ci.yml", "src/findings.ts"])).toEqual({ code: true, workflows: true });
  });

  // A non-.md file under docs/ is not prose: `docs/design/m6-eval-runs/*.agreement.txt` is data,
  // and the arm names `.md` specifically. If it ever became `docs/*`, a data change would skip
  // verify.
  it("does not exempt a non-markdown file under docs/", () => {
    expect(route(["docs/design/m6-eval-runs/run3.agreement.txt"]).code).toBe(true);
  });

  // Without this the whole suite degrades silently the day someone restructures the step: the
  // extraction would return "" and every `route()` call would report `{code:false, workflows:false}`
  // — which passes three of the assertions above.
  it("refuses a workflow whose router it cannot find, rather than asserting against an empty string", () => {
    const gutted = readFileSync(CI_YML, "utf8").replace("\n          code=false\n", "\n          initialise\n");
    expect(() => routerScript(gutted)).toThrow(/no longer reading the shipped code/);
    const renamed = readFileSync(CI_YML, "utf8").replace('case "$f" in', 'case "$path" in');
    expect(() => routerScript(renamed)).toThrow(/not the router's case statement/);
  });
});
