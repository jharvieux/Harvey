// #1025 — an executable guard on the CI tier router in `.github/workflows/ci.yml`.
//
// The router decides whether `build` (which runs `pnpm verify`) and `heavy-cli` run at all. A
// mis-route is expensive in both directions: too narrow and a code PR merges with no verify run at
// all; too wide and every prose PR pays the full suite. PR #1031 deleted `src/ci-docs-tier.test.ts` — correctly, it
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
 * initialiser through the three `$GITHUB_OUTPUT` writes. The `git diff` that produces `$files` is
 * deliberately NOT included — this test supplies the change set instead, which is the only way to
 * exercise arms no PR in the repo's history has hit.
 *
 * Fails loud rather than silently testing an empty string: a refactor that renames the variables or
 * restructures the step must break this test, not quietly reduce it to a tautology.
 */
function routerScript(yaml: string = readFileSync(CI_YML, "utf8")): string {
  const start = yaml.indexOf("\n          code=false\n");
  const end = yaml.indexOf('} >> "$GITHUB_OUTPUT"', start);
  if (start === -1 || end === -1) {
    throw new Error(`could not find the tier router's classification loop in ${CI_YML} — it was renamed or restructured, and this guard is no longer reading the shipped code`);
  }
  const body = yaml.slice(start, yaml.indexOf("\n", end));
  if (!body.includes("case \"$f\" in") || !body.includes("SESSION.md")) {
    throw new Error("the extracted span is not the router's case statement — refusing to assert against it");
  }
  return body;
}

type Route = { code: boolean; workflows: boolean; docs: boolean };

function parseRouteOutput(out: string): Route {
  const values = new Map(out.trim().split("\n").map((line) => line.split("=", 2) as [string, string]));
  for (const key of ["code", "workflows", "docs"] as const) {
    if (!/^(true|false)$/.test(values.get(key) ?? "")) throw new Error(`router did not emit one boolean ${key} output: ${out}`);
  }
  return { code: values.get("code") === "true", workflows: values.get("workflows") === "true", docs: values.get("docs") === "true" };
}

function runRouter(script: string, input = ""): Route {
  const dir = mkdtempSync(join(tmpdir(), "harvey-tier-router-"));
  const outFile = join(dir, "github_output");
  try {
    execFileSync("bash", ["-c", `set -eu\n: > "$GITHUB_OUTPUT"\n${script}\n`], {
      input,
      env: { ...process.env, GITHUB_OUTPUT: outFile },
      encoding: "utf8",
    });
    return parseRouteOutput(readFileSync(outFile, "utf8"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function route(files: string[], yaml: string = readFileSync(CI_YML, "utf8")): Route {
  // `bash`, not `sh`: GitHub's default shell for a `run:` block on ubuntu-latest is bash, and the
  // router uses a `<<<` here-string, which is a bashism. Running it under sh would fail for a
  // reason the real job never hits.
  return runRouter(`files=$(cat)\n${routerScript(yaml)}`, files.join("\n"));
}

function routeNonPullRequest(eventName: "push" | "merge_group" | "schedule" | "workflow_dispatch", yaml: string = readFileSync(CI_YML, "utf8")): Route {
  const startToken = '\n          if [ "${{ github.event_name }}" != "pull_request" ]; then\n';
  const start = yaml.indexOf(startToken);
  const endToken = "\n          fi";
  const end = yaml.indexOf(endToken, start + startToken.length);
  if (start === -1 || end === -1) throw new Error("could not find the non-pull-request router arm");
  const body = yaml.slice(start, end + endToken.length).replace("${{ github.event_name }}", eventName);
  return runRouter(body);
}

function jobBlock(name: string, yaml: string = readFileSync(CI_YML, "utf8")): string {
  const header = `\n  ${name}:\n`;
  const start = yaml.indexOf(header);
  if (start === -1) throw new Error(`could not find ${name} job`);
  const rest = yaml.slice(start + header.length);
  const next = rest.search(/^ {2}[a-zA-Z0-9_-]+:\s*$/m);
  return yaml.slice(start, next === -1 ? yaml.length : start + header.length + next);
}

function eventBlock(name: string, yaml: string = readFileSync(CI_YML, "utf8")): string {
  const onEnd = yaml.indexOf("\nconcurrency:");
  const events = yaml.slice(0, onEnd);
  const header = `\n  ${name}:`;
  const start = events.indexOf(header);
  if (start === -1) throw new Error(`could not find ${name} event`);
  const rest = events.slice(start + header.length);
  const next = rest.search(/^ {2}[a-zA-Z0-9_-]+:\s*$/m);
  return events.slice(start, next === -1 ? events.length : start + header.length + next);
}

describe("the CI tier router (#1025)", () => {
  it("routes the exact cheap-docs whitelist to claim checks without the full build", () => {
    const docsOnly = { code: false, workflows: false, docs: true };
    expect(route(["AGENTS.md"])).toEqual(docsOnly);
    expect(route(["CLAUDE.md"])).toEqual(docsOnly);
    expect(route(["MODULES.md"])).toEqual(docsOnly);
    expect(route(["README.md"])).toEqual(docsOnly);
    expect(route(["SESSION.md"])).toEqual(docsOnly);
    expect(route([".codex/agents/acceptance-verifier.toml"])).toEqual(docsOnly);
    expect(route(["docs/design/free-tier-recall-measurement.md"])).toEqual(docsOnly);
    expect(route(["docs/tier1-runbook.md", "docs/runbooks/README.md", "SESSION.md"])).toEqual(docsOnly);
  });

  // `docs/*.md` is a `case` pattern, not a glob: `*` matches `/` here. The tier would silently
  // narrow to top-level docs only if anyone "corrected" it to `docs/**/*.md`, and every nested doc
  // would then start paying a full verify.
  it("treats a NESTED docs path as prose too", () => {
    expect(route(["docs/gtm/03-pricing-packaging.md"])).toEqual({ code: false, workflows: false, docs: true });
  });

  it("keeps Markdown outside the exact whitelist on the full-build catch-all", () => {
    for (const f of [
      "packages/widget/README.md",
      "briefs/anti-patterns.md",
      "targets/calibration/README.md",
      "src/scan/__fixtures__/semgrep/PROVENANCE.md",
    ]) {
      expect(route([f]), f).toEqual({ code: true, workflows: false, docs: false });
    }
  });

  it("does not broaden the Codex/docs exception beyond TOML and Markdown", () => {
    for (const f of ["docs/data.json", ".codex/agents/unclassified.txt", ".codex/agents/team/nested.toml"]) {
      expect(route([f]), f).toEqual({ code: true, workflows: false, docs: false });
    }
  });

  it("runs the full verify for briefs/** — briefs are tool input the scanners read at runtime", () => {
    expect(route(["briefs/anti-patterns.md"])).toEqual({ code: true, workflows: false, docs: false });
    expect(route(["briefs/fp-rules.txt"])).toEqual({ code: true, workflows: false, docs: false });
  });

  it("runs the full verify for code, targets and manifests", () => {
    for (const f of ["src/findings.ts", "targets/calibration/app/page.tsx", "package.json", "dry-run/findings.json"]) {
      expect(route([f]), f).toEqual({ code: true, workflows: false, docs: false });
    }
  });

  it("routes a workflow-only PR to actionlint and not to build", () => {
    expect(route([".github/workflows/ci.yml"])).toEqual({ code: false, workflows: true, docs: false });
  });

  it("accumulates docs and workflow routes instead of making them exclusive", () => {
    expect(route(["README.md", ".github/workflows/ci.yml"])).toEqual({ code: false, workflows: true, docs: true });
  });

  // A composite action is NOT under .github/workflows/, so it falls to the catch-all and runs the
  // full verify. That is the safe direction and worth pinning: the six alert paths all call into
  // .github/actions/alert-issue, and routing it to actionlint alone would test none of it.
  it("does not treat everything under .github/ as a workflow", () => {
    expect(route([".github/actions/alert-issue/action.yml"])).toEqual({ code: true, workflows: false, docs: false });
    expect(route([".github/alert-paths.json"])).toEqual({ code: true, workflows: false, docs: false });
  });

  it("takes the widest tier when a change set mixes them — one prose file cannot exempt a code PR", () => {
    expect(route(["README.md", "src/findings.ts"])).toEqual({ code: true, workflows: false, docs: true });
    expect(route(["docs/design/x.md", ".github/workflows/ci.yml", "src/findings.ts"])).toEqual({ code: true, workflows: true, docs: true });
  });

  // A non-.md file under docs/ is not prose: `docs/design/m6-eval-runs/*.agreement.txt` is data,
  // and the arm names `.md` specifically. If it ever became `docs/*`, a data change would skip
  // verify.
  it("does not exempt a non-markdown file under docs/", () => {
    expect(route(["docs/design/m6-eval-runs/run3.agreement.txt"])).toEqual({ code: true, workflows: false, docs: false });
  });

  it("runs every route on push, merge queue, schedule, and manual dispatch events", () => {
    for (const event of ["push", "merge_group", "schedule", "workflow_dispatch"] as const) {
      expect(eventBlock(event), `${event} trigger`).toBeTruthy();
      expect(routeNonPullRequest(event), event).toEqual({ code: true, workflows: true, docs: true });
    }
  });

  it("keeps pull_request unfiltered and the always-reporting verify aggregate wired to docs claims", () => {
    expect(eventBlock("pull_request")).not.toMatch(/^ {4}paths(?:-ignore)?:/m);

    const docsClaims = jobBlock("docs-claims");
    expect(docsClaims).toMatch(/^ {4}needs: changes$/m);
    expect(docsClaims).toMatch(/^ {4}if: needs\.changes\.outputs\.docs == 'true'$/m);
    expect(docsClaims).toContain("src/local-verify.test.ts src/recorded-reasons.test.ts src/ci-tier-router.test.ts src/corpus-tier-router.test.ts");
    expect(docsClaims).toContain("tomllib");
    expect(docsClaims).not.toContain("pnpm verify");

    const verify = jobBlock("verify");
    expect(verify).toMatch(/^ {4}if: always\(\)$/m);
    expect(verify).toMatch(/^ {4}needs: \[[^\]]*docs-claims[^\]]*\]$/m);
    expect(verify.match(/needs\['docs-claims'\]\.result/g)).toHaveLength(2);
  });

  // Without this the whole suite degrades silently the day someone restructures the step: the
  // extraction would return "" and every `route()` call would report all three routes false
  // — which passes three of the assertions above.
  it("refuses a workflow whose router it cannot find, rather than asserting against an empty string", () => {
    const gutted = readFileSync(CI_YML, "utf8").replace("\n          code=false\n", "\n          initialise\n");
    expect(() => routerScript(gutted)).toThrow(/no longer reading the shipped code/);
    const renamed = readFileSync(CI_YML, "utf8").replace('case "$f" in', 'case "$path" in');
    expect(() => routerScript(renamed)).toThrow(/not the router's case statement/);
  });
});
