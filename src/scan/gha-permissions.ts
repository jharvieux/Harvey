// #1212 — GITHUB_TOKEN permission scope in GitHub Actions workflows.
//
// GitHub Actions IS already scanned: MEASURED 2026-07-27 against a deliberately hostile workflow,
// Harvey's own six-pack + custom invocation produced four registry classes from p/security-audit
// (mutable action tag, pull_request_target code checkout, run-shell injection, curl|sh). What it
// produced ZERO of, on the same run, was anything about the token's own scope — and that is the
// half that turns `pull_request_target` + a PR-head checkout from a nuisance into repository
// compromise. This closes that half.
//
// Two shapes, and only one of them is a pattern:
//   1. `permissions: write-all` — an explicit grant of every scope to GITHUB_TOKEN, at workflow or
//      job level. A fact in the file.
//   2. NO `permissions:` block anywhere in the workflow. In a repository whose default workflow
//      permissions are still "Read and write" (GitHub's setting for repos created before Feb 2023,
//      and for any org that has not changed it), the token then gets write scope on every job
//      implicitly. This is the more common shape by far and there is nothing in the file to match
//      on — it needs an ABSENCE check per workflow file, which is why this is a TS pass and not a
//      semgrep rule.
//
// Routing (#996): findings land in CI_PIPELINE_CATEGORY, reported in full but non-grading, exactly
// like the other GHA classes — a CI token scope is not app-surface exploitability. Shape 1 is an
// exact fact (`high`); shape 2 depends on a repository setting this scan cannot read, so it asks
// rather than asserts (`review`).

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { readNamesSafe } from "../fs-walk.js";
import type { Finding } from "../findings.js";
import { mechanicalFinding } from "./common.js";
import { CI_PIPELINE_CATEGORY } from "./semgrep.js";

const WORKFLOW_FILE = /\.ya?ml$/i;
// `permissions: write-all` at any indentation — top-level (whole workflow) or under a job.
const WRITE_ALL = /^(\s*)permissions:\s*write-all\s*$/;
// Any `permissions:` key at all, at any indentation, including the mapping form that opens a block.
const ANY_PERMISSIONS = /^\s*permissions:/;
// A workflow must declare jobs; a file under .github/workflows that has none is a reusable
// fragment or a stray, and has no token to scope.
const JOBS_KEY = /^jobs:/m;

function workflowFiles(dir: string): string[] {
  const wf = join(dir, ".github", "workflows");
  if (!existsSync(wf)) return [];
  return readNamesSafe(wf).filter((f) => WORKFLOW_FILE.test(f)).sort();
}

export function checkWorkflowPermissions(dir: string): Finding[] {
  const findings: Finding[] = [];
  for (const name of workflowFiles(dir)) {
    const rel = `.github/workflows/${name}`;
    const lines = readFileSync(join(dir, ".github", "workflows", name), "utf8").split("\n");
    const raw = lines.join("\n");
    if (!JOBS_KEY.test(raw)) continue;

    const writeAll = lines.findIndex((l) => WRITE_ALL.test(l));
    if (writeAll >= 0) {
      const scope = WRITE_ALL.exec(lines[writeAll]!)![1] === "" ? "the whole workflow" : "a job";
      findings.push(
        mechanicalFinding({
          id: `CI-GHA-WRITE-ALL-${name}`,
          title: `${rel} grants GITHUB_TOKEN write-all`,
          severity: "High",
          category: CI_PIPELINE_CATEGORY,
          taxonomy: "GitHub Actions workflow grants write-all token permissions",
          location: `${rel}:${writeAll + 1}`,
          evidence: `\`permissions: write-all\` is declared for ${scope} in ${rel}, giving GITHUB_TOKEN every scope GitHub offers — contents, packages, deployments, id-token, and write access to issues, pull requests and actions.`,
          impact:
            "Any code that runs in this workflow — a build script, a third-party action, an injected string from a pull-request title — acts with full write access to the repository. Combined with a pull_request_target trigger that checks out the PR head, this is the standard path from an untrusted PR to a repository takeover.",
          fix: "Replace write-all with the narrowest block the jobs actually need (`permissions: { contents: read }` at the top of the workflow, widened per job only where a job genuinely writes). Set the repository default workflow permissions to read-only so an omitted block is safe too.",
          precisionTier: "high",
        }),
      );
      continue;
    }

    if (lines.some((l) => ANY_PERMISSIONS.test(l))) continue;
    findings.push(
      mechanicalFinding({
        id: `CI-GHA-NO-PERMISSIONS-${name}`,
        title: `${rel} declares no GITHUB_TOKEN permissions`,
        severity: "Medium",
        category: CI_PIPELINE_CATEGORY,
        taxonomy: "GitHub Actions workflow declares no token permissions",
        location: rel,
        evidence: `${rel} defines jobs but has no \`permissions:\` block at workflow or job level, so GITHUB_TOKEN inherits the repository's DEFAULT workflow permissions. That default is a repository/organisation setting this scan cannot read.`,
        impact:
          "Where the default is still 'Read and write' — GitHub's setting for repositories created before February 2023, and for any organisation that has not changed it — every job in this workflow runs with a token that can push commits, publish packages and edit pull requests, whether or not it needs to.",
        fix: "Add an explicit least-privilege block (`permissions: { contents: read }`) at the top of the workflow and widen it per job where a job genuinely writes. Independently, set the repository/organisation default workflow permissions to read-only.",
        precisionTier: "review",
      }),
    );
  }
  return findings;
}
