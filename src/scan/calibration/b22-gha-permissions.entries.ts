// Batch B22 (#1212) — GITHUB_TOKEN permission scope in GitHub Actions workflows.
//
// GitHub Actions is NOT covered by the infrastructure out-of-scope decision (#903,
// docs/design/infrastructure-out-of-scope.md, which names Dockerfiles/Compose/Terraform/K8s):
// Harvey already ships four registry GHA classes from p/security-audit and a non-grading category
// built for them (CI_PIPELINE_CATEGORY, #996). So this is a gap INSIDE an in-scope area.
//
// MEASURED 2026-07-27 before writing the detector: Harvey's own semgrep invocation over a workflow
// carrying `permissions: write-all`, and over one with no permissions block at all, produced ZERO
// findings on both — while the same run flagged the mutable action tag, the pull_request_target
// checkout, the run-shell injection and the curl|sh in neighbouring fixtures. Harvey reported one
// half of the pull_request_target pair (the checkout) and not the other (the token that makes it
// repository compromise rather than a nuisance).
//
// Why a TS pass and not a `harvey-*` semgrep rule: the second shape is an ABSENCE. A workflow with
// no `permissions:` block inherits the repository's default, which is still "Read and write" for
// repositories created before February 2023 — and there is nothing in the file to pattern-match.
// src/scan/gha-permissions.ts checks per file; write-all is `high` (an exact fact), the missing
// block is `review` (it depends on a repository setting the scan cannot read). Both route to
// CI_PIPELINE_CATEGORY, reported in full and non-grading, consistent with the other GHA classes.
//
// See GROUND-TRUTH.md §B22.

import type { CorpusEntry } from "./types.js";

export const b22GhaPermissionsEntries: CorpusEntry[] = [
  // --- POSITIVES (must be caught) ---
  { id: "P-GHA-WRITE-ALL", kind: "positive", cls: "GitHub Actions workflow grants GITHUB_TOKEN write-all", location: ".github/workflows/token-write-all.yml", match: ["gha-write-all"], expectedTier: "high", expectedSeverity: "High", note: "#1212: `permissions: write-all` at workflow level in .github/workflows/token-write-all.yml, on a pull_request_target trigger that checks out the PR head. The registry rules already catch the checkout half; nothing caught the token half (MEASURED 2026-07-27: zero findings on this exact shape). checkWorkflowPermissions → high, because the grant is an exact fact in the file, not an inference. Non-grading regardless (CI_PIPELINE_CATEGORY)." },
  { id: "P-GHA-JOB-WRITE-ALL", kind: "positive", cls: "GitHub Actions JOB re-widens a narrow workflow-level permissions block to write-all", location: ".github/workflows/token-job-write-all.yml", match: ["gha-write-all"], expectedTier: "high", expectedSeverity: "High", note: "#1212: the workflow-level block is `contents: read` — correct — and the `release` job overrides it with `permissions: write-all`. Present because a rule that only read the top-level key would score P-GHA-WRITE-ALL and silently miss this, which is the shape a reviewer skims past. The detector matches the key at ANY indentation and reports which level it was found at." },
  { id: "P-GHA-NO-PERMISSIONS", kind: "positive", cls: "GitHub Actions workflow declares no permissions block at all", location: ".github/workflows/saml-integration-test.yml", match: ["gha-no-permissions"], expectedTier: "review", expectedSeverity: "Medium", note: "#1212 shape 2, and the more common one by far: .github/workflows/saml-integration-test.yml defines a job and never mentions `permissions:`, so GITHUB_TOKEN inherits the repository default. It is invisible by construction — there is nothing to pattern-match — so it needs an absence check per workflow file rather than a rule. REVIEW tier, not high: whether the inherited default is read-only or read-write is a repository/organisation setting this scan cannot read, so the finding asks rather than asserts. The file is an existing fixture (its own N-SAML-TEST-PRIVATE-KEY entry scores the private-key class on it, keyed on a disjoint match term)." },

  // --- NEGATIVES (must NOT be flagged in the free count) ---
  { id: "N-GHA-LEAST-PRIVILEGE", kind: "negative", cls: "GitHub Actions workflow with an explicit least-privilege permissions block", location: ".github/workflows/token-least-privilege.yml", match: ["gha-write-all", "gha-no-permissions"], note: "#1212: `permissions: { contents: read }` at workflow level, widened to `pull-requests: write` on the one job that comments. Neither rule may fire: not write-all, and not absent. Load-bearing in both directions — a rule that flagged every workflow it read (the obvious implementation of the absence check) would fire here, and so would one that keyed on the mere presence of the word `write`." },
];
