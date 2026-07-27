# Infrastructure / IaC / container security is out of scope — and is disclosed, not omitted

Decision record for #886. Written so this is not re-litigated as a coverage gap every time the
module list is reviewed.

## The decision

Harvey does **not** analyse infrastructure code: Dockerfiles, docker-compose, Terraform/OpenTofu,
Kubernetes and Helm manifests. No M1–M10 module reads them, and none is planned.

<!--
REASON: infrastructure/IaC/container code is out of Harvey's scope — this is a product ruling about where the differentiator lies, not a statement that scanning it is technically impossible
KIND: decisional
PROVENANCE: MEASURED 2026-07-23 (the ruling recorded in this document when it landed in #903/#886)
OWNER: operator
DECISION: docs/design/infrastructure-out-of-scope.md (#886); revisit condition in "What would change this" below
-->


## What this decision does NOT cover: GitHub Actions workflows are IN scope

Recorded here so the boundary is not re-litigated at the next module-list review (#1212).

`.github/workflows/*.yml` is **not** infrastructure code for the purposes of this decision, and the
files above are not a list Actions belongs on. Harvey analyses workflows today:

- Four classes arrive inherited from the registry `p/security-audit` pack the mechanical scan
  already runs (`yaml.github-actions.security.*`): mutable action tag, `pull_request_target` with a
  checkout of the PR head, shell injection through a `run:` interpolation, and `curl | sh`. MEASURED
  2026-07-27 against a deliberately hostile workflow — the run recorded in #1212 and in
  `src/scan/gha-permissions.ts`'s header, which is also where the count comes from. Do not quote it
  from here; `pnpm detector-census` is the current answer.
- Harvey's own `GITHUB_TOKEN`-scope pass (`src/scan/gha-permissions.ts`, #1212/#1245) covers what
  that measurement showed missing: `permissions: write-all` at workflow level, the same at job
  level, and the absence check for a workflow that declares no `permissions:` block at all and so
  inherits the repository default.
- Everything above lands in `CI_PIPELINE_CATEGORY` ("CI/CD pipeline hygiene"), which
  `src/quick-scan.ts` reports but does **not** grade (#996) — a `curl | sh` in CI is a real finding
  but not app-surface exploitability.
- `src/scan/infra-scope.ts` does not classify workflow YAML as infrastructure (its Kubernetes test
  requires both `apiVersion:` and `kind:`), so nothing here is double-counted as not-assessed.

The reason the line falls here rather than at "any YAML that isn't application code": a workflow is
part of the **software supply chain of the repository under audit**, not of the customer's deployed
infrastructure. A `pull_request_target` job that checks out attacker-controlled code with a
write-scoped token compromises the repo — including the tenant-isolation code that is Harvey's whole
thesis. Terraform describing a VPC does not. That is also why the commodity argument below does not
transfer: the ASPM tools own the IaC ruleset market, but the classes here ride along with a scanner
Harvey already runs, at no build cost, and are reported in their own non-grading category.

So a repo with `.github/workflows/` gets findings, not an `INFRA-SCOPE-00` not-assessed row. A gap
in this area is an ordinary detection gap to be filed and closed, not a scope question to be
reopened.

## Why not

IaC and container scanning is consolidated ASPM territory — Trivy, Checkov, Aikido, Cycode,
Checkmarx One, OX. It is a commodity: the rule sets are open, the tools are free or bundled, and
buyers already own one. Building it would trade Harvey's differentiator — a **proven** multi-tenant
isolation boundary, demonstrated dynamically against a live two-tenant stack — for parity in a
market we would enter last.

The same reasoning governs the sibling decision on multi-language SAST (#871): where a second
language matters to Harvey's thesis it is because *DB-access code in it bypasses the tenant
boundary*, not because generic SAST coverage is missing.

## What we DO owe the client

The coverage guard in `CLAUDE.md` is absolute on this point: *"an unstated limitation reads as a
clean bill of health"*. A repo with a `terraform/` directory whose report never mentions it is
telling the client, by omission, that it was looked at and found fine.

So the mechanical scan detects infrastructure files and emits a single `INFRA-SCOPE-00` row
(Info / N-A, `src/scan/infra-scope.ts`) naming each class found, its file count and an example
path, stating plainly that it was not assessed and pointing at a dedicated scanner. The row fires
only when such files exist — a repo without them gets nothing.

## What would change this

A client engagement where the tenant boundary itself is enforced in infrastructure — for example,
per-tenant network policies or per-tenant database credentials issued by Terraform — is inside
Harvey's thesis rather than outside it. That is a targeted extension of M1, not the general IaC
scanner this record rejects.
