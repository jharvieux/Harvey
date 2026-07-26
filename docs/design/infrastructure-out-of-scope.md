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
