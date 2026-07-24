// #886 — infrastructure code (Dockerfiles, docker-compose, Terraform, Kubernetes/Helm manifests) is
// OUT OF SCOPE for a Harvey audit, deliberately: container and IaC scanning is consolidated ASPM
// territory (Trivy, Checkov, Aikido, Cycode, …) and competing there trades Harvey's differentiator —
// proven multi-tenant isolation — for parity in a commodity market. The decision is recorded in
// docs/design/infrastructure-out-of-scope.md so it is not re-litigated as a gap each review.
//
// What is NOT acceptable is silence: a client repo with a terraform/ directory currently receives a
// report in which those files simply do not appear, and "an unstated limitation reads as a clean
// bill of health". So: detect what is there, count it, and state plainly that it was not assessed.
// This module deliberately does NOT analyse the files' contents for misconfiguration.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { Finding } from "../findings.js";

const EXCLUDED_DIR = /^(node_modules|\.git|\.next|dist|build|coverage|out|vendor|venv|\.venv|__pycache__)$/;

// Filename → the infrastructure class it evidences. Kubernetes/Helm manifests have no reliable
// filename convention, so they are matched on the two keys every manifest carries instead.
const K8S_MANIFEST = /^apiVersion:/m;
const K8S_KIND = /^kind:/m;

function classify(name: string): string | undefined {
  if (/^Dockerfile(\..+)?$/i.test(name) || /\.dockerfile$/i.test(name)) return "Container image (Dockerfile)";
  if (/^(docker-)?compose(\..+)?\.ya?ml$/i.test(name)) return "Container orchestration (Compose)";
  if (/\.tf$/i.test(name) || /\.tfvars$/i.test(name)) return "Terraform / OpenTofu";
  if (/^Chart\.ya?ml$/i.test(name)) return "Kubernetes (Helm chart)";
  return undefined;
}

interface InfraHits {
  files: number;
  example: string;
}

function findInfrastructureFiles(dir: string): Map<string, InfraHits> {
  const byClass = new Map<string, InfraHits>();
  const record = (kind: string, path: string): void => {
    const hit = byClass.get(kind);
    if (hit) hit.files += 1;
    else byClass.set(kind, { files: 1, example: path });
  };
  const walk = (current: string): void => {
    for (const entry of readdirSync(current)) {
      const full = join(current, entry);
      if (statSync(full).isDirectory()) {
        if (!EXCLUDED_DIR.test(entry)) walk(full);
        continue;
      }
      const rel = relative(dir, full).split(sep).join("/");
      const kind = classify(entry);
      if (kind) record(kind, rel);
      else if (/\.ya?ml$/i.test(entry) && isKubernetesManifest(full)) record("Kubernetes manifest", rel);
    }
  };
  walk(dir);
  return byClass;
}

// A YAML carrying both `apiVersion:` and `kind:` is a Kubernetes object; nothing else in a typical
// app repo (CI workflows, tool config) has that pair. Large files are skipped — a manifest is small,
// and a multi-megabyte YAML is a data dump we shouldn't read into memory to classify.
function isKubernetesManifest(path: string): boolean {
  if (statSync(path).size > 512 * 1024) return false;
  const text = readFileSync(path, "utf8");
  return K8S_MANIFEST.test(text) && K8S_KIND.test(text);
}

export function checkInfrastructureScope(dir: string): Finding[] {
  const byClass = findInfrastructureFiles(dir);
  if (byClass.size === 0) return [];

  const ranked = [...byClass.entries()].sort((a, b) => b[1].files - a[1].files);
  const summary = ranked.map(([kind, hit]) => `${kind}: ${hit.files} file${hit.files === 1 ? "" : "s"} (e.g. ${hit.example})`).join("; ");
  return [
    {
      id: "INFRA-SCOPE-00",
      title: "Infrastructure code found and NOT assessed — out of scope for this audit",
      severity: "Info",
      confidence: "N/A",
      category: "Infrastructure",
      taxonomy: "Coverage — infrastructure/IaC out of scope",
      location: "(repo-wide)",
      status: "Open",
      evidence: `The target contains infrastructure definitions that no Harvey module reads: ${summary}. None of these files was analysed — not for exposed ports or privileged containers, not for public storage buckets or over-broad IAM, not for missing network policies.`,
      impact:
        "Container and IaC misconfiguration is a whole risk class this report says nothing about. It is excluded by design (see docs/design/infrastructure-out-of-scope.md), not by oversight — recorded here so its absence cannot be read as 'assessed and clean'.",
      fix: "If infrastructure assurance is in scope for your programme, run a dedicated IaC/container scanner (Trivy, Checkov, or your ASPM platform) over these paths. Harvey's audit covers the application and its database boundary.",
      value: 1,
      ease: 4,
      safety: 5,
      mechanical: true,
    },
  ];
}
