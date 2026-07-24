import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { checkInfrastructureScope } from "./infra-scope.js";

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function makeTarget(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-infra-"));
  dirs.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    const full = join(dir, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return dir;
}

describe("checkInfrastructureScope (#886)", () => {
  it("names every infrastructure class it found, with counts and an example path", () => {
    const dir = makeTarget({
      Dockerfile: "FROM node:20\n",
      "docker-compose.yml": "services:\n  web:\n    build: .\n",
      "terraform/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
      "terraform/variables.tf": 'variable "region" {}\n',
      "k8s/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
      "app/page.tsx": "export default function Page() { return null; }\n",
    });
    const [finding] = checkInfrastructureScope(dir);
    expect(finding).toMatchObject({ id: "INFRA-SCOPE-00", severity: "Info", confidence: "N/A" });
    expect(finding?.evidence).toContain("Terraform / OpenTofu: 2 files");
    expect(finding?.evidence).toContain("Container image (Dockerfile): 1 file");
    expect(finding?.evidence).toContain("Container orchestration (Compose): 1 file");
    expect(finding?.evidence).toContain("Kubernetes manifest: 1 file");
    // The row's job is to say it was NOT assessed, and to point somewhere useful.
    expect(finding?.evidence).toContain("None of these files was analysed");
    expect(finding?.impact).toContain("docs/design/infrastructure-out-of-scope.md");
  });

  it("emits nothing for an application repo with no infrastructure files", () => {
    const dir = makeTarget({
      "app/page.tsx": "export default function Page() { return null; }\n",
      "package.json": `{"name":"app"}`,
    });
    expect(checkInfrastructureScope(dir)).toEqual([]);
  });

  it("does not mistake an ordinary YAML for a Kubernetes manifest", () => {
    const dir = makeTarget({
      ".github/workflows/ci.yml": "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
      "config/settings.yaml": "featureFlags:\n  beta: true\n",
    });
    expect(checkInfrastructureScope(dir)).toEqual([]);
  });
});
