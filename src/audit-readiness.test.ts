import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  discoverReadinessPlan,
  readinessStageId,
  serializeReadinessPlanV1,
  validateReadinessPlanV1,
  type ReadinessPlanV1,
  type ReadinessStageKind,
} from "./audit-readiness.js";

const processCanary = vi.hoisted(() => ({
  execFile: vi.fn(),
  execFileSync: vi.fn(),
  spawn: vi.fn(),
  spawnSync: vi.fn(),
}));
vi.mock("node:child_process", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:child_process")>(),
  ...processCanary,
}));

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  vi.clearAllMocks();
});

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "harvey-readiness-"));
  roots.push(root);
  return root;
}

function writePackage(root: string, dir: string, body: object): void {
  mkdirSync(join(root, dir), { recursive: true });
  writeFileSync(join(root, dir, "package.json"), JSON.stringify(body));
}

function stage(plan: ReadinessPlanV1, workspaceId: string, kind: ReadinessStageKind) {
  const row = plan.stages.find((candidate) => candidate.id === readinessStageId(workspaceId as `workspace:${string}`, kind));
  if (!row) throw new Error(`fixture plan lacks ${workspaceId}/${kind}`);
  return row;
}

describe("discoverReadinessPlan", () => {
  it.each([
    ["npm", "package-lock.json", ["install", "--no-audit", "--no-fund"]],
    ["pnpm", "pnpm-lock.yaml", ["install"]],
    ["yarn", "yarn.lock", ["install"]],
  ] as const)("plans a %s install only from matching target evidence", (manager, lockfile, args) => {
    const root = fixture();
    writePackage(root, ".", { name: "app", scripts: { build: "vite build", test: "vitest run" } });
    writeFileSync(join(root, lockfile), "lock bytes\n");

    const plan = discoverReadinessPlan(root);
    expect(plan.packageManager).toMatchObject({ status: "selected", manager, lockfile });
    expect(stage(plan, "workspace:root", "install")).toMatchObject({
      assessment: "planned",
      command: { bin: manager, args: [...args], cwd: "." },
    });
    expect(stage(plan, "workspace:root", "build")).toMatchObject({
      assessment: "planned",
      command: { bin: manager, args: ["run", "build"], cwd: "." },
    });
  });

  it("shares one install stage across a root and all monorepo members without duplicating identities", () => {
    const root = fixture();
    writePackage(root, ".", { name: "root", workspaces: ["packages/*", "apps/*"] });
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    writePackage(root, "packages/lib", { name: "@acme/lib", scripts: { build: "tsc -p tsconfig.json" } });
    writePackage(root, "apps/web", { name: "@acme/web", scripts: { build: "next build", test: "vitest" } });

    const plan = discoverReadinessPlan(root);
    expect(plan.workspaces.map((workspace) => workspace.id)).toEqual([
      "workspace:apps/web",
      "workspace:packages/lib",
      "workspace:root",
    ]);
    expect(plan.stages.filter((candidate) => candidate.kind === "install")).toHaveLength(1);
    expect(new Set(plan.workspaces.map((workspace) => workspace.installStageId))).toEqual(new Set(["stage:workspace:root:install"]));
    expect(plan.workspaceInventory.applicationWorkspaceIds).toEqual(["workspace:apps/web", "workspace:packages/lib"]);
  });

  it("retains every missing stage as an explicit absent or not-assessed row", () => {
    const root = fixture();
    writePackage(root, ".", { name: "app" });
    writeFileSync(join(root, "package-lock.json"), "{}");
    writeFileSync(join(root, "tsconfig.json"), "{}");

    const plan = discoverReadinessPlan(root);
    expect(stage(plan, "workspace:root", "build")).toMatchObject({ assessment: "absent", reasonCode: "missing-script-and-config" });
    expect(stage(plan, "workspace:root", "typecheck")).toMatchObject({ assessment: "not-assessed", reasonCode: "supported-config-without-script" });
    expect(stage(plan, "workspace:root", "lint")).toMatchObject({ assessment: "absent" });
    expect(stage(plan, "workspace:root", "test")).toMatchObject({ assessment: "absent" });
    expect(plan.workspaces[0]?.stageIds).toHaveLength(6);

    writePackage(root, ".", { name: "app", scripts: { typecheck: "tsc --noEmit", "type-check": "tsc -p tsconfig.json" } });
    expect(stage(discoverReadinessPlan(root), "workspace:root", "typecheck")).toMatchObject({
      assessment: "not-assessed",
      reasonCode: "ambiguous-scripts",
    });

    writePackage(root, ".", { name: "app", scripts: { typecheck: "tsc --noEmit" } });
    expect(stage(discoverReadinessPlan(root), "workspace:root", "typecheck")).toMatchObject({
      assessment: "planned",
      command: { args: ["run", "typecheck"] },
    });
  });

  it("keeps conflicting, missing, and unsupported manager evidence non-executable", () => {
    const root = fixture();
    writePackage(root, ".", { name: "app", scripts: { build: "vite build" } });
    writeFileSync(join(root, "package-lock.json"), "{}");
    writeFileSync(join(root, "yarn.lock"), "# yarn\n");
    let plan = discoverReadinessPlan(root);
    expect(plan.packageManager).toMatchObject({ status: "not-assessed", reason: "conflicting-evidence" });
    expect(stage(plan, "workspace:root", "install")).toMatchObject({ assessment: "not-assessed", safety: "non-executable" });
    expect(stage(plan, "workspace:root", "build")).toMatchObject({ assessment: "not-assessed", reasonCode: "package-manager-not-selected" });

    rmSync(join(root, "yarn.lock"));
    plan = discoverReadinessPlan(root);
    expect(plan.packageManager).toMatchObject({ status: "selected", manager: "npm" });
    expect(stage(plan, "workspace:root", "build")).toMatchObject({ assessment: "planned" });

    rmSync(join(root, "package-lock.json"));
    writePackage(root, ".", { name: "app", packageManager: "bun@1.1.0", scripts: { build: "vite build" } });
    expect(discoverReadinessPlan(root).packageManager).toMatchObject({ status: "not-assessed", reason: "unsupported-manager" });
    expect(processCanary.execFile).not.toHaveBeenCalled();
    expect(processCanary.execFileSync).not.toHaveBeenCalled();
    expect(processCanary.spawn).not.toHaveBeenCalled();
    expect(processCanary.spawnSync).not.toHaveBeenCalled();
  });

  it("keeps unreadable root and member manifests counted with explicit non-executable stages", () => {
    const root = fixture();
    writeFileSync(join(root, "package.json"), "{not json");

    let plan = discoverReadinessPlan(root);
    expect(plan.workspaces.map((workspace) => workspace.id)).toEqual(["workspace:root"]);
    expect(plan.packageManager).toMatchObject({ status: "not-assessed", reason: "unreadable-manifest" });
    expect(stage(plan, "workspace:root", "build")).toMatchObject({
      assessment: "not-assessed",
      reasonCode: "unreadable-manifest",
      safety: "non-executable",
    });

    writePackage(root, ".", { name: "root", workspaces: ["apps/*"] });
    writeFileSync(join(root, "package-lock.json"), "{}");
    mkdirSync(join(root, "apps", "broken"), { recursive: true });
    writeFileSync(join(root, "apps", "broken", "package.json"), "{still not json");
    plan = discoverReadinessPlan(root);
    expect(plan.workspaceInventory.applicationWorkspaceIds).toEqual(["workspace:apps/broken"]);
    expect(stage(plan, "workspace:apps/broken", "test")).toMatchObject({
      assessment: "not-assessed",
      reasonCode: "unreadable-manifest",
    });
    expect(processCanary.spawn).not.toHaveBeenCalled();
  });

  it("models supported postinstall codegen as an install effect and blocks build/test behind it", () => {
    const root = fixture();
    writePackage(root, ".", {
      name: "generated-app",
      packageManager: "pnpm@9.15.3",
      scripts: {
        postinstall: "prisma generate",
        build: "next build",
        test: "vitest run",
      },
    });
    mkdirSync(join(root, "prisma"), { recursive: true });
    writeFileSync(join(root, "prisma", "schema.prisma"), "generator client { provider = \"prisma-client-js\" }\n");

    const plan = discoverReadinessPlan(root);
    const codegen = stage(plan, "workspace:root", "codegen");
    expect(codegen).toMatchObject({
      assessment: "implicit",
      fulfilledByStageId: "stage:workspace:root:install",
      prerequisiteStageIds: ["stage:workspace:root:install"],
    });
    expect(stage(plan, "workspace:root", "build").prerequisiteStageIds).toContain(codegen.id);
    expect(stage(plan, "workspace:root", "test").prerequisiteStageIds).toContain(codegen.id);

    writePackage(root, ".", { name: "generated-app", packageManager: "pnpm@9.15.3", scripts: { postinstall: 'echo "prisma generate"', build: "next build", test: "vitest run" } });
    expect(stage(discoverReadinessPlan(root), "workspace:root", "codegen")).toMatchObject({
      assessment: "not-assessed",
      reasonCode: "supported-config-without-script",
    });
  });

  it("stores package-manager argv rather than parsing or interpolating a target shell body", () => {
    const root = fixture();
    const marker = join(root, "SHOULD-NOT-EXIST");
    writePackage(root, ".", {
      name: "app",
      packageManager: "npm@10.8.2",
      scripts: {
        build: `node -e "require('node:fs').writeFileSync('${marker}', process.env.SECRET_VALUE)" && vite build`,
      },
    });
    process.env.SECRET_VALUE = "secret-shaped-value-that-must-not-enter-plan";
    try {
      const plan = discoverReadinessPlan(root);
      expect(stage(plan, "workspace:root", "build")).toMatchObject({
        assessment: "planned",
        command: { bin: "npm", args: ["run", "build"], cwd: "." },
      });
      expect(readFileSync(join(root, "package.json"), "utf8")).toContain("SHOULD-NOT-EXIST");
      expect(() => readFileSync(marker, "utf8")).toThrow();
      expect(processCanary.execFile).not.toHaveBeenCalled();
      expect(processCanary.execFileSync).not.toHaveBeenCalled();
      expect(processCanary.spawn).not.toHaveBeenCalled();
      expect(processCanary.spawnSync).not.toHaveBeenCalled();
      expect(serializeReadinessPlanV1(plan)).not.toContain(process.env.SECRET_VALUE);
    } finally {
      delete process.env.SECRET_VALUE;
    }
  });

  it("records required environment names from scripts/config without reading their values", () => {
    const root = fixture();
    writePackage(root, ".", {
      name: "app",
      packageManager: "yarn@4.5.1",
      scripts: { build: "deploy --token $DEPLOY_TOKEN --url ${API_URL}" },
    });
    writeFileSync(join(root, "next.config.js"), "export default { endpoint: process.env.INTERNAL_API_URL };\n");
    process.env.DEPLOY_TOKEN = "never-serialize-this-value";
    try {
      const build = stage(discoverReadinessPlan(root), "workspace:root", "build");
      expect(build.requiredEnvNames).toEqual(["API_URL", "DEPLOY_TOKEN", "INTERNAL_API_URL"]);
      expect(JSON.stringify(build)).not.toContain(process.env.DEPLOY_TOKEN);
    } finally {
      delete process.env.DEPLOY_TOKEN;
    }
  });

  it("keeps stable IDs and canonical bytes when workspace declarations and plan arrays reorder", () => {
    const root = fixture();
    writeFileSync(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    writePackage(root, "apps/a", { name: "a", scripts: { test: "vitest" } });
    writePackage(root, "packages/z", { name: "z", scripts: { lint: "eslint ." } });
    writePackage(root, ".", { name: "root", workspaces: ["packages/*", "apps/*"] });
    const first = discoverReadinessPlan(root);

    writePackage(root, ".", { name: "root", workspaces: ["apps/*", "packages/*"] });
    const second = discoverReadinessPlan(root);
    expect(serializeReadinessPlanV1(second)).toBe(serializeReadinessPlanV1(first));

    const shuffled = structuredClone(first);
    shuffled.workspaces.reverse();
    for (const workspace of shuffled.workspaces) workspace.stageIds.reverse();
    shuffled.stages.reverse();
    for (const candidate of shuffled.stages) candidate.prerequisiteStageIds.reverse();
    shuffled.workspaceInventory.packages.reverse();
    shuffled.workspaceInventory.observations.reverse();
    expect(serializeReadinessPlanV1(shuffled)).toBe(serializeReadinessPlanV1(first));
  });
});

describe("validateReadinessPlanV1", () => {
  function validPlan(): ReadinessPlanV1 {
    const root = fixture();
    writePackage(root, ".", { name: "app", packageManager: "npm@10.8.2", scripts: { codegen: "prisma generate", build: "vite build", test: "vitest" } });
    return discoverReadinessPlan(root);
  }

  it("rejects an unknown schema version", () => {
    expect(() => validateReadinessPlanV1({ ...validPlan(), schemaVersion: 2 })).toThrow(/schemaVersion/);
  });

  it("rejects duplicate ids, dangling prerequisites, and a missing stage kind", () => {
    const duplicate = structuredClone(validPlan());
    duplicate.stages.push(structuredClone(duplicate.stages[0]!));
    expect(() => validateReadinessPlanV1(duplicate)).toThrow(/duplicate.*stage id/);

    const dangling = structuredClone(validPlan());
    dangling.stages.find((candidate) => candidate.kind === "build")!.prerequisiteStageIds.push("stage:workspace:missing:codegen");
    expect(() => validateReadinessPlanV1(dangling)).toThrow(/dangling prerequisite/);

    const missing = structuredClone(validPlan());
    missing.workspaces[0]!.stageIds = missing.workspaces[0]!.stageIds.filter((id) => !id.endsWith(":lint"));
    expect(() => validateReadinessPlanV1(missing)).toThrow(/exactly one stage per kind/);

    const independentBuild = structuredClone(validPlan());
    const build = independentBuild.stages.find((candidate) => candidate.kind === "build")!;
    build.prerequisiteStageIds = build.prerequisiteStageIds.filter((id) => !id.endsWith(":codegen"));
    expect(() => validateReadinessPlanV1(independentBuild)).toThrow(/prerequisites inconsistent/);
  });

  it("rejects an absolute cwd and accepts the production plan", () => {
    const plan = validPlan();
    expect(validateReadinessPlanV1(plan)).toBe(plan);
    const build = plan.stages.find((candidate) => candidate.kind === "build");
    if (!build || build.assessment !== "planned") throw new Error("fixture lacks planned build");
    build.command.cwd = "/tmp/escape";
    expect(() => validateReadinessPlanV1(plan)).toThrow(/canonical relative cwd/);
  });

  it("rejects an uncited argv body and unknown fields", () => {
    const argv = validPlan();
    const build = argv.stages.find((candidate) => candidate.kind === "build");
    if (!build || build.assessment !== "planned") throw new Error("fixture lacks planned build");
    build.command.args = ["vite", "build", "&&", "curl", "example.invalid"];
    expect(() => validateReadinessPlanV1(argv)).toThrow(/not backed by its cited package script/);

    const unknown = validPlan() as ReadinessPlanV1 & { generatedAt?: string };
    unknown.generatedAt = new Date().toISOString();
    expect(() => validateReadinessPlanV1(unknown)).toThrow(/unknown field/);
  });
});
