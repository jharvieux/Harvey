import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  classifyCorpusDriftRelevance,
  buildCorpusInputOwnership,
  CORPUS_DRIFT_RUNTIME_ROOTS,
  defaultCorpusInputOwnership,
  discoverCorpusNonImportInputs,
  type CorpusDriftRelevanceReceipt,
  type CorpusInputOwnership,
} from "./corpus-drift-relevance.js";

const disposable: string[] = [];

function git(root: string, args: string[]): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8" }).trim();
}

function put(root: string, path: string, body: string | Buffer): void {
  const absolute = join(root, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, body);
}

function commit(root: string, message: string, add = true): string {
  if (add) git(root, ["add", "-A"]);
  git(root, ["commit", "-qm", message]);
  return git(root, ["rev-parse", "HEAD"]);
}

function ownership(): CorpusInputOwnership {
  const base = defaultCorpusInputOwnership(["alpha", "beta"], [
    { producer: "fixture-producer", phase: "structural-ast", order: 10, module: "M1", registryFile: "src/scan/mechanical-detector-registry.ts" },
  ]);
  return {
    ...base,
    consumers: base.consumers.map((consumer, index) => ({
      ...consumer,
      targetSelection: {
        ...consumer.targetSelection,
        targets: index === 0 ? ["alpha"] : ["beta"],
      },
    })),
    nonImportInputs: [{
      consumer: base.consumers[0]!.consumer,
      path: "src/scan/rules/semgrep/fixture.yml",
      targetSelection: {
        ...base.consumers[0]!.targetSelection,
        targets: ["alpha"],
      },
    }],
  };
}

function putDiscoveryInputs(root: string): void {
  put(root, "src/scan/secrets.ts", 'const config = new URL("./rules/gitleaks-supabase.toml", import.meta.url);\nvoid config;\n');
  put(root, "src/scan/rules/gitleaks-supabase.toml", "title = \"fixture\"\n");
  put(root, "src/scan/semgrep.ts", 'const rules = new URL("./rules/semgrep/", import.meta.url);\nvoid rules;\n');
  put(root, "src/scan/rules/semgrep/fixture.yml", "rules: []\n");
  put(root, "package.json", '{"name":"fixture"}\n');
  put(root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
  put(root, "pnpm-workspace.yaml", "packages: []\n");
  put(root, ".nvmrc", "24\n");
  put(root, "tsconfig.json", '{}\n');
  put(root, ".github/actions/fixture/action.yml", [
    "name: fixture",
    "runs:",
    "  using: composite",
    "  steps:",
    '    - run: bash "$GITHUB_ACTION_PATH/run.sh"',
    "      shell: bash",
    "",
  ].join("\n"));
  put(root, ".github/actions/fixture/run.sh", "#!/usr/bin/env bash\nexit 0\n");
  put(root, ".github/workflows/corpus-drift.yml", [
    "jobs:",
    "  drift:",
    "    steps:",
    "      - uses: actions/setup-node@v4",
    "        with:",
    "          node-version-file: .nvmrc",
    "      - run: pnpm install --frozen-lockfile",
    "      - uses: ./.github/actions/fixture",
    "      - run: pnpm exec tsx src/cli/corpus-drift-relevance.ts ownership --out /tmp/ownership.json",
    "      - run: node src/cli/corpus-cache-transport.ts",
    "",
  ].join("\n"));
}

function createRepository(): { root: string; base: string; ownership: CorpusInputOwnership } {
  const root = mkdtempSync(join(tmpdir(), "harvey-corpus-relevance-"));
  disposable.push(root);
  git(root, ["init", "-q", "-b", "main"]);
  git(root, ["config", "user.name", "Fixture"]);
  git(root, ["config", "user.email", "fixture@example.test"]);

  for (const runtimeRoot of CORPUS_DRIFT_RUNTIME_ROOTS) {
    put(root, runtimeRoot, 'export { sharedValue } from "../shared/common.js";\n');
  }
  put(root, "src/cli/corpus-drift.ts", [
    'import "../shared/side.js";',
    'export { helper } from "../shared/helper.js";',
    'void import("../shared/dynamic.js");',
    'const required = require("../shared/required.js");',
    'import type { TypeOnly } from "../shared/type-only.js";',
    "void required;",
    "",
  ].join("\n"));
  put(root, "src/cli/corpus-cache-transport.ts", 'export { cacheHelper } from "../corpus-cache-helper.js";\n');
  put(root, "src/cli/corpus-drift-relevance.ts", "export const relevance = true;\n");
  put(root, "src/corpus-cache-helper.ts", "export const cacheHelper = 1;\n");
  put(root, "src/shared/common.ts", "export const sharedValue = 1;\n");
  put(root, "src/shared/side.ts", "export const side = 1;\n");
  put(root, "src/shared/helper.ts", 'export { nested as helper } from "./nested/index.js";\n');
  put(root, "src/shared/nested/index.ts", "export const nested = 1;\n");
  put(root, "src/shared/dynamic.ts", "export const dynamic = 1;\n");
  put(root, "src/shared/required.ts", "export const required = 1;\n");
  put(root, "src/shared/type-only.ts", "export interface TypeOnly { value: string }\n");
  putDiscoveryInputs(root);
  put(root, "report-template/render.mjs", "export const render = true;\n");
  put(root, "site/app/page.tsx", "export default function Page() { return null; }\n");
  return { root, base: commit(root, "base"), ownership: ownership() };
}

function mutate(path: string, body: string | Buffer): { receipt: CorpusDriftRelevanceReceipt; root: string } {
  const fixture = createRepository();
  put(fixture.root, path, body);
  commit(fixture.root, `change ${path}`);
  return {
    root: fixture.root,
    receipt: classifyCorpusDriftRelevance({ repoRoot: fixture.root, base: fixture.base, ownership: fixture.ownership }),
  };
}

function codes(receipt: CorpusDriftRelevanceReceipt): string[] {
  return receipt.reasons.map((reason) => reason.code);
}

afterEach(() => {
  for (const root of disposable.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("corpus-drift immutable runtime closure", () => {
  it("keeps the live manifest, baseline, schema, taxonomy, and mechanical implementation in runtime closure", () => {
    const sourceRoot = fileURLToPath(new URL("..", import.meta.url));
    const root = mkdtempSync(join(tmpdir(), "harvey-corpus-live-closure-"));
    disposable.push(root);
    execFileSync("git", ["clone", "-q", "--no-hardlinks", sourceRoot, root]);
    const head = git(root, ["rev-parse", "HEAD"]);
    const liveOwnership = defaultCorpusInputOwnership(["fixture"]);
    const receipt = classifyCorpusDriftRelevance({ repoRoot: root, base: head, ownership: liveOwnership });
    const runtimePaths = receipt.closure?.head.runtimeRootClosure.files.map((file) => file.path) ?? [];
    const discoveredPaths = discoverCorpusNonImportInputs({ repoRoot: root, pinnedTargets: ["fixture"] }).map((input) => input.path);

    expect(receipt.decision).toBe("declared-no-op");
    expect(runtimePaths).toEqual(expect.arrayContaining([
      "src/scan/external-corpus.ts",
      "src/findings.ts",
      "src/scan/mechanical.ts",
      "src/scan/mechanical-engine-registry.ts",
      "src/scan/mechanical-detector-registry.ts",
      "src/scan/secrets.ts",
      "src/scan/semgrep.ts",
    ]));
    expect(discoveredPaths).not.toEqual(expect.arrayContaining([
      "src/scan/external-corpus.ts",
      "src/findings.ts",
      "src/scan/mechanical.ts",
      "src/scan/mechanical-engine-registry.ts",
      "src/scan/mechanical-detector-registry.ts",
    ]));
  });

  it("discovers every live non-import path class and newly referenced members automatically", () => {
    const fixture = createRepository();
    const initial = discoverCorpusNonImportInputs({ repoRoot: fixture.root, pinnedTargets: ["beta", "alpha", "alpha"] });
    const initialPaths = initial.map((input) => input.path);
    expect(initialPaths).toEqual(expect.arrayContaining([
      "src/scan/rules/gitleaks-supabase.toml",
      "src/scan/rules/semgrep/fixture.yml",
      ".github/workflows/corpus-drift.yml",
      ".github/actions/fixture/action.yml",
      ".github/actions/fixture/run.sh",
      "package.json",
      "pnpm-lock.yaml",
      "pnpm-workspace.yaml",
      ".nvmrc",
      "tsconfig.json",
    ]));
    expect(initial.every((input) => input.targetSelection.targets.join(",") === "alpha,beta"
      && input.consumer.length > 0
      && input.targetSelection.provenance.length > 0
      && input.targetSelection.falsifier.length > 0)).toBe(true);

    put(fixture.root, "src/scan/rules/semgrep/new-rule.yaml", "rules: []\n");
    put(fixture.root, ".github/actions/new-action/action.yaml", [
      "name: new action",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - run: bash ${{ github.action_path }}/nested/helper.sh",
      "      shell: bash",
      "",
    ].join("\n"));
    put(fixture.root, ".github/actions/new-action/nested/helper.sh", "#!/usr/bin/env bash\nexit 0\n");
    put(fixture.root, ".github/workflows/corpus-drift.yml", [
      "jobs:",
      "  drift:",
      "    steps:",
      "      - uses: actions/setup-node@v4",
      "        with:",
      "          node-version-file: .nvmrc",
      "      - run: pnpm install --frozen-lockfile",
      "      - uses: ./.github/actions/fixture",
      "      - uses: ./.github/actions/new-action",
      "      - run: pnpm exec tsx src/cli/corpus-drift-relevance.ts ownership --out /tmp/ownership.json",
      "      - run: node src/cli/corpus-cache-transport.ts",
      "",
    ].join("\n"));
    commit(fixture.root, "add discovered path-class members");
    const expandedPaths = discoverCorpusNonImportInputs({ repoRoot: fixture.root, pinnedTargets: ["alpha", "beta"] }).map((input) => input.path);
    expect(expandedPaths).toEqual(expect.arrayContaining([
      "src/scan/rules/semgrep/new-rule.yaml",
      ".github/actions/new-action/action.yaml",
      ".github/actions/new-action/nested/helper.sh",
    ]));
  });

  it("classifies known config, action, and runtime identity changes as owned inputs", () => {
    const fixture = createRepository();
    const discovered = discoverCorpusNonImportInputs({ repoRoot: fixture.root, pinnedTargets: ["alpha", "beta"] });
    const registeredOwnership = buildCorpusInputOwnership({
      pinnedTargets: ["alpha", "beta"],
      mechanicalOwnership: {
        schema: 1,
        producers: [{ producer: "fixture-producer", phase: "structural-ast", order: 10, module: "M1", registryFile: "src/scan/mechanical-detector-registry.ts" }],
      },
      nonImportInputs: discovered,
    });
    put(fixture.root, "src/scan/rules/gitleaks-supabase.toml", "title = \"changed\"\n");
    put(fixture.root, ".github/actions/fixture/run.sh", "#!/usr/bin/env bash\nexit 1\n");
    put(fixture.root, "package.json", '{"name":"changed"}\n');
    commit(fixture.root, "change registered inputs");
    const receipt = classifyCorpusDriftRelevance({ repoRoot: fixture.root, base: fixture.base, ownership: registeredOwnership });

    expect(receipt.decision).toBe("full-scan");
    for (const path of ["src/scan/rules/gitleaks-supabase.toml", ".github/actions/fixture/run.sh", "package.json"]) {
      expect(receipt.reasons).toContainEqual(expect.objectContaining({ code: "owned-input-change", path }));
    }
    expect(receipt.reasons).not.toContainEqual(expect.objectContaining({ code: "unknown-runtime-input" }));
    expect(receipt.targetSelections.every((selection) => selection.targets.join(",") === "alpha,beta")).toBe(true);
  });

  it("walks the exact nine roots plus the workflow command with runtime-only static/dynamic edges", () => {
    const fixture = createRepository();
    const receipt = classifyCorpusDriftRelevance({ repoRoot: fixture.root, base: fixture.base, ownership: fixture.ownership });

    expect(receipt.decision).toBe("declared-no-op");
    expect(receipt.git).toMatchObject({ base: fixture.base, head: fixture.base, clean: true });
    expect(receipt.closure?.head.roots).toEqual([
      ...CORPUS_DRIFT_RUNTIME_ROOTS,
      "src/cli/corpus-cache-transport.ts",
      "src/cli/corpus-drift-relevance.ts",
    ]);
    const paths = receipt.closure?.head.files.map((file) => file.path);
    expect(paths).toEqual(expect.arrayContaining([
      "src/shared/helper.ts",
      "src/shared/nested/index.ts",
      "src/shared/dynamic.ts",
      "src/shared/required.ts",
      "src/corpus-cache-helper.ts",
    ]));
    expect(paths).not.toContain("src/shared/type-only.ts");
    expect(receipt.closure?.head.edges.map((edge) => edge.kind)).toEqual(expect.arrayContaining(["import", "export", "dynamic-import", "require"]));
    expect(receipt.assessment).toMatchObject({ status: "nothing-assessed", unitsAssessed: 0 });
    expect(receipt.assessment.statement).toMatch(/Nothing was assessed.*not an assessed-clean/i);
  });

  it.each([
    ["producer", "src/cli/corpus-drift.ts", 'import "../shared/side.js";\nexport const changed = true;\n', "alpha"],
    ["helper", "src/shared/common.ts", "export const sharedValue = 2;\n", "beta"],
    ["registered data", "src/scan/rules/semgrep/fixture.yml", "rules:\n  - id: changed\n", "alpha"],
    ["workflow-discovered helper", "src/corpus-cache-helper.ts", "export const cacheHelper = 2;\n", "alpha"],
  ])("forces a full scan for a representative %s change", (_label, path, body, expectedTarget) => {
    const { receipt } = mutate(path, body);
    expect(receipt.decision).toBe("full-scan");
    expect(codes(receipt)).toContain("owned-input-change");
    expect(receipt.targetSelections.some((selection) => selection.targets.includes(expectedTarget))).toBe(true);
    expect(receipt.hostedBackstop.mode).toBe("required-full-pinned-corpus");
  });

  it("declares exact report-template and site changes disjoint without claiming they were assessed", () => {
    const fixture = createRepository();
    put(fixture.root, "report-template/render.mjs", "export const render = false;\n");
    put(fixture.root, "site/app/page.tsx", "export default function Page() { return <main />; }\n");
    commit(fixture.root, "change disjoint apps");

    const receipt = classifyCorpusDriftRelevance({ repoRoot: fixture.root, base: fixture.base, ownership: fixture.ownership });
    expect(receipt.decision).toBe("declared-no-op");
    expect(receipt.changed.flatMap((change) => [change.oldPath, change.newPath])).toEqual(expect.arrayContaining([
      "report-template/render.mjs",
      "site/app/page.tsx",
    ]));
    expect(receipt.assessment).toMatchObject({ status: "nothing-assessed", unitsAssessed: 0 });
    expect(receipt.targetSelections).toEqual([]);
  });

  it("checks both sides of a Git rename against their own immutable closures", () => {
    const fixture = createRepository();
    renameSync(join(fixture.root, "src/shared/helper.ts"), join(fixture.root, "src/shared/helper-renamed.ts"));
    put(fixture.root, "src/cli/corpus-drift.ts", [
      'import "../shared/side.js";',
      'export { helper } from "../shared/helper-renamed.js";',
      'void import("../shared/dynamic.js");',
      'const required = require("../shared/required.js");',
      "void required;",
      "",
    ].join("\n"));
    commit(fixture.root, "rename runtime helper");

    const receipt = classifyCorpusDriftRelevance({ repoRoot: fixture.root, base: fixture.base, ownership: fixture.ownership });
    expect(receipt.decision).toBe("full-scan");
    expect(receipt.changed).toContainEqual(expect.objectContaining({ status: "R", oldPath: "src/shared/helper.ts", newPath: "src/shared/helper-renamed.ts" }));
    expect(receipt.reasons).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "owned-input-change", path: "src/shared/helper.ts" }),
      expect.objectContaining({ code: "owned-input-change", path: "src/shared/helper-renamed.ts" }),
    ]));
  });

  it("fails open on nonliteral dynamic and unresolved literal runtime edges", () => {
    const dynamic = mutate("src/cli/corpus-drift.ts", 'const name = "../shared/dynamic.js";\nvoid import(name);\n');
    expect(dynamic.receipt.decision).toBe("full-scan");
    expect(codes(dynamic.receipt)).toContain("nonliteral-dynamic-edge");

    const unresolved = mutate("src/cli/corpus-drift.ts", 'import "../shared/missing.js";\n');
    expect(unresolved.receipt.decision).toBe("full-scan");
    expect(codes(unresolved.receipt)).toContain("unresolved-runtime-edge");
  });

  it("fails open on an unknown tracked runtime file and an untracked physical file", () => {
    const unknown = mutate("src/unowned-runtime.ts", "export const unknown = true;\n");
    expect(unknown.receipt.decision).toBe("full-scan");
    expect(codes(unknown.receipt)).toContain("unknown-runtime-input");

    const fixture = createRepository();
    put(fixture.root, "src/physical-untracked.ts", "export const unknown = true;\n");
    const dirty = classifyCorpusDriftRelevance({ repoRoot: fixture.root, base: fixture.base, ownership: fixture.ownership });
    expect(dirty.decision).toBe("full-scan");
    expect(codes(dirty)).toContain("dirty-root");
  });

  it("binds classification to the checked-out head rather than reading another commit through a mutable root", () => {
    const fixture = createRepository();
    put(fixture.root, "report-template/render.mjs", "export const render = false;\n");
    commit(fixture.root, "advance head");

    const receipt = classifyCorpusDriftRelevance({
      repoRoot: fixture.root,
      base: fixture.base,
      head: fixture.base,
      ownership: fixture.ownership,
    });
    expect(receipt.decision).toBe("full-scan");
    expect(codes(receipt)).toContain("head-mismatch");
    expect(receipt.git).toBeNull();
  });

  it("fails open before reading a copied non-Git root or conflicting ownership registry", () => {
    const nonGit = mkdtempSync(join(tmpdir(), "harvey-corpus-nongit-"));
    disposable.push(nonGit);
    const nonGitReceipt = classifyCorpusDriftRelevance({ repoRoot: nonGit, base: "HEAD", ownership: ownership() });
    expect(nonGitReceipt.decision).toBe("full-scan");
    expect(codes(nonGitReceipt)).toContain("non-git-root");

    const fixture = createRepository();
    const conflicted: CorpusInputOwnership = {
      ...fixture.ownership,
      consumers: [...fixture.ownership.consumers, fixture.ownership.consumers[0]!],
    };
    const conflict = classifyCorpusDriftRelevance({ repoRoot: fixture.root, base: fixture.base, ownership: conflicted });
    expect(conflict.decision).toBe("full-scan");
    expect(codes(conflict)).toContain("registry-conflict");
    expect(conflict.git).toBeNull();

    const malformed = classifyCorpusDriftRelevance({
      repoRoot: fixture.root,
      base: fixture.base,
      ownership: { schema: 1 } as CorpusInputOwnership,
    });
    expect(malformed.decision).toBe("full-scan");
    expect(codes(malformed)).toContain("registry-conflict");
    expect(malformed.git).toBeNull();
  });

  it("fails open on unreadable and malformed implementation blobs", () => {
    const unreadable = mutate("src/shared/common.ts", Buffer.from([0xff, 0xfe, 0xfd]));
    expect(unreadable.receipt.decision).toBe("full-scan");
    expect(codes(unreadable.receipt)).toContain("unreadable-input");

    const malformed = mutate("src/cli/corpus-drift.ts", "export const = ;\n");
    expect(malformed.receipt.decision).toBe("full-scan");
    expect(codes(malformed.receipt)).toContain("malformed-source");
  });

  it("fails open on tracked symlink and gitlink seams", () => {
    const symlinkFixture = createRepository();
    symlinkSync("common.ts", join(symlinkFixture.root, "src/shared/link.ts"));
    put(symlinkFixture.root, "src/cli/corpus-drift.ts", 'import "../shared/link.js";\n');
    commit(symlinkFixture.root, "add runtime symlink");
    const symlink = classifyCorpusDriftRelevance({ repoRoot: symlinkFixture.root, base: symlinkFixture.base, ownership: symlinkFixture.ownership });
    expect(symlink.decision).toBe("full-scan");
    expect(codes(symlink)).toContain("symlink-seam");

    const gitlinkFixture = createRepository();
    const object = "8c92f838e2b4c6311c5b970d2b32635d36de9a24";
    git(gitlinkFixture.root, ["update-index", "--add", "--cacheinfo", `160000,${object},vendor/nested-repo`]);
    mkdirSync(join(gitlinkFixture.root, "vendor/nested-repo"), { recursive: true });
    commit(gitlinkFixture.root, "add gitlink", false);
    const gitlink = classifyCorpusDriftRelevance({ repoRoot: gitlinkFixture.root, base: gitlinkFixture.base, ownership: gitlinkFixture.ownership });
    expect(gitlink.decision).toBe("full-scan");
    expect(codes(gitlink)).toContain("gitlink-seam");
  });
});
