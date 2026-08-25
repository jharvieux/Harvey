import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  CORPUS_DRIFT_RUNTIME_ROOTS,
  defaultCorpusInputOwnership,
  type CorpusDriftRelevanceReceipt,
} from "../corpus-drift-relevance.js";

const CLI = fileURLToPath(new URL("./corpus-drift-relevance.ts", import.meta.url));
const TSX = createRequire(import.meta.url).resolve("tsx");
const disposable: string[] = [];

function git(root: string, args: string[]): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8" }).trim();
}

function put(root: string, path: string, body: string): void {
  const absolute = join(root, path);
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, body);
}

function commit(root: string, message: string): string {
  git(root, ["add", "-A"]);
  git(root, ["commit", "-qm", message]);
  return git(root, ["rev-parse", "HEAD"]);
}

function fixture(): { root: string; base: string } {
  const root = mkdtempSync(join(tmpdir(), "harvey-corpus-relevance-cli-"));
  disposable.push(root);
  git(root, ["init", "-q", "-b", "main"]);
  git(root, ["config", "user.name", "Fixture"]);
  git(root, ["config", "user.email", "fixture@example.test"]);
  for (const runtimeRoot of CORPUS_DRIFT_RUNTIME_ROOTS) put(root, runtimeRoot, "export const runtime = true;\n");
  put(root, "src/cli/corpus-cache-transport.ts", "export const transport = true;\n");
  put(root, "src/cli/corpus-drift-relevance.ts", "export const relevance = true;\n");
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
  put(root, "report-template/render.mjs", "export const render = true;\n");
  return { root, base: commit(root, "base") };
}

function run(root: string, base: string): { status: number | null; stdout: string; stderr: string; receipt: CorpusDriftRelevanceReceipt } {
  const inputs = mkdtempSync(join(tmpdir(), "harvey-corpus-relevance-inputs-"));
  disposable.push(inputs);
  const ownershipPath = join(inputs, "ownership.json");
  writeFileSync(ownershipPath, `${JSON.stringify(defaultCorpusInputOwnership(["fixture"]), null, 2)}\n`);
  const result = spawnSync(process.execPath, ["--import", TSX, CLI, "classify", "--root", root, "--base", base, "--ownership", ownershipPath], {
    encoding: "utf8",
    cwd: fileURLToPath(new URL("../..", import.meta.url)),
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    receipt: JSON.parse(result.stdout) as CorpusDriftRelevanceReceipt,
  };
}

afterEach(() => {
  for (const root of disposable.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("corpus-drift-relevance CLI", () => {
  it("loads sync-stdio before every other import", () => {
    expect(readFileSync(CLI, "utf8").split("\n")[0]).toBe('import "./sync-stdio.js";');
  });

  it("generates canonical ownership from the exact C3 schema without a workflow-side map", () => {
    const repository = fixture();
    const inputs = mkdtempSync(join(tmpdir(), "harvey-corpus-ownership-cli-"));
    disposable.push(inputs);
    const mechanical = join(inputs, "mechanical.json");
    const out = join(inputs, "ownership.json");
    writeFileSync(mechanical, `${JSON.stringify({
      schema: 1,
      producers: [{
        producer: "fixture-producer",
        phase: "structural-ast",
        order: 10,
        module: "M1",
        registryFile: "src/scan/mechanical-detector-registry.ts",
      }, {
        producer: "fixture-dependency",
        phase: "dependency-advisory",
        order: 10,
        module: "M1",
        registryFile: "src/scan/mechanical-dependency-registry.ts",
      }],
    }, null, 2)}\n`);
    const result = spawnSync(process.execPath, [
      "--import", TSX, CLI, "ownership", "--mechanical-ownership", mechanical, "--out", out,
    ], {
      encoding: "utf8",
      cwd: repository.root,
    });
    expect(result.status).toBe(0);
    const generated = JSON.parse(readFileSync(out, "utf8")) as ReturnType<typeof defaultCorpusInputOwnership>;
    expect(generated.schema).toBe(1);
    expect(generated.consumers.map((consumer) => consumer.runtimeRoots[0])).toEqual(CORPUS_DRIFT_RUNTIME_ROOTS);
    expect(generated.producers).toEqual([
      expect.objectContaining({ producer: "fixture-producer" }),
      expect.objectContaining({ producer: "fixture-dependency" }),
    ]);
    expect(generated.consumers[0]!.targetSelection.targets.length).toBeGreaterThan(0);
    expect(generated.nonImportInputs.length).toBeGreaterThan(0);
    expect(result.stderr).toMatch(/wrote schema 1 with 9 runtime roots, 2 live mechanical producer row/);
  });

  it("ships unflagged ownership with discovered inputs and fails loudly when a live registration disappears", () => {
    const repository = fixture();
    const outputs = mkdtempSync(join(tmpdir(), "harvey-corpus-shipping-ownership-"));
    disposable.push(outputs);
    const out = join(outputs, "ownership.json");
    const invoke = () => spawnSync(process.execPath, ["--import", TSX, CLI, "ownership", "--out", out], {
      encoding: "utf8",
      cwd: repository.root,
    });

    const generatedResult = invoke();
    expect(generatedResult.status).toBe(0);
    const generated = JSON.parse(readFileSync(out, "utf8")) as ReturnType<typeof defaultCorpusInputOwnership>;
    expect(generated.nonImportInputs.length).toBeGreaterThan(0);
    expect(generated.nonImportInputs).toEqual(expect.arrayContaining([
      expect.objectContaining({ consumer: "src/scan/secrets.ts", path: "src/scan/rules/gitleaks-supabase.toml" }),
      expect.objectContaining({ consumer: "src/scan/semgrep.ts", path: "src/scan/rules/semgrep/fixture.yml" }),
      expect.objectContaining({ consumer: ".github/workflows/corpus-drift.yml", path: ".github/actions/fixture/action.yml" }),
      expect.objectContaining({ consumer: ".github/actions/fixture/action.yml", path: ".github/actions/fixture/run.sh" }),
      expect.objectContaining({ consumer: ".github/workflows/corpus-drift.yml", path: "package.json" }),
      expect.objectContaining({ consumer: ".github/workflows/corpus-drift.yml", path: "pnpm-lock.yaml" }),
      expect.objectContaining({ consumer: ".github/workflows/corpus-drift.yml", path: "pnpm-workspace.yaml" }),
      expect.objectContaining({ consumer: ".github/workflows/corpus-drift.yml", path: ".nvmrc" }),
      expect.objectContaining({ consumer: ".github/workflows/corpus-drift.yml", path: "tsconfig.json" }),
    ]));
    expect(generated.nonImportInputs.every((input) => input.targetSelection.targets.length > 0
      && input.targetSelection.provenance.length > 0
      && input.targetSelection.falsifier.length > 0)).toBe(true);

    put(repository.root, "src/scan/secrets.ts", "export const registrationWasRemoved = true;\n");
    commit(repository.root, "remove gitleaks registration");
    rmSync(out, { force: true });
    const missingRegistration = invoke();
    expect(missingRegistration.status).toBe(2);
    expect(missingRegistration.stderr).toMatch(/discovery disagreement.*no longer registers.*gitleaks-supabase\.toml/);
  });

  it("prints a machine receipt that distinguishes nothing-assessed no-op from full scan", () => {
    const { root, base } = fixture();
    put(root, "report-template/render.mjs", "export const render = false;\n");
    commit(root, "change report renderer");

    const noOp = run(root, base);
    expect(noOp.status).toBe(0);
    expect(noOp.receipt.decision).toBe("declared-no-op");
    expect(noOp.receipt.assessment).toMatchObject({ status: "nothing-assessed", unitsAssessed: 0 });
    expect(noOp.stderr).toMatch(/declared-no-op — nothing assessed/);

    put(root, "src/cli/corpus-drift.ts", "export const runtime = false;\n");
    commit(root, "change producer");
    const full = run(root, base);
    expect(full.status).toBe(0);
    expect(full.receipt.decision).toBe("full-scan");
    expect(full.receipt.reasons).toEqual(expect.arrayContaining([expect.objectContaining({ code: "owned-input-change" })]));
    expect(full.stderr).toMatch(/full-scan.*hosted full-pinned-corpus gate remains the backstop/);
  });

  it("rejects malformed invocation instead of guessing a Git range", () => {
    const result = spawnSync(process.execPath, ["--import", TSX, CLI, "classify", "--head", "HEAD"], {
      encoding: "utf8",
      cwd: fileURLToPath(new URL("../..", import.meta.url)),
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/requires --base.*--ownership/);
  });
});
