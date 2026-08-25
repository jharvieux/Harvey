import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  put(root, ".github/workflows/corpus-drift.yml", "jobs:\n  drift:\n    steps:\n      - run: node src/cli/corpus-cache-transport.ts\n");
  put(root, "report-template/render.mjs", "export const render = true;\n");
  return { root, base: commit(root, "base") };
}

function run(root: string, base: string): { status: number | null; stdout: string; stderr: string; receipt: CorpusDriftRelevanceReceipt } {
  const inputs = mkdtempSync(join(tmpdir(), "harvey-corpus-relevance-inputs-"));
  disposable.push(inputs);
  const ownershipPath = join(inputs, "ownership.json");
  writeFileSync(ownershipPath, `${JSON.stringify(defaultCorpusInputOwnership(["fixture"]), null, 2)}\n`);
  const result = spawnSync(process.execPath, ["--import", "tsx", CLI, "classify", "--root", root, "--base", base, "--ownership", ownershipPath], {
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
      "--import", "tsx", CLI, "ownership", "--mechanical-ownership", mechanical, "--out", out,
    ], {
      encoding: "utf8",
      cwd: fileURLToPath(new URL("../..", import.meta.url)),
    });
    const generated = JSON.parse(readFileSync(out, "utf8")) as ReturnType<typeof defaultCorpusInputOwnership>;
    expect(result.status).toBe(0);
    expect(generated.schema).toBe(1);
    expect(generated.consumers.map((consumer) => consumer.runtimeRoots[0])).toEqual(CORPUS_DRIFT_RUNTIME_ROOTS);
    expect(generated.producers).toEqual([
      expect.objectContaining({ producer: "fixture-producer" }),
      expect.objectContaining({ producer: "fixture-dependency" }),
    ]);
    expect(generated.consumers[0]!.targetSelection.targets.length).toBeGreaterThan(0);
    expect(result.stderr).toMatch(/wrote schema 1 with 9 runtime roots, 2 live mechanical producer row/);
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
    const result = spawnSync(process.execPath, ["--import", "tsx", CLI, "classify", "--head", "HEAD"], {
      encoding: "utf8",
      cwd: fileURLToPath(new URL("../..", import.meta.url)),
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/requires --base.*--ownership/);
  });
});
