import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { m9SourceTierCorpus, sourceTierCorpus } from "../scan/source-recall.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const TSX_LOADER = join(REPO_ROOT, "node_modules", "tsx", "dist", "loader.mjs");
const directories: string[] = [];

function temporary(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  directories.push(dir);
  return dir;
}

afterEach(() => {
  while (directories.length) rmSync(directories.pop()!, { recursive: true, force: true });
});

function finding(entry: { id: string; location: string; match?: string[] }) {
  return {
    id: entry.id,
    title: entry.match?.[0] ?? entry.id,
    severity: "High",
    confidence: "Confirmed",
    category: "fixture",
    taxonomy: "fixture",
    location: entry.location,
    status: "Open",
    evidence: entry.match?.join(" ") ?? "",
    impact: "",
    fix: "",
    value: 3,
    ease: 3,
    safety: 3,
    mechanical: true,
    precisionTier: "high",
  };
}

function gatePassingFindings() {
  return [...sourceTierCorpus(), ...m9SourceTierCorpus()]
    .filter((entry) => entry.kind === "positive" && entry.expectedTier === "high")
    .map(finding);
}

function runFixture(findings: unknown[], mutate?: (source: string) => string) {
  const root = temporary("harvey-source-recall-cli-");
  cpSync(join(REPO_ROOT, "package.json"), join(root, "package.json"));
  cpSync(join(REPO_ROOT, "src"), join(root, "src"), { recursive: true });
  symlinkSync(join(REPO_ROOT, "node_modules"), join(root, "node_modules"), "dir");
  const mechanical = join(root, "src", "scan", "mechanical.ts");
  writeFileSync(mechanical, `export async function runMechanicalScan() { return ${JSON.stringify(findings)}; }\n`);
  const cli = join(root, "src", "cli", "validate-source-recall.ts");
  if (mutate !== undefined) writeFileSync(cli, mutate(readFileSync(cli, "utf8")));
  const result = spawnSync(process.execPath, ["--import", TSX_LOADER, cli, "--json"], { cwd: root, encoding: "utf8" });
  if (!result.stdout) throw new Error(`fixture CLI produced no JSON (status ${result.status}):\n${result.stderr}`);
  return { result, json: JSON.parse(result.stdout) as { ok: boolean; sourceTier: { rows: Array<{ kind: string; expectedTier: string; highFlagged: boolean }> } } };
}

describe("validate-source-recall JSON gate contract (#2107)", () => {
  it("returns the same nonzero gate verdict in JSON mode and includes the missed high-tier evidence", () => {
    const { result, json } = runFixture([]);
    expect(result.status, result.stderr).toBe(1);
    expect(json.ok).toBe(false);
    expect(json.sourceTier.rows.filter((row) => row.kind === "positive" && row.expectedTier === "high" && !row.highFlagged)).not.toHaveLength(0);
  });

  it("returns JSON ok and status 0 when the local producer supplies every required high-tier hit", () => {
    const { result, json } = runFixture(gatePassingFindings());
    expect(result.status, result.stderr).toBe(0);
    expect(json.ok).toBe(true);
  });

  it("consumer-level control detects removal of JSON failure handling while keeping --real separate", () => {
    const { result, json } = runFixture([], (source) => source.replace("process.exit(gatePass ? 0 : 1);", "process.exit(0);"));
    expect(result.status, result.stderr).toBe(0);
    expect(json.ok).toBe(false);
  });
});
