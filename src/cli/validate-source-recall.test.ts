import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
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

function runFixture(findings: unknown[], options: { json?: boolean; real?: boolean; mutate?: (source: string) => string } = {}) {
  const root = temporary("harvey-source-recall-cli-");
  cpSync(join(REPO_ROOT, "package.json"), join(root, "package.json"));
  cpSync(join(REPO_ROOT, "src"), join(root, "src"), { recursive: true });
  symlinkSync(join(REPO_ROOT, "node_modules"), join(root, "node_modules"), "dir");
  const mechanical = join(root, "src", "scan", "mechanical.ts");
  writeFileSync(mechanical, `export async function runMechanicalScan() { return ${JSON.stringify(findings)}; }\n`);
  const cli = join(root, "src", "cli", "validate-source-recall.ts");
  if (options.mutate !== undefined) writeFileSync(cli, options.mutate(readFileSync(cli, "utf8")));
  const realSource = join(root, "src", "scan", "real-source-recall.ts");
  const bin = temporary("harvey-source-recall-bin-");
  let path = process.env.PATH ?? "";
  if (options.real) {
    const source = readFileSync(realSource, "utf8");
    const start = source.indexOf("export const REAL_SOURCE_RECALL_TARGETS");
    const end = source.indexOf("\n];", start) + 3;
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    const target = 'export const REAL_SOURCE_RECALL_TARGETS: RealSourceRecallTarget[] = [{ slug: "fixture", repo: "fixture/local", commit: "fixture", disclosureIssue: 0, entries: [{ id: "P-REAL-FIXTURE", kind: "positive", module: "REAL", cls: "fixture real-code gap", location: "fixture.ts", match: ["fixture"], expectedTier: "high", note: "local report-only fixture" }] }];';
    writeFileSync(realSource, `${source.slice(0, start)}${target}${source.slice(end)}`);
    const git = join(bin, "git");
    writeFileSync(git, `#!${process.execPath}\nprocess.exit(0);\n`);
    chmodSync(git, 0o755);
    path = `${bin}:${path}`;
  }
  const args = ["--import", TSX_LOADER, cli, ...(options.real ? ["--real"] : options.json ? ["--json"] : [])];
  const result = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8", env: { ...process.env, PATH: path } });
  if (options.json) {
    if (!result.stdout) throw new Error(`fixture CLI produced no JSON (status ${result.status}):\n${result.stderr}`);
    return { result, json: JSON.parse(result.stdout) as { ok: boolean; sourceTier: { rows: Array<{ kind: string; expectedTier: string; highFlagged: boolean }> } } };
  }
  return { result, json: undefined };
}

describe("validate-source-recall JSON gate contract (#2107)", () => {
  it("returns native status 1 for the same missed high-tier matrix in text and JSON modes", () => {
    const text = runFixture([]);
    const json = runFixture([], { json: true });
    expect(text.result.status, text.result.stderr).toBe(1);
    expect(text.result.stdout).toContain("GATE FAIL — high-tier source positives no longer caught at high");
    expect(json.result.status, json.result.stderr).toBe(1);
    expect(json.json?.ok).toBe(false);
    expect(json.json?.sourceTier.rows.filter((row) => row.kind === "positive" && row.expectedTier === "high" && !row.highFlagged)).not.toHaveLength(0);
  });

  it("returns native status 0 for the same passing matrix in text and JSON modes", () => {
    const text = runFixture(gatePassingFindings());
    const json = runFixture(gatePassingFindings(), { json: true });
    expect(text.result.status, text.result.stderr).toBe(0);
    expect(text.result.stdout).toContain("GATE PASS");
    expect(json.result.status, json.result.stderr).toBe(0);
    expect(json.json?.ok).toBe(true);
  });

  it("consumer-level control detects removal of JSON failure handling", () => {
    const { result, json } = runFixture([], { json: true, mutate: (source) => source.replace("process.exit(gatePass ? 0 : 1);", "process.exit(0);") });
    expect(result.status, result.stderr).toBe(0);
    expect(json?.ok).toBe(false);
  });

  it("keeps --real report-only when a local real-code gap is scored", () => {
    const { result } = runFixture([], { real: true });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("fixture (fixture/local @ fixture, disclosure #0):");
    expect(result.stdout).toContain("GAP");
    expect(result.stdout).toContain("REAL-CODE RECALL — 0/1");
  });
});
