import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "corpus-drift.ts");
const temporaryDirectories: string[] = [];

interface DiagnosticFinding {
  location: string;
  taxonomy: string;
  severity: "Low";
}

interface DiagnosticReplay {
  schemaVersion: 1;
  kind: "corpus-drift-diagnostic-replay";
  failedRow: {
    slug: string;
    check: string;
    module: string;
    detail: string;
  };
  currentFindings: DiagnosticFinding[];
  priorSnapshot: { path: string; findings: DiagnosticFinding[] } | null;
}

const finding = (location: string): DiagnosticFinding => ({
  location,
  taxonomy: "M5 — Else after return",
  severity: "Low",
});

const replay = (overrides: Partial<DiagnosticReplay> = {}): DiagnosticReplay => ({
  schemaVersion: 1,
  kind: "corpus-drift-diagnostic-replay",
  failedRow: {
    slug: "multi-tenant-starter",
    check: "M5-slop baseline",
    module: "M5-slop",
    detail: "DRIFT +1: expected 1 counted, got 2",
  },
  currentFindings: [finding("package.json:1"), finding("src/a.ts:4")],
  priorSnapshot: {
    path: "run1.json",
    findings: [finding("package.json:1"), finding("src/a.ts:4")],
  },
  ...overrides,
});

function runDiagnostic(input: unknown): {
  status: number | null;
  stderr: string;
  livenessReceipt: string;
} {
  const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-drift-diagnostic-"));
  temporaryDirectories.push(dir);
  const inputPath = join(dir, "replay.json");
  const livenessReceipt = join(dir, "liveness.txt");
  writeFileSync(inputPath, JSON.stringify(input));
  const result = spawnSync(process.execPath, ["--import", "tsx", CLI, "--diagnostic-replay", inputPath], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { ...process.env, HARVEY_LIVENESS_RECEIPT: livenessReceipt },
  });
  if (result.error) throw result.error;
  return { status: result.status, stderr: result.stderr, livenessReceipt };
}

afterEach(() => {
  for (const dir of temporaryDirectories.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("corpus-drift failed-row diagnostic replay (#1580)", () => {
  it("executes the shipping failed-row reporter for equal rows and stays non-green/non-liveness", () => {
    const result = runDiagnostic(replay());

    expect(result.status).toBe(1);
    expect(existsSync(result.livenessReceipt)).toBe(false);
    const ordered = [
      "DIAGNOSTIC REPLAY ONLY",
      "✗ DRIFT multi-tenant-starter / M5-slop baseline",
      "prior snapshot CONSULTED for multi-tenant-starter: run1.json",
      "2 M5-slop row(s) there vs 2 in this run",
      "committed manifest baseline in src/scan/external-corpus.ts",
      "NO ROW-LEVEL MOVEMENT",
      "INCOMPLETE POPULATION CHECK",
      "matching, loading, resolution, reachability, or invocation",
      "PRECISION FIX",
      "REAL REGRESSION",
      "SETUP FAILURE",
      "✗ COUNTED-BASELINE AGGREGATE FAILURE",
    ];
    let cursor = -1;
    for (const text of ordered) {
      const next = result.stderr.indexOf(text);
      expect(next, `${text} must appear after the preceding diagnostic output`).toBeGreaterThan(cursor);
      cursor = next;
    }
    expect(result.stderr).not.toMatch(/\n\s+ADDED \(/);
    expect(result.stderr).not.toMatch(/\n\s+REMOVED \(/);
    expect(result.stderr.match(/✗ COUNTED-BASELINE AGGREGATE FAILURE/g)).toHaveLength(1);
    expect(result.stderr).toContain("proven blast radius");
    expect(result.stderr).toContain("not only the issue examples");
  });

  it("reports actual ADDED and REMOVED identities through the same failed-row reporter", () => {
    const result = runDiagnostic(replay({
      currentFindings: [finding("src/new.ts:8")],
      priorSnapshot: { path: "run1.json", findings: [finding("src/old.ts:3")] },
    }));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("ADDED (1)");
    expect(result.stderr).toContain("src/new.ts:8  M5 — Else after return [Low]");
    expect(result.stderr).toContain("REMOVED (1)");
    expect(result.stderr).toContain("src/old.ts:3  M5 — Else after return [Low]");
    expect(result.stderr).not.toContain("NO ROW-LEVEL MOVEMENT");
  });

  it("discloses when no prior snapshot was supplied", () => {
    const result = runDiagnostic(replay({ priorSnapshot: null }));

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("NO PRIOR SNAPSHOT CONSULTED for multi-tenant-starter");
    expect(result.stderr).toContain("CURRENT (2)");
    expect(existsSync(result.livenessReceipt)).toBe(false);
  });

  it("fails loud on schema-invalid replay input without reporting drift or liveness", () => {
    const invalid = replay() as unknown as Record<string, unknown>;
    invalid.kind = "corpus-drift-result";
    invalid.pass = true;
    const result = runDiagnostic(invalid);

    expect(result.status).toBe(2);
    expect(result.stderr).toContain("corpus-drift diagnostic replay rejected");
    expect(result.stderr).toContain("must contain exactly");
    expect(result.stderr).not.toContain("✗ DRIFT");
    expect(result.stderr).not.toContain("INCOMPLETE POPULATION CHECK");
    expect(result.stderr).not.toContain("COUNTED-BASELINE AGGREGATE FAILURE");
    expect(existsSync(result.livenessReceipt)).toBe(false);
  });
});
