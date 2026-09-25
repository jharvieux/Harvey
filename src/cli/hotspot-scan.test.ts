// #624: vitals resolves its git root and its `.vitals` provenance DB relative to CWD. hotspot-scan
// passed the target as a positional path but ran vitals in the Harvey worktree's CWD, so vitals
// analyzed the wrong tree — misreported as "plugin unavailable". This drives the real CLI with a
// fake `vitals_cli.py` on PATH that emits a report ONLY when a marker file is visible in its CWD; it
// succeeds only if the CLI runs vitals with cwd set to the target. (Real vitals does NOT require a
// pre-captured `.vitals` store — `report` computes churn×complexity from git — but the CWD-relative
// marker is a faithful stand-in for proving the CLI runs vitals from the target directory.)
// The fake also answers the `version` subcommand (#808) so the CLI's version assertion passes.

import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "hotspot-scan.ts");
type M3Artifact = {
  historyBinding: { cacheKey: string; toolVersion: string; sourceDirty: boolean; windows: Record<string, number>; history: { status: string } };
  availability: { currentHealth: Record<string, unknown>; historyTrend: Record<string, unknown> };
  findings: Array<{ id: string; evidence: string }>;
};

// A stand-in for vitals_cli.py: it reports the expected version, then emits a valid (empty) report
// only when the target's marker file is present in the process CWD — proving the CLI runs vitals
// with cwd set to the target.
const FAKE_VITALS = `#!/bin/bash
if [ "$1" = "version" ]; then echo "Vitals v0.2.0"; exit 0; fi
if [ -f "target.marker" ]; then
  echo '{"hotspots":[],"coupling":[],"knowledge_risk":[]}'
  exit 0
fi
echo "No source files found. Check that the path contains code files." >&2
exit 1
`;

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) {
    try { chmodSync(join(d, ".vitals"), 0o755); } catch { /* absent */ }
    try { chmodSync(join(d, ".vitals", "store.db"), 0o644); } catch { /* absent */ }
    rmSync(d, { recursive: true, force: true });
  }
});

describe("hotspot-scan CLI runs vitals from the target's CWD (#624)", () => {
  it("finds the target's .vitals/store.db when invoked from a different CWD", () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-hotspot-target-"));
    dirs.push(target);
    writeFileSync(join(target, "target.marker"), "target cwd");

    const bin = mkdtempSync(join(tmpdir(), "harvey-hotspot-bin-"));
    dirs.push(bin);
    const fake = join(bin, "vitals_cli.py");
    writeFileSync(fake, FAKE_VITALS);
    chmodSync(fake, 0o755);

    // Run from the Harvey worktree (REPO_ROOT), NOT the target — the exact condition #624 hit. Only
    // the cwd:targetDir fix lets the fake vitals see the store; without it the CLI exits 1 and this
    // execFileSync throws.
    const out = execFileSync("node_modules/.bin/tsx", [CLI, target], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: ["ignore", "pipe", "pipe"],
    });
    expect(out).toContain("M3 hotspot table");
  });
});

// #1075: a real vitals report in "complexity-only" mode (no git history in the target) sets
// risk_score 0.0 for every hotspot — the CLI must disclose this as unranked rather than presenting
// the filesystem-walk-order table as a churn×complexity ranking.
const FAKE_VITALS_UNRANKED = `#!/bin/bash
if [ "$1" = "version" ]; then echo "Vitals v0.2.0"; exit 0; fi
cat <<'JSON'
{
  "mode": "complexity-only",
  "hotspots": [
    { "file_path": "z.ts", "health": 5, "role": "core", "centrality": 0, "churn_data": {"changes":0,"lines_added":0,"lines_removed":0,"author_count":0,"last_change":""}, "churn_label": "LOW", "complexity_score": 12, "coupling_strength": 0, "changes": 0, "risk_score": 0 },
    { "file_path": "a.ts", "health": 5, "role": "core", "centrality": 0, "churn_data": {"changes":0,"lines_added":0,"lines_removed":0,"author_count":0,"last_change":""}, "churn_label": "LOW", "complexity_score": 3, "coupling_strength": 0, "changes": 0, "risk_score": 0 }
  ],
  "coupling": [],
  "knowledge_risk": []
}
JSON
`;

const FAKE_VITALS_HISTORY = `#!/bin/bash
if [ "$1" = "version" ]; then echo "Vitals v0.2.0"; exit 0; fi
if [ -n "$VITALS_REPORT_MARKER" ]; then touch "$VITALS_REPORT_MARKER"; fi
if [ -f ".emit-empty" ]; then
  python3 -c 'import sqlite3; c=sqlite3.connect(".vitals/store.db"); c.execute("create table if not exists failed_capture(value text)"); c.commit(); c.close()'
  echo '{"mode":"full","hotspots":[],"coupling":[],"knowledge_risk":[],"provenance":{"has_data":false},"trends":null,"file_health":{},"files_analyzed":0}'
  exit 0
fi
if [ -f ".vitals/store.db" ] && python3 -c 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); raise SystemExit(0 if c.execute("select count(*) from sqlite_master where name=\\"old_history\\"").fetchone()[0] else 1)' .vitals/store.db; then
  trends=',"trends":{"previous_overall":7,"previous_timestamp":1,"days_since":3,"overall_delta":-1,"degrading":[{"file_path":"src/a.ts","previous":8,"current":6,"delta":-2}],"improving":[]}'
else
  trends=',"trends":null'
fi
python3 -c 'import sqlite3; c=sqlite3.connect(".vitals/store.db"); c.execute("create table if not exists advanced(value text)"); c.execute("insert into advanced values (\\"new-history\\")"); c.commit(); c.close()'
echo '{"mode":"full","hotspots":[{"file_path":"src/a.ts","health":6,"role":"core","centrality":0,"churn_data":{"changes":3,"lines_added":1,"lines_removed":1,"author_count":1,"last_change":"2026-09-20"},"churn_label":"HIGH","complexity_score":5,"coupling_strength":0,"changes":3,"risk_score":12}],"coupling":[],"knowledge_risk":[],"provenance":{"has_data":false},"overall_health":6,"file_health":{"src/a.ts":6},"files_analyzed":1'$trends'}'
`;

describe("hotspot-scan CLI discloses an unranked (complexity-only) vitals report (#1075)", () => {
  it("prints the M3 UNRANKED disclosure and writes an empty --hotspots-out (no downstream enrichment)", () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-hotspot-unranked-target-"));
    dirs.push(target);

    const bin = mkdtempSync(join(tmpdir(), "harvey-hotspot-unranked-bin-"));
    dirs.push(bin);
    const fake = join(bin, "vitals_cli.py");
    writeFileSync(fake, FAKE_VITALS_UNRANKED);
    chmodSync(fake, 0o755);

    const hotspotsOut = join(target, "hotspots.txt");
    const out = execFileSync("node_modules/.bin/tsx", [CLI, target, "--hotspots-out", hotspotsOut], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: ["ignore", "pipe", "pipe"],
    });
    expect(out).toContain("M3 UNRANKED");
    expect(out).toContain("complexity-only");
    expect(readFileSync(hotspotsOut, "utf8").trim()).toBe(""); // no files — nothing to enrich against
  });
});

describe("hotspot-scan isolates Vitals history from the client checkout (#2135)", () => {
  const setup = (history?: string) => {
    const target = mkdtempSync(join(tmpdir(), "harvey-vitals-history-target-"));
    const bin = mkdtempSync(join(tmpdir(), "harvey-vitals-history-bin-"));
    const cache = mkdtempSync(join(tmpdir(), "harvey-vitals-history-cache-"));
    dirs.push(target, bin, cache);
    mkdirSync(join(target, "src"));
    writeFileSync(join(target, "src", "a.ts"), "export const a = 1;\n");
    if (history !== undefined) {
      mkdirSync(join(target, ".vitals"));
      const db = join(target, ".vitals", "store.db");
      if (history === "old-history") {
        execFileSync("python3", ["-c", "import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); c.execute('create table old_history(value text)'); c.execute(\"insert into old_history values ('preserved')\"); c.execute('create table health_snapshots (snapshot_id integer primary key, timestamp real, scope text)'); c.execute('create table file_snapshots (snapshot_id integer, file_path text)'); c.execute('insert into health_snapshots values (1, ?, null)', (time.time()-86400,)); c.execute(\"insert into file_snapshots values (1, 'src/a.ts')\"); c.commit(); c.close()", db]);
      } else {
        writeFileSync(db, history);
      }
    }
    const fake = join(bin, "vitals_cli.py");
    writeFileSync(fake, FAKE_VITALS_HISTORY);
    chmodSync(fake, 0o755);
    return { target, bin, cache };
  };

  it("preserves a permitted prior snapshot, writes only audit cache, and emits a bound trend once", () => {
    const { target, bin, cache } = setup("old-history");
    chmodSync(join(target, ".vitals", "store.db"), 0o444);
    chmodSync(join(target, ".vitals"), 0o555);
    const clientBefore = readFileSync(join(target, ".vitals", "store.db"));
    const outPath = join(cache, "M3.json");
    const stdout = execFileSync("node_modules/.bin/tsx", [CLI, target, "--out", outPath, "--history-cache", cache], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const artifact = JSON.parse(readFileSync(outPath, "utf8")) as M3Artifact;
    expect(stdout).toContain("writable audit scratch ready; history usable (client-checkout)");
    expect(readFileSync(join(target, ".vitals", "store.db"))).toEqual(clientBefore);
    expect(readFileSync(join(cache, artifact.historyBinding.cacheKey, "store.db"), "utf8")).toContain("new-history");
    expect(artifact.historyBinding).toMatchObject({ toolVersion: "0.2.0", sourceDirty: false, windows: { churnDays: 90, couplingDays: 180, knowledgeDays: 730, provenanceDays: 30 } });
    expect(artifact.availability.historyTrend).toEqual({ status: "examined", unitsExamined: 1 });
    expect(artifact.findings.filter((finding) => finding.id === "M3-TREND-00")).toHaveLength(1);
  });

  it("classifies an actual history-subprocess failure, retries current health, and retains the client DB", () => {
    const { target, bin, cache } = setup("CORRUPT");
    const outPath = join(cache, "M3.json");
    const stdout = execFileSync("node_modules/.bin/tsx", [CLI, target, "--out", outPath, "--history-cache", cache], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const artifact = JSON.parse(readFileSync(outPath, "utf8")) as M3Artifact;
    expect(stdout).toContain("history failed (client-checkout)");
    expect(artifact.availability.currentHealth).toEqual({ status: "examined", unitsExamined: 1 });
    expect(artifact.availability.historyTrend).toMatchObject({ status: "failed", unitsExamined: 0 });
    expect(readFileSync(join(target, ".vitals", "store.db"), "utf8")).toBe("CORRUPT");
  });

  it("labels missing history as not assessed instead of a clean trend", () => {
    const { target, bin, cache } = setup();
    const outPath = join(cache, "M3.json");
    execFileSync("node_modules/.bin/tsx", [CLI, target, "--out", outPath, "--history-cache", cache], {
      cwd: REPO_ROOT,
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: ["ignore", "ignore", "pipe"],
    });
    const artifact = JSON.parse(readFileSync(outPath, "utf8")) as M3Artifact;
    expect(artifact.historyBinding.history.status).toBe("missing");
    expect(artifact.availability.historyTrend).toMatchObject({ status: "not-assessed", unitsExamined: 0 });
    expect(artifact.findings.find((finding) => finding.id === "M3-AVAILABILITY-00")?.evidence).toContain("History trend: not-assessed; 0 unit(s) examined");
  });

  it("does not let an empty failed capture supersede a successful history cache", () => {
    const { target, bin, cache } = setup();
    const outPath = join(cache, "M3.json");
    const run = () => execFileSync("node_modules/.bin/tsx", [CLI, target, "--out", outPath, "--history-cache", cache, "--artifacts-dir", cache], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` },
      stdio: ["ignore", "pipe", "pipe"],
    });
    run();
    const first = JSON.parse(readFileSync(outPath, "utf8")) as M3Artifact;
    const cachePath = join(cache, first.historyBinding.cacheKey, "store.db");
    const successfulHistory = readFileSync(cachePath);
    const successfulArtifact = readFileSync(outPath);
    const successfulPass = readFileSync(join(cache, "M3.pass.json"));
    writeFileSync(join(target, ".emit-empty"), "");
    const stdout = run();
    expect(stdout).toContain("Vitals history cache: retained");
    expect(stdout).toContain("M3 EMPTY CAPTURE");
    expect(stdout).toContain("currentHealth=failed/0");
    expect(readFileSync(cachePath)).toEqual(successfulHistory);
    expect(readFileSync(outPath)).toEqual(successfulArtifact);
    expect(readFileSync(join(cache, "M3.pass.json"))).toEqual(successfulPass);
  });

  it("fails cache writability preflight before invoking the Vitals report", () => {
    const { target, bin, cache } = setup();
    const marker = join(target, "report-ran.marker");
    chmodSync(cache, 0o555);
    expect(() => execFileSync("node_modules/.bin/tsx", [CLI, target, "--out", join(target, "M3.json"), "--history-cache", cache], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}`, VITALS_REPORT_MARKER: marker },
      stdio: ["ignore", "pipe", "pipe"],
    })).toThrow(/cache preflight|permission denied|EACCES/i);
    expect(existsSync(marker)).toBe(false);
  });
});
