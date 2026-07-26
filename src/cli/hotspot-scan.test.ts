// #624: vitals resolves its git root and its `.vitals` provenance DB relative to CWD. hotspot-scan
// passed the target as a positional path but ran vitals in the Harvey worktree's CWD, so vitals
// analyzed the wrong tree — misreported as "plugin unavailable". This drives the real CLI with a
// fake `vitals_cli.py` on PATH that emits a report ONLY when a marker file is visible in its CWD; it
// succeeds only if the CLI runs vitals with cwd set to the target. (Real vitals does NOT require a
// pre-captured `.vitals` store — `report` computes churn×complexity from git — but the CWD-relative
// marker is a faithful stand-in for proving the CLI runs vitals from the target directory.)
// The fake also answers the `version` subcommand (#808) so the CLI's version assertion passes.

import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "hotspot-scan.ts");

// A stand-in for vitals_cli.py: it reports the expected version, then emits a valid (empty) report
// only when the target's marker file is present in the process CWD — proving the CLI runs vitals
// with cwd set to the target.
const FAKE_VITALS = `#!/bin/bash
if [ "$1" = "version" ]; then echo "Vitals v0.2.0"; exit 0; fi
if [ -f ".vitals/store.db" ]; then
  echo '{"hotspots":[],"coupling":[],"knowledge_risk":[]}'
  exit 0
fi
echo "No source files found. Check that the path contains code files." >&2
exit 1
`;

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("hotspot-scan CLI runs vitals from the target's CWD (#624)", () => {
  it("finds the target's .vitals/store.db when invoked from a different CWD", () => {
    const target = mkdtempSync(join(tmpdir(), "harvey-hotspot-target-"));
    dirs.push(target);
    mkdirSync(join(target, ".vitals"));
    writeFileSync(join(target, ".vitals", "store.db"), "fake-store");

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
