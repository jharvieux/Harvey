// #624: vitals reads its precomputed store from `./.vitals/store.db` relative to CWD. hotspot-scan
// passed the target as a positional path but ran vitals in the Harvey worktree's CWD, so vitals
// found no store and exited "No source files found" — misreported as "plugin unavailable". This
// drives the real CLI with a fake `vitals_cli.py` on PATH that emits a report ONLY when the store
// is visible in its CWD; it succeeds only if the CLI runs vitals with cwd set to the target.

import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(REPO_ROOT, "src", "cli", "hotspot-scan.ts");

// A stand-in for vitals_cli.py: it emits a valid (empty) report only when the target's
// `.vitals/store.db` is present in the process CWD — exactly vitals's own CWD-relative store lookup.
const FAKE_VITALS = `#!/bin/bash
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
