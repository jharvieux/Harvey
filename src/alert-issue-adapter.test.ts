import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ACTION_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", ".github", "actions", "alert-issue");
const ACTION_YML = resolve(ACTION_DIR, "action.yml");
const FIND_OR_UPDATE_SH = resolve(ACTION_DIR, "find-or-update.sh");

function runProductionAdapter(result: string, upstreamExit = 0) {
  const script = [
    "set -euo pipefail",
    `source "${FIND_OR_UPDATE_SH}"`,
    "find_or_update() {",
    `  printf '%s\\n' '${result}'`,
    `  return ${upstreamExit}`,
    "}",
    'run_production_find_or_update "Alert title" "Alert body"',
  ].join("\n");

  return spawnSync("bash", ["-c", script], { encoding: "utf8" });
}

describe("alert-issue production result adapter (#1348)", () => {
  it("binds the live non-drill action branch to the tested adapter", () => {
    const action = readFileSync(ACTION_YML, "utf8");
    expect(action.match(/run_production_find_or_update "\$TITLE" "\$BODY"/g)).toHaveLength(1);
    expect(action).not.toContain("result=$(find_or_update real");
  });

  it("parses and reports a created result from the production wire format", () => {
    const run = runProductionAdapter("created\t42\thttps://example.invalid/issues/42");
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toBe("Opened tracking issue https://example.invalid/issues/42.\n");
  });

  it("parses and reports a commented result from the production wire format", () => {
    const run = runProductionAdapter("commented\t42\t");
    expect(run.status, run.stderr).toBe(0);
    expect(run.stdout).toBe("Commented on existing tracking issue #42.\n");
  });

  it("rejects an unknown production status instead of treating it as commented", () => {
    const run = runProductionAdapter("unexpected\t42\t");
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("find_or_update returned unknown status 'unexpected'");
    expect(run.stdout).toBe("");
  });

  it("propagates find_or_update failure without reporting production success", () => {
    const run = runProductionAdapter("commented\t42\t", 23);
    expect(run.status).toBe(23);
    expect(run.stdout).toBe("");
  });
});
