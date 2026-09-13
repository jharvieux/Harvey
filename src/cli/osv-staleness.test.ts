import { spawn } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CURATED_CLAIMS } from "../scan/dependencies.js";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const CLI = join(ROOT, "src/cli/osv-staleness.ts");
const FETCH = join(ROOT, "src/__fixtures__/osv-staleness/fetch.mjs");

async function runCli(scenario: string): Promise<{ code: number | null; output: string }> {
  const child = spawn(process.execPath, ["--import", "tsx", "--import", FETCH, CLI], {
    cwd: ROOT,
    env: { ...process.env, HARVEY_OSV_STALENESS_SCENARIO: scenario },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 15_000,
  });
  let output = "";
  child.stdout.setEncoding("utf8").on("data", (chunk: string) => { output += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk: string) => { output += chunk; });
  return await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, output }));
  });
}

describe("shipping OSV staleness checker (#2054)", () => {
  it.each(["valid", "limit_excludes"])("verifies the complete curated population for %s", async (scenario) => {
    const result = await runCli(scenario);
    expect(result.output).toContain(`OFFLINE_FETCH_REQUESTS=${CURATED_CLAIMS.length}`);
    expect(result.output).toContain(`All ${CURATED_CLAIMS.length} curated claims still match OSV.`);
    expect(result.code).toBe(0);
  }, 20_000);

  it.each([
    ["overlap_open", "remains affected"],
    ["explicit_version", "remains affected"],
    ["limit_affects", "remains affected"],
    ["wrong_ecosystem", "no affected entry for npm/next"],
    ["missing_ecosystem", "malformed package identity"],
    ["unsupported_range", "unsupported type or malformed events"],
    ["malformed_event", "exactly one boundary"],
    ["malformed_versions", "malformed versions array"],
    ["conflicting_events", "conflicting boundaries at one version"],
    ["malformed_json", "cannot verify OSV response"],
  ])("fails a %s record with a concrete reason", async (scenario, reason) => {
    const result = await runCli(scenario);
    expect(result.output).toContain(`OFFLINE_FETCH_REQUESTS=${CURATED_CLAIMS.length}`);
    expect(result.output).toContain(reason);
    expect(result.output).toMatch(/\d+ of \d+ curated claims no longer match OSV\./);
    expect(result.code).toBe(1);
  }, 20_000);
});
