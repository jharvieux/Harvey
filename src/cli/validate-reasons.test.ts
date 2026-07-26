// #1033 acceptance: "a gate that has never fired on a known-bad input is not evidence." These run
// the real CLI as a child process against a planted corpus — one reason whose falsifier now succeeds
// (the blocker is gone, the text still asserts it) and one malformed block — and assert the gate
// exits non-zero naming both.

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = "src/cli/validate-reasons.ts";

function plant(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-reasons-"));
  for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
  return dir;
}

function gate(root: string, ...args: string[]): { code: number; out: string } {
  try {
    return { code: 0, out: execFileSync("node_modules/.bin/tsx", [CLI, "--root", root, ...args], { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (e) {
    const err = e as { status: number; stdout: string; stderr: string };
    return { code: err.status, out: `${err.stdout}${err.stderr}` };
  }
}

const STALE_REASON = [
  "// REASON: nothing in this repo can do the thing (planted; its falsifier succeeds)",
  "// KIND: empirical",
  "// PROVENANCE: ASSUMED 2026-07-25",
  "// FALSIFIER: true",
].join("\n");

const LIVE_REASON = [
  "// REASON: the blocker this one describes really is still standing",
  "// KIND: empirical",
  "// PROVENANCE: MEASURED 2026-07-25",
  "// FALSIFIER: false",
].join("\n");

const DECISIONAL_REASON = [
  "REASON: out of scope pending an operator ruling",
  "KIND: decisional",
  "PROVENANCE: ASSUMED 2026-07-25",
  "OWNER: operator",
  "DECISION: docs/design/infrastructure-out-of-scope.md",
].join("\n");

describe("validate-reasons CLI", () => {
  it("fails loud on a planted reason whose falsifier now succeeds, and leaves the still-true one alone", () => {
    const { code, out } = gate(plant({ "stale.ts": STALE_REASON, "live.ts": LIVE_REASON }), "--revalidate");
    expect(code).toBe(1);
    expect(out).toContain("STALE");
    expect(out).toContain("planted; its falsifier succeeds");
    expect(out).not.toContain("really is still standing");
  });

  it("passes when every falsifier still exits non-zero", () => {
    const { code, out } = gate(plant({ "live.ts": LIVE_REASON }), "--revalidate");
    expect(code).toBe(0);
    expect(out).toContain("no reason has outlived its truth");
  });

  it("excludes decisional reasons from the re-validation pass instead of re-testing a human ruling", () => {
    const { code, out } = gate(plant({ "d.md": DECISIONAL_REASON }), "--revalidate");
    expect(code).toBe(0);
    expect(out).toContain("Re-validated 0 empirical falsifier(s); 1 decisional reason(s) excluded by kind");
  });

  it("fails structurally — with no command run — on an empirical reason carrying no falsifier", () => {
    const { code, out } = gate(plant({ "bad.md": STALE_REASON.split("\n").slice(0, 3).join("\n").replace(/\/\/ /g, "") }));
    expect(code).toBe(1);
    expect(out).toContain("unfalsifiable and therefore permanent");
  });
});
