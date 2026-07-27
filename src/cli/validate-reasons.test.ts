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

function gate(root: string, args: string[] = [], env: NodeJS.ProcessEnv = {}): { code: number; out: string } {
  try {
    return { code: 0, out: execFileSync("node_modules/.bin/tsx", [CLI, "--root", root, ...args], { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } }) };
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

// A live-only falsifier planted with `true` would go STALE if run — so it running offline would fail
// the gate. It must not: skipped-with-a-reason offline, executed only under --live (#1072).
const LIVE_TIER_REASON = [
  "// REASON: only a live Lighthouse pass can re-test this (planted; its falsifier would succeed if run)",
  "// KIND: empirical",
  "// PROVENANCE: MEASURED 2026-07-26",
  "// FALSIFIER: true",
  "// FALSIFIER-TIER: lighthouse",
].join("\n");

// The shape that made all five live falsifiers unfalsifiable until #1072's second half: `true <x>`
// would exit 0 (STALE) if the placeholder were bound, and exit 1 unrun — reading as "holds" — if it
// reached the shell verbatim. Which of those the gate reports is the whole point.
const PLACEHOLDER_REASON = [
  "// REASON: only a live Lighthouse pass can re-test this, against an operator-supplied target",
  "// KIND: empirical",
  "// PROVENANCE: MEASURED 2026-07-27",
  "// FALSIFIER: true <served-target>",
  "// FALSIFIER-TIER: lighthouse",
].join("\n");

describe("validate-reasons CLI", () => {
  it("skips a live-only falsifier offline — disclosed, not run, not a failure — and runs it under --live (#1072)", () => {
    const dir = plant({ "live-tier.ts": LIVE_TIER_REASON });
    const offline = gate(dir, ["--revalidate"]);
    expect(offline.code).toBe(0);
    expect(offline.out).toContain("SKIPPED-LIVE");
    expect(offline.out).toContain("live-only skipped");
    const live = gate(dir, ["--revalidate", "--live"]);
    expect(live.code).toBe(1);
    expect(live.out).toContain("STALE");
  });

  it("refuses an unknown --tier rather than silently enabling nothing", () => {
    const { code, out } = gate(plant({ "live-tier.ts": LIVE_TIER_REASON }), ["--revalidate", "--tier", "made-up"]);
    expect(code).toBe(1);
    expect(out).toContain("unknown --tier");
  });

  it("fails loud on a planted reason whose falsifier now succeeds, and leaves the still-true one alone", () => {
    const { code, out } = gate(plant({ "stale.ts": STALE_REASON, "live.ts": LIVE_REASON }), ["--revalidate"]);
    expect(code).toBe(1);
    expect(out).toContain("STALE");
    expect(out).toContain("planted; its falsifier succeeds");
    expect(out).not.toContain("really is still standing");
  });

  it("passes when every falsifier still exits non-zero", () => {
    const { code, out } = gate(plant({ "live.ts": LIVE_REASON }), ["--revalidate"]);
    expect(code).toBe(0);
    expect(out).toContain("no reason has outlived its truth");
  });

  it("excludes decisional reasons from the re-validation pass instead of re-testing a human ruling", () => {
    const { code, out } = gate(plant({ "d.md": DECISIONAL_REASON }), ["--revalidate"]);
    expect(code).toBe(0);
    expect(out).toContain("Re-validated 0 empirical falsifier(s); 0 live-only skipped; 1 decisional reason(s) excluded by kind");
  });

  it("reports an unbound live-tier placeholder UNVERIFIABLE instead of letting the shell eat it as a redirect (#1072)", () => {
    const dir = plant({ "placeholder.ts": PLACEHOLDER_REASON });
    const unbound = gate(dir, ["--revalidate", "--tier", "lighthouse"]);
    expect(unbound.code).toBe(1);
    expect(unbound.out).toContain("UNVERIFIABLE");
    expect(unbound.out).toContain("HARVEY_FALSIFIER_SERVED_TARGET");

    const bound = gate(dir, ["--revalidate", "--tier", "lighthouse"], { HARVEY_FALSIFIER_SERVED_TARGET: "/dev/null" });
    expect(bound.code).toBe(1);
    expect(bound.out).toContain("STALE");
    expect(bound.out).toContain("true /dev/null");
  });

  it("fails structurally — with no command run — on an empirical reason carrying no falsifier", () => {
    const { code, out } = gate(plant({ "bad.md": STALE_REASON.split("\n").slice(0, 3).join("\n").replace(/\/\/ /g, "") }));
    expect(code).toBe(1);
    expect(out).toContain("unfalsifiable and therefore permanent");
  });

  it("fails on a TOUCHES: path that is not in the checkout — a typo makes drift silent forever (#1246)", () => {
    const { code, out } = gate(plant({ "typo.ts": `${LIVE_REASON}\n// TOUCHES: src/detectors/no-such-file.ts` }));
    expect(code).toBe(1);
    expect(out).toContain("is not a path in this checkout");
  });

  // Silence from a reason with nothing to watch looks exactly like silence from a quiet subsystem,
  // so the two are separated in the output rather than left to be inferred (#1246).
  it("counts the empirical reasons subsystem drift can and cannot watch", () => {
    const { code, out } = gate(plant({ "unwatched.ts": LIVE_REASON }));
    expect(code).toBe(0);
    expect(out).toContain("Subsystem drift watches 0/1 empirical reason(s)");
  });

  it("counts claim-shaped prose outside every block instead of reading well-formed as complete (#1246)", () => {
    const { code, out } = gate(plant({ "prose.md": "Harvey cannot analyse Elixir today.\n" }), ["--census"]);
    expect(code).toBe(0);
    expect(out).toContain("Untriaged claim-shaped prose lines");
    expect(out).toContain("prose.md:1  Harvey cannot analyse Elixir today.");
  });
});
