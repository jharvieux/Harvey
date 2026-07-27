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

/** The per-block validation errors the gate printed, so a control can assert it tripped ONE rule. */
const errors = (out: string): string[] => [...out.matchAll(/^ *• (.*)$/gm)].map((m) => m[1] ?? "");

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

// A supervised-path blocker correctly routed to a human — everything but the relay venue, which each
// control below supplies, so the DECISION: line is the only thing under test.
const RELAYED_REASON = [
  "// REASON: not wired up: .github/workflows/ is supervised and needs operator approval",
  "// KIND: decisional",
  "// PROVENANCE: MEASURED 2026-07-27",
  "// OWNER: operator",
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

  // #1319's rules reach the CLI, not just validateRecordedReason: the planted violations below must
  // take the real gate to a non-zero exit, or the rules are unit-tested prose. Each asserts EXACTLY
  // ONE error — a control that trips two rules at once no longer proves the rule it is named for.
  it("fails on impossibility vocabulary spent over an ASSUMED provenance (#1319)", () => {
    const planted = STALE_REASON.replace("can do the thing", "is out of reach").replace("FALSIFIER: true", "FALSIFIER: false");
    const { code, out } = gate(plant({ "budget.ts": planted }));
    expect(code).toBe(1);
    expect(errors(out)).toEqual([expect.stringContaining('says "out of reach" on an ASSUMED provenance')]);
  });

  it("fails on a supervised-path blocker recorded as empirical rather than relayed (#1319)", () => {
    const planted = LIVE_REASON.replace("the blocker this one describes really is still standing", "not wired up: .github/workflows/ is supervised and needs operator approval");
    const { code, out } = gate(plant({ "supervised.ts": planted }));
    expect(code).toBe(1);
    expect(errors(out)).toEqual([expect.stringContaining("produces a RELAY, never a silent stop")]);
  });

  // The venue rule shipped as /#\d+|\//, where any slash satisfied it. A relay with no findable venue
  // is the silent close wearing a field name, so a bare "go/no-go" must not buy one.
  it("fails on a supervised-path relay whose DECISION names no findable venue (#1319)", () => {
    const planted = [RELAYED_REASON, "// DECISION: pending a go/no-go"].join("\n");
    const { code, out } = gate(plant({ "no-venue.ts": planted }));
    expect(code).toBe(1);
    expect(errors(out)).toEqual([expect.stringContaining("names no venue for a supervised-path blocker")]);
  });

  it("passes the same relay once the DECISION points at the issue or the decision record (#1319)", () => {
    for (const venue of ["#1319", "docs/design/recorded-reasons.md"]) {
      const { code, out } = gate(plant({ "relay.ts": [RELAYED_REASON, `// DECISION: ${venue}`].join("\n") }));
      expect(errors(out)).toEqual([]);
      expect(code).toBe(0);
    }
  });

  // The negative control for the supervised-path rule's precision: this reason CITES a supervised
  // path as the record of a ruling rather than naming it as the blocker, and both vocabularies are
  // present one clause apart. Refusing it would be the gate crying wolf on a legitimate reason.
  it("passes an empirical reason that merely cites a supervised path as its reference (#1319)", () => {
    const planted = LIVE_REASON.replace(
      "the blocker this one describes really is still standing",
      "the source loader does not read .svelte files; the scope rationale and the operator ruling behind it are recorded in docs/design/infrastructure-out-of-scope.md",
    );
    const { code, out } = gate(plant({ "cites.ts": planted }));
    expect(errors(out)).toEqual([]);
    expect(code).toBe(0);
  });

  it("counts claim-shaped prose outside every block instead of reading well-formed as complete (#1246)", () => {
    const { code, out } = gate(plant({ "prose.md": "Harvey cannot analyse Elixir today.\n" }), ["--census"]);
    expect(code).toBe(0);
    expect(out).toContain("Untriaged claim-shaped prose lines");
    expect(out).toContain("prose.md:1  Harvey cannot analyse Elixir today.");
  });
});
