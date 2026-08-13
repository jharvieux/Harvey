// #1516 (remainder of #1509) — NOTHING ASSERTED THE SAVED BINARY CACHE WAS COMPLETE.
//
// The 2026-07-29 outage: semgrep installed to the runner's preinstalled /opt/pipx_bin, which is not
// under the cached paths. A cache was saved holding the three curl'd binaries and no semgrep, every
// later run took a cache HIT, skipped the install, and had no semgrep at all — blocking every open
// PR for a day. #1509 fixed the cause (PIPX_HOME/PIPX_BIN_DIR). It left the PROPERTY unguarded: the
// liveness check used `command -v`, which searches the whole PATH, so any tool resolving from a
// system location still looked like a successfully populated cache.
//
// The failure is displaced in TIME AND BLAME — the PR that poisons the cache goes green and an
// unrelated PR pays for it — which is why this is a gate and not a comment.
//
// MEASURED 2026-07-31 against the identical incomplete tree used in the second test below:
//   old check (`command -v` over the full PATH) -> exit 0, printed "mechanical binaries OK"
//   new check (`-x "$BIN_DIR/$b"`)              -> exit 1, naming semgrep
// so the guard is load-bearing rather than decorative.

import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "yaml";
import { readFileSync } from "node:fs";
import { readNamesSafe } from "./fs-walk.js";
import { TRUFFLEHOG_PINNED_VERSION } from "./scan/fixture-drift-contracts.js";

const ACTION_DIR = join(process.cwd(), ".github", "actions", "mechanical-binaries");
const SCRIPT = join(ACTION_DIR, "assert-complete.sh");
const TOOLS = ["semgrep", "trufflehog", "osv-scanner", "gitleaks"];

function tree(present: string[], executable: string[] = present): string {
  const dir = mkdtempSync(join(tmpdir(), "harvey-mech-bins-"));
  for (const b of present) {
    writeFileSync(join(dir, b), "#!/bin/sh\necho 1.0\n");
    if (executable.includes(b)) chmodSync(join(dir, b), 0o755);
  }
  return dir;
}

/** Runs the real guard, returning its exit code and output. `pathDir` fronts PATH, as a runner's preinstalled tooling does. */
function assertComplete(binDir: string, pathDir?: string): { status: number; out: string } {
  try {
    const out = execFileSync("bash", [SCRIPT], {
      encoding: "utf8",
      stdio: "pipe",
      env: { ...process.env, BIN_DIR: binDir, ...(pathDir ? { PATH: `${pathDir}:${process.env["PATH"]}` } : {}) },
    });
    return { status: 0, out };
  } catch (e) {
    const err = e as { status: number; stdout: string; stderr: string };
    return { status: err.status, out: `${err.stdout}${err.stderr}` };
  }
}

describe("#1516 the mechanical-binaries cache is asserted complete BEFORE it is saved", () => {
  it("pins TruffleHog to the captured release and rejects the former mutable-main installer", () => {
    const yml = readFileSync(join(ACTION_DIR, "action.yml"), "utf8");
    expect(yml).toContain(`TRUFFLEHOG=${TRUFFLEHOG_PINNED_VERSION}`);
    expect(yml).toContain(`releases/download/v\${{ steps.versions.outputs.trufflehog }}/trufflehog_\${{ steps.versions.outputs.trufflehog }}_linux_amd64.tar.gz`);
    expect(yml).toContain('trufflehog identity differs from the pinned release');
    expect(yml).not.toContain("trufflesecurity/trufflehog/main/scripts/install.sh");
    expect(yml).not.toContain("TRUFFLEHOG=head");
  });

  it("passes a tree holding all four, executable", () => {
    const dir = tree(TOOLS);
    try {
      const r = assertComplete(dir);
      expect(r.status).toBe(0);
      expect(r.out).toContain("COMPLETE");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // THE 2026-07-29 OUTAGE, reconstructed. semgrep is absent from the cached tree and present in a
  // preinstalled system location — the state in which the old `command -v` check reported success
  // and a cache was saved without it.
  it("fails when a tool resolves only from a system location, not from the cached tree", () => {
    const cached = tree(["trufflehog", "osv-scanner", "gitleaks"]);
    const system = tree(["semgrep"]);
    try {
      const r = assertComplete(cached, system);
      expect(r.status).toBe(1);
      expect(r.out).toContain("INCOMPLETE");
      expect(r.out).toContain("semgrep");
      // The diagnostic has to name where it DID resolve, or the next reader repeats the diagnosis.
      expect(r.out).toContain(join(system, "semgrep"));
    } finally {
      rmSync(cached, { recursive: true, force: true });
      rmSync(system, { recursive: true, force: true });
    }
  });

  // -x, not -e: caching ~/.local/bin without ~/.local/pipx leaves a semgrep shim that resolves and
  // then dies at exec, which is the reason the action caches both paths or neither.
  it("fails on a present-but-not-executable entry, the dangling-shim case", () => {
    const dir = tree(TOOLS, ["trufflehog", "osv-scanner", "gitleaks"]);
    try {
      const r = assertComplete(dir);
      expect(r.status).toBe(1);
      expect(r.out).toContain("semgrep");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("names every tool the action installs, so a fifth binary cannot be added past the guard", () => {
    const yml = readFileSync(join(ACTION_DIR, "action.yml"), "utf8");
    const script = readFileSync(SCRIPT, "utf8");
    for (const b of TOOLS) {
      expect(yml, `${b} is installed by the action`).toContain(b);
      expect(script, `${b} is asserted by the guard`).toContain(b);
    }
  });
});

// The script passing proves the CHECK works. It does not prove the check RUNS BEFORE THE SAVE, which
// is the whole of criterion 2 — and an assertion that runs after the cache is written guards nothing.
// So the ORDER is asserted against the action manifest itself.
describe("#1516 the save cannot be reached on an incomplete tree", () => {
  const steps = (parse(readFileSync(join(ACTION_DIR, "action.yml"), "utf8")) as { runs: { steps: Record<string, unknown>[] } }).runs.steps;
  const index = (pred: (s: Record<string, unknown>) => boolean) => steps.findIndex(pred);

  const restore = index((s) => String(s["uses"] ?? "").startsWith("actions/cache/restore"));
  const assertStep = index((s) => String(s["run"] ?? "").includes("assert-complete.sh"));
  const save = index((s) => String(s["uses"] ?? "").startsWith("actions/cache/save"));

  it("splits restore from save, rather than letting actions/cache save in a post step", () => {
    // The combined action saves at the end of the job — after every assertion here, and outside this
    // action's control. Owning the save is what makes the ordering below meaningful.
    expect(restore, "actions/cache/restore step").toBeGreaterThanOrEqual(0);
    expect(save, "actions/cache/save step").toBeGreaterThanOrEqual(0);
    expect(steps.some((s) => String(s["uses"] ?? "").match(/^actions\/cache@/))).toBe(false);
  });

  it("orders restore -> assert -> save", () => {
    expect(assertStep).toBeGreaterThan(restore);
    expect(save).toBeGreaterThan(assertStep);
  });

  // A conditional on the assert step would reintroduce the hole on whichever path skipped it, and
  // an `always()`/`!cancelled()` on the save would let a failed assert be written anyway.
  it("runs the assert unconditionally and gives the save no way to survive a failed one", () => {
    expect(steps[assertStep]?.["if"]).toBeUndefined();
    expect(String(steps[save]?.["if"] ?? "")).not.toMatch(/always|cancelled|failure/);
  });

  it("restores and saves under ONE key expression, so a save cannot land under a key nothing restores", () => {
    const keyOf = (i: number) => (steps[i]?.["with"] as Record<string, unknown>)["key"];
    expect(keyOf(save)).toBe(keyOf(restore));
    expect(String(keyOf(restore))).toContain("steps.versions.outputs.key");
  });
});

// #1516's fourth criterion is "the four consumers of this action still pass". MEASURED 2026-08-01:
// there are SEVEN, not four — free-recall.yml (#1185) and ci.yml joined after the issue was
// written, and reasons-drift.yml joined in #1826 (61dd15d), which landed the seventh consumer
// without updating this list and left `pnpm verify` red on `main`. That is the enumeration working:
// the count is listed here rather than quoted, because a consumer list in prose is exactly the kind
// of recorded number that decays — this action's blast radius IS its consumer set, and an eighth
// added silently would widen it with nobody re-reading the issue.
describe("#1516 the action's blast radius, enumerated rather than recalled", () => {
  const consumers = readNamesSafe(join(process.cwd(), ".github", "workflows"))
    .filter((f) => f.endsWith(".yml"))
    .filter((f) => readFileSync(join(process.cwd(), ".github", "workflows", f), "utf8").includes("./.github/actions/mechanical-binaries"))
    .sort();

  it("is used by exactly these seven workflows", () => {
    expect(consumers).toEqual([
      "ci.yml",
      "conservation.yml",
      "corpus-drift.yml",
      "dry-run-drift.yml",
      "free-recall.yml",
      "reasons-drift.yml",
      "secbench.yml",
    ]);
  });

  // The restore/save split changed the action's INSIDE. With no inputs declared and none passed,
  // every consumer's contract with it is byte-identical either side of the change.
  it("declares no inputs, and no consumer passes any — so the split changed nothing at the call site", () => {
    const manifest = parse(readFileSync(join(ACTION_DIR, "action.yml"), "utf8")) as { inputs?: unknown };
    expect(manifest.inputs).toBeUndefined();
    for (const f of consumers) {
      const text = readFileSync(join(process.cwd(), ".github", "workflows", f), "utf8");
      for (const m of text.matchAll(/uses: \.\/\.github\/actions\/mechanical-binaries\n(\s*)(\S)/g)) {
        expect(m[2], `${f} passes something to mechanical-binaries`).not.toBe("w");
      }
    }
  });
});
