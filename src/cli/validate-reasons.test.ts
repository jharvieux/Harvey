// #1033 acceptance: "a gate that has never fired on a known-bad input is not evidence." These run
// the real CLI as a child process against a planted corpus — one reason whose falsifier now succeeds
// (the blocker is gone, the text still asserts it) and one malformed block — and assert the gate
// exits non-zero naming both.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
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
    expect(out).toContain("Untriaged claim-shaped lines");
    expect(out).toContain("prose.md:1  Harvey cannot analyse Elixir today.");
  });

  // #1347 — the census read `.md` only until 2026-07-28, so a claim written as a source comment
  // moved nothing. Through the CLI end-to-end, and paired with the code line beside it: a widening
  // to whole-file `.ts` would light the second one, which is ordinary code prose.
  it("censuses a claim in a .ts COMMENT and not the code line under it (#1347)", () => {
    const src = '// Harvey cannot analyse Elixir today.\nthrow new Error("cannot parse");\n';
    const { code, out } = gate(plant({ "loader.ts": src }), ["--census"]);
    expect(code).toBe(0);
    expect(out).toContain("loader.ts:1  // Harvey cannot analyse Elixir today.");
    expect(out).not.toContain("loader.ts:2");
  });
});

// #1616 — the RATCHET path, which every test above skips by construction. `--root` narrows the
// census to a caller-chosen surface, and the ratchet declines to score a narrowed run (it would
// compare two different populations against a baseline written for DEFAULT_ROOTS). So the two
// `spawnSync` helpers that feed `attributeClaim` in that path — `blameLine` and `branchCommits`
// (#1401) — were reachable by no test at all: MEASURED 2026-07-31 by the acceptance verifier on
// PR #1613, stubbing `blameLine` to `return undefined` left `vitest run src/recorded-reasons.test.ts
// src/cli/validate-reasons.test.ts` at 88 passed. Every attributed row would have silently degraded
// to "provenance unavailable" — the #1407 shape, a library-level test with the CLI's own call site
// unproven.
//
// The fixture is a SELF-CONTAINED git repo, not a worktree of this one, and that is the load-bearing
// choice: attribution is a question about the commit range between HEAD and the base branch, so
// borrowing this checkout's history would make the answer depend on how CI cloned it — `attributeClaim`
// itself degrades to "no commit range" on a depth-1 checkout. A fresh `git init` over every tracked file
// gives full fidelity (every path a TOUCHES: line names exists, so the structural pass is clean) with
// a history the test writes itself.
//
// It copies the WORKING TREE (`git ls-files` piped through tar), not `git archive HEAD`. The archive
// form was written first and is wrong in a way that hides: it exports the COMMITTED tree, so an
// uncommitted edit to validate-reasons.ts is invisible to the fixture and the negative control below
// passed with the helper stubbed out. In CI the checkout is the commit under review either way, which
// is exactly what makes that a silent hole rather than a loud one.
describe("the claim ratchet's provenance attribution, through the real CLI (#1616)", () => {
  const PLANT = "src/planted-claim.ts";
  const CLAIM = "// A planted census line: this shape cannot be attributed without a blame lookup.";
  let fixture: string;

  const git = (...args: string[]): string =>
    execFileSync("git", ["-c", "user.email=t@example.com", "-c", "user.name=Test", "-c", "commit.gpgsign=false", ...args], {
      cwd: fixture,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

  /** The real CLI over the fixture as its OWN repo root — no `--root`, so the ratchet scores. */
  const ratchet = (): { code: number; out: string } => {
    try {
      return { code: 0, out: execFileSync("node_modules/.bin/tsx", [join(fixture, CLI)], { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) };
    } catch (e) {
      const err = e as { status: number; stdout: string; stderr: string };
      return { code: err.status, out: `${err.stdout}${err.stderr}` };
    }
  };

  /** The `↳` line the CLI prints under the planted row — the whole point of the attribution. */
  const attribution = (out: string): string => out.split("\n").find((l) => l.includes("↳"))?.trim() ?? "(no attribution line printed)";

  beforeAll(() => {
    fixture = mkdtempSync(join(tmpdir(), "harvey-ratchet-"));
    execFileSync("sh", ["-c", `git ls-files -z | tar --null -T - -cf - | tar -x -C '${fixture}'`], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    // The fixture is a copy of the TRACKED tree only, so it has no node_modules. The CLI resolves
    // its imports relative to its own path, so anything it pulls in from a package must resolve
    // inside the fixture. Symlink the real one in: it is not tracked, so it cannot arrive with the
    // tar, and this broke `main` once already (2026-07-31) when #1732 gave src/scored-gates.ts a
    // `yaml` import that this CLI transitively loads — neither PR was wrong alone.
    symlinkSync(join(REPO_ROOT, "node_modules"), join(fixture, "node_modules"), "dir");
    git("init", "-q", "-b", "main");
    git("add", "-A");
    git("commit", "-q", "-m", "fixture base");
    // Rebuild the baseline from the fixture itself, so the ONLY breach below is the planted line
    // whatever state this checkout's committed baseline happens to be in.
    execFileSync("node_modules/.bin/tsx", [join(fixture, CLI), "--update-baseline"], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
    git("add", "-A");
    git("commit", "-q", "--allow-empty", "-m", "fixture baseline");
  }, 120_000);

  afterAll(() => {
    if (fixture) rmSync(fixture, { recursive: true, force: true });
  });

  it("scores clean with nothing planted — so a breach below is the plant, not the fixture", () => {
    const { code, out } = ratchet();
    // Prefix only, NOT the full banner: #1732 renamed it to `Ratchet (#1318/#1399/#1685)` and the
    // original assertion's closing paren made it stop matching. That broke `main` (2026-07-31)
    // together with the node_modules symlink above — two independent interactions from one merge
    // pair, neither PR wrong alone. Assert the part that identifies the SCORED branch (the not-run
    // branch prints `Ratchet (#1318): not scored`) and let the issue list grow.
    expect(out).toContain("Ratchet (#1318/");
    expect(out).not.toContain("CLAIM RATCHET");
    expect(code).toBe(0);
  });

  it("says AUTHORED on this branch when the breaching line's commit is in the branch range", () => {
    git("checkout", "-q", "-b", "feature/planted");
    writeFileSync(join(fixture, PLANT), `${CLAIM}\n`);
    git("add", "-A");
    git("commit", "-q", "-m", "plant a claim line");
    const sha = git("rev-parse", "--short", "HEAD").trim();

    const { code, out } = ratchet();
    expect(code).toBe(1);
    expect(out).toContain(`NEW  ${PLANT}:1  ${CLAIM}`);
    // Both helpers had to work: branchCommits() to produce a range at all, blameLine() to name the
    // commit. The sha proves the blame lookup ran rather than defaulting.
    expect(attribution(out)).toBe(`↳ AUTHORED on this branch by ${sha} plant a claim line`);
    expect(out).toContain("1 row(s) AUTHORED on this branch, 0 INHERITED from the base branch, 0 unattributable.");
  });

  it("says INHERITED for the SAME line once its commit is reachable from the base branch", () => {
    git("checkout", "-q", "main");
    git("merge", "-q", "--ff-only", "feature/planted");
    const sha = git("rev-parse", "--short", "HEAD").trim();

    const { code, out } = ratchet();
    expect(code).toBe(1);
    // Same file, same line, same blame sha — only the RANGE moved, so this verdict and the one above
    // pin down both helpers together. MEASURED 2026-07-31 by stubbing each in turn: `blameLine`
    // returning undefined reddens both, and a `branchCommits` returning an empty set unconditionally
    // reddens the AUTHORED one while leaving this one green.
    expect(attribution(out)).toBe(`↳ INHERITED — already on the base branch by ${sha} plant a claim line`);
    expect(out).toContain("0 row(s) AUTHORED on this branch, 1 INHERITED from the base branch, 0 unattributable.");
  });

  it("says provenance unavailable, naming the blame, when the breaching line is not committed yet", () => {
    git("checkout", "-q", "-b", "feature/uncommitted");
    git("rm", "-q", "--cached", PLANT);
    git("commit", "-q", "-m", "untrack the planted line");

    const { code, out } = ratchet();
    expect(code).toBe(1);
    // blameLine's OWN failing direction: `git blame` exits non-zero on an untracked path, so the
    // helper returns undefined and the CLI states that rather than guessing an author.
    expect(attribution(out)).toBe(`↳ provenance unavailable: git blame could not read ${PLANT}:1 — an uncommitted line has no commit yet`);
    expect(out).toContain("0 row(s) AUTHORED on this branch, 0 INHERITED from the base branch, 1 unattributable.");
  });

  it("says provenance unavailable, naming the missing range, when no base branch resolves", () => {
    git("checkout", "-q", "--detach");
    git("branch", "-q", "-D", "main");
    git("branch", "-q", "-D", "feature/planted");
    git("branch", "-q", "-D", "feature/uncommitted");
    writeFileSync(join(fixture, PLANT), `${CLAIM}\n`);

    const { code, out } = ratchet();
    expect(code).toBe(1);
    // branchCommits' OWN failing direction, and it needs its own control: neither `origin/main` nor
    // `main` resolves, so `git merge-base` fails for both and the helper returns undefined BEFORE
    // blameLine is consulted. It is the shallow-CI-checkout case the CLI degrades to on purpose.
    expect(attribution(out)).toContain("↳ provenance unavailable: no commit range against the base branch");
    expect(out).toContain("0 row(s) AUTHORED on this branch, 0 INHERITED from the base branch, 1 unattributable.");
  });
});
