// Guards the SINGLE-KEY link between the dry-run scorecard and the gated corpus (#425). The dry-run
// no longer holds a second matcher: each planted bug names a corpus entry (corpusId) or an M2 replay
// (replayId), and detection is derived from the gated corpus — which cannot drift, it fails
// `pnpm verify`. These tests prove the link is intact and can't rot silently:
//   - every bug GROUND-TRUTH plants has an entry here (an unmapped bug is invisible, not "missed");
//   - every static bug's corpusId resolves to a real gated corpus entry (a dangling FK throws);
//   - every dynamic bug's replayId is a registered M2 replay (a live-run promise no code can keep);
//   - the corpus-derived verdicts on the committed findings are the expected ones — the historically
//     drifted RLS classes (#332/#337) score caught, the accepted WEBHOOK-REPLAY gap scores missed.

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { AUTOMATED_REPLAY_IDS } from "../pentest/verify.js";
import type { DynamicScorecard } from "../pentest/scorecard.js";
import { scoreCoverage, summarizeCoverage } from "../coverage-scorecard.js";
import { CORPUS, scoreEntry } from "../scan/calibration.js";
import { GROUND_TRUTH_BUGS, resolveDetection } from "./dry-run-scorecard.js";

const findings = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "dry-run", "findings.json"), "utf8")) as Finding[];

describe("dry-run planted bugs are keyed to the single gated answer key (#425)", () => {
  it("keys each bug to exactly one detection source — a static corpus entry XOR a dynamic replay", () => {
    for (const b of GROUND_TRUTH_BUGS) {
      expect(Boolean(b.corpusId) !== Boolean(b.replayId), `${b.id} must set exactly one of corpusId / replayId`).toBe(true);
    }
  });

  // A static bug's corpusId is a foreign key into the gated corpus. resolveDetection throws on a
  // dangling id, so this fails loud if a corpus entry is renamed/removed without re-keying here —
  // the drift the parallel matcher used to allow is now structurally impossible.
  it("every static bug's corpusId resolves to a gated corpus entry", () => {
    for (const b of GROUND_TRUTH_BUGS.filter((x) => x.corpusId)) {
      expect(CORPUS.find((e) => e.id === b.corpusId), `${b.id} → ${b.corpusId} is not in the gated corpus`).toBeDefined();
      expect(() => resolveDetection(b, findings)).not.toThrow();
    }
  });

  it.each(GROUND_TRUTH_BUGS.filter((b) => b.replayId).map((b) => [b.id, b.replayId!] as const))(
    "dynamic bug %s names a real registered M2 replay (%s)",
    (id, replayId) => {
      // "needs a live run" is only honest while a probe for this bug exists. Delete the replay (or
      // typo the id) and the bug becomes undetectable by any tier — which must fail here, not sit in
      // scorecard.json as a live-run promise no code can keep.
      expect(AUTOMATED_REPLAY_IDS, `${id} maps to replay "${replayId}" but no replay is registered under it`).toContain(replayId);
    },
  );

  // Guards the two files against drifting apart, which is how GROUND-TRUTH rows 9–12 once went
  // unlisted: they were planted and nothing required the scorecard to acknowledge them, so
  // `requires-live-run: 0` kept claiming nothing awaited a live run. Parsing the answer key is the
  // only check that fails when a row is added or removed rather than drifting along with it.
  it("has an entry for every bug GROUND-TRUTH plants — an unmapped bug is invisible, not 'missed'", () => {
    const groundTruth = readFileSync(join(import.meta.dirname, "..", "..", "targets", "calibration", "GROUND-TRUTH.md"), "utf8");
    // The planted-bug tables are the only ones keyed by a leading row NUMBER (`| 9 | SHADOW-API… |`);
    // every later corpus table is keyed by a string id, so this can't over-collect from them.
    const planted = [...groundTruth.matchAll(/^\| *\d+ *\| *([A-Z0-9-]+) *\|/gm)].map((m) => m[1]!);
    expect(planted.length, "parsed no planted-bug rows out of GROUND-TRUTH.md — the table format changed and this guard is silently vacuous").toBeGreaterThanOrEqual(12);

    const mapped = new Set(GROUND_TRUTH_BUGS.map((b) => b.id));
    expect(
      planted.filter((id) => !mapped.has(id)),
      "GROUND-TRUTH plants these bugs but GROUND_TRUTH_BUGS has no entry, so scorecard.json omits them entirely.",
    ).toEqual([]);
  });
});

describe("corpus-derived verdicts over the committed dry-run findings (#425)", () => {
  const scored = scoreCoverage(
    GROUND_TRUTH_BUGS.map((b) => ({
      id: b.id,
      severity: b.severity,
      location: b.location,
      expectedModule: b.expectedModule,
      detection: resolveDetection(b, findings),
    })),
  );
  const statusOf = (id: string) => scored.find((s) => s.id === id)!.status;

  // The exact under-selling #332 (RLS-AUTH-ROLE) and #337 (RLS-USING-TRUE) did: a class the gated
  // corpus proves detectable must not score requires-live-run/missed. Bound over the SAME committed
  // findings the corpus is scored against, so the two keys cannot disagree.
  it.each([
    ["RLS-USING-TRUE", "P-RLS-USING-TRUE-STATIC"],
    ["RLS-AUTH-ROLE", "P-RLS-AUTH-ROLE-STATIC"],
  ])("%s scores caught, matching its gated corpus entry %s on the same findings", (bugId, corpusId) => {
    const entry = CORPUS.find((e) => e.id === corpusId)!;
    expect(scoreEntry(entry, findings).pass, `${corpusId} must fire on the committed findings`).toBe(true);
    expect(statusOf(bugId)).toBe("caught");
  });

  it("WEBHOOK-REPLAY is the accepted no-mechanical-rule gap — scores missed, corpus entry is 'none' tier", () => {
    expect(statusOf("WEBHOOK-REPLAY")).toBe("missed");
    const bug = GROUND_TRUTH_BUGS.find((b) => b.id === "WEBHOOK-REPLAY")!;
    expect(CORPUS.find((e) => e.id === bug.corpusId)!.expectedTier).toBe("none");
  });

  it("every dynamic (M2) bug scores requires-live-run when NO pen-test scorecard is supplied", () => {
    for (const b of GROUND_TRUTH_BUGS.filter((x) => x.replayId)) expect(statusOf(b.id)).toBe("requires-live-run");
  });

  it("classifies all twelve planted bugs — none silently dropped", () => {
    expect(scored).toHaveLength(GROUND_TRUTH_BUGS.length);
    expect(GROUND_TRUTH_BUGS).toHaveLength(12);
  });
});

// #1310 — `statusFromDynamicProbe` was built for exactly this and had NO production caller for
// eleven days, so the four M2 rows could never leave requires-live-run however many live runs
// happened. These bind the dynamic half of resolveDetection in BOTH directions: a recorded verdict
// resolves the row, and an absent/undecided one still does not.
describe("dynamic (M2) rows resolve against a committed pen-test scorecard (#1310/#347)", () => {
  const dynamicBug = (id: string) => GROUND_TRUTH_BUGS.find((b) => b.replayId === id)!;
  const card = (probes: DynamicScorecard["probes"]): DynamicScorecard => ({
    target: "http://127.0.0.1:3100",
    generatedAt: "2026-07-31T08:27:46.786Z",
    allowDestructive: true,
    probes,
    summary: { caught: 0, cleared: 0, "not-applicable": 0, "not-run": 0, "not-assessed": 0 },
  });
  const probe = (findingId: string, status: DynamicScorecard["probes"][number]["status"]) =>
    ({ findingId, status, severity: "High", evidence: `${findingId} scored ${status}` }) as DynamicScorecard["probes"][number];

  it("a probe that CAUGHT the bug live scores caught, at high tier — a live replay asserts, it does not surface", () => {
    const d = resolveDetection(dynamicBug("SHADOW-API-VERSION"), findings, card([probe("SHADOW-API-VERSION", "caught")]));
    expect(d).not.toBeNull();
    expect(d!.caught).toBe(true);
    expect(d!.tier).toBe("high");
    expect(d!.note).toContain("http://127.0.0.1:3100");
  });

  // The direction that matters most: `cleared` means the probe RAN against a target where the bug is
  // planted and did not prove it. That is a MISS, and collapsing it into requires-live-run would hide
  // a real detection gap behind a deferral.
  it("a probe that ran and CLEARED the bug scores missed, not a deferral", () => {
    const d = resolveDetection(dynamicBug("CACHE-CROSS-USER"), findings, card([probe("CACHE-CROSS-USER", "cleared")]));
    expect(d!.caught).toBe(false);
    expect(d!.tier).toBeUndefined();
  });

  it.each(["not-applicable", "not-run"] as const)("a probe recorded %s yields no verdict — the row stays requires-live-run", (status) => {
    expect(resolveDetection(dynamicBug("NO-RATE-LIMIT"), findings, card([probe("NO-RATE-LIMIT", status)]))).toBeNull();
  });

  it("a scorecard that names OTHER replays leaves this row requires-live-run — it never borrows another probe's verdict", () => {
    expect(resolveDetection(dynamicBug("ANON-PRIVILEGED-RPC"), findings, card([probe("NO-RATE-LIMIT", "caught")]))).toBeNull();
  });

  it("scoreCoverage drops requires-live-run as the recorded verdicts land", () => {
    const live = card([
      probe("SHADOW-API-VERSION", "caught"),
      probe("NO-RATE-LIMIT", "caught"),
      probe("CACHE-CROSS-USER", "cleared"),
    ]);
    const summary = summarizeCoverage(
      scoreCoverage(GROUND_TRUTH_BUGS.map((b) => ({ id: b.id, severity: b.severity, location: b.location, expectedModule: b.expectedModule, detection: resolveDetection(b, findings, live) }))),
    );
    // Four M2 rows; three now carry a live verdict, so only ANON-PRIVILEGED-RPC still defers.
    expect(summary["requires-live-run"]).toBe(1);
    expect(summary.asserted).toBeGreaterThanOrEqual(4);
  });
});

// #1310's CLI half. Everything above drives `resolveDetection` directly, so replacing main()'s
// `const dynamic = loadDynamicScorecard()` with `undefined` left all 123 src/cli tests green — the
// #1407 blind spot, one level up: the library resolves the row, and nothing proved the flag reaches
// it. This runs the REAL CLI as a child process. Reverting that line makes both of these fail.
describe("dry-run-scorecard reads the recorded pen-test scorecard through its own CLI flag (#1310)", () => {
  let dir: string;
  beforeEach(() => (dir = mkdtempSync(join(tmpdir(), "harvey-scorecard-cli-"))));
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const CLI = join(import.meta.dirname, "dry-run-scorecard.ts");
  const REPO_ROOT = join(import.meta.dirname, "..", "..");

  const run = (extraArgs: string[]) =>
    execFileSync("node_modules/.bin/tsx", [CLI, "--out", dir, ...extraArgs], { cwd: REPO_ROOT, encoding: "utf8" });

  const written = () => JSON.parse(readFileSync(join(dir, "scorecard.json"), "utf8")) as { bugs: { id: string; status: string; tier?: string; note?: string }[] };

  it("resolves the M2 rows against the scorecard the flag names, and says which run they came from", () => {
    const card: DynamicScorecard = {
      target: "http://127.0.0.1:9999",
      generatedAt: "2026-07-31T00:00:00.000Z",
      allowDestructive: true,
      probes: [{ findingId: "ANON-PRIVILEGED-RPC", status: "caught", severity: "Critical", evidence: "HARVEY_CLI_FLAG_PROOF" }],
      summary: { caught: 1, cleared: 0, "not-applicable": 0, "not-run": 0, "not-assessed": 0 },
    };
    const cardPath = join(dir, "dynamic.json");
    writeFileSync(cardPath, JSON.stringify(card));

    const stdout = run(["--dynamic-scorecard", cardPath]);
    expect(stdout).toContain("M2 dynamic rows resolved against 1 probe(s) recorded on 2026-07-31T00:00:00.000Z against http://127.0.0.1:9999");

    const row = written().bugs.find((b) => b.id === "ANON-PRIVILEGED-RPC")!;
    expect(row.status).toBe("caught");
    expect(row.tier).toBe("high");
    expect(row.note).toContain("HARVEY_CLI_FLAG_PROOF");
  });

  // The other direction: a named-but-missing file is a hard error, never a silent fall back to
  // requires-live-run — which would read as "no live run has happened yet" when one just did.
  it("exits non-zero when the named scorecard does not exist", () => {
    try {
      run(["--dynamic-scorecard", join(dir, "absent.json")]);
      throw new Error("expected a non-zero exit");
    } catch (err) {
      const e = err as { status?: number; stderr?: string };
      expect(e.status).toBe(1);
      expect(e.stderr).toContain("does not exist");
    }
  });
});
