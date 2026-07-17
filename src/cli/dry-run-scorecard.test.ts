// Guards the SINGLE-KEY link between the dry-run scorecard and the gated corpus (#425). The dry-run
// no longer holds a second matcher: each planted bug names a corpus entry (corpusId) or an M2 replay
// (replayId), and detection is derived from the gated corpus — which cannot drift, it fails
// `pnpm verify`. These tests prove the link is intact and can't rot silently:
//   - every bug GROUND-TRUTH plants has an entry here (an unmapped bug is invisible, not "missed");
//   - every static bug's corpusId resolves to a real gated corpus entry (a dangling FK throws);
//   - every dynamic bug's replayId is a registered M2 replay (a live-run promise no code can keep);
//   - the corpus-derived verdicts on the committed findings are the expected ones — the historically
//     drifted RLS classes (#332/#337) score caught, the accepted WEBHOOK-REPLAY gap scores missed.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { AUTOMATED_REPLAY_IDS } from "../pentest/verify.js";
import { scoreCoverage } from "../coverage-scorecard.js";
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

  it("every dynamic (M2) bug scores requires-live-run — deferred with a reason, never absent", () => {
    for (const b of GROUND_TRUTH_BUGS.filter((x) => x.replayId)) expect(statusOf(b.id)).toBe("requires-live-run");
  });

  it("classifies all twelve planted bugs — none silently dropped", () => {
    expect(scored).toHaveLength(GROUND_TRUTH_BUGS.length);
    expect(GROUND_TRUTH_BUGS).toHaveLength(12);
  });
});
