// #912 — regression lock for the three corpus targets whose semantic tier was re-scored on
// 2026-07-24 (superredhat 12/12, supatest 9/9, cipherx 20/20). validate-semantic.ts needs a live
// pass artifact it cannot manufacture, so it is out of `pnpm verify`; this test carries the recorded
// pass FINDINGS (docs/design/semantic-corpus-passes/*.triage.json — the exact triage output that was
// scored) and re-scores them here, in verify. It fails if a corpus edit drops a planted-flaw match
// (recall regression) or weakens a precision negative (an FP that should fail no longer would).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { SEMANTIC_CORPUS, scoreSemanticPass } from "./semantic-corpus.js";

const passesDir = join(dirname(fileURLToPath(import.meta.url)), "../../docs/design/semantic-corpus-passes");

const loadPass = (slug: string): Finding[] =>
  JSON.parse(readFileSync(join(passesDir, `${slug}.triage.json`), "utf8")) as Finding[];

// slug → the count the 2026-07-24 re-score measured (== the corpus recordedCaught it must not fall below).
const RESCORED: Record<string, number> = { superredhat: 12, supatest: 9, cipherx: 20 };

describe("2026-07-24 semantic re-score (#912) — committed pass findings, scored in verify", () => {
  for (const [slug, expectedCaught] of Object.entries(RESCORED)) {
    const target = SEMANTIC_CORPUS.find((t) => t.slug === slug);
    if (!target) throw new Error(`corpus target ${slug} missing — the re-score lock cannot run`);

    it(`${slug}: catches all ${expectedCaught} planted flaws and never below the recorded baseline`, () => {
      const result = scoreSemanticPass(target, loadPass(slug));
      expect(result.positivesCaught).toBe(expectedCaught);
      expect(result.positivesCaught).toBe(result.positivesTotal); // full recall on every planted flaw
      expect(result.recordedCaught).toBe(expectedCaught); // the committed baseline == the measured value
      expect(result.regressed).toBe(false);
    });

    it(`${slug}: the recorded pass reports no recorded non-vulnerability (precision cleared)`, () => {
      const result = scoreSemanticPass(target, loadPass(slug));
      expect(result.negativesCleared).toBe(result.negativesTotal);
    });
  }

  it("gates precision: at least 4 recorded non-vulnerabilities across the scored corpus", () => {
    // Before #912 the corpus carried ONE negative (cipherx CX-21), so validate-semantic printed a
    // 'precision essentially ungated' caveat. #912 added one per re-scored target. If this drops back
    // to <=1 that caveat returns — this asserts precision stays gated.
    const negatives = SEMANTIC_CORPUS.filter((t) => RESCORED[t.slug] !== undefined).flatMap((t) =>
      t.entries.filter((e) => e.kind === "negative"),
    );
    expect(negatives.length).toBeGreaterThanOrEqual(4);
  });

  it("the precision negatives actually TRIP on the false positive they guard against", () => {
    // A negative is only a gate if reporting the benign construct fails. Feed each its FP and assert
    // the negative row flips to a false positive (pass === false).
    const fp = (location: string, title: string): Finding => ({
      id: "FP-01",
      title,
      severity: "High",
      confidence: "Likely",
      category: "Security",
      taxonomy: "M1 — Multi-tenant security",
      location,
      status: "Open",
      evidence: title,
      impact: "",
      fix: "",
      value: 4,
      ease: 3,
      safety: 4,
    });

    const srh = SEMANTIC_CORPUS.find((t) => t.slug === "superredhat")!;
    const srhRes = scoreSemanticPass(srh, [
      fp("app/api/notes/route.ts:20", "Unauthenticated route — no authentication on POST /api/notes"),
    ]);
    expect(srhRes.rows.find((r) => r.id === "F-N1")?.pass).toBe(false);

    const supa = SEMANTIC_CORPUS.find((t) => t.slug === "supatest")!;
    const supaRes = scoreSemanticPass(supa, [
      fp("src/lib/supabase.ts:13", "Exposed secret — hardcoded Supabase anon key in browser client"),
    ]);
    expect(supaRes.rows.find((r) => r.id === "F-N1")?.pass).toBe(false);

    const cx = SEMANTIC_CORPUS.find((t) => t.slug === "cipherx")!;
    const cxRes = scoreSemanticPass(cx, [
      fp("src/lib/supabase/client.ts:4", "Exposed secret — hardcoded Supabase anon key / publishable credential"),
    ]);
    expect(cxRes.rows.find((r) => r.id === "CX-22")?.pass).toBe(false);
  });
});
