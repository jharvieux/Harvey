// pass artifact it cannot manufacture, so it is out of `pnpm verify`; this test carries the recorded
// completed-triage evidence instead.
// Regression lock for the four completed 2026-09-03 triage artifacts audited in #1947. The test
// drives those skill-native objects through the production completed-triage adapter before scoring,
// so duplicate provenance and the 35-row answer key are tested at the same seam record-pass uses.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { findingsFromCompletedTriage } from "../triage-findings.js";
import { SEMANTIC_CORPUS, scoreSemanticPass } from "./semantic-corpus.js";

const passesDir = join(dirname(fileURLToPath(import.meta.url)), "../../docs/design/semantic-corpus-passes");

const loadPass = (slug: string): Finding[] =>
  findingsFromCompletedTriage(JSON.parse(
    readFileSync(join(passesDir, `${slug}.2026-09-03.triage.json`), "utf8"),
  ));

const RESCORED: Record<string, number> = {
  "nocode-rescue": 5,
  superredhat: 9,
  supatest: 5,
  cipherx: 16,
};

describe("2026-09-03 audited semantic corpus (#1947) — completed triage scored in verify", () => {
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

  it("gates precision with exactly four recorded non-vulnerabilities", () => {
    const negatives = SEMANTIC_CORPUS.filter((t) => RESCORED[t.slug] !== undefined).flatMap((t) =>
      t.entries.filter((e) => e.kind === "negative"),
    );
    expect(negatives).toHaveLength(4);
  });

  it("needs Supatest's validated article-DELETE duplicate provenance to satisfy F2", () => {
    const target = SEMANTIC_CORPUS.find((candidate) => candidate.slug === "supatest")!;
    const completed = JSON.parse(readFileSync(
      join(passesDir, "supatest.2026-09-03.triage.json"),
      "utf8",
    ));
    const withDuplicate = scoreSemanticPass(target, findingsFromCompletedTriage(completed));
    expect(withDuplicate.rows.find((row) => row.id === "F2")?.pass).toBe(true);

    completed.findings = completed.findings.filter((finding: { id: string }) => finding.id !== "f006");
    const withoutDuplicate = scoreSemanticPass(target, findingsFromCompletedTriage(completed));
    expect(withoutDuplicate.rows.find((row) => row.id === "F2")?.pass).toBe(false);
    expect(withoutDuplicate.rows.find((row) => row.id === "F1")?.pass).toBe(true);
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
