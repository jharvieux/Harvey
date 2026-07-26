// #1096 invariant (1). Each violation the ledger exists to catch is SEEDED here and proven to fail,
// on the same rule as src/audit-conservation.test.ts: a gate nobody has watched fail is not evidence
// that it can (#350's guard passed review, had tests, and could not fire for nine months).

import { describe, expect, it } from "vitest";
import { baselineLedger, conservationLedger, formatBaselineLedger, formatLedger } from "./conservation-ledger.js";
import type { Finding } from "./findings.js";

const finding = (id: string, over: Partial<Finding> = {}): Finding => ({
  id, title: "t", severity: "Medium", confidence: "Confirmed", category: "c", taxonomy: "M9 — x",
  location: "app/page.tsx:1", status: "Open", evidence: "e", impact: "i", fix: "f", value: 3, ease: 3, safety: 3,
  ...over,
});

describe("conservation ledger — the healthy shape", () => {
  it("balances when every produced finding is delivered", () => {
    const produced = [finding("A"), finding("B")];
    const ledger = conservationLedger(produced, produced, { M9: produced });
    expect(ledger.ok).toBe(true);
    expect(ledger.produced).toBe(2);
    expect(ledger.deliveredFromProduced).toBe(2);
    expect(ledger.unaccounted).toBe(0);
    expect(formatLedger(ledger)).toContain("LEDGER PASS");
  });

  // The shared-CLI double capture: quality-scan is captured under M4 AND M5, detect-static under
  // M6/M7/M8/M9, so the same row legitimately arrives twice and the assembler collapses it. That is
  // an accounted disposition, not a loss.
  it("accounts a byte-identical duplicate capture as deduped, not as a loss", () => {
    const a = finding("A");
    const ledger = conservationLedger([a, { ...a }, finding("B")], [a, finding("B")], { M4: [a], M5: [{ ...a }] });
    expect(ledger.ok).toBe(true);
    expect(ledger.deduped).toBe(1);
    expect(ledger.produced).toBe(ledger.deliveredFromProduced + ledger.deduped);
    expect(ledger.rows.find((r) => r.id === "A")?.reason).toMatch(/byte-identical duplicate capture/);
  });

  // The assembler adds M10-ESCALATION-00 when no data map exists (#1049) — a declared synthesizer,
  // so the gain is legitimate. Anything else appearing from nowhere is not (below).
  it("accepts a declared synthesizer as a legitimate gain", () => {
    const produced = [finding("A")];
    const ledger = conservationLedger(produced, [...produced, finding("M10-ESCALATION-00")], { M9: produced });
    expect(ledger.ok).toBe(true);
    expect(ledger.synthesized).toBe(1);
    expect(ledger.undeclaredGains).toEqual([]);
  });
});

describe("conservation ledger — SEEDED violations, each proven to fail", () => {
  // SEED: the #1040/#1061 shape — the probe produced it, the deliverable does not carry it, and
  // nothing in the pipeline declared a reason.
  it("FAILS on a produced finding that is not delivered and carries no disposition", () => {
    const produced = [finding("A"), finding("B")];
    const ledger = conservationLedger(produced, [produced[0]!], { M9: produced });
    expect(ledger.ok).toBe(false);
    expect(ledger.unaccounted).toBe(1);
    const out = formatLedger(ledger);
    expect(out).toContain("LEDGER FAIL");
    expect(out).toContain("LOST  B (produced by M9)");
  });

  // Removing the seed restores the pass — otherwise the failure above proves only that the gate is
  // stuck red, which is as useless as one stuck green.
  it("PASSES once the seeded loss is removed", () => {
    const produced = [finding("A"), finding("B")];
    expect(conservationLedger(produced, produced, { M9: produced }).ok).toBe(true);
  });

  // SEED: a report that grows rows from nowhere is as wrong as one that loses them — an undeclared
  // gain means some consumer is inventing findings, or an id collided.
  it("FAILS on a delivered finding that no probe produced and no synthesizer declares", () => {
    const produced = [finding("A")];
    const ledger = conservationLedger(produced, [...produced, finding("GHOST-1")], { M9: produced });
    expect(ledger.ok).toBe(false);
    expect(ledger.undeclaredGains).toEqual(["GHOST-1"]);
    expect(formatLedger(ledger)).toMatch(/NO probe produced and no synthesizer declares/);
  });

  // SEED: assembly multiplied a row (the #620 id-collision shape, before namespacing). The
  // deliverable carries more copies of an id than the probes produced distinct bodies for.
  it("FAILS when the deliverable carries more copies of an id than were produced", () => {
    const a = finding("A");
    const ledger = conservationLedger([a], [a, { ...a }], { M9: [a] });
    expect(ledger.ok).toBe(false);
    expect(ledger.undeclaredGains).toContain("A");
  });

  // A same-id-different-body pair is deliberately NOT collapsed by the assembler (validateFindings
  // flags it loudly instead), so both bodies must arrive. One arriving is a loss, not a dedupe —
  // this is the case that separates "counting distinct bodies" from "counting ids".
  it("FAILS when two distinct bodies share an id and only one is delivered", () => {
    const a = finding("A");
    const variant = { ...a, title: "different" };
    const ledger = conservationLedger([a, variant], [a], { M4: [a], M5: [variant] });
    expect(ledger.ok).toBe(false);
    expect(ledger.unaccounted).toBe(1);
    expect(ledger.deduped).toBe(0);
  });

  it("names the producing module on a loss even when two probes produced the id", () => {
    const a = finding("A");
    const ledger = conservationLedger([a, { ...a, title: "x" }], [], { M4: [a], M5: [a] });
    expect(formatLedger(ledger)).toContain("produced by M4, M5");
  });
});

// #1146: the suppressed/capped/not-applicable columns get a real, validated producer — a DeclaredDrop.
// The same drop that is `unaccounted` (a failure) when nobody claims it becomes an accounted column
// when a transform declares it, and a claim that does not match a real loss is itself a failure.
describe("conservation ledger — declared dispositions (#1146)", () => {
  it("accounts a declared drop into its column instead of failing as unaccounted", () => {
    const produced = [finding("A"), finding("B")];
    const undeclared = conservationLedger(produced, [produced[0]!], { M9: produced });
    expect(undeclared.ok).toBe(false); // baseline: an unexplained drop fails

    const ledger = conservationLedger(produced, [produced[0]!], { M9: produced }, [
      { id: "B", disposition: "capped", reason: "over the per-shape threshold", by: "rollupFindings" },
    ]);
    expect(ledger.ok).toBe(true);
    expect(ledger.capped).toBe(1);
    expect(ledger.unaccounted).toBe(0);
    expect(ledger.produced).toBe(ledger.deliveredFromProduced + ledger.capped);
    expect(ledger.rows.find((r) => r.id === "B")?.reason).toMatch(/over the per-shape threshold — dropped by rollupFindings/);
  });

  it("routes each disposition to the right column", () => {
    const produced = [finding("A"), finding("B"), finding("C"), finding("D")];
    const ledger = conservationLedger(produced, [produced[0]!], { M9: produced }, [
      { id: "B", disposition: "suppressed", reason: "s", by: "x" },
      { id: "C", disposition: "capped", reason: "c", by: "x" },
      { id: "D", disposition: "not-applicable", reason: "n", by: "x" },
    ]);
    expect(ledger.ok).toBe(true);
    expect([ledger.suppressed, ledger.capped, ledger.notApplicable]).toEqual([1, 1, 1]);
  });

  // SEED: a disposition claimed against a finding that is STILL delivered — the column would close
  // the arithmetic on a fiction. Must fail loud.
  it("FAILS when a declared drop's finding is actually still delivered", () => {
    const produced = [finding("A"), finding("B")];
    const ledger = conservationLedger(produced, produced, { M9: produced }, [
      { id: "B", disposition: "suppressed", reason: "s", by: "x" },
    ]);
    expect(ledger.ok).toBe(false);
    expect(ledger.misdeclaredDispositions).toEqual(["B"]);
    expect(ledger.suppressed).toBe(0);
    expect(formatLedger(ledger)).toMatch(/did not actually go missing/);
  });

  // SEED: a disposition claimed against an id no probe produced.
  it("FAILS when a declared drop names a finding that was never produced", () => {
    const produced = [finding("A")];
    const ledger = conservationLedger(produced, produced, { M9: produced }, [
      { id: "GHOST", disposition: "capped", reason: "c", by: "x" },
    ]);
    expect(ledger.ok).toBe(false);
    expect(ledger.misdeclaredDispositions).toEqual(["GHOST"]);
  });
});

// #1146: the baseline seam. applyBaseline TAGS the current set and drops/adds nothing to it, so the
// invariant is entered == retained == exited. A dropped NEW finding or an invented row must fail.
describe("baseline ledger — across applyBaseline (#1146)", () => {
  it("passes when the baseline diff only tags (no member of the current set added or removed)", () => {
    const before = [finding("A"), finding("B")];
    const after = before.map((f) => ({ ...f, baselineStatus: "new" as const }));
    const ledger = baselineLedger(before, after, { M9: before });
    expect(ledger.ok).toBe(true);
    expect(ledger.retained).toBe(2);
    expect(ledger.removed).toEqual([]);
    expect(formatBaselineLedger(ledger)).toContain("BASELINE LEDGER PASS");
  });

  // SEED: the guard the task names — the baseline application silently deletes a NEW finding.
  it("FAILS when a finding entered the baseline diff and did not come out", () => {
    const before = [finding("A"), finding("B")];
    const after = [{ ...before[0]!, baselineStatus: "new" as const }];
    const ledger = baselineLedger(before, after, { M9: before });
    expect(ledger.ok).toBe(false);
    expect(ledger.removed.map((r) => r.id)).toEqual(["B"]);
    expect(formatBaselineLedger(ledger)).toContain("DELETED  B (produced by M9)");
  });

  // SEED: the baseline diff invents/duplicates a row that never entered.
  it("FAILS when a row exits the baseline diff that did not enter it", () => {
    const before = [finding("A")];
    const after = [{ ...before[0]! }, finding("INVENTED")];
    const ledger = baselineLedger(before, after);
    expect(ledger.ok).toBe(false);
    expect(ledger.gained).toEqual(["INVENTED"]);
  });
});
