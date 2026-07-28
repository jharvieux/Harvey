// #1454 — the gate over PARITY_EXEMPTIONS. An exemption silently closes a coverage question ("this
// module has no fixtures, and that is fine because <gate>"), and until this file it was the only
// claim-bearing structure in the repo that nothing checked: `{ module, reason }`, free text, no
// KIND, no PROVENANCE, no OWNER, no FALSIFIER, while every `REASON:` block is held to exactly those
// by `pnpm validate-reasons`.
//
// The controls below matter more than the pass. Each one plants a defective exemption and asserts
// the specific error — because a gate nobody has watched fail is indistinguishable from a gate that
// is incapable of failing, and the M6 row this issue came from would have passed a shape-only
// check: it was a
// well-formed English sentence and it was false the day it was written.
//
// This rides inside `pnpm verify`. The same function runs at the live gate
// (src/cli/validate-calibration.ts) with a real `existsSync`, which is what makes the
// substitute-gate path check real rather than structural.

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parityExemptionReasons, validateParityExemptions, type ParityExemption } from "./calibration.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const inRepo = (path: string): boolean => existsSync(resolve(REPO_ROOT, path));

const WELL_FORMED: ParityExemption = {
  module: "M2",
  substituteGate: "src/cli/pentest.ts --mode=coverage → assertComplete (src/pentest/targets.ts)",
  reason: {
    claim: "a probe-only module produces no offline finding a planted fixture could be scored against",
    kind: "empirical",
    provenance: "MEASURED 2026-07-28 — ran the offline scan and counted zero findings of this module's taxonomy",
    falsifier: "test -f dry-run/findings.json || exit 127; grep -q 'nope' dry-run/findings.json",
  },
};

const modify = (over: Partial<ParityExemption>, reason: Partial<ParityExemption["reason"]> = {}): ParityExemption => ({
  ...WELL_FORMED,
  ...over,
  reason: { ...WELL_FORMED.reason, ...reason },
});

/** Errors for a single planted exemption, so each control reads as one assertion. */
function errorsFor(e: ParityExemption): string[] {
  return validateParityExemptions([e], inRepo)[0]?.errors ?? [];
}

describe("#1454 a parity exemption is held to the recorded-reasons registry", () => {
  it("every COMMITTED exemption is well-formed against the real checkout", () => {
    // The live assertion: not a fixture. If someone adds an exemption asserting anything, this fails.
    expect(validateParityExemptions(undefined, inRepo)).toEqual([]);
    // Canary — an empty list would satisfy the line above vacuously.
    expect(parityExemptionReasons().length).toBeGreaterThan(0);
  });

  it("every committed exemption declares a kind, a dated provenance, and either a falsifier or a named ruler", () => {
    for (const r of parityExemptionReasons()) {
      expect(r.fields.KIND, r.file).toMatch(/^(empirical|decisional)$/);
      expect(r.fields.PROVENANCE, r.file).toMatch(/^(MEASURED|TRIED|ASSUMED) \d{4}-\d{2}-\d{2}/);
      if (r.fields.KIND === "empirical") expect(r.fields.FALSIFIER, r.file).toBeTruthy();
      else expect([r.fields.OWNER, r.fields.DECISION].every(Boolean), r.file).toBe(true);
    }
  });

  it("the well-formed control is accepted — so every rejection below is about its planted defect", () => {
    expect(errorsFor(WELL_FORMED)).toEqual([]);
  });

  it("CONTROL — an exemption with no KIND is refused", () => {
    const errors = errorsFor(modify({}, { kind: undefined as unknown as "empirical" }));
    expect(errors.join(" ")).toMatch(/KIND: must be "empirical"/);
  });

  it("CONTROL — an exemption with no dated provenance is refused", () => {
    expect(errorsFor(modify({}, { provenance: "we looked into it" })).join(" ")).toMatch(/PROVENANCE: must start/);
  });

  it("CONTROL — an empirical exemption with no falsifier is refused (it is unfalsifiable, therefore permanent)", () => {
    expect(errorsFor(modify({}, { falsifier: undefined })).join(" ")).toMatch(/FALSIFIER: missing/);
  });

  it("CONTROL — a decisional exemption with no OWNER and no DECISION venue is refused", () => {
    const errors = errorsFor(modify({}, { kind: "decisional", falsifier: undefined }));
    expect(errors.join(" ")).toMatch(/OWNER: missing/);
    expect(errors.join(" ")).toMatch(/DECISION: missing/);
  });

  it("CONTROL — THE M6 SHAPE: impossibility vocabulary on an ASSUMED provenance is a structural error", () => {
    // Verbatim from the row that caused this issue. It is grammatical, confident, and was measured
    // false the same day it was written; a shape-only check would have passed it.
    const errors = errorsFor(modify({}, {
      claim: "M6's indicators are whole-repo shape counts, which a planted single-file fixture cannot express",
      provenance: "ASSUMED 2026-07-28",
    }));
    expect(errors.join(" ")).toMatch(/impossibility's vocabulary/);
  });

  it("CONTROL — a substitute gate naming a path that is not in the checkout is refused", () => {
    const errors = errorsFor(modify({ substituteGate: "src/cli/pentest-coverage-runner.ts --mode=coverage" }));
    expect(errors.join(" ")).toMatch(/substituteGate: names path\(s\) that do not exist here/);
  });

  it("CONTROL — a substitute gate naming no path at all is refused (a sentence is not a gate)", () => {
    expect(errorsFor(modify({ substituteGate: "covered by the pentest suite" })).join(" ")).toMatch(/names no path in this checkout/);
  });

  it("CONTROL — an exemption for a module outside M1–M10 exempts nothing and is refused", () => {
    expect(errorsFor(modify({ module: "M11" })).join(" ")).toMatch(/is not one of the ten audited modules/);
  });
});
