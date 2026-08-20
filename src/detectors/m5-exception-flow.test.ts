import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { SourceInput } from "./common.js";
import { detectM1ExceptionFlowFindings, detectM5ExceptionFlowFindings } from "./m5-exception-flow.js";

const CALIBRATION = fileURLToPath(new URL("../../targets/calibration/src/", import.meta.url));

function fixture(path: string): SourceInput {
  return { path, text: readFileSync(`${CALIBRATION}${path}`, "utf8") };
}

const unsafe = fixture("m5-exception-flow/unsafe.ts");
const nestedUnsafe = fixture("m5-exception-flow/nested-unsafe.ts");
const safe = fixture("m5-exception-flow/safe-controls.ts");
const boundaries = [
  fixture("m5-exception-flow/auth/session.ts"),
  fixture("m5-exception-flow/billing/charge.ts"),
  fixture("m5-exception-flow/app/api/orders/route.ts"),
];

describe("M5 exception-flow AST classifier", () => {
  it("reports empty, log-only, ambiguous-success, and nested catches at review tier with exact evidence", () => {
    const findings = detectM5ExceptionFlowFindings([unsafe, nestedUnsafe]);
    expect(findings).toHaveLength(4);
    expect(findings.map((finding) => finding.taxonomy)).toEqual([
      "M5 — Empty catch",
      "M5 — Log-only catch",
      "M5 — Ambiguous exception success",
      "M5 — Empty catch",
    ]);
    expect(findings.map((finding) => finding.location)).toEqual([
      "m5-exception-flow/unsafe.ts:7",
      "m5-exception-flow/unsafe.ts:14",
      "m5-exception-flow/unsafe.ts:26",
      "m5-exception-flow/nested-unsafe.ts:9",
    ]);
    for (const finding of findings) {
      expect(finding).toMatchObject({ confidence: "Review", category: "Maintainability", status: "Open" });
      expect(finding.evidence).toMatch(/catch \(.+\).*\.$/);
    }
  });

  it("keeps rationale-bearing cleanup/telemetry, rethrows, typed failure, compensation, termination, and nesting silent", () => {
    expect(detectM5ExceptionFlowFindings([safe])).toEqual([]);
    expect(detectM1ExceptionFlowFindings([safe])).toEqual([]);
  });

  it("routes auth, billing, and request-boundary cases only to the M1 export", () => {
    expect(detectM5ExceptionFlowFindings(boundaries)).toEqual([]);
    const security = detectM1ExceptionFlowFindings(boundaries);
    expect(security).toHaveLength(3);
    expect(security.map((finding) => finding.taxonomy)).toEqual([
      "M1 — Swallowed exception at auth/security boundary",
      "M1 — Swallowed exception at billing/payment boundary",
      "M1 — Swallowed exception at request boundary",
    ]);
    expect(new Set(security.map((finding) => finding.location)).size).toBe(3);
  });

  it("treats an explicit HTTP error response followed by a bare return as termination", () => {
    const responseControl: SourceInput = {
      path: "pages/api/redirect.ts",
      text: "export default function handler(_req: unknown, res: any) { try { parse(); } catch (error) { res.status(400).json({ error: 'invalid' }); return; } }",
    };
    expect(detectM1ExceptionFlowFindings([responseControl])).toEqual([]);
  });

  it("fails closed when the production classifiers are disabled", () => {
    const enabled = detectM5ExceptionFlowFindings([unsafe, nestedUnsafe]);
    const disabled = detectM5ExceptionFlowFindings([unsafe, nestedUnsafe], {
      emptyCatch: false,
      logOnlyFallthrough: false,
      ambiguousSuccess: false,
    });
    expect(enabled).toHaveLength(4);
    expect(disabled).toHaveLength(0);
  });
});
