import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { SourceInput } from "./common.js";
import { detectM5TypeEscapeFindings } from "./m5-type-escape.js";

const CALIBRATION = fileURLToPath(new URL("../../targets/calibration/src/", import.meta.url));

function fixture(path: string): SourceInput {
  return { path, text: readFileSync(`${CALIBRATION}${path}`, "utf8") };
}

const unsafe = fixture("m5-type-escape/unsafe.ts");
const safe = fixture("m5-type-escape/safe-controls.ts");

describe("M5 type-escape AST classifier", () => {
  it("reports as-any, collapsed unknown chains, and unexplained ts-ignore at review tier", () => {
    const findings = detectM5TypeEscapeFindings([unsafe]);
    expect(findings).toHaveLength(4);
    expect(findings.map((finding) => finding.taxonomy)).toEqual([
      "M5 — Type escape (`as any`)",
      "M5 — Type escape (double assertion)",
      "M5 — Type escape (double assertion)",
      "M5 — Unexplained @ts-ignore",
    ]);
    expect(findings.map((finding) => finding.location)).toEqual([
      "m5-type-escape/unsafe.ts:11",
      "m5-type-escape/unsafe.ts:12",
      "m5-type-escape/unsafe.ts:13",
      "m5-type-escape/unsafe.ts:15",
    ]);
    for (const finding of findings) {
      expect(finding).toMatchObject({ confidence: "Review", category: "Maintainability", status: "Open" });
      expect(finding.evidence).toContain("Escaped expression:");
      expect(finding.evidence).toContain("no runtime validation/narrowing boundary is visible");
    }
    expect(findings.filter((finding) => finding.location.endsWith(":13"))).toHaveLength(1);
  });

  it("keeps validated parsing, prior narrowing, justified interop, and suppression controls silent", () => {
    expect(detectM5TypeEscapeFindings([safe])).toEqual([]);
  });

  it("does not blanket-flag @ts-expect-error and requires an inline reason for @ts-ignore", () => {
    const findings = detectM5TypeEscapeFindings([{
      path: "src/interop.ts",
      text: [
        "declare const raw: unknown;",
        "// @ts-expect-error",
        "const expected: number = raw;",
        "// @ts-ignore: upstream declaration omits the documented property",
        "const explained: number = raw;",
        "// @ts-ignore",
        "const unexplained: number = raw;",
      ].join("\n"),
    }]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.location).toBe("src/interop.ts:6");
    expect(findings[0]?.evidence).toContain("const unexplained: number = raw;");
  });

  it("excludes declarations, generated source, tests, and calibration paths", () => {
    const escaped = "declare const raw: unknown; export const value = raw as any;";
    expect(detectM5TypeEscapeFindings([
      { path: "src/types.d.ts", text: escaped },
      { path: "src/client.generated.ts", text: escaped },
      { path: "src/client.test.ts", text: escaped },
      { path: "tests/client.ts", text: escaped },
      { path: "targets/calibration/src/client.ts", text: escaped },
    ])).toEqual([]);
  });

  it("fails closed when both production classifiers are disabled", () => {
    expect(detectM5TypeEscapeFindings([unsafe])).toHaveLength(4);
    expect(detectM5TypeEscapeFindings([unsafe], { assertions: false, tsIgnore: false })).toHaveLength(0);
  });
});
