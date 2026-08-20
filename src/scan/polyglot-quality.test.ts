import { describe, expect, it } from "vitest";
import type { SourceInput } from "../detectors/common.js";
import {
  detectM5PolyglotQualityAndCoverageFindings,
  classifyM5PolyglotQualityFindings,
  detectM6PolyglotCoverageFindings,
  formatSourcePopulationReceipt,
  parseSourcePopulationReceipt,
  sourcePopulationReceipt,
} from "./polyglot-quality.js";

const sources: SourceInput[] = [
  { path: "src/app.ts", text: "export const ready = true;\n" },
  { path: "src/unsafe.py", text: "try:\n    run()\nexcept RuntimeError:\n    pass\n" },
  { path: "src/safe.py", text: "try:\n    run()\nexcept RuntimeError as error:\n    raise ServiceError() from error\n" },
  { path: "pkg/library.go", text: "package ledger\nfunc load() { panic(\"missing\") }\n" },
  { path: "cmd/app.go", text: "package main\nfunc main() { panic(\"fatal config\") }\n" },
  { path: "src/unsafe.rs", text: "pub fn load() { todo!(\"implement\") }\n" },
  { path: "src/safe.rs", text: "pub fn load() -> Result<(), Error> { Err(Error::Missing) }\n" },
  { path: "src/service.cs", text: "public class Service {}\n" },
  { path: "src/service.c", text: "int service(void) { return 0; }\n" },
  { path: "src/service.cpp", text: "int service() { return 0; }\n" },
];

describe("#1928 polyglot source quality", () => {
  it("emits the calibrated Python, Go, and Rust positives while preserving benign twins", () => {
    const findings = classifyM5PolyglotQualityFindings(sources);
    expect(findings.map((finding) => finding.location)).toEqual([
      "src/unsafe.py:3",
      "pkg/library.go:2",
      "src/unsafe.rs:1",
    ]);
    expect(findings.every((finding) => finding.mechanical && finding.precisionTier === "review")).toBe(true);
  });

  it("records identified and examined counts independently with provenance and falsifiers", () => {
    const receipt = sourcePopulationReceipt("M5", sources);
    expect(receipt.populations.find((row) => row.language === "python")).toMatchObject({
      identified: { count: 2 }, examined: { count: 2 }, status: "partial",
    });
    expect(receipt.populations.find((row) => row.language === "csharp")).toMatchObject({
      identified: { count: 1 }, examined: { count: 0 }, status: "not-assessed",
    });
    expect(receipt.populations.every((row) => row.provenance.length > 0 && row.falsifier.length > 0)).toBe(true);
    expect(parseSourcePopulationReceipt(formatSourcePopulationReceipt(receipt), "M5")).toEqual(receipt);
  });

  it("renders bounded and unsupported populations as coverage findings", () => {
    const m5 = detectM5PolyglotQualityAndCoverageFindings(sources);
    const m6 = detectM6PolyglotCoverageFindings(sources);
    expect(m5.some((finding) => finding.taxonomy === "M5 — Source coverage not-assessed: csharp" && finding.evidence.includes("examined=0"))).toBe(true);
    expect(m6.some((finding) => finding.taxonomy === "M6 — Source coverage not-assessed: python" && finding.evidence.includes("Identified=2"))).toBe(true);
  });
});
