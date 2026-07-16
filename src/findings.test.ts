import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bftb, validateFindings } from "./findings.js";

const example = JSON.parse(readFileSync(new URL("../report-template/findings.atc.json", import.meta.url), "utf8"));

describe("validateFindings", () => {
  it("accepts the shipped example report (the renderer's reference input)", () => {
    const result = validateFindings(example);
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("rejects non-object documents", () => {
    expect(validateFindings(null).ok).toBe(false);
    expect(validateFindings([]).ok).toBe(false);
  });

  it("reports unknown severities and out-of-range BFTB inputs by path", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], severity: "Catastrophic", value: 0 }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].severity"));
    expect(errors).toContainEqual(expect.stringContaining("findings[0].value"));
  });

  it("rejects duplicate finding ids — ids anchor the report and client follow-ups", () => {
    const doc = { ...example, findings: [example.findings[0], example.findings[0]] };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("duplicate id"));
  });
});

describe("validateFindings — mechanical scan fields", () => {
  it("accepts a finding with mechanical + precisionTier set", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], mechanical: true, precisionTier: "high" }],
    };
    expect(validateFindings(doc).ok).toBe(true);
  });

  it("rejects an unknown precisionTier", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], precisionTier: "certain" }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].precisionTier"));
  });

  it("rejects a non-boolean mechanical flag", () => {
    const doc = {
      ...example,
      findings: [{ ...example.findings[0], mechanical: "yes" }],
    };
    const { ok, errors } = validateFindings(doc);
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("findings[0].mechanical"));
  });
});

describe("validateFindings — coverage ledger (#349)", () => {
  const ledger = [
    { module: "M4", name: "Duplication", status: "ran", detail: "pnpm quality-scan /t" },
    { module: "M2", name: "Local pen-test (dynamic)", status: "requires-live-run", reason: "no local supabase stack" },
    { module: "M7", name: "Performance", status: "partial", reason: "code tier only — no DB creds" },
  ];

  it("accepts a well-formed derived ledger alongside findings", () => {
    expect(validateFindings({ ...example, coverage: ledger }).ok).toBe(true);
  });

  it("still accepts a document with no coverage ledger — back-compat with hand-authored docs", () => {
    expect(validateFindings(example).ok).toBe(true);
    expect(Object.hasOwn(example, "coverage")).toBe(false);
  });

  it("rejects an unknown coverage status", () => {
    const { ok, errors } = validateFindings({ ...example, coverage: [{ module: "M1", name: "x", status: "skipped" }] });
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("coverage[0].status"));
  });

  // The whole point of the ledger: a non-"ran" row without a reason is a silent skip wearing a
  // status, which reads in the report as "clean". It must not validate.
  it("rejects a partial / requires-live-run row with no reason", () => {
    const { ok, errors } = validateFindings({ ...example, coverage: [{ module: "M5", name: "Slop", status: "requires-live-run" }] });
    expect(ok).toBe(false);
    expect(errors).toContainEqual(expect.stringContaining("coverage[0].reason"));
  });

  it("does not require a reason on a clean ran row", () => {
    expect(validateFindings({ ...example, coverage: [{ module: "M4", name: "Duplication", status: "ran" }] }).ok).toBe(true);
  });
});

describe("bftb", () => {
  it("matches the renderer's formula: round(value*ease*safety/125*100)", () => {
    expect(bftb({ value: 5, ease: 5, safety: 5 })).toBe(100);
    expect(bftb({ value: 1, ease: 1, safety: 1 })).toBe(1);
    expect(bftb({ value: 4, ease: 3, safety: 5 })).toBe(48);
  });
});
