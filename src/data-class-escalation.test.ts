import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type DataClassMap, dataClassJoinNotAssessed, escalateFindingsByDataClass, isDataClassMap } from "./data-class-escalation.js";
import { type Finding, validateFindings } from "./findings.js";

// The two poles of the differentiator: a table stacking regulated data (score ≥ 8 → Critical) and a
// table holding only a display name (score 0.3 → Low). Shapes copied from tools/pii-classify.mjs's
// buildDataMap output (dry-run/pii-data-map.json).
const dataMap: DataClassMap = {
  patients: {
    columns: [
      { column: "email", infotype: "EMAIL", category: "PII", confidence: "high" },
      { column: "medical_record_number", infotype: "MRN", category: "PHI", confidence: "high" },
      { column: "passport_number", infotype: "PASSPORT", category: "SENSITIVE_PII", confidence: "high" },
    ],
    infotypes: ["EMAIL", "MRN", "PASSPORT"],
    categories: ["PII", "PHI", "SENSITIVE_PII"],
    severityScore: 11,
    severity: "Critical",
  },
  counters: {
    columns: [{ column: "name", infotype: "NAME?", category: "PII", confidence: "low" }],
    infotypes: ["NAME?"],
    categories: ["PII"],
    severityScore: 0.3,
    severity: "Low",
  },
};

const finding = (over: Partial<Finding>): Finding => ({
  id: "F-01",
  title: "t",
  severity: "Medium",
  confidence: "Confirmed",
  category: "Multi-tenant",
  taxonomy: "M1 — Multi-tenant security",
  location: "supabase/migrations/0001_rls.sql:12",
  status: "Open",
  evidence: "e",
  impact: "i",
  fix: "f",
  value: 3,
  ease: 3,
  safety: 3,
  ...over,
});

describe("escalateFindingsByDataClass", () => {
  it("escalates a finding on a regulated table to the table's data severity", () => {
    const f = finding({ location: "supabase/migrations/0001_rls.sql:12 (public.patients.patients_select_all)" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.severity).toBe("Critical");
    expect(out?.dataClass?.escalatedFrom).toBe("Medium");
    expect(out?.dataClass?.table).toBe("patients");
    // Legibility is the acceptance criterion: the reader must see WHICH table and WHICH classes.
    expect(out?.dataClass?.reason).toContain("PHI");
    expect(out?.dataClass?.reason).toContain("patients");
  });

  it("does not escalate a finding on a non-sensitive table", () => {
    const f = finding({ location: "supabase/migrations/0001_rls.sql:40", title: "public.counters is created but never gets RLS enabled" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.severity).toBe("Medium");
    expect(out?.dataClass?.escalatedFrom).toBeUndefined();
    expect(out?.dataClass?.reason).toContain("no escalation");
  });

  it("joins on the table named in the TITLE when the location is only a migration file", () => {
    const f = finding({ severity: "Low", title: "public.patients is created but never gets RLS enabled in any migration" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.severity).toBe("Critical");
  });

  it("never lowers a severity the detecting module set higher", () => {
    const f = finding({ severity: "Critical", location: "public.counters" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.severity).toBe("Critical");
  });

  it("leaves an unrelated path alone even when a table name appears in it", () => {
    const f = finding({ location: "src/app/counters/route.ts:8" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.dataClass).toBeUndefined();
  });

  it("leaves M10's own classification findings untouched — their severity IS the table score", () => {
    const f = finding({ severity: "Low", location: "patients", taxonomy: "M10 — Data classification (PII/PHI/PCI)" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.severity).toBe("Low");
    expect(out?.dataClass).toBeUndefined();
  });

  it("does not re-severity a Perf finding onto the security ladder", () => {
    const f = finding({ severity: "Perf", location: "public.patients" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.severity).toBe("Perf");
    expect(out?.dataClass?.escalatedFrom).toBeUndefined();
  });

  it("prices a finding naming two classified tables by the more sensitive one", () => {
    const f = finding({ location: "public.counters <> public.patients" });
    const [out] = escalateFindingsByDataClass([f], dataMap);
    expect(out?.dataClass?.table).toBe("patients");
    expect(out?.severity).toBe("Critical");
  });

  it("produces findings the report schema accepts", () => {
    const escalated = escalateFindingsByDataClass([finding({ location: "public.patients" })], dataMap);
    const doc = {
      meta: { client: "c", subtitle: "s", date: "d", commit: "abc", auditor: "a", confidential: true, overallHealth: 5, tenantIsolation: "t", authModel: "m", headline: "h", scope: "s", methodology: "m", outOfScope: "o" },
      findings: escalated,
    };
    expect(validateFindings(doc)).toEqual({ ok: true, errors: [] });
  });
});

describe("validateFindings on dataClass", () => {
  it("rejects an escalation with no stated reason", () => {
    const f = { ...finding({}), dataClass: { table: "patients", categories: ["PHI"], infotypes: ["MRN"], escalatedFrom: "Medium", reason: "" } };
    const doc = {
      meta: { client: "c", subtitle: "s", date: "d", commit: "abc", auditor: "a", confidential: true, overallHealth: 5, tenantIsolation: "t", authModel: "m", headline: "h", scope: "s", methodology: "m", outOfScope: "o" },
      findings: [f],
    };
    expect(validateFindings(doc).errors).toContainEqual(expect.stringContaining("dataClass.reason"));
  });
});

describe("dataClassJoinNotAssessed", () => {
  it("names the M10 reason so the absence of escalation cannot read as benign data", () => {
    const row = dataClassJoinNotAssessed("no live DB and no schema found — nothing to classify");
    expect(row.id).toBe("M10-ESCALATION-00");
    expect(row.evidence).toContain("nothing to classify");
    expect(row.impact).toContain("NOT evidence the data is benign");
  });
});

// #1060 — the end-to-end control. Everything above is hand-built inputs, which is how the join
// could pass every test while raising NOTHING on real output: until targets/calibration planted an
// M1 finding on a regulated table, all 7 real matches were on tables scoring Low and the join
// correctly declined every time. These assertions run over the COMMITTED dry-run artifacts —
// actual scanner output, regenerated by the dry-run-drift gate — so a regression in the
// location/title matcher, the schema-qualifier gate, or the classifier's scoring breaks them.
describe("escalateFindingsByDataClass over the committed dry-run artifacts (#1060)", () => {
  const root = join(import.meta.dirname, "..");
  const findings = JSON.parse(readFileSync(join(root, "dry-run", "findings.json"), "utf8")) as Finding[];
  const dataMap = JSON.parse(readFileSync(join(root, "dry-run", "pii-data-map.json"), "utf8")) as DataClassMap;
  const escalated = escalateFindingsByDataClass(findings, dataMap).filter((f) => f.dataClass?.escalatedFrom);

  it("raises the planted M1 finding on public.patient_billing from High to Critical", () => {
    const row = escalated.find((f) => f.dataClass?.table === "patient_billing");
    expect(row, "no finding escalated off patient_billing — the corpus plant or the join is broken").toBeDefined();
    expect(row?.dataClass?.escalatedFrom).toBe("High");
    expect(row?.severity).toBe("Critical");
    expect(row?.taxonomy).toBe("M1 — Multi-tenant security");
    expect(row?.location).toContain("patient_billing_select_all");
    expect(row?.dataClass?.infotypes).toEqual(expect.arrayContaining(["US_SSN", "CARD"]));
    expect(row?.dataClass?.reason).toContain("Severity raised High → Critical");
  });

  it("escalates nothing the data map does not out-rank", () => {
    // The 2026-07-25 measurement that opened #1060: the join MATCHES far more than it raises, and
    // a match without a raise must stay a match. If this count ever equals the match count the
    // ladder comparison has been inverted.
    const matched = escalateFindingsByDataClass(findings, dataMap).filter((f) => f.dataClass);
    expect(matched.length).toBeGreaterThan(escalated.length);
    for (const f of matched) {
      if (f.dataClass?.escalatedFrom) continue;
      expect(f.dataClass?.reason).toContain("no escalation");
    }
  });
});

describe("isDataClassMap", () => {
  it("accepts the classifier's map and rejects the findings array shape", () => {
    expect(isDataClassMap(dataMap)).toBe(true);
    expect(isDataClassMap([])).toBe(false);
    expect(isDataClassMap({ patients: { columns: [] } })).toBe(false);
  });
});
