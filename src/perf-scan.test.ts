import { describe, expect, it } from "vitest";
import { parseAdvisorFindings, type AdvisorReport } from "./perf-scan.js";
import { buildCoverageMatrix } from "./scan/calibration.js";
import { m7Entries } from "./scan/calibration/m7.entries.js";

// Fixture shaped from the Supabase Management API's documented advisors response
// (GET /v1/projects/{ref}/advisors/performance → { lints: [...] }, fields name/title/level/
// detail/metadata) — mirrors the real advisor pull behind report-template/findings.atc.json's
// F-04 (124 unindexed FKs), F-05 (50 auth_rls_initplan hits), F-07 (86 unused indexes).
const report: AdvisorReport = {
  lints: [
    {
      name: "unindexed_foreign_keys",
      title: "Unindexed foreign keys",
      level: "INFO",
      detail: 'Table `public.bookings` has a foreign key `bookings_tenant_id_fkey` without a covering index',
      metadata: { schema: "public", name: "bookings", type: "table" },
    },
    {
      name: "unindexed_foreign_keys",
      title: "Unindexed foreign keys",
      level: "INFO",
      detail: 'Table `public.line_items` has a foreign key `line_items_booking_id_fkey` without a covering index',
      metadata: { schema: "public", name: "line_items", type: "table" },
    },
    {
      name: "auth_rls_initplan",
      title: "Auth RLS Initialization Plan",
      level: "WARN",
      detail: 'Table `public.bookings` has a row level security policy that re-evaluates auth.uid() for each row',
      metadata: { schema: "public", name: "bookings", type: "table" },
    },
    {
      name: "unused_index",
      title: "Unused Index",
      level: "INFO",
      detail: 'Index `idx_bookings_legacy_status` on `public.bookings` has not been used',
      metadata: { schema: "public", name: "bookings", type: "table" },
    },
  ],
};

describe("parseAdvisorFindings", () => {
  it("groups lints by rule name into one Finding per rule, sorted worst (highest count) first", () => {
    const findings = parseAdvisorFindings(report);
    expect(findings).toHaveLength(3);
    expect(findings[0]?.title).toBe("2 unindexed foreign keys");
    expect(findings[0]?.id).toBe("M7-01");
  });

  it("maps unindexed_foreign_keys to severity Perf with the value/ease/safety of a real prior engagement", () => {
    const [fk] = parseAdvisorFindings(report);
    expect(fk?.severity).toBe("Perf");
    expect(fk).toMatchObject({ value: 4, ease: 5, safety: 5, taxonomy: "Missing index" });
  });

  it("maps auth_rls_initplan to severity Perf and singularizes the title for a single hit", () => {
    const findings = parseAdvisorFindings(report);
    const rls = findings.find((f) => f.taxonomy === "auth_rls_initplan");
    expect(rls?.severity).toBe("Perf");
    expect(rls?.title).toBe("1 RLS policy re-evaluates auth.* per row");
  });

  it("maps unused_index to severity Low, not Perf — hygiene, not a hot-path cost", () => {
    const findings = parseAdvisorFindings(report);
    const unused = findings.find((f) => f.taxonomy === "Index hygiene");
    expect(unused?.severity).toBe("Low");
  });

  it("never drops an uncurated rule — falls back to a level-derived severity instead", () => {
    const withUnknown: AdvisorReport = {
      lints: [
        ...report.lints,
        {
          name: "some_new_rule_not_yet_curated",
          title: "Some new advisor rule",
          level: "ERROR",
          detail: "a brand-new rule Supabase shipped after this module was written",
          metadata: { schema: "public", name: "invoices", type: "table" },
        },
      ],
    };
    const findings = parseAdvisorFindings(withUnknown);
    const novel = findings.find((f) => f.taxonomy === "Advisor: some_new_rule_not_yet_curated");
    expect(novel).toBeDefined();
    expect(novel?.severity).toBe("High"); // ERROR level fallback
    expect(novel?.title).toBe("1 × Some new advisor rule");
  });

  it("deduplicates and caps the table list in location, appending a '+N more' count", () => {
    const manyTables: AdvisorReport = {
      lints: Array.from({ length: 12 }, (_, i) => ({
        name: "unindexed_foreign_keys",
        title: "Unindexed foreign keys",
        level: "INFO" as const,
        detail: `Table public.t${i} is missing a covering index`,
        metadata: { schema: "public", name: `t${i}`, type: "table" },
      })),
    };
    const [fk] = parseAdvisorFindings(manyTables);
    expect(fk?.location).toContain("+4 more");
    expect(fk?.location.split(", ")).toHaveLength(9); // 8 listed + the "+4 more" segment
  });

  it("includes the rule name and an example detail line in evidence, for reproducibility", () => {
    const [fk] = parseAdvisorFindings(report);
    expect(fk?.evidence).toContain("unindexed_foreign_keys");
    expect(fk?.evidence).toContain("bookings_tenant_id_fkey");
  });

  it("tags every finding precisionTier: high — advisor lints are schema-truth, ~100% precise once connected (spec §72 M7(d))", () => {
    for (const f of parseAdvisorFindings(report)) expect(f.precisionTier, f.taxonomy).toBe("high");
  });
});

// M7 calibration corpus (#72 §M7) — a MODELED advisor JSON shaped from what a live Splinter
// pull over targets/calibration/supabase/migrations/20260708000004_perf_calibration.sql should
// return (NOT a live capture — the connected-tier live confirmation is a deferred supervisor
// pass, SESSION.md "Owed: connected-tier live confirmation pass"). Exercises the answer key's
// location+match matching against parseAdvisorFindings' real shaping logic: exactly the 3
// planted lints appear (perf_line_items' unindexed FK, perf_orders' bare-auth.uid() RLS policy,
// perf_orders' unused legacy_region index); the 3 benign lookalikes (perf_shipments' indexed FK,
// perf_events' wrapped RLS policy, perf_orders' used customer_email index) generate no lint at
// all, so they're absent from this report by construction.
const m7CalibrationReport: AdvisorReport = {
  lints: [
    {
      name: "unindexed_foreign_keys",
      title: "Unindexed foreign keys",
      level: "INFO",
      detail: "Table `public.perf_line_items` has a foreign key `perf_line_items_order_id_fkey` without a covering index",
      metadata: { schema: "public", name: "perf_line_items", type: "table" },
    },
    {
      name: "auth_rls_initplan",
      title: "Auth RLS Initialization Plan",
      level: "WARN",
      detail: "Table `public.perf_orders` has a row level security policy that re-evaluates auth.uid() for each row",
      metadata: { schema: "public", name: "perf_orders", type: "table" },
    },
    {
      name: "unused_index",
      title: "Unused Index",
      level: "INFO",
      detail: "Index `idx_perf_orders_legacy_region` on `public.perf_orders` has not been used",
      metadata: { schema: "public", name: "perf_orders", type: "table" },
    },
  ],
};

describe("M7 calibration corpus — modeled advisor pull (#72 §M7)", () => {
  const findings = parseAdvisorFindings(m7CalibrationReport);

  it("attributes exactly the 3 planted lints to their answer-key entries, at high precision", () => {
    for (const e of m7Entries.filter((e) => e.kind === "positive")) {
      const row = buildCoverageMatrix(findings, [e]).rows[0];
      expect(row?.caughtTier, `${e.id}: ${row?.detail}`).toBe("high");
      expect(row?.expectedTier).toBe("connected"); // N/A in this static test; a live pull scores it for real
    }
  });

  it("clears all 3 benign lookalikes — none draw a finding from the modeled report", () => {
    for (const e of m7Entries.filter((e) => e.kind === "negative")) {
      const row = buildCoverageMatrix(findings, [e]).rows[0];
      expect(row?.highFlagged, `${e.id}: ${row?.detail}`).toBe(false);
    }
  });
});
