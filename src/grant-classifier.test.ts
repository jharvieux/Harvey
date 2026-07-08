import { describe, expect, it } from "vitest";
import { classifyNoPolicyTable, grantFindings, type NoPolicyTable } from "./grant-classifier.js";

// Fixtures modeled on docs/example-report-atc.md F-03 (13 RLS-no-policy tables,
// mostly deny-all-by-design; tier_definitions/stripe_price_map/pricing_* called
// out to confirm) and the issue's ATC calibration note (11 of 13 locked, 2 flagged).

const serviceRoleOnly: NoPolicyTable = {
  schema: "public",
  table: "webhook_events",
  grants: [
    { grantee: "service_role", privilege: "SELECT" },
    { grantee: "service_role", privilege: "INSERT" },
  ],
  queriedByClientCode: false,
};

const grantedButUnread: NoPolicyTable = {
  schema: "public",
  table: "internal_audit_log",
  grants: [
    { grantee: "authenticated", privilege: "SELECT" },
    { grantee: "service_role", privilege: "SELECT" },
  ],
  queriedByClientCode: false,
};

const grantedAndQueried: NoPolicyTable = {
  schema: "public",
  table: "pricing_tiers",
  grants: [{ grantee: "anon", privilege: "SELECT" }],
  queriedByClientCode: true,
};

describe("classifyNoPolicyTable", () => {
  it("clears a table with no client-facing SELECT grant as deny-all by design", () => {
    const v = classifyNoPolicyTable(serviceRoleOnly);
    expect(v.verdict).toBe("ok");
    expect(v.clientSelectGrant).toBe(false);
  });

  it("flags a client SELECT grant with no policy and no client reader as a vestigial grant", () => {
    const v = classifyNoPolicyTable(grantedButUnread);
    expect(v.verdict).toBe("flag");
    expect(v.reason).toContain("vestigial");
  });

  it("flags a client SELECT grant with no policy where client code actually queries the table — the read is silently broken", () => {
    const v = classifyNoPolicyTable(grantedAndQueried);
    expect(v.verdict).toBe("flag");
    expect(v.reason).toContain("silently returning zero rows");
  });

  it("surfaces over-broad TRUNCATE/REFERENCES grants independent of the main verdict", () => {
    const v = classifyNoPolicyTable({
      ...serviceRoleOnly,
      grants: [...serviceRoleOnly.grants, { grantee: "authenticated", privilege: "TRUNCATE" }],
    });
    expect(v.verdict).toBe("ok");
    expect(v.overBroadGrants).toEqual(["authenticated: TRUNCATE"]);
  });
});

describe("grantFindings", () => {
  it("reports a per-table verdict, not a blanket finding across all RLS-no-policy tables", () => {
    const verdicts = [serviceRoleOnly, grantedButUnread, grantedAndQueried].map(classifyNoPolicyTable);
    const findings = grantFindings(verdicts);
    expect(findings.map((f) => f.location)).toEqual(["public.internal_audit_log", "public.pricing_tiers"]);
  });

  it("does not emit a finding for the deny-all-by-design table", () => {
    const verdicts = [serviceRoleOnly].map(classifyNoPolicyTable);
    expect(grantFindings(verdicts)).toHaveLength(0);
  });

  it("emits a separate low-severity finding for an over-broad grant even on an otherwise-OK table", () => {
    const overBroad: NoPolicyTable = {
      ...serviceRoleOnly,
      grants: [...serviceRoleOnly.grants, { grantee: "anon", privilege: "REFERENCES" }],
    };
    const findings = grantFindings([classifyNoPolicyTable(overBroad)]);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.title).toContain("Over-broad grant");
    expect(findings[0]?.severity).toBe("Low");
  });
});
