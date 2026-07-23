import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import type { AttachedRef, CreatedRef, ItemInput, Tracker } from "./types.js";
import { fileFindings, findingMarker, findingToTicket, planTickets, ticketLabels } from "./findings-to-tickets.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-01", title: "Missing RLS on orders", severity: "Critical", confidence: "Confirmed",
    category: "Multi-tenant isolation", taxonomy: "auth_rls_missing", location: "supabase/migrations/003.sql:42",
    status: "open", evidence: "orders table has no RLS policy", impact: "cross-tenant read",
    fix: "enable RLS and add a tenant policy", value: 5, ease: 4, safety: 5,
    ...over,
  };
}

// A Tracker double that records every call and lets a test pre-seed findByMarker hits.
function fakeTracker(existingMarkers: Record<string, CreatedRef> = {}) {
  const calls: { op: string; arg?: unknown; epicId?: string }[] = [];
  let n = 0;
  const tracker: Tracker = {
    async createEpic(input: ItemInput): Promise<CreatedRef> {
      calls.push({ op: "createEpic", arg: input });
      return { id: `E-${++n}`, url: `https://tracker/${n}` };
    },
    async createStory(input: ItemInput, epicId: string): Promise<CreatedRef> {
      calls.push({ op: "createStory", arg: input, epicId });
      return { id: `S-${++n}`, url: `https://tracker/${n}` };
    },
    async setLabels(id: string, labels: string[]): Promise<void> {
      calls.push({ op: "setLabels", arg: { id, labels } });
    },
    async setEstimate(): Promise<void> {},
    async attachBrief(): Promise<AttachedRef> {
      return { url: "x" };
    },
    async findByMarker(marker: string): Promise<CreatedRef | null> {
      calls.push({ op: "findByMarker", arg: marker });
      return existingMarkers[marker] ?? null;
    },
    async updateStory(): Promise<void> {},
  };
  return { tracker, calls };
}

describe("findingToTicket mapping", () => {
  it("maps a finding to a stable title/body/labels shape", () => {
    const t = findingToTicket(finding());
    expect(t.title).toBe("[Critical] Missing RLS on orders");
    expect(t.labels).toEqual(["harvey", "harvey:severity:critical", "harvey:confidence:confirmed"]);
    // Body leads with severity/confidence framing (the coverage-honesty guardrail) and carries the
    // location, fix, and the dedup marker.
    expect(t.body).toContain("**Severity:** Critical · **Confidence:** Confirmed");
    expect(t.body).toContain("**Location:** `supabase/migrations/003.sql:42`");
    expect(t.body).toContain("enable RLS and add a tenant policy");
    expect(t.body).toContain(t.marker);
  });

  it("adds a needs-triage label when confidence is not Confirmed", () => {
    expect(ticketLabels(finding({ confidence: "Review" }))).toContain("harvey:needs-triage");
    expect(ticketLabels(finding({ confidence: "Confirmed" }))).not.toContain("harvey:needs-triage");
  });

  it("derives the same marker for the same finding across runs regardless of line number", () => {
    // #457 identity ignores line/column churn, so a moved finding dedups to the same ticket.
    const a = findingMarker(finding({ location: "supabase/migrations/003.sql:42" }));
    const b = findingMarker(finding({ location: "supabase/migrations/003.sql:99" }));
    expect(a).toBe(b);
  });

  it("scopes the marker by engagement so two clients don't collide", () => {
    expect(findingMarker(finding(), "acme")).not.toBe(findingMarker(finding(), "globex"));
  });
});

describe("planTickets (dry-run / preview)", () => {
  it("is pure — computing a preview touches no tracker (no API calls possible)", () => {
    // The function takes no Tracker; a preview provably cannot write. This is the dry-run guarantee.
    const plan = planTickets([finding(), finding({ id: "F-02", category: "Performance" })]);
    expect(plan.tickets).toHaveLength(2);
    expect(plan.epics.map((e) => e.category).sort()).toEqual(["Multi-tenant isolation", "Performance"]);
  });

  it("flat grouping yields no epics", () => {
    const plan = planTickets([finding()], { grouping: "flat" });
    expect(plan.epics).toEqual([]);
    expect(plan.grouping).toBe("flat");
  });
});

describe("fileFindings dispatch + dedup", () => {
  it("grouped mode creates one epic per category and files findings as stories under it", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await fileFindings(tracker, [finding(), finding({ id: "F-02", category: "Performance" })], { grouping: "grouped" });

    expect(res.epicsCreated).toBe(2);
    expect(res.created).toHaveLength(2);
    const stories = calls.filter((c) => c.op === "createStory");
    expect(stories).toHaveLength(2);
    expect(stories.every((s) => typeof s.epicId === "string" && s.epicId.startsWith("E-"))).toBe(true);
  });

  it("skips a finding whose marker already exists — a re-audit does not duplicate", async () => {
    const f = finding();
    const marker = findingMarker(f);
    const { tracker, calls } = fakeTracker({ [marker]: { id: "S-99", url: "https://tracker/99" } });

    const res = await fileFindings(tracker, [f], { grouping: "flat" });

    expect(res.created).toHaveLength(0);
    expect(res.skipped).toEqual([{ marker, ref: { id: "S-99", url: "https://tracker/99" } }]);
    expect(calls.some((c) => c.op === "createEpic" || c.op === "createStory")).toBe(false);
  });

  it("flat mode files each finding as a standalone issue with its labels", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await fileFindings(tracker, [finding()], { grouping: "flat" });

    expect(res.epicsCreated).toBe(0);
    expect(res.created).toHaveLength(1);
    expect(calls.filter((c) => c.op === "createEpic")).toHaveLength(1);
    const labelCall = calls.find((c) => c.op === "setLabels");
    expect((labelCall?.arg as { labels: string[] }).labels).toContain("harvey:severity:critical");
  });
});
