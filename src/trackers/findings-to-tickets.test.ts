import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Finding } from "../findings.js";
import { TrackerError } from "./http.js";
import { makePacer } from "./rate-limit.js";
import type { AttachedRef, CreatedRef, ItemInput, Tracker, UpdateStoryPatch } from "./types.js";
import { fileFindings, filingEligibility, findingMarker, findingToTicket, planTickets, ticketLabels } from "./findings-to-tickets.js";

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
    async updateStory(id: string, patch: UpdateStoryPatch): Promise<void> {
      calls.push({ op: "updateStory", arg: { id, patch } });
    },
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

  it("#825: embeds a verified suggested diff under the Fix prose on a paid run", () => {
    const f = finding({ suggestedFix: { diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new", verified: true, verification: "applies cleanly" } });
    const t = findingToTicket(f, { paid: true });
    expect(t.body).toContain("**Fix:** enable RLS and add a tenant policy");
    expect(t.body).toContain("```diff");
    expect(t.body).toContain("+new");
    expect(t.body).toContain("_Mechanically verified: applies cleanly_");
  });

  it("#825: never embeds a diff on the free tier, nor an UNVERIFIED diff on a paid run", () => {
    const verified = { diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new", verified: true };
    expect(findingToTicket(finding({ suggestedFix: verified }), { paid: false }).body).not.toContain("```diff");
    const unverified = { diff: "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new", verified: false };
    expect(findingToTicket(finding({ suggestedFix: unverified }), { paid: true }).body).not.toContain("```diff");
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

  it("deduplicates root, separator, dot, and symlink aliases without conflating case-sensitive files", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-tracker-identity-"));
    try {
      mkdirSync(join(root, "src"), { recursive: true });
      writeFileSync(join(root, "src", "a.ts"), "export {}\n");
      symlinkSync("src/a.ts", join(root, "alias.ts"));
      const options = { root, caseSensitive: true };
      const equivalent = [
        "src/a.ts:7", "./src//a.ts:19", "src\\.\\a.ts#L42",
        join(root, "src", "a.ts") + ":88", "alias.ts:3",
      ];
      expect(new Set(equivalent.map((location) => findingMarker(finding({ location }), "harvey", options))).size).toBe(1);
      expect(findingMarker(finding({ location: "src/Foo.ts" }), "harvey", options)).not.toBe(
        findingMarker(finding({ location: "src/foo.ts" }), "harvey", options),
      );
      expect(findingMarker(finding({ location: "src/Foo.ts" }), "harvey", { ...options, caseSensitive: false })).toBe(
        findingMarker(finding({ location: "src/foo.ts" }), "harvey", { ...options, caseSensitive: false }),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("scopes the marker by engagement so two clients don't collide", () => {
    expect(findingMarker(finding(), "acme")).not.toBe(findingMarker(finding(), "globex"));
  });
});

describe("planTickets (dry-run / preview)", () => {
  it("is pure — computing a preview touches no tracker (no API calls possible)", () => {
    // The function takes no Tracker; a preview provably cannot write. This is the dry-run guarantee.
    const plan = planTickets([finding(), finding({ id: "F-02", category: "Performance" })], { paid: true });
    expect(plan.tickets).toHaveLength(2);
    expect(plan.epics.map((e) => e.category).sort()).toEqual(["Multi-tenant isolation", "Performance"]);
  });

  it("flat grouping yields no epics", () => {
    const plan = planTickets([finding()], { grouping: "flat", paid: true });
    expect(plan.epics).toEqual([]);
    expect(plan.grouping).toBe("flat");
  });
});

describe("#824 paid-tier / content gate", () => {
  it("files nothing on a free-tier engagement, disclosing each held-back finding with a reason", () => {
    const plan = planTickets([finding(), finding({ id: "F-02" })], { paid: false });
    expect(plan.tickets).toHaveLength(0);
    expect(plan.epics).toHaveLength(0);
    expect(plan.excluded).toHaveLength(2);
    expect(plan.excluded[0]?.reason).toContain("paid-tier add-on");
  });

  it("on a paid run, drops Info-severity and Review-confidence indicators but keeps actionable findings", () => {
    const { fileable, excluded } = filingEligibility(
      [
        finding({ id: "keep", severity: "Critical", confidence: "Confirmed" }),
        finding({ id: "info", severity: "Info", confidence: "Confirmed" }),
        finding({ id: "watch", severity: "Watch", confidence: "Confirmed" }),
        finding({ id: "review", severity: "High", confidence: "Review" }),
        finding({ id: "na", severity: "High", confidence: "N/A" }),
      ],
      true,
    );
    expect(fileable.map((f) => f.id)).toEqual(["keep"]);
    expect(excluded.map((e) => e.finding.id)).toEqual(["info", "watch", "review", "na"]);
    expect(excluded.every((e) => e.reason.includes("filing threshold"))).toBe(true);
  });

  it("an all-Info/Review free-tier findings set yields zero tickets", () => {
    const noisy = [finding({ severity: "Info", confidence: "Review" }), finding({ id: "F-02", severity: "Watch", confidence: "Review" })];
    const plan = planTickets(noisy, { paid: false });
    expect(plan.tickets).toHaveLength(0);
    expect(plan.excluded).toHaveLength(2);
  });

  it("fileFindings on a free-tier run writes nothing and surfaces the exclusions", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await fileFindings(tracker, [finding()], { grouping: "flat", paid: false });
    expect(res.created).toHaveLength(0);
    expect(res.excluded).toHaveLength(1);
    expect(calls.some((c) => c.op === "createEpic" || c.op === "createStory")).toBe(false);
  });
});

describe("fileFindings dispatch + dedup", () => {
  it("grouped mode creates one epic per category and files findings as stories under it", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await fileFindings(tracker, [finding(), finding({ id: "F-02", category: "Performance" })], { grouping: "grouped", paid: true });

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

    const res = await fileFindings(tracker, [f], { grouping: "flat", paid: true });

    expect(res.created).toHaveLength(0);
    expect(res.skipped).toEqual([{ marker, ref: { id: "S-99", url: "https://tracker/99" } }]);
    expect(calls.some((c) => c.op === "createEpic" || c.op === "createStory")).toBe(false);
  });

  it("#747 --update patches an already-filed ticket instead of skipping it", async () => {
    const f = finding();
    const marker = findingMarker(f);
    const { tracker, calls } = fakeTracker({ [marker]: { id: "S-99", url: "https://tracker/99" } });

    const res = await fileFindings(tracker, [f], { grouping: "flat", paid: true, update: true });

    expect(res.skipped).toHaveLength(0);
    expect(res.updated).toEqual([{ marker, ref: { id: "S-99", url: "https://tracker/99" } }]);
    const upd = calls.find((c) => c.op === "updateStory");
    expect((upd?.arg as { id: string }).id).toBe("S-99");
  });

  it("#747 backs off on a 429 during filing without creating a duplicate", async () => {
    const clock = { t: 0 };
    const pacer = makePacer({ baseBackoffMs: 1, now: () => clock.t, sleep: async (ms: number) => void (clock.t += ms) });
    let attempts = 0;
    const created: string[] = [];
    const tracker: Tracker = {
      async createEpic(input: ItemInput): Promise<CreatedRef> {
        attempts++;
        if (attempts === 1) throw new TrackerError("POST", "u", 429, "secondary rate limit");
        created.push(input.title);
        return { id: "E-1", url: "u" };
      },
      async createStory(): Promise<CreatedRef> {
        return { id: "S-1", url: "u" };
      },
      async setLabels(): Promise<void> {},
      async setEstimate(): Promise<void> {},
      async attachBrief(): Promise<AttachedRef> {
        return { url: "x" };
      },
      async findByMarker(): Promise<CreatedRef | null> {
        return null;
      },
      async updateStory(): Promise<void> {},
    };

    const res = await fileFindings(tracker, [finding()], { grouping: "flat", paid: true, pacer });

    expect(attempts).toBe(2); // retried the 429 once
    expect(created).toEqual(["[Critical] Missing RLS on orders"]); // created exactly once — no duplicate
    expect(res.created).toHaveLength(1);
  });

  it("flat mode files each finding as a standalone issue with its labels", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await fileFindings(tracker, [finding()], { grouping: "flat", paid: true });

    expect(res.epicsCreated).toBe(0);
    expect(res.created).toHaveLength(1);
    expect(calls.filter((c) => c.op === "createEpic")).toHaveLength(1);
    const labelCall = calls.find((c) => c.op === "setLabels");
    expect((labelCall?.arg as { labels: string[] }).labels).toContain("harvey:severity:critical");
  });
});
