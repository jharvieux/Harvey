// #883 ticket write-back: only a verified transition touches a ticket. Resolved ⇒ comment + close;
// regressed ⇒ comment + reopen; persistent/unverifiable/already-resolved ⇒ provably no tracker
// call; a missing ticket or a tracker failure is disclosed per finding, never silently dropped.

import { describe, expect, it } from "vitest";
import type { GateReport, GateResult } from "../fix/gate.js";
import type { CreatedRef, TicketState, TicketWriteback } from "./types.js";
import { writeBackVerification } from "./verify-writeback.js";

function result(o: Partial<GateResult>): GateResult {
  return {
    findingId: "F-07", identity: "m5 — unused parameter::app/api/route.ts", marker: "<!-- harvey-finding:abc -->",
    title: "Unused parameter", taxonomy: "M5 — Unused parameter", location: "app/api/route.ts:8",
    status: "resolved", detail: "clean at app/api/route.ts", ...o,
  };
}

function report(results: GateResult[]): GateReport {
  const counts = { resolved: 0, persistent: 0, regressed: 0, unverifiable: 0 };
  for (const r of results) counts[r.status]++;
  return { engagement: "harvey", targetDir: "/tmp/t", commit: "abc1234", generatedAt: "2026-07-24T00:00:00Z", results, counts };
}

interface Call { method: string; args: unknown[] }

function fakeTracker(ticket: CreatedRef | null = { id: "42", url: "https://tracker/42" }) {
  const calls: Call[] = [];
  const tracker: TicketWriteback = {
    findByMarker: async (marker: string) => {
      calls.push({ method: "findByMarker", args: [marker] });
      return ticket;
    },
    addComment: async (id: string, body: string) => {
      calls.push({ method: "addComment", args: [id, body] });
    },
    transitionState: async (id: string, to: TicketState) => {
      calls.push({ method: "transitionState", args: [id, to] });
    },
  };
  return { tracker, calls };
}

describe("writeBackVerification", () => {
  it("closes a newly-verified-resolved finding's ticket with a verification comment", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await writeBackVerification(tracker, report([result({ status: "resolved" })]));

    expect(res.closed).toBe(1);
    expect(calls.map((c) => c.method)).toEqual(["findByMarker", "addComment", "transitionState"]);
    expect(calls[1]?.args[1]).toContain("resolved");
    expect(calls[1]?.args[1]).toContain("abc1234"); // the verified commit is in the note
    expect(calls[2]?.args).toEqual(["42", "closed"]);
    expect(res.records[0]).toMatchObject({ findingId: "F-07", action: "closed", ticket: { id: "42" } });
  });

  it("reopens a regressed finding's ticket with a reintroduction comment", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await writeBackVerification(tracker, report([result({ status: "regressed", previousStatus: "resolved", detail: "still firing" })]));

    expect(res.reopened).toBe(1);
    expect(calls[1]?.args[1]).toContain("reintroduced");
    expect(calls[2]?.args).toEqual(["42", "reopened"]);
  });

  it("makes NO tracker call for persistent, unverifiable, or already-resolved findings", async () => {
    const { tracker, calls } = fakeTracker();
    const res = await writeBackVerification(
      tracker,
      report([
        result({ findingId: "F-01", status: "persistent", detail: "still firing" }),
        result({ findingId: "F-02", status: "unverifiable", detail: "no detector re-run resolver" }),
        result({ findingId: "F-03", status: "resolved", previousStatus: "resolved" }),
      ]),
    );

    expect(calls).toEqual([]); // an open ticket is untouched; an unverified one is NEVER closed
    expect(res.closed + res.reopened + res.failed).toBe(0);
    expect(res.records.map((r) => r.action)).toEqual(["none", "none", "none"]);
    expect(res.records[1]?.reason).toContain("never closed on faith");
  });

  it("discloses a resolved finding whose marker has no ticket, without failing the batch", async () => {
    const { tracker, calls } = fakeTracker(null);
    const res = await writeBackVerification(tracker, report([result({ status: "resolved" })]));

    expect(calls.map((c) => c.method)).toEqual(["findByMarker"]); // no comment, no close
    expect(res.closed).toBe(0);
    expect(res.records[0]?.action).toBe("none");
    expect(res.records[0]?.reason).toContain("no ticket found");
  });

  it("captures a tracker failure on one ticket and continues with the rest", async () => {
    const { tracker, calls } = fakeTracker();
    const failing: TicketWriteback = {
      ...tracker,
      transitionState: async (id: string, to: TicketState) => {
        if (id === "42" && calls.filter((c) => c.method === "addComment").length === 1) throw new Error("Jira: no workflow transition available");
        calls.push({ method: "transitionState", args: [id, to] });
      },
    };
    const res = await writeBackVerification(
      failing,
      report([result({ findingId: "F-01", status: "resolved" }), result({ findingId: "F-02", status: "resolved" })]),
    );

    expect(res.failed).toBe(1);
    expect(res.closed).toBe(1);
    expect(res.records[0]?.error).toContain("no workflow transition");
    expect(res.records[1]?.action).toBe("closed"); // the batch went on
  });
});
