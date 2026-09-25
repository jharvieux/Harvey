import { describe, expect, it } from "vitest";
import { canTransition, transition, WORKFLOW_EVENTS, type WorkflowEvent } from "./state-machine.js";
import { SESSION_STATES, type SessionState } from "./types.js";

const expectedStates: SessionState[] = [
  "intake", "clarify", "epic-draft", "epic-review", "stories-fan-out",
  "stories-review", "publish", "summary", "done",
];
const expectedEvents: WorkflowEvent[] = [
  "clarify-start", "clarify-done", "epic-drafted", "epic-revise", "epic-accept",
  "stories-drafted", "story-redraft", "stories-accept", "publish-ok", "publish-partial",
  "summary-shown",
];
const allowed = new Map<string, SessionState>([
  ["intake:clarify-start", "clarify"],
  ["clarify:clarify-done", "epic-draft"],
  ["epic-draft:epic-drafted", "epic-review"],
  ["epic-review:epic-revise", "epic-draft"],
  ["epic-review:epic-accept", "stories-fan-out"],
  ["stories-fan-out:stories-drafted", "stories-review"],
  ["stories-review:story-redraft", "stories-fan-out"],
  ["stories-review:stories-accept", "publish"],
  ["publish:publish-ok", "summary"],
  ["publish:publish-partial", "publish"],
  ["summary:summary-shown", "done"],
]);

describe("state machine", () => {
  it("exhaustively enforces the independently enumerated state/event contract", () => {
    expect([...SESSION_STATES]).toEqual(expectedStates);
    expect([...WORKFLOW_EVENTS]).toEqual(expectedEvents);
    let allowedCount = 0;
    let rejectedCount = 0;
    for (const state of SESSION_STATES) {
      for (const event of WORKFLOW_EVENTS) {
        const expected = allowed.get(`${state}:${event}`);
        expect(canTransition(state, event), `${state} + ${event}`).toBe(expected !== undefined);
        if (expected) {
          expect(transition(state, event)).toBe(expected);
          allowedCount++;
        } else {
          expect(() => transition(state, event)).toThrow(`invalid transition: ${event} is not allowed from state "${state}"`);
          rejectedCount++;
        }
      }
    }
    expect({ allowedCount, rejectedCount }).toEqual({ allowedCount: 11, rejectedCount: 88 });
  });

  it("walks the happy path intake -> done", () => {
    const path: [SessionState, WorkflowEvent, SessionState][] = [
      ["intake", "clarify-start", "clarify"],
      ["clarify", "clarify-done", "epic-draft"],
      ["epic-draft", "epic-drafted", "epic-review"],
      ["epic-review", "epic-accept", "stories-fan-out"],
      ["stories-fan-out", "stories-drafted", "stories-review"],
      ["stories-review", "stories-accept", "publish"],
      ["publish", "publish-ok", "summary"],
      ["summary", "summary-shown", "done"],
    ];
    for (const [from, event, to] of path) expect(transition(from, event)).toBe(to);
  });

  it("loops epic-review back to epic-draft on revise", () => {
    expect(transition("epic-review", "epic-revise")).toBe("epic-draft");
  });

  it("keeps publish in place on a partial failure for idempotent re-run", () => {
    expect(transition("publish", "publish-partial")).toBe("publish");
  });

  it("re-enters fan-out when a story needs a full redraft", () => {
    expect(transition("stories-review", "story-redraft")).toBe("stories-fan-out");
  });

  it("rejects transitions that skip the review gates", () => {
    // Accepting an epic before it has been drafted must not be possible.
    expect(canTransition("intake", "epic-accept")).toBe(false);
    expect(() => transition("epic-draft", "epic-accept")).toThrow(/invalid transition/);
  });

  it("treats done as terminal", () => {
    expect(canTransition("done", "summary-shown")).toBe(false);
  });
});
