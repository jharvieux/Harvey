import { describe, expect, it } from "vitest";
import { canTransition, transition, type WorkflowEvent } from "./state-machine.js";
import type { SessionState } from "./types.js";

describe("state machine", () => {
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
