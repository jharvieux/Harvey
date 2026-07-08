import { describe, expect, it } from "vitest";
import { revisionFlags, selectTier } from "./tier-policy.js";

describe("tier policy", () => {
  it("uses the base tier per task with no escalation", () => {
    expect(selectTier({ task: "clarify", revisionCount: 0, flags: [] })).toBe("standard");
    expect(selectTier({ task: "story-draft", revisionCount: 0, flags: [] })).toBe("standard");
    expect(selectTier({ task: "consistency", revisionCount: 0, flags: [] })).toBe("flagship");
    expect(selectTier({ task: "qa", revisionCount: 0, flags: [] })).toBe("flagship");
  });

  it("escalates a standard task to flagship on the third revision", () => {
    // The empirical "cheap model isn't getting it" point (design §7).
    expect(revisionFlags(2)).toEqual([]);
    expect(revisionFlags(3)).toEqual(["revision-loop"]);
    expect(selectTier({ task: "revise", revisionCount: 3, flags: revisionFlags(3) })).toBe("flagship");
    expect(selectTier({ task: "revise", revisionCount: 2, flags: revisionFlags(2) })).toBe("standard");
  });

  it("forces flagship when the user requests it", () => {
    expect(selectTier({ task: "revise", revisionCount: 0, flags: ["user-requested"] })).toBe("flagship");
  });

  it("escalates on a consistency contradiction and sizing anomaly", () => {
    expect(selectTier({ task: "epic-draft", revisionCount: 0, flags: ["contradiction"] })).toBe("flagship");
    expect(selectTier({ task: "story-draft", revisionCount: 0, flags: ["sizing-anomaly"] })).toBe("flagship");
  });
});
