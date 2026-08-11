import { describe, expect, it } from "vitest";
import { collectRelayCensus, type RelayCensusNode } from "./relay-census.js";

function node(overrides: Partial<RelayCensusNode> = {}): RelayCensusNode {
  return {
    number: 40,
    state: "CLOSED",
    url: "https://example.test/issues/40",
    body: "## Acceptance\n1. the criterion\n",
    comments: { totalCount: 0, nodes: [] },
    closedByPullRequestsReferences: { totalCount: 0, nodes: [] },
    ...overrides,
  };
}

describe("relay census venue parity and attribution (#1790)", () => {
  it("NEGATIVE CONTROL: ignores an unlinked PR even when it carries a relayed disposition", () => {
    const fixture = node({
      closedByPullRequestsReferences: {
        totalCount: 1,
        nodes: [{ number: 1346, body: "ACCEPTANCE #40.1 met: src/relay-census.ts:1 carries the completion" }],
      },
      unlinkedPullRequests: [{ number: 1374, body: "ACCEPTANCE #40.1 relayed: stale text in a venue the gate never reads" }],
    });

    expect(collectRelayCensus([fixture])).toEqual({ rows: [], duplicates: [] });
  });

  it("labels the retiring and retired venues separately", () => {
    const fixture = node({
      comments: {
        totalCount: 2,
        nodes: [
          { url: "https://example.test/comments/1", body: "Operator: may I apply the supervised edit?" },
          { url: "https://example.test/comments/2", body: "ACCEPTANCE #40.1 met: src/foo.ts:9 carries the ruled edit" },
        ],
      },
      closedByPullRequestsReferences: {
        totalCount: 1,
        nodes: [{ number: 1456, body: "ACCEPTANCE #40.1 relayed: supervised path awaiting the operator" }],
      },
    });

    const [row] = collectRelayCensus([fixture]).rows;
    expect(row).toMatchObject({
      status: "superseded",
      retired: { venue: "linked PR #1456", line: 1 },
      retiredBy: { venue: "#40 comment 2", line: 1, disposition: "met" },
    });
  });

  it("measures duplicate-disposition criteria instead of dropping them from the census", () => {
    const fixture = node({
      comments: {
        totalCount: 2,
        nodes: [
          { url: "https://example.test/comments/1", body: "ACCEPTANCE #40.1 met: src/foo.ts:9 covers it" },
          { url: "https://example.test/comments/2", body: "ACCEPTANCE #40.1 met: src/bar.ts:4 also covers it" },
        ],
      },
    });

    const result = collectRelayCensus([fixture]);
    expect(result.rows).toEqual([]);
    expect(result.duplicates).toEqual([
      expect.objectContaining({ issue: 40, index: 1, problem: expect.stringContaining("mapped 2 times") }),
    ]);
  });
});
