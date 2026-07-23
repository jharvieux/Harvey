import { describe, expect, it } from "vitest";
import { tryChromeCandidates } from "./lighthouse-chrome-candidates.js";

describe("tryChromeCandidates (#841)", () => {
  it("returns the first candidate that succeeds without trying any other", async () => {
    const tried: string[] = [];
    const result = await tryChromeCandidates([
      {
        label: "bundled-playwright",
        attempt: async () => {
          tried.push("bundled-playwright");
          return "bundled-result";
        },
      },
      { label: "system", attempt: async () => { tried.push("system"); return "system-result"; } },
    ]);
    expect(result).toBe("bundled-result");
    expect(tried).toEqual(["bundled-playwright"]);
  });

  it("falls through to the next candidate when the first one throws while launching (pre-#841 behavior, unchanged)", async () => {
    const tried: string[] = [];
    const result = await tryChromeCandidates([
      {
        label: "bundled-playwright",
        attempt: async () => {
          tried.push("bundled-playwright");
          throw new Error("ENOENT");
        },
      },
      { label: "system", attempt: async () => { tried.push("system"); return "system-result"; } },
    ]);
    expect(result).toBe("system-result");
    expect(tried).toEqual(["bundled-playwright", "system"]);
  });

  // #841: the actual regression. launchChrome() wires each candidate's post-launch verification
  // (the real Lighthouse audit of the probe route) into the SAME attempt() as the launch, so a
  // candidate that launched fine but then failed to measure anything (NO_FCP or any other
  // Lighthouse runtimeError) throws from attempt() too — indistinguishable, from this generic
  // loop's perspective, from a launch failure. Modeled here directly: candidate 1's attempt()
  // throws AFTER "launching" (proven by the tried[] entry existing before the throw), and the loop
  // must still advance to candidate 2.
  it("falls through to the next candidate when the first one launches but then fails to measure anything (soft NO_FCP)", async () => {
    const tried: string[] = [];
    const result = await tryChromeCandidates([
      {
        label: "bundled-playwright",
        attempt: async () => {
          tried.push("bundled-playwright launched");
          throw new Error("Lighthouse could not measure /: NO_FCP");
        },
      },
      {
        label: "system",
        attempt: async () => {
          tried.push("system launched and measured");
          return "system-result";
        },
      },
    ]);
    expect(result).toBe("system-result");
    expect(tried).toEqual(["bundled-playwright launched", "system launched and measured"]);
  });

  it("throws naming the last candidate's failure once every candidate is exhausted", async () => {
    await expect(
      tryChromeCandidates([
        { label: "bundled-playwright", attempt: async () => { throw new Error("ENOENT"); } },
        { label: "system", attempt: async () => { throw new Error("NO_FCP"); } },
      ]),
    ).rejects.toThrow(/system: NO_FCP/);
  });

  it("throws a default message when given zero candidates", async () => {
    await expect(tryChromeCandidates([])).rejects.toThrow(/no Chrome candidate was reachable/);
  });
});
