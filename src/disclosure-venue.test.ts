import { describe, expect, it } from "vitest";
import {
  auditDisclosureVenue,
  commentBounds,
  loadSemgrepRules,
  parseSemgrepRules,
  verdict,
  type SemgrepRule,
} from "./disclosure-venue.js";

const rule = (comment: string, message: string): string =>
  ["rules:", `  # ${comment}`, "  - id: harvey-fixture", "    message: >", `      ${message}`, "    pattern: foo()"].join(
    "\n",
  );

const one = (comment: string, message: string): SemgrepRule => {
  const [first] = parseSemgrepRules(rule(comment, message), "fixture.yml");
  if (!first) throw new Error("no rule parsed");
  return first;
};

const verdictOf = (comment: string, message: string): string => {
  const r = one(comment, message);
  return verdict(r, commentBounds(r));
};

describe("parseSemgrepRules", () => {
  it("gives a preamble to the rule below it, not the rule above — a bound read off the neighbour is a false accusation and a real miss", () => {
    const text = [
      "rules:",
      "  - id: harvey-first",
      "    message: >",
      "      First.",
      "",
      "  # NOTE: does not cover the wrapped form.",
      "  - id: harvey-second",
      "    message: >",
      "      Second.",
    ].join("\n");
    const [first, second] = parseSemgrepRules(text, "fixture.yml");
    expect(commentBounds(first!)).toHaveLength(0);
    expect(commentBounds(second!).map((h) => h.marker)).toContain("NOTE:");
  });

  it("keeps a deeply-indented comment with the rule it sits inside", () => {
    const text = [
      "rules:",
      "  - id: harvey-first",
      "    message: >",
      "      First.",
      "    patterns:",
      "      # NOTE: this arm does not cover the async form.",
      "      - pattern: foo()",
      "  - id: harvey-second",
      "    message: >",
      "      Second.",
    ].join("\n");
    const [first, second] = parseSemgrepRules(text, "fixture.yml");
    expect(commentBounds(first!).map((h) => h.marker)).toContain("NOTE:");
    expect(commentBounds(second!)).toHaveLength(0);
  });

  it("throws on a rule with no message rather than reading it as an empty one — an empty message passes every check here", () => {
    const text = ["rules:", "  - id: harvey-first", "    pattern: foo()"].join("\n");
    expect(() => parseSemgrepRules(text, "fixture.yml")).toThrow(/no `message: >` block/);
  });
});

describe("verdict", () => {
  it("fails a rule whose comment declares a bound and whose message never mentions it", () => {
    expect(verdictOf("NOTE: does not cover the interpolated form.", "An interpolated value reaches a sink.")).toBe(
      "no-scope-sentence",
    );
  });

  it("fails a scope sentence with nothing of the declared bound in it — the sticker is not the disclosure", () => {
    expect(
      verdictOf(
        "NOTE: does not cover the interpolated form.",
        "A value reaches a sink. SCOPE OF THIS CHECK: nothing worth naming.",
      ),
    ).toBe("unrelated-scope-sentence");
  });

  it("passes when the message carries a scope sentence naming the bound", () => {
    expect(
      verdictOf(
        "NOTE: does not cover the interpolated form.",
        "A value reaches a sink. SCOPE OF THIS CHECK: an interpolated regex is not assessed.",
      ),
    ).toBe("stated");
  });

  it("corresponds across punctuation — a comment's hosting-layer bound is stated by a message's hosting layer", () => {
    expect(
      verdictOf(
        "Review — same hosting-layer caveat as HSTS.",
        "No HSTS here. SCOPE OF THIS CHECK: a header set at the CDN/hosting layer is invisible to a source scan.",
      ),
    ).toBe("stated");
  });

  it("does not read pattern mechanics as a bound — 'does not match' describes correct non-firing", () => {
    expect(verdictOf("A short TTL (e.g. 300) does not match.", "The signed URL TTL is very long.")).toBe(
      "no-bound-recorded",
    );
  });
});

describe("the committed semgrep rules", () => {
  const rules = loadSemgrepRules();

  it("has a non-empty bounded population — a gate judging nothing passes for the wrong reason", () => {
    expect(rules.length).toBeGreaterThan(0);
    expect(rules.filter((r) => commentBounds(r).length > 0).length).toBeGreaterThan(0);
  });

  it("states every recorded bound in the finding it bounds", () => {
    const violations = auditDisclosureVenue(rules);
    expect(violations.map((v) => `${v.id} (${v.verdict})`)).toEqual([]);
  });
});
