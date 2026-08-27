import { describe, expect, it } from "vitest";

// Operational probe: this comment intentionally exercises disclosure-workflow path relevance.
import {
  BOUNDED_RULES,
  BOUND_TRIAGE,
  auditDisclosureVenue,
  boundedRatchet,
  commentBounds,
  compoundScopeProblems,
  loadSemgrepRuleFiles,
  loadSemgrepRules,
  parseSemgrepRules,
  residualBoundish,
  boundTriageSourceProblems,
  scopeSentence,
  tsDetectorFilesRead,
  unattributedBounds,
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

  // Shaped like a real rule message, not a one-sentence stub: the descriptive half reuses the
  // comment's vocabulary, exactly as a genuine finding's does. A stub message shares no words with
  // the comment and so passes this test for the wrong reason — it never exercises the scoping.
  it("fails a scope sentence with nothing of the declared bound in it, even when the DESCRIPTIVE half reuses the comment's words — the sticker is not the disclosure", () => {
    expect(
      verdictOf(
        "NOTE: does not cover the interpolated form.",
        "An interpolated value reaches the sink on this line, so the string it builds is" +
          " attacker-controlled at runtime. SCOPE OF THIS CHECK: nothing worth naming.",
      ),
    ).toBe("unrelated-scope-sentence");
  });

  // The other direction, pinned so it is a known bound rather than a surprise: correspondence is a
  // keyword overlap, so a faultless paraphrase sharing no term with the comment is refused. Stated
  // in disclosure-venue.ts's SCOPE block. If this test ever goes red, an adjudicator replaced the
  // overlap — update that block rather than deleting this.
  it("over-refuses a correct paraphrase that shares no wording with the comment — a stated bound of the overlap approach", () => {
    expect(
      verdictOf(
        "LIMITATION: dynamically-interpolated selectors are unhandled by the shape below.",
        "An untrusted value reaches a DOM sink. SCOPE OF THIS CHECK: only a string literal written" +
          " inline is examined; a value built at runtime from concatenation or a template is outside" +
          " what this rule can see, so silence there is not a clean result.",
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
    expect(compoundScopeProblems(rules)).toEqual([]);
  });

  it("NEGATIVE CONTROL: rejects either #1411.4 precision false negative missing from the path-traversal scope", () => {
    const traversal = rules.find((r) => r.id === "harvey-path-traversal");
    expect(traversal).toBeDefined();

    const withoutNormalize = rules.map((r) => r.id === traversal!.id
      ? { ...r, message: r.message.replace("`path.normalize(...)` is not recognised as a containment guard", "Normalization is discussed elsewhere") }
      : r);
    const withoutBareOpen = rules.map((r) => r.id === traversal!.id
      ? { ...r, message: r.message.replace("A bare or named-import `open(path)` is not examined", "Some file-open calls are discussed elsewhere") }
      : r);

    expect(compoundScopeProblems(withoutNormalize)).toEqual([
      expect.stringContaining("path.normalize is not recognised as a containment guard"),
    ]);
    expect(compoundScopeProblems(withoutBareOpen)).toEqual([
      expect.stringContaining("bare or named-import open is not examined"),
    ]);
  });

  // The population-level negative control, and the one that measured the defect. A fixture proves
  // the gate CAN reject a contentless sticker; only this proves it rejects one on the rules it
  // actually guards. Measured 2026-07-27 against the whole message: 9 of 13 still passed.
  //
  // The sticker's own wording matters, which #1342 found the hard way: the previous text ("nothing
  // worth naming") shared the word "naming" with harvey-secret-in-url-param's bound ("this is a
  // naming heuristic"), which the widened vocabulary brought into the population — so the control
  // passed that one rule for a reason that had nothing to do with disclosure. A control must carry
  // no content word any real bound might use.
  it("rejects a contentless sticker substituted for the real disclosure on EVERY bounded rule", () => {
    const bounded = rules.filter((r) => commentBounds(r).length > 0);
    const stillPassing = bounded
      .map((r) => {
        const scope = scopeSentence(r.message);
        if (scope === null) throw new Error(`${r.id} passes the gate with no scope sentence`);
        const prefix = r.message.slice(0, r.message.length - scope.length);
        return { ...r, message: `${prefix}SCOPE OF THIS CHECK: n/a.` };
      })
      .filter((r) => verdict(r, commentBounds(r)) === "stated")
      .map((r) => r.id);
    expect(stillPassing).toEqual([]);
  });
});

// #1342: a bound the ORIGINAL vocabulary already covered was invisible purely because the author
// pressed return in the middle of the phrase. harvey-jwt-sign-noexpiry and
// harvey-edgefn-secret-fallback were both found this way, not by widening the words.
describe("a bound that wraps across comment lines", () => {
  it("is seen, and the hit carries only the lines the phrase spans", () => {
    const text = [
      "rules:",
      "  # A variable options argument is NOT flagged — this rule can't",
      "  # see whether expiresIn lives inside it, so it stays out.",
      "  # An unrelated note about pattern mechanics.",
      "  - id: harvey-fixture",
      "    message: >",
      "      A finding. SCOPE OF THIS CHECK: an options object held in a variable is not assessed.",
      "    pattern: foo()",
    ].join("\n");
    const [parsed] = parseSemgrepRules(text, "fixture.yml");
    const hits = commentBounds(parsed as SemgrepRule);

    expect(hits.map((h) => h.marker)).toContain("cannot see");
    expect(hits[0]?.text).toContain("expiresIn");
    expect(hits[0]?.text).not.toContain("unrelated note"); // the bound's vocabulary, not the preamble's
    expect(verdict(parsed as SemgrepRule, hits)).toBe("stated");
  });
});

describe("boundedRatchet (#1330's deletion vector)", () => {
  it("reports a rule that still exists and has lost its recorded bound", () => {
    const kept = loadSemgrepRules();
    const stripped = kept.map((r) => (r.id === BOUNDED_RULES[0] ? { ...r, comments: [] } : r));

    expect(boundedRatchet(stripped)).toEqual([BOUNDED_RULES[0]]);
  });

  it("is silent about a baseline rule that no longer exists — renaming and deleting are legitimate", () => {
    expect(boundedRatchet([])).toEqual([]);
  });

  it("passes on the committed rule set", () => {
    expect(boundedRatchet(loadSemgrepRules())).toEqual([]);
  });
});

// #1342 criteria 3 and 4: what the gate cannot judge is counted, never absent.
describe("the gate's own residual", () => {
  it("triages every rule carrying bound-ish prose outside the marker vocabulary", () => {
    const residual = residualBoundish(loadSemgrepRules()).map((r) => r.id).sort();

    expect(residual).toEqual([...BOUND_TRIAGE.map((t) => t.id)].sort());
    expect(boundTriageSourceProblems(loadSemgrepRules())).toEqual([]);
  });

  it("NEGATIVE CONTROL: rejects a mutated sourceExcerpt absent from the spawn rule comments", () => {
    const inverted = BOUND_TRIAGE.map((entry) => entry.id === "harvey-spawn-shell-true"
      ? { ...entry, sourceExcerpt: "the argv-array rules do cover the excluded spawn/execFile family" }
      : entry);

    expect(boundTriageSourceProblems(loadSemgrepRules(), inverted)).toEqual([
      expect.stringContaining("harvey-spawn-shell-true: source excerpt is not present"),
    ]);
  });

  // #1714: the recorded blocker at src/disclosure-venue.ts says a TS/AST detector's bound comments
  // are read by no gate, and its falsifier reads this number. Both directions, because a surface
  // report that can only ever say 0 re-tests nothing — which is the defect #1714 was filed for.
  it("reports the TS/AST detector sources on the gate's scan surface — none today, and it can say otherwise", () => {
    expect(tsDetectorFilesRead(loadSemgrepRuleFiles())).toEqual([]);
    expect(
      tsDetectorFilesRead(
        new Map([
          ["src/scan/rules/semgrep/base.yml", "rules: []"],
          ["src/scan/emitter-error.ts", "// SAME-FILE HEURISTIC ONLY"],
          ["src/detectors/app-router.ts", "// LIMITATION: ..."],
        ]),
      ),
    ).toEqual(["src/scan/emitter-error.ts", "src/detectors/app-router.ts"]);
  });

  it("counts and names the marker-bearing comment lines that belong to no rule", () => {
    const rules = loadSemgrepRules();
    const { commentLines, unattributed, bearing } = unattributedBounds(rules, loadSemgrepRuleFiles());

    expect(unattributed).toBeGreaterThan(0);
    expect(unattributed).toBeLessThan(commentLines);
    // Zero here would mean the shared-anchor gap reads as closed when it is only unmeasured.
    expect(bearing.length).toBeGreaterThan(0);
    expect(bearing.every((b) => b.file.endsWith(".yml") && b.line > 0 && b.text.length > 0)).toBe(true);
  });
});
