import { describe, expect, it } from "vitest";
import { auditRuleReach, deadFocusArmsInDoc, unreachedMessageTokens } from "./rule-claim-reach.js";
import { loadSemgrepRuleFiles } from "./disclosure-venue.js";

// The #1657 defect, reconstructed: ONE block-level `focus-metavariable: $OPTS` over a four-arm
// disjunction in which only the search arms bind $OPTS, while the message enumerates all four call
// sites. This is the shape the gate exists to refuse.
const PRE_1657_LDAP = `rules:
  - id: harvey-ldap-injection
    languages: [javascript, typescript]
    mode: taint
    message: >
      Request input reaches an LDAP search filter or bind DN unescaped. SCOPE OF THIS CHECK: the
      search/searchAsync options object, the bind DN, the compare value and the modify Change.
    pattern-sources:
      - pattern: req.query
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $C.search($BASE, $OPTS, ...)
              - pattern: $C.searchAsync($BASE, $OPTS, ...)
              - pattern: $C.bind($DN, ...)
              - pattern: $C.compare($DN, $ATTR, $X, ...)
              - pattern: $C.modify($DN, $CHANGE, ...)
          - focus-metavariable: $OPTS
          - pattern-either:
              - pattern-inside: |
                  require("$MOD")
                  ...
          - metavariable-regex:
              metavariable: $MOD
              regex: ^(ldapjs|ldapts)$
`;

// Post-#1657: each arm focuses its own argument, so no arm depends on a metavariable it never binds.
const POST_1657_LDAP = PRE_1657_LDAP.replace(
  `          - pattern-either:
              - pattern: $C.search($BASE, $OPTS, ...)
              - pattern: $C.searchAsync($BASE, $OPTS, ...)
              - pattern: $C.bind($DN, ...)
              - pattern: $C.compare($DN, $ATTR, $X, ...)
              - pattern: $C.modify($DN, $CHANGE, ...)
          - focus-metavariable: $OPTS
`,
  `          - pattern-either:
              - patterns:
                  - pattern: $C.search($BASE, $OPTS, ...)
                  - focus-metavariable: $OPTS
              - patterns:
                  - pattern: $C.bind($DN, ...)
                  - focus-metavariable: $DN
`,
);

describe("deadFocusArmsInDoc", () => {
  it("names the three #1657 arms that could never fire while the message advertised them", () => {
    const report = deadFocusArmsInDoc(PRE_1657_LDAP, "injection.yml");
    expect(report.dead.map((d) => d.arm)).toEqual([
      JSON.stringify({ pattern: "$C.bind($DN, ...)" }),
      JSON.stringify({ pattern: "$C.compare($DN, $ATTR, $X, ...)" }),
      JSON.stringify({ pattern: "$C.modify($DN, $CHANGE, ...)" }),
    ]);
    expect(report.dead.every((d) => d.focus === "$OPTS" && d.id === "harvey-ldap-injection")).toBe(true);
  });

  it("passes the #1657 fix — the same rule with a per-arm focus reports nothing", () => {
    expect(deadFocusArmsInDoc(POST_1657_LDAP, "injection.yml").dead).toEqual([]);
    expect(deadFocusArmsInDoc(POST_1657_LDAP, "injection.yml").focusBlocks).toBeGreaterThan(0);
  });

  it("spares a disjunction whose focus is bound by a sibling conjunct — the sanitizer shape, 16 of 16 hits before this exemption", () => {
    const sanitizer = `rules:
  - id: harvey-fixture
    message: >
      A fixture.
    pattern-sanitizers:
      - patterns:
          - pattern: fetch($X, ...)
          - pattern-either:
              - pattern-inside: |
                  if (!$ALLOW.includes($HOST)) { ... return; }
                  ...
              - pattern-inside: |
                  if (!$ALLOW.has($HOST)) { ... return; }
                  ...
          - focus-metavariable: $X
`;
    expect(deadFocusArmsInDoc(sanitizer, "base.yml").dead).toEqual([]);
  });

  it("spares a disjunction that binds the focus in NO arm — a context guard is not the binder", () => {
    const contextOnly = `rules:
  - id: harvey-fixture
    message: >
      A fixture.
    pattern-sinks:
      - patterns:
          - pattern-either:
              - patterns:
                  - pattern: $C.search($BASE, $OPTS, ...)
                  - focus-metavariable: $OPTS
          - pattern-either:
              - pattern-inside: |
                  require("$MOD")
                  ...
`;
    expect(deadFocusArmsInDoc(contextOnly, "injection.yml").dead).toEqual([]);
  });

  it("does not let $OPTSX stand in for $OPTS — a metavariable name runs to a word boundary", () => {
    const nearMiss = PRE_1657_LDAP.replace("- pattern: $C.bind($DN, ...)", "- pattern: $C.bind($OPTSX, ...)");
    expect(deadFocusArmsInDoc(nearMiss, "injection.yml").dead).toHaveLength(3);
  });
});

describe("the live rule set", () => {
  it("carries no dead focus arm", () => {
    const report = auditRuleReach(loadSemgrepRuleFiles());
    expect(report.rules).toBeGreaterThan(100);
    expect(report.focusBlocks).toBeGreaterThan(50);
    expect(report.dead).toEqual([]);
  });

  // The measured reason the message-side predicate is reported and not gated: its hits are the fix
  // the message recommends, not coverage the patterns lack. A rise here is a prompt to re-read them.
  it("has every unreached message token owned by a rule that was read", () => {
    const hits = unreachedMessageTokens(loadSemgrepRuleFiles());
    expect(hits.map((h) => h.id).sort()).toEqual([
      "harvey-client-trusted-price",
      "harvey-csv-formula-injection",
      "harvey-jwt-decode-render",
      "harvey-jwt-verify-noalg",
      "harvey-ldap-injection",
      "harvey-path-traversal",
      "harvey-secret-in-url-param",
      "harvey-template-injection",
      "harvey-xxe-parse",
    ]);
  });
});
