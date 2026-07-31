// #1307 — the ratchet's two pawls. A gate that only ever adds rows is a suppression list, and one
// that only ever removes them cannot catch a regression; both directions have to fail.

import { describe, expect, it } from "vitest";
import { blindSpotSuspects, collect, compare, exportedNames, hiddenByFlag, inFileConsumers, reasonTriaged, toBaseline } from "./test-only-exports.js";

const report = {
  files: ["src/fix/escalation.ts"],
  issues: [{ file: "src/fix/schedule.ts", exports: [{ name: "runScheduled" }], types: [{ name: "Caps" }] }],
};

describe("collect", () => {
  it("keeps the unreachable FILE and its module's exports apart, and records no line numbers", () => {
    expect(collect(report)).toEqual([
      { kind: "file", id: "src/fix/escalation.ts" },
      { kind: "export", id: "src/fix/schedule.ts:runScheduled" },
      { kind: "type", id: "src/fix/schedule.ts:Caps" },
    ]);
  });
});

describe("compare", () => {
  const baseline = toBaseline(collect(report));

  it("passes when the report matches the baseline exactly", () => {
    expect(compare(collect(report), baseline)).toEqual({ added: [], stale: [] });
  });

  it("reports a capability that shipped without a production caller", () => {
    const rows = [...collect(report), { kind: "export", id: "src/fix/new.ts:justShipped" } as const];
    expect(compare(rows, baseline).added).toEqual([{ kind: "export", id: "src/fix/new.ts:justShipped" }]);
  });

  it("reports a baseline row that has since gained a caller, so the list can only shrink", () => {
    const rows = collect(report).filter((r) => r.id !== "src/fix/schedule.ts:runScheduled");
    expect(compare(rows, baseline).stale).toEqual([{ kind: "export", id: "src/fix/schedule.ts:runScheduled" }]);
  });

  it("does not confuse an export with a type of the same name in the same file", () => {
    const renamedKind = [{ kind: "export", id: "src/fix/schedule.ts:Caps" } as const];
    expect(compare(renamedKind, { files: [], exports: [], types: ["src/fix/schedule.ts:Caps"] }).added).toEqual(renamedKind);
  });
});

describe("exportedNames", () => {
  it("names what is inside an unreachable file, which knip reports only as a path", () => {
    const text = "export function runEscalation() {}\nexport const MAX = 1;\nexport interface Plan { a: number }\nfunction internal() {}\n";
    expect(exportedNames("src/fix/escalation.ts", text)).toEqual(["runEscalation", "MAX", "Plan"]);
  });
});

// #1328 — the compensating check for `ignoreExportsUsedInFile`. The live repo currently reports ZERO
// suspects, so without these the check would look identical to one that has no failing direction.
describe("inFileConsumers", () => {
  const text = [
    "export const DEFAULT_CAPS = { maxSlots: 4 };",
    "export function runScheduled(caps = DEFAULT_CAPS) { return caps; }",
    "export function unrelated() { return 1; }",
  ].join("\n");

  it("names the declaration keeping a symbol alive, not the symbol's own declaration", () => {
    expect(inFileConsumers("src/fix/schedule.ts", text, "DEFAULT_CAPS")).toEqual(["runScheduled"]);
  });

  it("reports no consumer for a symbol nothing in the file references", () => {
    expect(inFileConsumers("src/fix/schedule.ts", text, "unrelated")).toEqual([]);
  });
});

describe("blindSpotSuspects", () => {
  // The two instances #1331 found BY HAND, in the shape they had at that baseline: each was kept
  // alive solely by a consumer that was itself on the backlog. Both have production callers today,
  // which is why the query must still be proven able to fire.
  const schedule = "export const DEFAULT_CAPS = { maxSlots: 4 };\nexport function runScheduled(caps = DEFAULT_CAPS) { return caps; }\n";
  const verify = "export function scrubSecrets(t: string) { return t; }\nexport function runCommand(c: string) { return scrubSecrets(c); }\n";
  const sources: Record<string, string> = { "src/fix/schedule.ts": schedule, "src/fix/verify.ts": verify };
  const read = (p: string): string => sources[p] ?? "";
  const hidden = [
    { kind: "export", id: "src/fix/schedule.ts:DEFAULT_CAPS" },
    { kind: "export", id: "src/fix/verify.ts:scrubSecrets" },
  ] as const;

  it("finds dead capability propping up dead capability — both instances #1331 found by hand", () => {
    const baseline = { files: [], exports: ["src/fix/schedule.ts:runScheduled", "src/fix/verify.ts:runCommand"], types: [] };
    expect(blindSpotSuspects(hidden, baseline, read)).toEqual([
      { id: "src/fix/schedule.ts:DEFAULT_CAPS", consumers: ["runScheduled"] },
      { id: "src/fix/verify.ts:scrubSecrets", consumers: ["runCommand"] },
    ]);
  });

  it("clears a row once its in-file consumer gains a production caller — the ratchet's self-heal", () => {
    const baseline = { files: [], exports: ["src/fix/verify.ts:runCommand"], types: [] };
    expect(blindSpotSuspects(hidden, baseline, read).map((s) => s.id)).toEqual(["src/fix/verify.ts:scrubSecrets"]);
  });

  it("treats a whole dead FILE as a dead consumer, since nothing in it is reachable", () => {
    const baseline = { files: ["src/fix/schedule.ts"], exports: [], types: [] };
    expect(blindSpotSuspects([hidden[0]], baseline, read).map((s) => s.id)).toEqual(["src/fix/schedule.ts:DEFAULT_CAPS"]);
  });
});

// #1547. The standing ruling is "a caller OR a recorded reason", and the gate could only ever see
// the first — so a triaged row and an untouched one printed identically and the backlog number could
// only fall by wiring. The binding is narrow on purpose; each direction below is one of the ways a
// loose one would let a row absolve itself.
describe("reasonTriaged (#1547)", () => {
  const rows = [
    { kind: "export", id: "src/a.ts:alpha" },
    { kind: "export", id: "src/a.ts:beta" },
    { kind: "file", id: "src/fixture.ts" },
  ] as const;
  const reason = (file: string, text: string) => ({ file, line: 7, fields: { REASON: text } });
  const SOURCE: Record<string, string> = { "src/fixture.ts": "export const recordedResponses = 1;\nexport function replay() {}\n" };
  const read = (p: string): string => SOURCE[p] ?? "";
  const triaged = (blocks: Parameters<typeof reasonTriaged>[1]) => reasonTriaged(rows, blocks, read).map((x) => x.row.id);

  it("marks a row whose OWN file carries a reason naming its symbol", () => {
    const t = reasonTriaged(rows, [reason("src/a.ts", "alpha is an oracle, so production never imports it")], read);
    expect(t.map((x) => x.row.id)).toEqual(["src/a.ts:alpha"]);
    expect(t[0]!.line).toBe(7);
  });

  it("does NOT let one reason in a file absolve every export in it", () => {
    expect(triaged([reason("src/a.ts", "alpha is an oracle")])).not.toContain("src/a.ts:beta");
  });

  it("does NOT accept a reason recorded in some OTHER file, however precisely it names the symbol", () => {
    expect(triaged([reason("src/elsewhere.ts", "src/a.ts:alpha and alpha are deliberate")])).toEqual([]);
  });

  it("takes a whole-file row's path OR any of its unreachable exports as what the claim must name", () => {
    expect(triaged([reason("src/fixture.ts", "src/fixture.ts is a recorded-response oracle")])).toEqual(["src/fixture.ts"]);
    expect(triaged([reason("src/fixture.ts", "recordedResponses is an answer key, never a production input")])).toEqual(["src/fixture.ts"]);
    expect(triaged([reason("src/fixture.ts", "this file is deliberate")])).toEqual([]);
  });

  // #1648 — the binding was satisfiable by a PASSING MENTION. Both vectors below were probed against
  // the shipped function on 2026-07-31 and both absolved their row.
  it("REFUSES a substring: alphaBetaGamma is not a claim about alpha", () => {
    expect(triaged([reason("src/a.ts", "alphaBetaGamma is deliberate")])).toEqual([]);
    expect(triaged([reason("src/a.ts", "prealpha is deliberate")])).toEqual([]);
    expect(triaged([reason("src/a.ts", "`alpha` is deliberate")])).toEqual(["src/a.ts:alpha"]);
  });

  it("REFUSES an incidental mention outside REASON: — only the field carrying the claim counts", () => {
    expect(triaged([{ file: "src/a.ts", line: 3, fields: { REASON: "unrelated", PROVENANCE: "MEASURED 2026-07-31 — grepped for alpha" } }])).toEqual([]);
    expect(triaged([{ file: "src/a.ts", line: 3, fields: { REASON: "unrelated", TOUCHES: "src/a.ts:beta" } }])).toEqual([]);
  });

  it("REFUSES a whole-file row absolved by a TOUCHES: that merely lists the file — that is what TOUCHES: always says", () => {
    expect(triaged([{ file: "src/fixture.ts", line: 3, fields: { REASON: "the scanner skips minified output", TOUCHES: "src/fixture.ts" } }])).toEqual([]);
  });
});

describe("hiddenByFlag", () => {
  it("is the rows the unflagged run reports and the gated run does not", () => {
    const unflagged = [
      { kind: "export", id: "src/a.ts:one" },
      { kind: "export", id: "src/a.ts:two" },
    ] as const;
    expect(hiddenByFlag(unflagged, [{ kind: "export", id: "src/a.ts:one" }])).toEqual([{ kind: "export", id: "src/a.ts:two" }]);
  });
});
