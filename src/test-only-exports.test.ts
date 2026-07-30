// #1307 — the ratchet's two pawls. A gate that only ever adds rows is a suppression list, and one
// that only ever removes them cannot catch a regression; both directions have to fail.

import { describe, expect, it } from "vitest";
import { blindSpotSuspects, collect, compare, exportedNames, hiddenByFlag, inFileConsumers, toBaseline } from "./test-only-exports.js";

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

describe("hiddenByFlag", () => {
  it("is the rows the unflagged run reports and the gated run does not", () => {
    const unflagged = [
      { kind: "export", id: "src/a.ts:one" },
      { kind: "export", id: "src/a.ts:two" },
    ] as const;
    expect(hiddenByFlag(unflagged, [{ kind: "export", id: "src/a.ts:one" }])).toEqual([{ kind: "export", id: "src/a.ts:two" }]);
  });
});
