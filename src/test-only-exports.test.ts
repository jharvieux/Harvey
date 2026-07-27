// #1307 — the ratchet's two pawls. A gate that only ever adds rows is a suppression list, and one
// that only ever removes them cannot catch a regression; both directions have to fail.

import { describe, expect, it } from "vitest";
import { collect, compare, exportedNames, toBaseline } from "./test-only-exports.js";

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
