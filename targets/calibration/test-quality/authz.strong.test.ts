import { describe, expect, it } from "vitest";
import { canAccess } from "./authz.js";

// M8-N-STRONG (#72 §M8) — planted STRONG test: exhaustive over the 2x2 role/action truth table,
// including the denial path a weak test would skip. Must NOT land on the false-confidence list —
// every mutant Stryker can plant on authz.ts (ConditionalExpression, EqualityOperator,
// BooleanLiteral, StringLiteral) flips at least one of these four outcomes, so all mutants die.
describe("canAccess (strong)", () => {
  it("lets an admin read", () => {
    expect(canAccess("admin", "read")).toBe(true);
  });

  it("lets an admin delete", () => {
    expect(canAccess("admin", "delete")).toBe(true);
  });

  it("lets a member read", () => {
    expect(canAccess("member", "read")).toBe(true);
  });

  it("denies a member from deleting", () => {
    expect(canAccess("member", "delete")).toBe(false);
  });
});
