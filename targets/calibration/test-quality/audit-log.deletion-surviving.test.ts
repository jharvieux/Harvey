import { describe, it } from "vitest";
import { logAuditEvent } from "./audit-log.js";

// M8-P-DELETION-SURVIVING (#373) — planted test that still passes when logAuditEvent's body is
// stubbed out: it calls the subject but asserts nothing about the result. "If you deleted the
// logic it covers, would this test go red?" (quality-extras.txt M8 litmus test) — no, never.
// src/stub-check.test.ts executes exactly that experiment against this pair.
describe("logAuditEvent (deletion-surviving)", () => {
  it("records an audit entry", () => {
    logAuditEvent("login", "user-1");
  });
});
