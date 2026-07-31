import { describe, expect, it } from "vitest";
import { canProbeWrite, classifyWriteResponse, pgCodeOf, requiredColumns } from "./supabase-write-probe.js";

// The response shapes below are the ONES MEASURED 2026-07-26 against postgres:16-alpine +
// postgrest:v14.12 (docs/design/postgrest-write-eval-order.md). Keeping the fixture faithful to the
// measurement is the point: if PostgREST's eval order ever changed, these asserts would have to be
// re-measured, not merely re-written.

describe("classifyWriteResponse — measured PostgREST write eval-order", () => {
  it("PERMISSIVE table (WITH CHECK true + grant), body omits the NOT NULL column -> 400/23502 -> writable", () => {
    // Positive fixture: `open_writable` returned HTTP 400 {"code":"23502", ...not-null...}
    expect(classifyWriteResponse(400, "23502")).toBe("writable");
  });

  it("SCOPED table (RLS WITH CHECK rejects the row) -> 401/42501 -> denied", () => {
    // Negative fixture: `scoped` returned HTTP 401 {"code":"42501","message":"new row violates row-level security policy"}
    expect(classifyWriteResponse(401, "42501")).toBe("denied");
    expect(classifyWriteResponse(403, "42501")).toBe("denied");
  });

  it("NO INSERT grant -> 401/42501 (permission denied for table) -> denied", () => {
    // Negative fixture: `nogrant` returned HTTP 401 {"code":"42501","message":"permission denied for table"}
    expect(classifyWriteResponse(401, "42501")).toBe("denied");
  });

  it("any 2xx is impossible with an all-columns-omitted body and is surfaced loudly, never as a pass", () => {
    expect(classifyWriteResponse(201, null)).toBe("persisted");
    expect(classifyWriteResponse(200, null)).toBe("persisted");
  });

  it("a different 400 (not not-null) or any other status is inconclusive, not a finding", () => {
    expect(classifyWriteResponse(400, "22P02")).toBe("inconclusive"); // invalid input syntax
    expect(classifyWriteResponse(404, null)).toBe("inconclusive");
    expect(classifyWriteResponse(500, null)).toBe("inconclusive");
  });
});

describe("write-probe safety gate — only fire when non-persistence is guaranteed", () => {
  it("a table with required (NOT NULL, no-default) columns can be probed", () => {
    const def = { required: ["tenant_id", "secret"], properties: {} };
    expect(canProbeWrite(def)).toBe(true);
    expect(requiredColumns(def)).toEqual(["tenant_id", "secret"]);
  });

  it("a table with NO required column is NOT probed (an empty INSERT could persist)", () => {
    expect(canProbeWrite({ required: [], properties: {} })).toBe(false);
    expect(canProbeWrite({ properties: {} })).toBe(false);
    expect(canProbeWrite(null)).toBe(false);
  });
});

describe("pgCodeOf", () => {
  it("extracts the PostgREST error code, tolerating junk", () => {
    expect(pgCodeOf({ code: "23502", message: "x" })).toBe("23502");
    expect(pgCodeOf([])).toBeNull();
    expect(pgCodeOf(null)).toBeNull();
    expect(pgCodeOf("nope")).toBeNull();
  });
});
