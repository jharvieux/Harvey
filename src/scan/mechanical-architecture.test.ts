import { describe, expect, it } from "vitest";
import { architectureFindings } from "./mechanical-architecture.js";

describe("architectureFindings", () => {
  it("records the app-layer architecture limit for a Prisma target", () => {
    const findings = architectureFindings("prisma");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("M1-ARCH-PRISMA");
    expect(findings[0]?.confidence).toBe("N/A");
  });

  it("does not emit an architecture exception for the native Supabase surface", () => {
    expect(architectureFindings("supabase")).toEqual([]);
  });
});
