import { describe, expect, it } from "vitest";
import { ENGAGEMENT_REQUIREMENTS, ENGAGEMENT_REQUIREMENTS_VERSION, engagementRequirement, renderEngagementRequirements } from "./engagement-requirements.js";

describe("shared non-secret engagement prerequisites #2134 #2141", () => {
  it("binds every capability to metadata, scoped access, a limit and a falsifier", () => {
    expect(ENGAGEMENT_REQUIREMENTS_VERSION).toBe("harvey-engagement-requirements/1");
    expect(new Set(ENGAGEMENT_REQUIREMENTS.map((r) => r.id)).size).toBe(ENGAGEMENT_REQUIREMENTS.length);
    for (const row of ENGAGEMENT_REQUIREMENTS) {
      expect(row.modules.length).toBeGreaterThan(0);
      expect(row.metadata.length).toBeGreaterThan(0);
      expect(row.access.length).toBeGreaterThan(0);
      for (const key of ["capability", "limitation", "falsifier", "nextStep"] as const) expect(row[key].trim()).not.toBe("");
    }
    expect(() => engagementRequirement("missing")).toThrow(/Unknown engagement requirement/);
  });
  it("renders the same registry and database contract into local intake documentation", () => {
    const document = renderEngagementRequirements();
    expect(document).toContain("registry.private-authorization");
    expect(document).toContain("database.encryption-boundaries");
    expect(document).toContain("Do not submit secrets or production row values");
    for (const row of ENGAGEMENT_REQUIREMENTS) {
      expect(document).toContain(row.falsifier);
      expect(document).toContain(row.nextStep);
    }
  });
});
