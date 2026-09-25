import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AUDIT_PREREQUISITES } from "../../../src/audit-prerequisites";
import DataHandling from "./page";
import { ENGAGEMENT_REQUIREMENTS } from "../../../src/engagement-requirements";

afterEach(() => vi.unstubAllGlobals());

describe("public audit prerequisite delivery", () => {
  it("renders every shared requirement and its missing-access consequence in the actual page", () => {
    // Vitest's TSX transform uses the classic runtime; Next supplies its own JSX runtime.
    vi.stubGlobal("React", React);
    const html = renderToStaticMarkup(React.createElement(DataHandling));
    expect(html).toContain('data-requirements-version="1"');
    expect(AUDIT_PREREQUISITES.requirements.map((row) => row.id)).toEqual([
      "dependency-metadata", "database-catalog", "platform-configuration", "application-protection",
    ]);
    for (const row of AUDIT_PREREQUISITES.requirements) {
      expect(html).toContain(`id="requirement-${row.id}"`);
      for (const value of [row.capability, row.requestedInput, row.accessBoundary, row.ifUnavailable, row.verification]) {
        const escaped = renderToStaticMarkup(React.createElement("span", null, value)).slice(6, -7);
        expect(html).toContain(escaped);
      }
    }
    for (const detail of ENGAGEMENT_REQUIREMENTS) {
      for (const text of [...detail.metadata, ...detail.access, detail.limitation, detail.falsifier, detail.nextStep]) {
        const escaped = renderToStaticMarkup(React.createElement("span", null, text)).slice(6, -7);
        expect(html).toContain(escaped);
      }
    }
    expect(html).toContain("never through a form or ordinary email");
    expect(html).toContain("no writes, DDL, production row sampling");
    expect(html).toContain("private/unpublished metadata unavailable");
  });
});
