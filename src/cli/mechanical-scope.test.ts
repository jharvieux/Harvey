import { describe, expect, it } from "vitest";
import { operatorMechanicalScopeRows } from "../scan/mechanical-engine-registry.js";
import { renderMechanicalScope } from "./mechanical-scope.js";

describe("operator-facing mechanical scope", () => {
  it("renders every registry producer and its operational fields without a copied list", () => {
    const rendered = renderMechanicalScope();
    for (const row of operatorMechanicalScopeRows()) {
      expect(rendered).toContain(`## ${row.phase}:${row.id} (${row.module})`);
      expect(rendered).toContain(`- Selector: ${row.selector}`);
      expect(rendered).toContain(`- Examined units: ${row.examinedUnits}`);
      expect(rendered).toContain(`- Fallback: ${row.fallback}`);
      expect(rendered).toContain(`- Cadence: ${row.cadence.status}`);
    }
  });
});
