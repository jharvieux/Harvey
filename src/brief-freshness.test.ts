import { describe, expect, it } from "vitest";
import { diffCatalog } from "./brief-freshness.js";

const vendored = `# Anti-patterns (D-091)

## 1. Stub-shaped code
body
### 2. Fail-open when the enforcement layer goes down (#137)
body
### 3. Claim-before-send in batch jobs
body
`;

describe("diffCatalog (#678 brief-freshness guard)", () => {
  it("reports classes present in the target but absent from the vendored copy as missing", () => {
    const target = vendored + "\n### 4. Env-schema secret registration\n### 5. Parameter-only DEFINER oracles\n";
    const { missing } = diffCatalog(vendored, target);
    expect(missing).toEqual(["env-schema secret registration", "parameter-only definer oracles"]);
  });

  it("is clean when the vendored copy covers every target class (renumbering-tolerant)", () => {
    // Same class set, different numbers/heading level — a title-based diff must not flag it.
    const target = `## 10. Claim-before-send in batch jobs\n## 20. Stub-shaped code\n### 30. Fail-open when the enforcement layer goes down (#999)\n`;
    expect(diffCatalog(vendored, target).missing).toEqual([]);
  });

  it("ignores trailing issue-ref parentheticals when matching titles", () => {
    const target = `### 1. Fail-open when the enforcement layer goes down (#1393/G6, extends #12)\n`;
    expect(diffCatalog(vendored, target).missing).toEqual([]);
  });

  it("surfaces Harvey-specific classes as vendoredExtra, never as a failure", () => {
    const withHarveyItem = vendored + "\n### 99. Server action mutates rows scoped by a client-supplied owner id (#221/#318)\n";
    const target = `## 1. Stub-shaped code\n`;
    const { missing, vendoredExtra } = diffCatalog(withHarveyItem, target);
    expect(missing).toEqual([]);
    expect(vendoredExtra).toContain("server action mutates rows scoped by a client-supplied owner id");
  });
});
