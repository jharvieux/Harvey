import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { decideCorpusRelevance, discoverCorpusClosure, type CorpusClosureReceipt } from "./corpus-relevance.js";

const root = process.cwd();

describe("discovered corpus relevance (#1870)", () => {
  const current = discoverCorpusClosure(root, "head");

  it("emits path/digest/consumer receipts for every required input category", () => {
    const required = ["rules", "config", "schema", "taxonomy", "manifest", "baseline", "workflow", "action", "tools", "package", "lock", "runtime"];
    expect([...new Set(current.inputs.map((input) => input.category))]).toEqual(expect.arrayContaining(required));
    for (const category of required) {
      const rows = current.inputs.filter((input) => input.category === category);
      expect(rows.length, category).toBeGreaterThan(0);
      expect(rows.every((row) => /^[a-f0-9]{64}$/.test(row.digest) && row.consumer.length > 10 && row.path.length > 0)).toBe(true);
    }
  });

  it.each([
    ["producer", "src/cli/corpus-drift.ts"],
    ["helper", "src/corpus-scanner-runner.ts"],
    ["rules", "src/scan/rules/gitleaks-supabase.toml"],
    ["manifest", "src/scan/external-corpus.ts"],
    ["action", ".github/actions/mechanical-binaries/action.yml"],
    ["package", "package.json"],
    ["lock", "pnpm-lock.yaml"],
    ["runtime", ".nvmrc"],
  ])("makes a representative %s change relevant", (_category, path) => {
    const decision = decideCorpusRelevance(current, current, [{ status: "M", path }]);
    expect(decision).toMatchObject({ relevant: true, verdict: "full-scan" });
    expect(decision.matched[0]?.path).toBe(path);
  });

  it("declares representative report, site, and unrelated-library changes disjoint", () => {
    const unrelated = current.inventory.find((path) => path.startsWith("src/") && path.endsWith(".ts") && !current.inputs.some((input) => input.path === path));
    expect(unrelated).toBeTruthy();
    const changed = ["docs/go-no-go.md", "site/app/page.tsx", unrelated!].map((path) => ({ status: "M", path }));
    const decision = decideCorpusRelevance(current, current, changed);
    expect(decision).toMatchObject({ relevant: false, verdict: "declared-no-op" });
    expect(decision.disjoint).toEqual(changed.map((change) => change.path).sort());
    expect(decision.reasons[0]).toContain(current.digest.slice(0, 12));
  });

  it("keeps a relevant deletion by taking the union of base and head closures", () => {
    const deleted = "src/corpus-scanner-runner.ts";
    const head: CorpusClosureReceipt = { ...current, inputs: current.inputs.filter((input) => input.path !== deleted), inventory: current.inventory.filter((path) => path !== deleted) };
    expect(decideCorpusRelevance(current, head, [{ status: "D", path: deleted }]).relevant).toBe(true);
  });

  it("fails open on unknown paths and every discovery uncertainty class", () => {
    expect(decideCorpusRelevance(current, current, [{ status: "D", path: "never-seen-or-readable.input" }]).relevant).toBe(true);
    for (const kind of ["dynamic", "unresolved", "unreadable", "discovery-error"] as const) {
      const uncertain: CorpusClosureReceipt = { ...current, uncertainties: [{ kind, path: "src/uncertain.ts", detail: "planted uncertainty" }] };
      const decision = decideCorpusRelevance(uncertain, current, [{ status: "M", path: "docs/go-no-go.md" }]);
      expect(decision.relevant, kind).toBe(true);
      expect(decision.uncertainties).toContainEqual(expect.objectContaining({ kind }));
    }
  });

  it("proves the relevance and no-op guards fail in both directions", () => {
    const relevantPath = "src/corpus-scanner-runner.ts";
    expect(decideCorpusRelevance(current, current, [{ status: "M", path: relevantPath }]).relevant).toBe(true);
    const disconnected: CorpusClosureReceipt = { ...current, inputs: current.inputs.filter((input) => input.path !== relevantPath) };
    expect(decideCorpusRelevance(disconnected, disconnected, [{ status: "M", path: relevantPath }]).relevant).toBe(false);

    const noOpPath = "docs/go-no-go.md";
    expect(decideCorpusRelevance(current, current, [{ status: "M", path: noOpPath }]).relevant).toBe(false);
    const injected = { category: "helper" as const, path: noOpPath, digest: "a".repeat(64), consumer: "planted downstream corpus consumer" };
    expect(decideCorpusRelevance({ ...current, inputs: [...current.inputs, injected] }, current, [{ status: "M", path: noOpPath }]).relevant).toBe(true);
  });

  it("uses the one shared walker and leaves no workflow case-list copy", () => {
    const mechanical = readFileSync(join(root, "src", "scan", "mechanical-phase-identity.ts"), "utf8");
    const relevance = readFileSync(join(root, "src", "scan", "corpus-relevance.ts"), "utf8");
    const workflow = readFileSync(join(root, ".github", "workflows", "corpus-drift.yml"), "utf8");
    expect(mechanical).toContain('from "./implementation-closure.js"');
    expect(relevance).toContain('from "./implementation-closure.js"');
    expect(workflow.match(/case "\$f" in/g) ?? []).toHaveLength(0);
  });
});
