import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { decideCorpusRelevance, discoverCorpusClosure, type CorpusClosureReceipt } from "./corpus-relevance.js";

const root = process.cwd();
const ADVISORY_SNAPSHOT_DIR = "src/scan/__fixtures__/corpus-advisories";
const ADVISORY_MANIFEST = `${ADVISORY_SNAPSHOT_DIR}/manifest.json`;
const ADVISORY_PAYLOAD = `${ADVISORY_SNAPSHOT_DIR}/boxyhq.osv.json.gz`;

const DECISION_AND_BENCHMARK_ROOTS = [
  "src/cli/corpus-relevance.ts",
  "src/cli/corpus-relevance-history.ts",
  "src/cli/corpus-benchmark.ts",
  "src/cli/corpus-benchmark-sample.ts",
] as const;

const DECISION_AND_BENCHMARK_SURFACE = [
  ...DECISION_AND_BENCHMARK_ROOTS,
  "src/scan/corpus-relevance.ts",
  "src/corpus-relevance-history.ts",
  "src/corpus-benchmark.ts",
  "src/corpus-benchmark-sample.ts",
] as const;

describe("discovered corpus relevance (#1870)", () => {
  const current = discoverCorpusClosure(root, "head");
  const scratchDirs: string[] = [];

  afterEach(() => scratchDirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const fixture = (): string => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-corpus-relevance-"));
    scratchDirs.push(dir);
    const paths = new Set([
      ...current.inputs.map((input) => input.path),
      ADVISORY_MANIFEST,
      ADVISORY_PAYLOAD,
      "audit-execution-log.json",
      "docs/go-no-go.md",
      "pnpm-workspace.yaml",
      "site/package.json",
    ]);
    for (const path of paths) {
      const destination = join(dir, path);
      mkdirSync(dirname(destination), { recursive: true });
      copyFileSync(join(root, path), destination);
    }
    return dir;
  };

  it("emits path/digest/consumer receipts for every required input category", () => {
    const required = ["rules", "config", "schema", "taxonomy", "manifest", "baseline", "ledger", "external-state", "workflow", "action", "tools", "package", "lock", "runtime"];
    expect([...new Set(current.inputs.map((input) => input.category))]).toEqual(expect.arrayContaining(required));
    for (const category of required) {
      const rows = current.inputs.filter((input) => input.category === category);
      expect(rows.length, category).toBeGreaterThan(0);
      expect(rows.every((row) => /^[a-f0-9]{64}$/.test(row.digest) && row.consumer.length > 10 && row.path.length > 0)).toBe(true);
    }
  });

  it.each([
    ["producer", "src/cli/corpus-drift.ts"],
    ["producer", "src/cli/static-detect.ts"],
    ["producer", "src/cli/quality-scan.ts"],
    ["producer", "src/cli/mutation-scan.ts"],
    ["helper", "src/corpus-scanner-runner.ts"],
    ["rules", "src/scan/rules/gitleaks-supabase.toml"],
    ["manifest", "src/scan/external-corpus.ts"],
    ["ledger", "audit-execution-log.json"],
    ["external-state", ADVISORY_MANIFEST],
    ["external-state", ADVISORY_PAYLOAD],
    ["action", ".github/actions/mechanical-binaries/action.yml"],
    ["package", "package.json"],
    ["package", "pnpm-workspace.yaml"],
    ["package", "site/package.json"],
    ["lock", "pnpm-lock.yaml"],
    ["runtime", ".nvmrc"],
  ])("makes a representative %s change relevant", (_category, path) => {
    const decision = decideCorpusRelevance(current, current, [{ status: "M", path }]);
    expect(decision).toMatchObject({ relevant: true, verdict: "full-scan" });
    expect(decision.matched[0]?.path).toBe(path);
  });

  it("registers the advisory manifest and every payload it addresses as one external-state surface", () => {
    const manifest = JSON.parse(readFileSync(join(root, ADVISORY_MANIFEST), "utf8")) as {
      targets: Record<string, { file: string }>;
    };
    const expected = [
      ADVISORY_MANIFEST,
      ...Object.values(manifest.targets).map((entry) => `${ADVISORY_SNAPSHOT_DIR}/${entry.file}`),
    ].sort();
    const actual = current.inputs
      .filter((input) => input.category === "external-state")
      .map((input) => input.path)
      .sort();
    expect(actual).toEqual(expected);
    expect(current.inputs.filter((input) => actual.includes(input.path)).every((input) =>
      input.consumer === "loadCorpusAdvisorySnapshot for corpus drift and current-mechanical replay")).toBe(true);
  });

  it.each([
    { label: "advisory manifest", path: ADVISORY_MANIFEST, consumer: "loadCorpusAdvisorySnapshot for corpus drift and current-mechanical replay" },
    { label: "advisory payload", path: ADVISORY_PAYLOAD, consumer: "loadCorpusAdvisorySnapshot for corpus drift and current-mechanical replay" },
    { label: "audit execution ledger", path: "audit-execution-log.json", consumer: "audit-coverage module initialization reached by quick-scan corpus scoring" },
    { label: "workspace manifest", path: "pnpm-workspace.yaml", consumer: "pnpm workspace topology and install configuration for corpus execution" },
    { label: "workspace member manifest", path: "site/package.json", consumer: "pnpm workspace dependency identity for corpus execution" },
  ])("makes a physical $label change relevant while changing its receipt digest", ({ path, consumer }) => {
    const baseDir = fixture();
    const headDir = fixture();
    writeFileSync(join(headDir, path), Buffer.concat([readFileSync(join(headDir, path)), Buffer.from("\n")]));
    const base = discoverCorpusClosure(baseDir, "base");
    const head = discoverCorpusClosure(headDir, "head");
    const before = base.inputs.find((input) => input.path === path);
    const after = head.inputs.find((input) => input.path === path);
    expect(before).toMatchObject({ consumer });
    expect(after).toMatchObject({ consumer });
    expect(after?.digest).not.toBe(before?.digest);
    expect(decideCorpusRelevance(base, head, [{ status: "M", path }])).toMatchObject({
      relevant: true,
      verdict: "full-scan",
      matched: [expect.objectContaining({
        path,
        consumers: expect.arrayContaining([expect.objectContaining({ consumer })]),
      })],
    });
  });

  it("fails open for a physically added unregistered file", () => {
    const baseDir = fixture();
    const headDir = fixture();
    const path = ".new-corpus-runtime-config";
    writeFileSync(join(headDir, path), "new runtime input\n");
    const base = discoverCorpusClosure(baseDir, "base");
    const head = discoverCorpusClosure(headDir, "head");
    expect(base.inventory).not.toContain(path);
    expect(head.inventory).toContain(path);
    expect(decideCorpusRelevance(base, head, [{ status: "A", path }])).toMatchObject({
      relevant: true,
      verdict: "full-scan",
      matched: [],
      reasons: [expect.stringContaining("cannot be proved disjoint")],
    });
  });

  it("keeps a physical change to a known unrelated file declared no-op", () => {
    const baseDir = fixture();
    const headDir = fixture();
    const path = "docs/go-no-go.md";
    writeFileSync(join(headDir, path), "\nphysical unrelated-change control\n", { flag: "a" });
    const base = discoverCorpusClosure(baseDir, "base");
    const head = discoverCorpusClosure(headDir, "head");
    expect(base.inventory).toContain(path);
    expect(head.inventory).toContain(path);
    const decision = decideCorpusRelevance(base, head, [{ status: "M", path }]);
    expect(decision).toMatchObject({
      relevant: false,
      verdict: "declared-no-op",
      disjoint: [path],
    });
    expect(decision.reasons[0]).toContain(base.digest.slice(0, 12));
    expect(decision.reasons[0]).toContain(head.digest.slice(0, 12));
  });

  it.each(DECISION_AND_BENCHMARK_SURFACE)("makes the directly participating decision/scorer path %s relevant", (path) => {
    const decision = decideCorpusRelevance(current, current, [{ status: "M", path }]);
    expect(decision).toMatchObject({ relevant: true, verdict: "full-scan" });
    expect(decision.matched[0]).toMatchObject({ path });

    const disconnected: CorpusClosureReceipt = {
      ...current,
      inputs: current.inputs.filter((input) => input.path !== path),
    };
    expect(decideCorpusRelevance(disconnected, disconnected, [{ status: "M", path }])).toMatchObject({
      relevant: false,
      verdict: "declared-no-op",
      disjoint: [path],
    });
  });

  it("ratchets the four package-script entry points against deletion or rename", () => {
    const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
    expect(Object.fromEntries([
      ["corpus-relevance", manifest.scripts["corpus-relevance"]],
      ["corpus-relevance-history", manifest.scripts["corpus-relevance-history"]],
      ["corpus-benchmark", manifest.scripts["corpus-benchmark"]],
      ["corpus-benchmark-sample", manifest.scripts["corpus-benchmark-sample"]],
    ])).toEqual({
      "corpus-relevance": "tsx src/cli/corpus-relevance.ts",
      "corpus-relevance-history": "tsx src/cli/corpus-relevance-history.ts",
      "corpus-benchmark": "tsx src/cli/corpus-benchmark.ts",
      "corpus-benchmark-sample": "tsx src/cli/corpus-benchmark-sample.ts",
    });
    expect(current.roots).toEqual(expect.arrayContaining([...DECISION_AND_BENCHMARK_ROOTS]));
    expect(current.uncertainties).toEqual([]);
    for (const path of DECISION_AND_BENCHMARK_ROOTS) {
      expect(current.inputs).toContainEqual(expect.objectContaining({ category: "producer", path }));
    }
  });

  it.each([
    "src/cli/static-detect.ts",
    "src/cli/quality-scan.ts",
    "src/cli/mutation-scan.ts",
  ])("fails the real scanner-root relevance control when %s is disconnected", (path) => {
    expect(decideCorpusRelevance(current, current, [{ status: "M", path }]).relevant).toBe(true);
    const disconnected: CorpusClosureReceipt = {
      ...current,
      inputs: current.inputs.filter((input) => input.path !== path),
    };
    expect(decideCorpusRelevance(disconnected, disconnected, [{ status: "M", path }])).toMatchObject({
      relevant: false,
      verdict: "declared-no-op",
      disjoint: [path],
    });
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
