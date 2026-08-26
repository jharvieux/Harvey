// Intent: runMechanicalScan's skipNetworkChecks option (added alongside the dry-run harness's
// network-independence fix) must actually gate the two live npm-registry calls
// (checkSlopsquat, checkLicenseCompliance) — the assertion is "never invoked", not "returned no
// findings" (which a network hiccup could also produce and wrongly pass). The other sub-scanners
// (secrets, semgrep) shell out to real binaries and are mocked here purely so this test stays
// fast and offline like the rest of the suite (matching pnpm verify's own deterministic-offline
// convention) — they aren't what this test is about.
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const checkSlopsquat = vi.fn(async () => []);
const checkLicenseCompliance = vi.fn(async () => []);
const scanSecrets = vi.fn(() => []);
// #950: default mock matches runSemgrep's real { result, failure? } return shape — a bare ""
// (the pre-#950 shape this mock used to return) would make `semgrep.failure` silently undefined
// on a string rather than proving the wiring, since parseSemgrepFindings below is ALSO mocked to
// ignore its argument. Kept a well-formed no-failure result so the two describe blocks lower down
// (which override this per-test to exercise the failure branch) have an honest baseline to diff.
const runSemgrep = vi.fn(() => ({
  result: { results: [], errors: [], paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } },
}) as { result: object; executionPlan?: object; failure?: string });

vi.mock("./supply-chain.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./supply-chain.js")>();
  return { ...actual, checkSlopsquat, checkLicenseCompliance };
});
vi.mock("./secrets.js", () => ({ scanSecrets, resolveBundleScan: vi.fn(() => ({})) }));
// Only runSemgrep is faked (it's the one that shells out to the real binary); parseSemgrepFindings/
// checkMissingCsp/checkPublicDirSensitive/semgrepUnavailableFinding stay real so the #950 failure-
// wiring test below exercises mechanical.ts's actual branch, not a second layer of mocking.
vi.mock("./semgrep.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./semgrep.js")>();
  return { ...actual, runSemgrep };
});

const { discoverMechanicalCorpusOwnership, runMechanicalScan, runMechanicalScanDetailed } = await import("./mechanical.js");
const { MechanicalScanContext } = await import("./mechanical-context.js");
const { runRegisteredDependencyDetectors } = await import("./mechanical-dependency-registry.js");
const { MECHANICAL_REGISTRY } = await import("./mechanical-engine-registry.js");
const { mechanicalExaminedUnitDigest } = await import("./mechanical-phase-cache.js");
const { buildSemgrepCommandSemanticReceipt } = await import("./semgrep-family-cache.js");
const { buildCoverageMatrix } = await import("./calibration.js");
const { b2DepsEntries } = await import("./calibration/b2-deps.entries.js");

function stableReceipt(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableReceipt).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stableReceipt(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function receiptSha(value: unknown): string {
  return createHash("sha256").update(stableReceipt(value)).digest("hex");
}

describe("mechanical corpus ownership discovery", () => {
  it("projects every live registry producer and discovers a newly registered producer without another ID list", () => {
    const live = discoverMechanicalCorpusOwnership();
    expect(live.schema).toBe(1);
    expect(live.producers.map(({ phase, producer }) => `${phase}:${producer}`)).toEqual(
      MECHANICAL_REGISTRY.map(({ phase, id }) => `${phase}:${id}`),
    );

    const added = { ...MECHANICAL_REGISTRY[0]!, id: "fixture-newly-registered-producer", order: 999 };
    const before = discoverMechanicalCorpusOwnership(MECHANICAL_REGISTRY);
    const after = discoverMechanicalCorpusOwnership([...MECHANICAL_REGISTRY, added]);
    expect(before.producers.some(({ producer }) => producer === added.id)).toBe(false);
    expect(after.producers.at(-1)).toEqual({
      producer: added.id,
      phase: added.phase,
      order: added.order,
      module: added.module,
      registryFile: added.registryFile,
    });
    expect(Object.isFrozen(after)).toBe(true);
    expect(Object.isFrozen(after.producers)).toBe(true);
  });
});

describe("runMechanicalScan skipNetworkChecks", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-mechanical-test-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture", dependencies: { react: "18.2.0" } }));
    checkSlopsquat.mockClear();
    checkLicenseCompliance.mockClear();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("skips the live registry existence check when set", async () => {
    await runMechanicalScan({ dir, skipNetworkChecks: true });
    expect(checkSlopsquat).not.toHaveBeenCalled();
  });

  // #1213: the license check is no longer all-or-nothing. Classification off a lockfile needs no
  // network, so the tier still RUNS under skipNetworkChecks — only its registry fallback is pinned
  // off, which keeps the committed dry-run artifact deterministic while leaving the copyleft
  // detection exercised by the gate rather than silent.
  it("still classifies licenses under skipNetworkChecks, with only the registry fallback pinned off", async () => {
    await runMechanicalScan({ dir, skipNetworkChecks: true });
    expect(checkLicenseCompliance).toHaveBeenCalledWith(expect.objectContaining({ source: "package.json" }), { skipRegistry: true });
  });

  it("still runs the live npm-registry checks by default", async () => {
    await runMechanicalScan({ dir });
    expect(checkSlopsquat).toHaveBeenCalledWith(["react"]);
    // #1213: the candidate set is the resolved tree, not the manifest. This fixture has no
    // lockfile, so collectDependencies degrades to the manifest fallback — which is exactly why
    // the scope is `incomplete`, and why SUP-LICENSE-00 has to say the transitive tier was never
    // in scope rather than staying silent.
    expect(checkLicenseCompliance).toHaveBeenCalledWith(
      expect.objectContaining({ candidates: [{ name: "react", version: "18.2.0", direct: true }], completeness: "incomplete" }),
      { skipRegistry: undefined },
    );
  });

  it("preserves real mechanical findings and examined scopes across a cold then warm faithful large fixture", async () => {
    const src = join(dir, "src");
    mkdirSync(src);
    for (let i = 0; i < 300; i++) writeFileSync(join(src, `route-${i}.ts`), `export function route${i}(tenantId: string) { return { tenantId, row: ${i} }; }\n`);
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-mechanical-cache-"));
    try {
      const phases = ["secrets-history", "dependency-advisory", "semgrep", "configuration", "structural-ast", "normalization"] as const;
      const phaseCache = {
        dir: cacheDir,
        mode: "read-write" as const,
        targetRevision: "large-fixture-revision",
        targetTree: "large-fixture-tree",
        implementation: Object.fromEntries(phases.map((phase) => [phase, `implementation:${phase}`])),
        externalInputs: Object.fromEntries(phases.map((phase) => [phase, { fixture: "v1" }])),
      };
      const cold = await runMechanicalScanDetailed({ dir, skipNetworkChecks: true, phaseCache });
      const warm = await runMechanicalScanDetailed({ dir, skipNetworkChecks: true, phaseCache });
      expect(warm.findings).toEqual(cold.findings);
      expect(warm.phases.map((phase) => phase.phase)).toEqual(cold.phases.map((phase) => phase.phase));
      expect(warm.phases.map((phase) => phase.scope)).toEqual(cold.phases.map((phase) => phase.scope));
      expect(warm.detectors.map((detector) => [detector.detector, detector.unitsExamined])).toEqual(
        cold.detectors.map((detector) => [detector.detector, detector.unitsExamined]),
      );
      expect(cold.detectors).toHaveLength(73);
      expect(new Set(cold.detectors.map((detector) => detector.phase))).toEqual(new Set(phases));
      expect(cold.detectors.every((detector) => detector.examinedUnitIdentities.length === detector.unitsExamined)).toBe(true);
      expect(cold.detectors.every((detector) => detector.examinedUnitIdentities.every((unit) => unit.producer === detector.detector))).toBe(true);
      expect(cold.detectors.every((detector) => detector.examinedUnitDigest === mechanicalExaminedUnitDigest(detector.examinedUnitIdentities))).toBe(true);
      expect(cold.detectors.find((detector) => detector.detector === "secrets-history-bundle")?.examinedUnitDigest).toMatch(/^[a-f0-9]{64}$/);
      expect(warm.detectors.map((detector) => detector.examinedUnitIdentities)).toEqual(
        cold.detectors.map((detector) => detector.examinedUnitIdentities),
      );
      expect(cold.detectors.filter((detector) => detector.phase === "structural-ast").reduce((sum, detector) => sum + detector.findings, 0)).toBe(
        cold.phases.find((phase) => phase.phase === "structural-ast")?.findings.length,
      );
      expect(warm.detectors.filter((detector) => detector.phase === "structural-ast").reduce((sum, detector) => sum + detector.findings, 0)).toBe(
        warm.phases.find((phase) => phase.phase === "structural-ast")?.findings.length,
      );
      expect(cold.detectors.map((detector) => `${detector.phase}:${detector.detector}`).sort()).toEqual(
        MECHANICAL_REGISTRY.map((producer) => `${producer.phase}:${producer.id}`).sort(),
      );
      expect(new Set(cold.detectors.filter((detector) => detector.phase === "configuration").map((detector) => detector.unitsExamined)).size).toBeGreaterThan(1);
      expect(new Set(cold.detectors.filter((detector) => detector.phase === "dependency-advisory").map((detector) => detector.unitsExamined)).size).toBeGreaterThan(1);
      expect(warm.detectors.filter((detector) => detector.status === "cached").length).toBeGreaterThan(20);
      expect(cold.context.astsBuilt).toBeGreaterThanOrEqual(300);
      expect(cold.context.astCacheHits).toBeGreaterThan(0);
      expect(cold.context.avoidedFileReads).toBeGreaterThan(0);
      expect(cold.context.astCacheRejectedEntries).toBeGreaterThan(0);
      expect(cold.context.astCachePeakEntries).toBeLessThan(cold.context.filesParsed);
      expect(cold.context.astCachePeakEntries).toBeLessThanOrEqual(cold.context.astCacheMaxEntries);
      expect(cold.context.astCachePeakSourceBytes).toBeLessThanOrEqual(cold.context.astCacheMaxSourceBytes);
      expect(cold.context.astCacheEntriesAtRelease).toBeGreaterThan(0);
      expect(cold.context.astCacheEntriesAfterRelease).toBe(0);
      expect(cold.context.astWorkingSetReleased).toBe(true);
      expect(warm.phases.filter((phase) => phase.cache === "hit").map((phase) => phase.phase).sort()).toEqual([
        "configuration",
        "semgrep",
        "structural-ast",
      ]);
      expect(warm.phases.find((phase) => phase.phase === "structural-ast")?.scope.unitsExamined).toBeGreaterThanOrEqual(300);
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  it("fails the real forced-cold scanner path when an empty cache provides nothing to compare", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "harvey-mechanical-verify-empty-"));
    const phases = ["secrets-history", "dependency-advisory", "semgrep", "configuration", "structural-ast", "normalization"] as const;
    try {
      await expect(runMechanicalScanDetailed({
        dir,
        skipNetworkChecks: true,
        phaseCache: {
          dir: cacheDir,
          mode: "verify",
          targetRevision: "empty-cache-revision",
          targetTree: "empty-cache-tree",
          implementation: Object.fromEntries(phases.map((phase) => [phase, `implementation:${phase}`])),
          externalInputs: Object.fromEntries(phases.map((phase) => [phase, { fixture: "v1" }])),
        },
      })).rejects.toThrow("forced-cold cache verification incomplete: semgrep=miss, configuration=miss, structural-ast=miss");
    } finally {
      rmSync(cacheDir, { recursive: true, force: true });
    }
  });

  // #1344: a workspace member is resolved from inside the repo, so the registry 404s on its name
  // and SUP-SLOPSQUAT calls it hallucinated — 10 such High rows graded saas-lite F on the free
  // tier. Both declaration styles are covered: the `workspace:` protocol (pnpm/yarn-berry) and a
  // plain range on a name that is itself a workspace member (npm/yarn-classic).
  it("#1344: never asks the registry about a workspace-internal package", async () => {
    const ws = mkdtempSync(join(tmpdir(), "harvey-mechanical-ws-"));
    try {
      writeFileSync(join(ws, "package.json"), JSON.stringify({ name: "root", workspaces: ["packages/*"], dependencies: { react: "18.2.0", "@kit/ui": "workspace:*", "@kit/auth": "1.0.0" } }));
      mkdirSync(join(ws, "packages", "auth"), { recursive: true });
      writeFileSync(join(ws, "packages", "auth", "package.json"), JSON.stringify({ name: "@kit/auth", dependencies: { zod: "3.0.0" } }));
      await runMechanicalScan({ dir: ws });
      expect(checkSlopsquat).toHaveBeenCalledWith(["react", "zod"]);
      const scope = (await runMechanicalScan({ dir: ws })).find((f) => f.id === "SUP-SCOPE-00");
      expect(scope?.evidence).toContain("@kit/ui, @kit/auth");
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });

  // #1213: `@img/sharp-*` are optionalDependencies of `sharp`, so even a DIRECT `sharp` would not
  // have surfaced its platform binaries — the manifest's optional/peer sections were never merged.
  it("submits optional and peer dependencies to the license check", async () => {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "fixture", dependencies: { react: "18.2.0" }, optionalDependencies: { fsevents: "2.3.3" }, peerDependencies: { next: "14.2.5" } }),
    );
    await runMechanicalScan({ dir });
    const [scope] = checkLicenseCompliance.mock.calls[0] as unknown as [{ candidates: { name: string }[] }];
    const names = scope.candidates.map((c) => c.name);
    expect(names).toEqual(["react", "fsevents", "next"]);
  });
});

// #1232: in a monorepo the root lockfile already resolves every member's packages, so widening the
// DECLARED set is not a coverage change — it is a labelling one, and the label is load-bearing
// twice over. It orders the capped registry-lookup budget (declared-first), and it decides whether
// a copyleft row tells the client "you chose this" or "something you depend on chose this". Before
// this, an app's own 200 dependencies were both.
describe("runMechanicalScan over a workspace monorepo (#1232)", () => {
  let dir: string;
  const member = (rel: string, body: object): void => {
    mkdirSync(join(dir, rel), { recursive: true });
    writeFileSync(join(dir, rel, "package.json"), JSON.stringify(body));
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-monorepo-test-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "monorepo", devDependencies: { typescript: "5.8.0" } }));
    writeFileSync(join(dir, "pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n");
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        packages: {
          "node_modules/typescript": { version: "5.8.0", license: "Apache-2.0" },
          "node_modules/react": { version: "18.2.0", license: "MIT" },
          "node_modules/tiny-transitive": { version: "1.0.0", license: "MIT" },
        },
      }),
    );
    // Declared by the member, not the root — the case the root-only read mislabelled.
    member("apps/web", { name: "web", dependencies: { react: "^18.2.0" } });
    // Not a workspace member: an unlisted fixture root whose pinned deps are deliberately wrong.
    member("examples/demo", { name: "demo", dependencies: { "flatmap-stream": "0.1.1" } });
    checkLicenseCompliance.mockClear();
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("labels a workspace member's own dependency declared, not transitive", async () => {
    await runMechanicalScan({ dir, skipNetworkChecks: true });
    const [scope] = checkLicenseCompliance.mock.calls[0] as unknown as [{ candidates: { name: string; direct: boolean }[] }];
    expect(scope.candidates.find((c) => c.name === "react")?.direct).toBe(true);
    expect(scope.candidates.find((c) => c.name === "tiny-transitive")?.direct).toBe(false);
  });

  it("flags the member's unpinned range, naming the member's manifest", async () => {
    const findings = await runMechanicalScan({ dir, skipNetworkChecks: true });
    const unpinned = findings.find((f) => f.id === "SUP-UNPINNED");
    expect(unpinned?.evidence).toContain(`react@^18.2.0 (${join("apps", "web", "package.json")})`);
  });

  // The trap #1232 names: a blind sweep for every package.json would read examples/demo and report
  // its IOC-feed dependency as one the application declared.
  it("does not read an unlisted examples/ manifest as the application's own", async () => {
    const findings = await runMechanicalScan({ dir, skipNetworkChecks: true });
    expect(findings.some((f) => f.id === "SUP-IOC-flatmap-stream")).toBe(false);
    expect(findings.find((f) => f.id === "SUP-SCOPE-00")?.evidence).toContain("2 manifests (pnpm-workspace.yaml)");
  });

  it("binds dependency-registry receipts to the sorted contained workspace population", async () => {
    const container = mkdtempSync(join(tmpdir(), "harvey-mechanical-workspace-boundary-"));
    try {
      const root = join(container, "repo");
      const outside = join(container, "outside");
      mkdirSync(join(root, "packages", "zeta"), { recursive: true });
      mkdirSync(join(root, "packages", "alpha"), { recursive: true });
      mkdirSync(outside);
      writeFileSync(join(root, "package.json"), JSON.stringify({
        name: "root",
        workspaces: ["./packages//*", "../outside", "linked"],
        dependencies: { rootdep: "1.0.0" },
      }));
      writeFileSync(join(root, "packages", "zeta", "package.json"), JSON.stringify({ name: "zeta", dependencies: { zetadep: "1.0.0" } }));
      writeFileSync(join(root, "packages", "alpha", "package.json"), JSON.stringify({ name: "alpha", dependencies: { alphadep: "1.0.0" } }));
      writeFileSync(join(outside, "package.json"), JSON.stringify({ name: "escaped", dependencies: { escapeddep: "1.0.0" } }));
      symlinkSync(outside, join(root, "linked"), "dir");

      const context = new MechanicalScanContext(root);
      try {
        const result = await runRegisteredDependencyDetectors({
          context,
          scanDir: root,
          pkg: { dependencies: { rootdep: "1.0.0" } },
          osv: { failure: "offline fixture" },
          skipNetworkChecks: true,
        }, "supply");
        expect(result.records.find((record) => record.detector === "manifest-install-scripts")?.examinedUnitIdentities).toEqual([
          { producer: "manifest-install-scripts", kind: "target-path", identity: "package.json" },
          { producer: "manifest-install-scripts", kind: "target-path", identity: "packages/alpha/package.json" },
          { producer: "manifest-install-scripts", kind: "target-path", identity: "packages/zeta/package.json" },
        ]);
        expect(result.records.find((record) => record.detector === "dependency-pinning")?.examinedUnitIdentities).toEqual([
          ["package.json", "root", "rootdep"],
          ["packages/alpha/package.json", "alpha", "alphadep"],
          ["packages/zeta/package.json", "zeta", "zetadep"],
        ].map(([source, owner, name]) => ({ producer: "dependency-pinning", kind: "declared-dependency",
          identity: JSON.stringify([1, source, "package-json", "unversioned", source, createHash("sha256").update(owner!).digest("hex"), null, "dependencies", name, createHash("sha256").update("1.0.0").digest("hex"), true]) })));
        expect(result.findings.find((finding) => finding.id === "SUP-SCOPE-00")?.evidence).toContain(
          "2 declared workspace glob(s) matched no package.json and were skipped: ../outside, linked",
        );
      } finally {
        context.dispose();
      }
    } finally {
      rmSync(container, { recursive: true, force: true });
    }
  });
});

describe("npm lockfile range edges (#1774)", () => {
  it("scores the natural calibration edge and synthetic twins through the shipping registry", async () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "../../targets/calibration");
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    const context = new MechanicalScanContext(root);
    try {
      const { findings } = await runRegisteredDependencyDetectors({ context, scanDir: root, pkg, osv: { failure: "offline range calibration fixture" }, skipNetworkChecks: true }, "supply");
      const entries = b2DepsEntries.filter((entry) => entry.location === "package-lock.json (third-party declaration ranges)");
      const matrix = buildCoverageMatrix(findings, entries);
      expect(matrix.rows.length).toBeGreaterThan(0);
      expect(matrix.rows.filter((row) => !row.pass)).toEqual([]);
      const unpinned = findings.find((finding) => finding.id === "SUP-UNPINNED-TREE");
      expect(unpinned?.dependencyRangeEvidence?.edges).toContainEqual(expect.objectContaining({
        ownerPath: "node_modules/@supabase/storage-js", name: "iceberg-js", range: "^0.8.1", section: "dependencies", direct: false,
      }));
    } finally { context.dispose(); }
  });

  it.each([
    ["npm v2", "package-lock.json", JSON.stringify({ lockfileVersion: 2, packages: { "node_modules/parent": { version: "1.0.0", dependencies: { child: "^2.0.0" } } } }), "package-lock version 2, read", "1 admitted third-party range edges"],
    ["npm v1", "package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: { parent: { version: "1.0.0", requires: { child: "^2.0.0" } } } }), "package-lock version 1, unsupported", "1 present/unread value(s)"],
    ["pnpm v9", "pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      child:\n        specifier: ^2.0.0\n        version: 2.0.0\npackages:\n  child@2.0.0:\n", "pnpm version 9.0, present-but-unread", "1 importer/root specifier"],
    ["Yarn classic", "yarn.lock", 'child@^2.0.0:\n  version "2.0.0"\n', "yarn version classic v1, present-but-unread", "1 selector range(s)"],
    ["Yarn Berry", "yarn.lock", '__metadata:\n  version: 8\n\n"child@npm:^2.0.0":\n  version: 2.0.0\n', "yarn version Berry 8, present-but-unread", "1 selector range(s)"],
    ["shrinkwrap", "npm-shrinkwrap.json", JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/parent": { version: "1.0.0", dependencies: { child: "^2.0.0" } } } }), "npm-shrinkwrap version 3, present-but-unread", "1 present/unread value(s)"],
    ["unknown version", "package-lock.json", JSON.stringify({ lockfileVersion: 99, packages: { "node_modules/parent": { version: "1.0.0", dependencies: { child: "^2.0.0" } } } }), "package-lock version 99, unsupported", "1 unsupported source schema(s)"],
    ["malformed", "package-lock.json", "{", "package-lock version unknown, unreadable", "1 present/unread value(s)"],
  ])("propagates %s parser scope through the real registry disclosure", async (_label, filename, text, version, population) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-range-format-"));
    const pkg = { dependencies: { direct: "1.0.0" } };
    let context: InstanceType<typeof MechanicalScanContext> | undefined;
    try {
      writeFileSync(join(root, "package.json"), JSON.stringify(pkg));
      writeFileSync(join(root, filename), text);
      context = new MechanicalScanContext(root);
      const result = await runRegisteredDependencyDetectors({ context, scanDir: root, pkg, osv: { failure: "offline format fixture" }, skipNetworkChecks: true }, "supply");
      const scope = result.findings.find((finding) => finding.id === "SUP-SCOPE-00")!;
      expect(scope.evidence).toContain(version);
      expect(scope.evidence).toContain(population);
      expect(scope.evidence).not.toContain("tree cannot answer");
    } finally { context?.dispose(); rmSync(root, { recursive: true, force: true }); }
  });

  it("reaches both real registry consumers, preserves every owner receipt, and clears exact/registry and peer-only twins", async () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-lock-ranges-"));
    const pkg = { name: "root", workspaces: ["packages/*"], dependencies: { direct: "1.0.0" } };
    const lock = { lockfileVersion: 3, packages: {
      "": { version: "1.0.0", dependencies: { direct: "*" } },
      "node_modules/parent": { version: "1.0.0", dependencies: { loose: "^2.0.0", remote: "git+https://fixture-user:fixture-password@example.invalid/repo.git?token=fixture-token#0123456", malformed: 4 }, optionalDependencies: { fixed: "2.0.0" } },
      "node_modules/other": { version: "1.0.0", dependencies: { loose: "^2.0.0", fixed: "2.0.0" }, peerDependencies: { compatibility: "*" } },
      "node_modules/parent/node_modules/other": { version: "2.0.0", dependencies: { loose: "^2.0.0" } },
      "node_modules/member": { link: true, resolved: "packages/member" },
      "packages/member": { version: "1.0.0", dependencies: { memberdep: "*" } },
    } };
    const scan = async () => {
      writeFileSync(join(root, "package-lock.json"), JSON.stringify(lock));
      const context = new MechanicalScanContext(root);
      try { return await runRegisteredDependencyDetectors({ context, scanDir: root, pkg, osv: { failure: "offline range fixture" }, skipNetworkChecks: true }, "supply"); }
      finally { context.dispose(); }
    };
    try {
      writeFileSync(join(root, "package.json"), JSON.stringify(pkg));
      mkdirSync(join(root, "packages/member"), { recursive: true });
      writeFileSync(join(root, "packages/member/package.json"), JSON.stringify({ name: "member", dependencies: { memberdep: "2.0.0" } }));
      const result = await scan();
      for (const detector of ["dependency-pinning", "non-registry-dependency"]) {
        const receipt = result.records.find((record) => record.detector === detector)!;
        expect(receipt.unitsExamined).toBe(8);
        expect(new Set(receipt.examinedUnitIdentities.map((unit) => unit.identity)).size).toBe(8);
        const identities = receipt.examinedUnitIdentities.map((unit) => JSON.parse(unit.identity) as unknown[]);
        expect(identities.filter((identity) => identity[10] === true)).toHaveLength(2);
        expect(identities.filter((identity) => identity[1] === "package-lock.json")).toHaveLength(6);
        expect(identities.some((identity) => identity[4] === "node_modules/parent/node_modules/other")).toBe(true);
      }
      const unpinned = result.findings.find((finding) => finding.id === "SUP-UNPINNED-TREE")!;
      const nonRegistry = result.findings.find((finding) => finding.id === "SUP-NON-REGISTRY-TREE")!;
      expect(unpinned?.dependencyRangeEvidence).toMatchObject({ examined: 6, matched: 3, distinctSpecifications: 1 });
      expect(unpinned.evidence).toContain("3 declarations across 3 owners");
      expect(unpinned.location).toContain("package-lock.json");
      expect(nonRegistry?.dependencyRangeEvidence).toMatchObject({ examined: 6, matched: 1 });
      expect(nonRegistry.dependencyRangeEvidence?.edges[0]).toMatchObject({ ownerPath: "node_modules/parent", section: "dependencies", direct: false, redacted: true });
      const serialized = JSON.stringify(result);
      for (const secret of ["fixture-user", "fixture-password", "fixture-token"]) expect(serialized).not.toContain(secret);
      const disclosure = result.findings.find((finding) => finding.id === "SUP-SCOPE-00")!;
      expect(disclosure.evidence).toContain("6 admitted third-party range edges");
      expect(disclosure.evidence).toContain("1 present/unread value(s)");
      expect(disclosure.evidence).toContain("peer 1");

      lock.packages["node_modules/parent"].dependencies.loose = "2.0.0";
      lock.packages["node_modules/parent"].dependencies.remote = "1.0.0";
      lock.packages["node_modules/other"].dependencies.loose = "2.0.0";
      lock.packages["node_modules/parent/node_modules/other"].dependencies.loose = "2.0.0";
      const benign = await scan();
      expect(benign.findings.filter((finding) => /^SUP-(?:UNPINNED|NON-REGISTRY)(?:-TREE)?$/.test(finding.id))).toEqual([]);
      expect(benign.findings.find((finding) => finding.id === "SUP-SCOPE-00")?.evidence).toContain("peer 1");
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

// #757 (part of #756): on a Prisma/Postgres app the Supabase-specific migration/RLS detectors have
// no DB-level surface, so they must record N/A-by-architecture (the M1-ARCH-PRISMA disclosure) and
// never fire — while a real Supabase app's RLS detectors must still fire unchanged. secrets/semgrep
// are mocked above; the Supabase-static SQL parsers run for real (pure filesystem), which is what
// these assertions exercise.
describe("runMechanicalScan Prisma/Supabase architecture gating (#757)", () => {
  const PRISMA_FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "__fixtures__", "prisma-app");
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const tmp = (): string => {
    const d = mkdtempSync(join(tmpdir(), "harvey-orm-gate-"));
    dirs.push(d);
    return d;
  };
  const writeSupabaseTarget = (): string => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "supa", dependencies: { "@supabase/supabase-js": "^2.45.0" } }));
    mkdirSync(join(d, "supabase", "migrations"), { recursive: true });
    // A public table that never gets ENABLE RLS — checkMigrationRlsStatic fires SB-RLS-STATIC-*.
    writeFileSync(join(d, "supabase", "migrations", "0001_schema.sql"), "create table public.audit_logs (id uuid primary key);");
    return d;
  };

  it("records N/A-by-architecture and fires no Supabase (SB-*) detector on a Prisma app", async () => {
    const d = tmp();
    cpSync(PRISMA_FIXTURE, d, { recursive: true });
    const findings = await runMechanicalScan({ dir: d, skipNetworkChecks: true });
    expect(findings.some((f) => f.id === "M1-ARCH-PRISMA")).toBe(true);
    expect(findings.some((f) => f.id.startsWith("SB-"))).toBe(false);
  });

  it("still fires the Supabase RLS detectors on a Supabase app (no regression, no N/A record)", async () => {
    const findings = await runMechanicalScan({ dir: writeSupabaseTarget(), skipNetworkChecks: true });
    expect(findings.some((f) => f.id === "SB-RLS-STATIC-audit_logs")).toBe(true);
    expect(findings.some((f) => f.id === "M1-ARCH-PRISMA")).toBe(false);
  });

  // #869/#901: a Drizzle target has no RLS surface. #901 ships a builder-chain tenant-scope detector,
  // so the note now records PARTIAL coverage (builder chain assessed; relational-query API / raw SQL
  // not) instead of "wholly unassessed" — still fail-loud, no longer "assessed and clean".
  it("discloses a Drizzle data layer with partial-coverage wording (builder chain now assessed)", async () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "drizzle-app", dependencies: { "drizzle-orm": "^0.30.0", pg: "^8.12.0" } }));
    const findings = await runMechanicalScan({ dir: d, skipNetworkChecks: true });
    const note = findings.find((f) => f.id === "M1-ARCH-DRIZZLE");
    expect(note).toBeDefined();
    expect(note).toMatchObject({ severity: "Info", confidence: "N/A", category: "Multi-tenant isolation" });
    expect(note?.evidence).toContain("Drizzle");
    expect(note?.evidence).toContain("drizzle-tenant-scope");
    expect(note?.impact).toContain("PARTIAL");
    expect(note?.impact).toContain("relational-query API");
    expect(findings.some((f) => f.id === "M1-ARCH-PRISMA")).toBe(false);
  });

  // #901: the detector itself — a Drizzle builder-chain read filtered by primary key alone gets a
  // REAL tenant-scope finding, not just the not-assessed row.
  it("flags a Drizzle query filtered by id alone and clears one scoped to the tenant column", async () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "drizzle-app", dependencies: { "drizzle-orm": "^0.30.0", pg: "^8.12.0" } }));
    writeFileSync(
      join(d, "unsafe.ts"),
      `import { eq } from "drizzle-orm";\nimport { db } from "./db";\nimport { tasks } from "./schema";\nexport const get = (id: string) => db.select().from(tasks).where(eq(tasks.id, id));\n`,
    );
    writeFileSync(
      join(d, "safe.ts"),
      `import { and, eq } from "drizzle-orm";\nimport { db } from "./db";\nimport { tasks } from "./schema";\nexport const get = (id: string, org: string) => db.select().from(tasks).where(and(eq(tasks.id, id), eq(tasks.organizationId, org)));\n`,
    );
    const findings = await runMechanicalScan({ dir: d, skipNetworkChecks: true });
    const scope = findings.filter((f) => f.taxonomy.includes("Drizzle query filtered by primary key"));
    expect(scope).toHaveLength(1);
    expect(scope[0]?.location).toContain("unsafe.ts");
    expect(scope[0]?.precisionTier).toBe("review");
  });

  it("discloses a raw-SQL data layer and says which app-layer detectors did cover it", async () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "pg-app", dependencies: { pg: "^8.12.0" } }));
    const findings = await runMechanicalScan({ dir: d, skipNetworkChecks: true });
    const note = findings.find((f) => f.id === "M1-ARCH-RAW-SQL");
    expect(note?.evidence).toContain("pg-idor");
  });

  it("emits no architecture note for a target with no recognised data layer at all", async () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "lib", dependencies: { lodash: "^4.17.21" } }));
    const findings = await runMechanicalScan({ dir: d, skipNetworkChecks: true });
    expect(findings.some((f) => f.id.startsWith("M1-ARCH-"))).toBe(false);
  });

  it("keeps the Supabase RLS detectors active when BOTH Prisma and Supabase signatures are present", async () => {
    const d = writeSupabaseTarget();
    // Add Prisma signatures on top of the Supabase surface — Supabase must win so the real RLS
    // surface is never suppressed.
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "hybrid", dependencies: { "@supabase/supabase-js": "^2.45.0", "@prisma/client": "^5.18.0" } }));
    mkdirSync(join(d, "prisma"), { recursive: true });
    writeFileSync(join(d, "prisma", "schema.prisma"), "model Note { id String @id }\n");
    const findings = await runMechanicalScan({ dir: d, skipNetworkChecks: true });
    expect(findings.some((f) => f.id === "SB-RLS-STATIC-audit_logs")).toBe(true);
    expect(findings.some((f) => f.id === "M1-ARCH-PRISMA")).toBe(false);
  });
});

// #950: a missing semgrep binary previously threw an uncaught ENOENT out of runMechanicalScan
// (propagating to quick-scan's main().catch() and hard-exiting the CLI), instead of degrading
// like osv-scanner already does (#512). This proves runMechanicalScan's own wiring — it must
// read runSemgrep's `failure` and substitute the SEM-00 disclosure instead of feeding a failed
// result into parseSemgrepFindings — using the REAL parseSemgrepFindings/semgrepUnavailableFinding
// (only runSemgrep itself is faked, see the mock above).
describe("runMechanicalScan degrades when semgrep is unavailable (#950)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-mechanical-semgrep-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
    runSemgrep.mockReturnValueOnce({ result: {}, failure: "semgrep not found on PATH" });
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("does not throw, and substitutes the SEM-00 disclosure for the failed pass", async () => {
    const findings = await runMechanicalScan({ dir, skipNetworkChecks: true });
    const disclosure = findings.find((f) => f.id === "SEM-00");
    expect(disclosure).toBeDefined();
    expect(disclosure?.severity).toBe("Info");
    expect(disclosure?.evidence).toContain("semgrep not found on PATH");
  });
});

// #1077: a file semgrep errored on (or chose to skip) still counts as "scanned" for SEM-SCOPE-00's
// purposes, so that disclosure alone can't catch it — this proves runMechanicalScan actually reads
// `semgrep.result.errors`/`paths.skipped` and emits SEM-ERR-00, rather than the whole-tree path
// discarding them the way the fix-pipeline single-file re-run never did.
describe("runMechanicalScan surfaces semgrep parse errors and skipped files (#1077)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-mechanical-semgrep-err-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
    runSemgrep.mockReturnValueOnce({
      result: {
        errors: [{ type: "Syntax error", message: "Syntax error at line 1", path: join(dir, "broken.tsx") }],
        paths: { scanned: [join(dir, "broken.tsx")], skipped: [{ path: join(dir, "vendor", "huge.js"), reason: "too_big" }] },
        time: { rules: [], fixpoint_timeouts: [] },
      },
    });
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("emits SEM-ERR-00 naming the errored and skipped files, never reading them as clean", async () => {
    const findings = await runMechanicalScan({ dir, skipNetworkChecks: true });
    const disclosure = findings.find((f) => f.id === "SEM-ERR-00");
    expect(disclosure).toBeDefined();
    expect(disclosure?.evidence).toContain("broken.tsx");
    expect(disclosure?.evidence).toContain("huge.js");
  });
});

// #1954: fixpoint timeout telemetry is intentionally excluded from SEM-ERR-00 because its raw
// rows are volatile. The stable replacement still has to cross the real registered-producer seam:
// execution receipt -> findingsFor companion -> phase result -> assembled client findings and the
// producer's conservation count. A unit test of semgrepTaintNotAssessedFindings alone would not
// prove that the disclosure ships.
describe("runMechanicalScan delivers stable Semgrep taint NotAssessed findings (#1954)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-mechanical-semgrep-taint-na-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture" }));
    const scanned = join(dir, "src", "route.ts");
    mkdirSync(dirname(scanned), { recursive: true });
    writeFileSync(scanned, "export const route = () => 'ok';\n");
    const raw = {
      results: [], errors: [], paths: { scanned: [scanned], skipped: [] },
      time: {
        rules: ["harvey-auth-taint"],
        fixpoint_timeouts: [{
          error_type: "Fixpoint timeout",
          severity: "warn",
          message: "volatile experimental timeout row",
          location: { path: scanned, start: { line: 1, col: 1, offset: 0 }, end: { line: 1, col: 2, offset: 1 } },
        }],
      },
    };
    const attempt = buildSemgrepCommandSemanticReceipt(
      raw, dir, ["semgrep"], 1, ["harvey-auth-taint"], undefined, "raw", ["harvey-auth-taint"],
    );
    const configSha256 = "1".repeat(64);
    const family = {
      ordinal: 0,
      id: "local-auth",
      familyId: "local-auth",
      sourceKind: "local-config" as const,
      sourceId: "auth.yml",
      sourceConfigSha256: configSha256,
      configSha256,
      ruleIds: ["harvey-auth-taint"],
      ownedRuleIds: ["harvey-auth-taint"],
      ownedTaintRuleIds: ["harvey-auth-taint"],
      loadedRuleIds: ["harvey-auth-taint"],
      loadedTaintRuleIds: ["harvey-auth-taint"],
      taintCoverage: "not-assessed" as const,
      excludedRuleIds: [],
      argv: ["semgrep"],
      topology: "single-command-v1" as const,
      mergeAlgorithm: "single-command-v1" as const,
      partitions: [],
      verification: "single" as const,
      status: "succeeded" as const,
      attempts: [attempt],
    };
    const ownership = [{
      ordinal: family.ordinal,
      id: family.id,
      sourceKind: family.sourceKind,
      sourceId: family.sourceId,
      sourceConfigSha256: family.sourceConfigSha256,
      configSha256: family.configSha256,
      ownedRuleIds: family.ownedRuleIds,
      ownedTaintRuleIds: family.ownedTaintRuleIds,
      excludedRuleIds: family.excludedRuleIds,
      semanticObjectSha256: undefined,
      selector: undefined,
      routingManifest: undefined,
      topology: family.topology,
      mergeAlgorithm: family.mergeAlgorithm,
      partitions: family.partitions,
      verification: family.verification,
    }];
    runSemgrep.mockReturnValueOnce({
      result: {
        results: [], errors: [], paths: { scanned: [scanned], skipped: [] },
        time: { rules: ["harvey-auth-taint"] },
      },
      executionPlan: {
        schema: 8,
        timeoutPolicy: "fixpoint-family-not-assessed-v1",
        status: "succeeded",
        strategy: "globally-owned-partitioned-families",
        ownershipSha256: receiptSha(ownership),
        families: [family],
      },
    });
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("ships one collision-free family row through assembly and producer conservation", async () => {
    const scan = await runMechanicalScanDetailed({ dir, skipNetworkChecks: true });
    const disclosure = scan.findings.find((finding) => finding.id === "SEM-TAINT-NA-local-auth");
    expect(disclosure).toBeDefined();
    expect(disclosure?.taxonomy).toBe("Next.js/web footgun — coverage not assessed");
    expect(disclosure?.evidence).toContain("One or more taint rules in this family did not complete");
    expect(disclosure?.evidence).toContain("harvey-auth-taint");
    expect(disclosure?.evidence).toContain("exact scope SHA-256");
    const semgrepProducer = scan.detectors.find((record) => record.detector === "semgrep-and-companion-config");
    expect(semgrepProducer).toBeDefined();
    expect(semgrepProducer?.findings).toBe(scan.phases.find((phase) => phase.phase === "semgrep")?.findings.length);
    expect(scan.findings.filter((finding) => finding.id.startsWith("SEM-TAINT-NA-"))).toEqual([disclosure]);
  });
});
