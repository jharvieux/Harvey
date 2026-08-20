// Intent: runMechanicalScan's skipNetworkChecks option (added alongside the dry-run harness's
// network-independence fix) must actually gate the two live npm-registry calls
// (checkSlopsquat, checkLicenseCompliance) — the assertion is "never invoked", not "returned no
// findings" (which a network hiccup could also produce and wrongly pass). The other sub-scanners
// (secrets, semgrep) shell out to real binaries and are mocked here purely so this test stays
// fast and offline like the rest of the suite (matching pnpm verify's own deterministic-offline
// convention) — they aren't what this test is about.
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
const runSemgrep = vi.fn(() => ({ result: {} }) as { result: object; failure?: string });

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

const { runMechanicalScan, runMechanicalScanDetailed } = await import("./mechanical.js");
const { MECHANICAL_REGISTRY } = await import("./mechanical-engine-registry.js");
const { mechanicalExaminedUnitDigest } = await import("./mechanical-phase-cache.js");

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
      expect(cold.detectors).toHaveLength(72);
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
