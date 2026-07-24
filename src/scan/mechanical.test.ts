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

vi.mock("./supply-chain.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./supply-chain.js")>();
  return { ...actual, checkSlopsquat, checkLicenseCompliance };
});
vi.mock("./secrets.js", () => ({ scanSecrets: vi.fn(() => []), resolveBundleScan: vi.fn(() => ({})) }));
vi.mock("./semgrep.js", () => ({
  runSemgrep: vi.fn(() => ""),
  parseSemgrepFindings: vi.fn(() => []),
  checkMissingCsp: vi.fn(() => []),
  checkPublicDirSensitive: vi.fn(() => []),
}));

const { runMechanicalScan } = await import("./mechanical.js");

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

  it("skips the live npm-registry checks when set", async () => {
    await runMechanicalScan({ dir, skipNetworkChecks: true });
    expect(checkSlopsquat).not.toHaveBeenCalled();
    expect(checkLicenseCompliance).not.toHaveBeenCalled();
  });

  it("still runs the live npm-registry checks by default", async () => {
    await runMechanicalScan({ dir });
    expect(checkSlopsquat).toHaveBeenCalledWith(["react"]);
    expect(checkLicenseCompliance).toHaveBeenCalledWith({ react: "18.2.0" });
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

  // #869 (the M1 sibling of #844): a Drizzle target has no RLS surface AND no tenant-scope detector.
  // The scan must say so by name — silence here reads as "no tenant-scope problems found".
  it("discloses a Drizzle data layer by name instead of reporting nothing", async () => {
    const d = tmp();
    writeFileSync(join(d, "package.json"), JSON.stringify({ name: "drizzle-app", dependencies: { "drizzle-orm": "^0.30.0", pg: "^8.12.0" } }));
    const findings = await runMechanicalScan({ dir: d, skipNetworkChecks: true });
    const note = findings.find((f) => f.id === "M1-ARCH-DRIZZLE");
    expect(note).toBeDefined();
    expect(note).toMatchObject({ severity: "Info", confidence: "N/A", category: "Multi-tenant isolation" });
    expect(note?.evidence).toContain("Drizzle");
    expect(note?.impact).toContain("INCOMPLETE");
    expect(findings.some((f) => f.id === "M1-ARCH-PRISMA")).toBe(false);
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
