import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../findings.js";
import type { OsvScanResult } from "./dependencies.js";

const provider = vi.hoisted(() => new Map<string, OsvScanResult>());
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, execFileSync: vi.fn((bin: string, args: string[], opts: unknown) => {
    if (bin !== "osv-scanner") return actual.execFileSync(bin as never, args as never, opts as never);
    const input = args.at(-1)!;
    const result = provider.get(input);
    if (!result) throw new Error(`No controlled provider output for ${input}`);
    return JSON.stringify({ ...result, results: result.results?.map((source) => ({ ...source, source: { path: input } })) });
  }) };
});
vi.mock("./dependencies.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./dependencies.js")>();
  return { ...actual, checkNextVersionCVEs: vi.fn(actual.checkNextVersionCVEs) };
});

const { runOsvScanner, checkNextVersionCVEs } = await import("./dependencies.js");
const { MechanicalScanContext } = await import("./mechanical-context.js");
const { runRegisteredDependencyDetectors } = await import("./mechanical-dependency-registry.js");
const { runRegisteredNormalizationEngines } = await import("./mechanical-normalization-registry.js");
const { assembleEngagementDocument } = await import("../audit-report.js");
const { conservationLedger } = await import("../conservation-ledger.js");
const { buildHtml } = await import("../../report-template/render.mjs");
const { esc } = await import("../../report-template/sections.mjs");
const { renderFidelityBreaches } = await import("../render-fidelity.js");

const ssrf = { id: "GHSA-c4j6-fc7j-m34r", aliases: ["CVE-2026-44578"], summary: "WebSocket SSRF", details: "Controlled provider advisory for a resolved dependency.", database_specific: { severity: "HIGH" } };
const csrf = { ...ssrf, id: "GHSA-mq59-m269-xvcx", aliases: ["CVE-2026-27978"], summary: "Server Actions CSRF" };
const rsc = { ...ssrf, id: "GHSA-fv66-9v8q-g76r", aliases: ["CVE-2025-55182"], summary: "React server components RCE" };
const pkg = (name: string, version: string, vulnerabilities = [ssrf]) => ({ package: { ecosystem: "npm", name, version }, vulnerabilities });
const osvId = (version: string, input = "package-lock.json", advisory = ssrf.id, name = "next") => `DEP-OSV-${advisory}-${name}@${version}${input.includes("/") ? `#${input}` : ""}`;

describe("OSV occurrences require emitted exact curated representatives (#2033)", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "harvey-osv-representatives-"));
    provider.clear();
    vi.mocked(checkNextVersionCVEs).mockClear();
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const write = (root: string, file: string, value: string | object) => {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), typeof value === "string" ? value : JSON.stringify(value));
  };
  function npm(input: string, packages: Record<string, { version: string }>, reported: ReturnType<typeof pkg>[]) {
    write(dir, input, { lockfileVersion: 3, packages });
    provider.set(join(dir, input), { results: [{ packages: reported }] });
  }
  function pnpm(input: string, version: string, reported: ReturnType<typeof pkg>[]) {
    write(dir, input, `lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      next:\n        specifier: ${version}\n        version: ${version}\npackages:\n  next@${version}:\n    resolution: {integrity: sha512-controlled}\nsnapshots:\n  next@${version}: {}\n`);
    provider.set(join(dir, input), { results: [{ packages: reported }] });
  }
  async function scan() {
    const manifest = existsSync(join(dir, "package.json")) ? JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) : null;
    const observed = runOsvScanner(dir);
    expect(observed.failure).toBeUndefined();
    const context = new MechanicalScanContext(dir);
    try {
      const early = await runRegisteredDependencyDetectors({ scanDir: dir, context, pkg: manifest, osv: observed, skipNetworkChecks: true }, "early");
      const normalized = runRegisteredNormalizationEngines({ findings: early.findings, scanDir: dir, directDeps: new Set(Object.keys({ ...manifest?.dependencies, ...manifest?.devDependencies })) });
      const doc = assembleEngagementDocument([], { connected: false, dynamic: false, llm: false }, normalized.findings, { client: "Controlled exact dependency inputs", subtitle: "OSV representative conservation", date: "2026-09-10", commit: "a".repeat(40), auditor: "Harvey", confidential: true, overallHealth: 5, tenantIsolation: "Unmeasured", authModel: "Unmeasured", headline: "Dependency advisory representation", scope: "Controlled dependency inputs", methodology: "Production registry, normalization, assembly and renderer", outOfScope: "Live deployment behavior" });
      expect(conservationLedger(normalized.findings, doc.findings).ok).toBe(true);
      const html = buildHtml(doc);
      expect(renderFidelityBreaches(doc, html)).toEqual([]);
      return { early, doc, html, observed };
    } finally { context.dispose(); }
  }
  const expectDelivered = (result: Awaited<ReturnType<typeof scan>>, id: string) => {
    const finding = result.doc.findings.find((finding: Finding) => finding.id === id);
    expect(finding, id).toBeDefined();
    expect(result.html).toContain(esc(finding!.evidence));
  };

  it("delivers the concrete source/identity replacement reason in the actual emitted curated finding", async () => {
    write(dir, "package.json", { dependencies: { next: "14.2.35" } });
    npm("package-lock.json", { "node_modules/next": { version: "14.2.35" } }, [pkg("next", "14.2.35")]);
    const result = await scan();
    expect(result.early.findings.some((finding) => finding.id === osvId("14.2.35"))).toBe(false);
    const representative = result.doc.findings.find((finding: Finding) => finding.id === "DEP-CVE-2026-44578")!;
    expect(representative.evidence).toContain("npm:next@14.2.35 from package-lock.json");
    expect(representative.evidence).toContain(result.observed.assessment.invocations[0]!.sha256);
    expect(representative.evidence).toContain("duplicate OSV row is not delivered separately");
    expect(result.html).toContain(esc(representative.evidence));
    expect(checkNextVersionCVEs).toHaveBeenCalledTimes(1);
  });

  it("retains the OSV occurrence if the registered alternate producer actually emits nothing", async () => {
    write(dir, "package.json", { dependencies: { next: "14.2.35" } });
    npm("package-lock.json", { "node_modules/next": { version: "14.2.35" } }, [pkg("next", "14.2.35")]);
    vi.mocked(checkNextVersionCVEs).mockReturnValueOnce([]);
    expectDelivered(await scan(), osvId("14.2.35"));
  });

  it("retains transitive Next advisories when the root declares no Next dependency", async () => {
    write(dir, "package.json", { name: "workspace-root" });
    npm("package-lock.json", { "node_modules/next": { version: "14.2.35" } }, [pkg("next", "14.2.35")]);
    const result = await scan();
    expect(result.early.findingsByDetector["next-curated-cves"]).toEqual([]);
    expectDelivered(result, osvId("14.2.35"));
  });

  it("retains both nested MVP advisory occurrences when there is no root manifest", async () => {
    write(dir, "nextjs/package.json", { dependencies: { next: "16.1.6" } });
    pnpm("nextjs/pnpm-lock.yaml", "16.1.6", [pkg("next", "16.1.6", [ssrf, csrf])]);
    const result = await scan();
    expect(result.early.findingsByDetector["next-curated-cves"]).toEqual([]);
    expectDelivered(result, osvId("16.1.6", "nextjs/pnpm-lock.yaml"));
    expectDelivered(result, osvId("16.1.6", "nextjs/pnpm-lock.yaml", csrf.id));
  });

  it.each(["16.2.4", "16.2.5"])("does not borrow an alternate npm lockfile's next@%s representative for selected pnpm input", async (alternateVersion) => {
    write(dir, "package.json", { dependencies: { next: "16.2.4" } });
    npm("package-lock.json", { "node_modules/next": { version: alternateVersion } }, []);
    pnpm("pnpm-lock.yaml", "16.2.4", [pkg("next", "16.2.4")]);
    const result = await scan();
    expect(result.observed.assessment.invocations.map((input) => input.path)).toEqual(["pnpm-lock.yaml"]);
    expectDelivered(result, osvId("16.2.4", "pnpm-lock.yaml"));
  });

  it("preserves an additional resolved version even when the advisory has a representative for another version", async () => {
    write(dir, "package.json", { dependencies: { next: "14.2.35" } });
    npm("package-lock.json", { "node_modules/next": { version: "14.2.35" }, "node_modules/host/node_modules/next": { version: "16.1.6" } }, [pkg("next", "14.2.35"), pkg("next", "16.1.6")]);
    const result = await scan();
    expectDelivered(result, osvId("16.1.6"));
    expect(result.early.findings.some((finding) => finding.id === osvId("14.2.35"))).toBe(false);
  });

  it("preserves the same version and advisory in another selected dependency root", async () => {
    write(dir, "package.json", { dependencies: { next: "14.2.35" } });
    write(dir, "nested/package.json", { dependencies: { next: "14.2.35" } });
    for (const input of ["package-lock.json", "nested/package-lock.json"]) npm(input, { "node_modules/next": { version: "14.2.35" } }, [pkg("next", "14.2.35")]);
    const result = await scan();
    expectDelivered(result, osvId("14.2.35", "nested/package-lock.json"));
    expect(result.early.findings.some((finding) => finding.id === osvId("14.2.35"))).toBe(false);
  });

  it("keeps the upstream React package occurrence distinct from a Next finding sharing its CVE alias", async () => {
    write(dir, "package.json", { dependencies: { next: "15.0.0" } });
    npm("package-lock.json", { "node_modules/next": { version: "15.0.0" }, "node_modules/react-server-dom-webpack": { version: "19.0.0" } }, [pkg("next", "15.0.0", []), pkg("react-server-dom-webpack", "19.0.0", [rsc])]);
    const result = await scan();
    expect(result.early.findings.some((finding) => finding.id === "DEP-CVE-2025-55182")).toBe(true);
    expectDelivered(result, osvId("19.0.0", "package-lock.json", rsc.id, "react-server-dom-webpack"));
  });
});
