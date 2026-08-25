import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { digestObservedPaths } from "../corpus-scanner-scope.js";
import { readEntriesSafe } from "../fs-walk.js";
import type { SourceInput } from "./common.js";
import {
  detectM1HardcodedTenantFindings,
  detectM5HardcodedDeploymentFindings,
  m5HardcodedSourceNotAssessed,
  M1_HARDCODED_TENANT_METADATA,
  M1_HARDCODED_TENANT_TAXONOMY,
  M5_HARDCODED_DEPLOYMENT_METADATA,
  M5_HARDCODED_ENDPOINT_TAXONOMY,
  M5_HARDCODED_IDENTIFIER_TAXONOMY,
  M5_HARDCODED_SOURCE_COVERAGE_ID,
  M5_HARDCODED_SOURCE_COVERAGE_TAXONOMY,
} from "./m5-hardcoded-deployment.js";

const FIXTURES = fileURLToPath(new URL("./__fixtures__/m5-hardcoded-deployment/", import.meta.url));
const CALIBRATION = fileURLToPath(new URL("../../targets/calibration/src/m5-hardcoded-deployment/", import.meta.url));
const M1_CALIBRATION = fileURLToPath(new URL("../../targets/calibration/src/m1-hardcoded-tenant/", import.meta.url));

function loadFixtureDir(relDir: string): SourceInput[] {
  const root = join(FIXTURES, relDir);
  const files: SourceInput[] = [];
  const walk = (dir: string): void => {
    for (const { name, path, isDirectory } of readEntriesSafe(dir).entries) {
      if (isDirectory) walk(path);
      else if (name.endsWith(".txt")) {
        files.push({
          path: relative(root, path).replace(/\.txt$/, "").split(sep).join("/"),
          text: readFileSync(path, "utf8"),
        });
      }
    }
  };
  walk(root);
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

describe("M5 hardcoded deployment classifier (#1929)", () => {
  it("detects only qualified server, client, configuration, request, route, and infrastructure literals", () => {
    const findings = detectM5HardcodedDeploymentFindings(loadFixtureDir("positive"));
    expect(findings).toHaveLength(10);
    expect(findings.filter((finding) => finding.taxonomy === M5_HARDCODED_ENDPOINT_TAXONOMY)).toHaveLength(6);
    expect(findings.filter((finding) => finding.taxonomy === M5_HARDCODED_IDENTIFIER_TAXONOMY)).toHaveLength(4);
    expect(new Set(findings.map((finding) => finding.location.split(":")[0]))).toEqual(new Set([
      "client/telemetry.tsx",
      "config/deployment.ts",
      "infra/provider.ts",
      "request/sync.ts",
      "routing/proxy.ts",
      "server/orders.ts",
    ]));
    for (const finding of findings) {
      expect(finding).toMatchObject({
        severity: "Medium",
        confidence: "Review",
        precisionTier: "review",
        category: "Maintainability",
      });
      expect(finding.evidence).toMatch(/Literal value `[^`]+` is consumed by (?:client construction|configuration|request|routing) node `/);
      expect(finding.evidence).toMatch(/Expected seam: validated env\/config key `[A-Z0-9_]+`/);
    }
  });

  it("redacts provider identifiers while retaining a reproducible value fingerprint", () => {
    const findings = detectM5HardcodedDeploymentFindings(loadFixtureDir("positive"));
    const account = findings.find((finding) => finding.taxonomy === M5_HARDCODED_IDENTIFIER_TAXONOMY
      && finding.location.startsWith("infra/provider.ts:"));
    expect(account?.evidence).toContain("`1234…9012`");
    expect(account?.evidence).not.toContain("123456789012");
    expect(account?.evidence).toContain("`ACCOUNT_ID`");
  });

  it("clears canonical public URLs, loopback/dev fixtures, non-product files, display text, config-backed values, and schema-validated config", () => {
    expect(detectM5HardcodedDeploymentFindings(loadFixtureDir("negative"))).toEqual([]);
    expect(detectM5HardcodedDeploymentFindings([{
      path: "src/provider.ts",
      text: `export const client = new ApiClient({ endpoint: "https://api.vendor.example-service.com" });`,
    }])).toEqual([]);
  });

  it.each(["server", "client", "config", "request", "infrastructure"])(
    "exercises the exact %s positive/negative calibration pair",
    (shape) => {
      const source = (suffix: "positive" | "negative"): SourceInput => ({
        path: `m5-hardcoded-deployment/${shape}-${suffix}.${shape === "client" ? "tsx" : "ts"}`,
        text: readFileSync(join(CALIBRATION, `${shape}-${suffix}.${shape === "client" ? "tsx" : "ts"}`), "utf8"),
      });
      expect(detectM5HardcodedDeploymentFindings([source("positive")])).toHaveLength(1);
      expect(detectM5HardcodedDeploymentFindings([source("negative")])).toHaveLength(0);
    },
  );

  it("partitions credentials from hardcoded tenant exposure and gives the tenant row only to M1", () => {
    const files: SourceInput[] = [{
      path: "src/server/auth.ts",
      text: `
        export const client = new ProviderClient({
          apiKey: "example-api-key",
          signingSecret: "example-signing-value",
        });
        await fetch("https://tenant.prod.harvey-platform.com/v1", {
          headers: { Authorization: "Bearer example-token", "X-Tenant-ID": "tenant_example-4821" },
        });
      `,
    }];
    const m5 = detectM5HardcodedDeploymentFindings(files);
    const m1 = detectM1HardcodedTenantFindings(files);
    expect(m5).toHaveLength(1);
    expect(m5[0]?.taxonomy).toBe(M5_HARDCODED_ENDPOINT_TAXONOMY);
    expect(m5[0]?.evidence).not.toMatch(/example-api-key|example-signing-value|example-token|tenant_example-4821/);
    expect(m1).toHaveLength(1);
    expect(m1[0]).toMatchObject({
      id: expect.stringMatching(/^M1-HARDCODED-TENANT-/),
      taxonomy: M1_HARDCODED_TENANT_TAXONOMY,
      severity: "High",
      confidence: "Review",
      precisionTier: "review",
    });
    expect(m1[0]?.evidence).toContain("authenticated/session context");
    expect(m1[0]?.fix).toContain("authenticated principal/session");
    expect(m1[0]?.fix).not.toMatch(/env(?:ironment)?(?: variable)?/i);

    const clientExposure: SourceInput = {
      path: "src/components/tenant-client.tsx",
      text: `"use client"; export const tenant = new TenantClient({ tenantId: "tenant_example-4821" });`,
    };
    expect(detectM5HardcodedDeploymentFindings([clientExposure])).toEqual([]);
    expect(detectM1HardcodedTenantFindings([clientExposure])).toHaveLength(1);
  });

  it("keeps dynamic/session-derived tenant identity and server configuration outside the M1 boundary owner", () => {
    const files: SourceInput[] = [
      {
        path: "src/components/tenant-client.tsx",
        text: `"use client"; export const tenant = (session: { tenantId: string }) => new TenantClient({ tenantId: session.tenantId });`,
      },
      {
        path: "src/config/deployment.ts",
        text: `export const deploymentConfig = { tenantId: "tenant_example-4821" };`,
      },
    ];
    expect(detectM1HardcodedTenantFindings(files)).toEqual([]);
    expect(detectM5HardcodedDeploymentFindings(files).map((finding) => finding.taxonomy)).toEqual([
      M5_HARDCODED_IDENTIFIER_TAXONOMY,
    ]);
  });

  it.each(["request", "client"])("exercises the exact M1 %s positive/negative calibration pair", (shape) => {
    const extension = shape === "client" ? "tsx" : "ts";
    const source = (suffix: "positive" | "negative"): SourceInput => ({
      path: `m1-hardcoded-tenant/${shape}-${suffix}.${extension}`,
      text: readFileSync(join(M1_CALIBRATION, `${shape}-${suffix}.${extension}`), "utf8"),
    });
    expect(detectM1HardcodedTenantFindings([source("positive")])).toHaveLength(1);
    expect(detectM1HardcodedTenantFindings([source("negative")])).toEqual([]);
    expect(detectM5HardcodedDeploymentFindings([source("positive")])).toEqual([]);
  });

  it("keeps the credential negative control excluded by M1 ownership, not fixture-path filtering", () => {
    const credentials = loadFixtureDir("negative").find((file) => file.path === "config/credentials.ts");
    expect(credentials).toBeDefined();
    expect(credentials?.text).toContain("apiKey:");
    expect(credentials?.text).toContain("signingSecret:");
    expect(credentials?.text).toContain("?token=synthetic_m1_owned_token_placeholder");
    expect(credentials?.text).toContain("synthetic-user:synthetic-password@");
    expect(detectM5HardcodedDeploymentFindings([credentials!])).toEqual([]);
  });

  it("does not turn dynamic or ambiguous strings into defects", () => {
    const files: SourceInput[] = [{
      path: "src/orders.ts",
      text: `
        const marketingCopy = "Use https://orders.prod.harvey-platform.com for production orders";
        const endpoint = resolveEndpoint(runtime.region);
        const client = new OrdersClient({ endpoint, projectId: runtime.projectId });
        export const card = { label: "https://orders.prod.harvey-platform.com" };
      `,
    }];
    expect(detectM5HardcodedDeploymentFindings(files)).toEqual([]);
  });

  it("has an explicit enabled/disabled failing direction", () => {
    const files = loadFixtureDir("positive");
    expect(detectM5HardcodedDeploymentFindings(files)).toHaveLength(10);
    expect(detectM5HardcodedDeploymentFindings(files, { enabled: false })).toHaveLength(0);
    const tenant: SourceInput[] = [{
      path: "src/components/tenant.tsx",
      text: `"use client"; export const tenant = new TenantClient({ tenantId: "tenant_example-4821" });`,
    }];
    expect(detectM1HardcodedTenantFindings(tenant)).toHaveLength(1);
    expect(detectM1HardcodedTenantFindings(tenant, { enabled: false })).toEqual([]);
  });

  it("emits one stable typed NotAssessed row only for a non-empty broad inventory with zero admitted files", () => {
    const broad: SourceInput[] = [
      { path: "src/service.py", text: "def run():\n    pass\n" },
      { path: "src/worker.go", text: "package worker\n" },
    ];
    const receipt = m5HardcodedSourceNotAssessed(broad, []);
    expect(receipt).toEqual({
      reason: expect.stringContaining("No source admitted by the exact M5 hardcoded-deployment JavaScript/TypeScript selector was examined"),
      provenance: expect.stringMatching(/loadSourceInventory.*isM5HardcodedDeploymentSource/),
      falsifier: "Add or identify an admitted JavaScript/TypeScript source, or extend the selector, then rerun.",
      inventory: {
        broadUnits: 2,
        selectedUnits: 0,
        pathSetDigest: digestObservedPaths(broad.map((file) => file.path)),
        scope: expect.stringContaining("tracked non-test product-source paths"),
      },
    });
    const findings = detectM5HardcodedDeploymentFindings([], { productSourceInventory: broad });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      id: M5_HARDCODED_SOURCE_COVERAGE_ID,
      taxonomy: M5_HARDCODED_SOURCE_COVERAGE_TAXONOMY,
      severity: "Info",
      confidence: "N/A",
      category: "Coverage",
    });
    expect(findings[0]?.evidence).toContain("Broad product-source inventory: 2 path(s)");
    expect(findings[0]?.evidence).toContain("exact JavaScript/TypeScript selector: 0 admitted");
    expect(findings[0]?.evidence).toContain(receipt?.inventory.pathSetDigest);
    expect(findings[0]?.evidence).toContain("Provenance:");
    expect(findings[0]?.evidence).toContain("Falsifier:");
    expect(detectM5HardcodedDeploymentFindings([], { productSourceInventory: [...broad].reverse() })).toEqual(findings);
  });

  it("keeps true-empty targets silent and stops disclosing once the exact selector admits a source", () => {
    expect(m5HardcodedSourceNotAssessed([], [])).toBeUndefined();
    expect(detectM5HardcodedDeploymentFindings([], { productSourceInventory: [] })).toEqual([]);
    const admitted: SourceInput = { path: "src/index.ts", text: "export const value = 1;\n" };
    expect(m5HardcodedSourceNotAssessed([admitted], [admitted])).toBeUndefined();
    expect(detectM5HardcodedDeploymentFindings([admitted], { productSourceInventory: [admitted] })).toEqual([]);
  });

  it("exports bounded source-only applicability and fallback metadata for registry integration", () => {
    expect(M1_HARDCODED_TENANT_METADATA).toMatchObject({
      id: "m1-hardcoded-tenant",
      module: "M1",
      precisionTier: "review",
    });
    expect(M1_HARDCODED_TENANT_METADATA.ownershipExclusions).toContain("M5-owned");
    expect(M5_HARDCODED_DEPLOYMENT_METADATA).toMatchObject({
      id: "m5-hardcoded-deployment",
      module: "M5",
      precisionTier: "review",
      providerLifecycle: "source-only; provider credentials, live state, and lifecycle APIs are never consulted",
    });
    expect(M5_HARDCODED_DEPLOYMENT_METADATA.applicableFiles).toContain("JavaScript/TypeScript");
    expect(M5_HARDCODED_DEPLOYMENT_METADATA.examinedUnit).toContain("source path");
    expect(M5_HARDCODED_DEPLOYMENT_METADATA.ownershipExclusions).toContain("M1-owned");
    expect(M5_HARDCODED_DEPLOYMENT_METADATA.fallback).toContain("Dynamic/computed values");
    expect(M5_HARDCODED_DEPLOYMENT_METADATA.findingIds).toContain(M5_HARDCODED_SOURCE_COVERAGE_ID);
  });
});
