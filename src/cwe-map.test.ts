import { readdirSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { classifyTaxonomyCwe, enrichFindingsCwe } from "./cwe-map.js";
import type { Finding } from "./findings.js";
import { MECHANICAL_DETECTORS } from "./scan/mechanical-detector-registry.js";
import { runRegisteredNormalizationEngines } from "./scan/mechanical-normalization-registry.js";
import { detectPgResponseExposureFindings } from "./scan/pg-response-exposure.js";
import { detectM1HardcodedTenantFindings } from "./detectors/m5-hardcoded-deployment.js";
import { toSarif } from "./sarif.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "F-1", title: "t", severity: "High", confidence: "Confirmed", category: "c",
    taxonomy: "SQL injection", location: "a.ts:1", status: "Open", evidence: "", impact: "", fix: "",
    value: 3, ease: 3, safety: 3, ...over,
  };
}

// Source-level taxonomy discovery deliberately follows the AST rather than one property spelling:
// a detector may assign a string literal, a named constant, or either arm of a conditional. Values
// that remain dynamic are covered by the live detector registry below and require an exercised
// producer control instead of being mistaken for an unclassified literal.
function sourceFiles(path: string): string[] {
  return readdirSync(path, { withFileTypes: true }).flatMap((entry) => {
    const child = join(path, entry.name);
    if (entry.isDirectory()) return sourceFiles(child);
    return entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") ? [child] : [];
  });
}

function taxonomyExpressionValues(
  expression: ts.Expression,
  checker: ts.TypeChecker,
  seen = new Set<ts.Symbol>(),
): string[] | undefined {
  if (ts.isStringLiteralLike(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) return [expression.text];
  if (ts.isParenthesizedExpression(expression)) return taxonomyExpressionValues(expression.expression, checker, seen);
  if (ts.isConditionalExpression(expression)) {
    const left = taxonomyExpressionValues(expression.whenTrue, checker, seen);
    const right = taxonomyExpressionValues(expression.whenFalse, checker, seen);
    return left && right ? [...left, ...right] : undefined;
  }
  if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = taxonomyExpressionValues(expression.left, checker, seen);
    const right = taxonomyExpressionValues(expression.right, checker, seen);
    return left && right ? left.flatMap((prefix) => right.map((suffix) => prefix + suffix)) : undefined;
  }
  if (!ts.isIdentifier(expression)) return undefined;
  const initialSymbol = checker.getSymbolAtLocation(expression);
  if (!initialSymbol) return undefined;
  const symbol = initialSymbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(initialSymbol) : initialSymbol;
  if (seen.has(symbol)) return undefined;
  const declaration = symbol.valueDeclaration;
  if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer) return undefined;
  return taxonomyExpressionValues(declaration.initializer, checker, new Set(seen).add(symbol));
}

interface TaxonomyDiscovery {
  taxonomies: string[];
  dynamicLocations: string[];
}

function detectorTaxonomies(): TaxonomyDiscovery {
  const paths = [
    ...sourceFiles("src/detectors"),
    ...sourceFiles("src/scan"),
  ];
  const program = ts.createProgram(paths, { module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, target: ts.ScriptTarget.ES2022, skipLibCheck: true });
  const checker = program.getTypeChecker();
  const taxonomies = new Set<string>();
  const dynamicLocations: string[] = [];
  for (const path of paths) {
    const source = program.getSourceFile(path)!;
    const visit = (node: ts.Node) => {
      const isTaxonomy = (ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node))
        && node.name.getText(source) === "taxonomy";
      if (isTaxonomy) {
        const expression = ts.isPropertyAssignment(node) ? node.initializer : node.name;
        const values = taxonomyExpressionValues(expression, checker);
        if (values) values.forEach((taxonomy) => taxonomies.add(taxonomy));
        else dynamicLocations.push(`${path}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  for (const finding of dynamicPgResponseExposureFindings()) taxonomies.add(finding.taxonomy);
  return { taxonomies: [...taxonomies].sort(), dynamicLocations: dynamicLocations.sort() };
}

const pgResponseExposureCases = [
  { kind: "direct", positive: `export function getUser(req, res) {
  res.json({ id: 1, passwordHash: "x" });
}`, safe: `export function getUser(req, res) {
  res.json({ id: 1, createdAt: "x" });
}` },
  { kind: "spread", positive: `export function getUser(req, res) {
  const user = { id: 1, refreshToken: "x" };
  res.json({ ...user });
}`, safe: `export function getUser(req, res) {
  const user = { id: 1, createdAt: "x" };
  res.json({ ...user });
}` },
  { kind: "select-star", positive: `export async function getUser(req, res) {
  const { rows } = await db.query("SELECT * FROM users");
  res.json(rows[0]);
}`, safe: `export async function getUser(req, res) {
  const { rows } = await db.query("SELECT id FROM users");
  res.json(rows[0]);
}` },
  { kind: "direct", positive: `export function getUser(req, res) {
  res.json({ "password\\nHash": "x" });
}`, safe: `export function getUser(req, res) {
  res.json({ createdAt: "x" });
}` },
  { kind: "spread", positive: `export function getUser(req, res) {
  const user = { "refresh\\nToken": "x" };
  res.json({ ...user });
}`, safe: `export function getUser(req, res) {
  const user = { createdAt: "x" };
  res.json({ ...user });
}` },
] as const;

function dynamicPgResponseExposureFindings(): Finding[] {
  return pgResponseExposureCases.flatMap(({ kind, positive }, index) => detectPgResponseExposureFindings([
    { path: `pg-response-${kind}-${index}.ts`, text: positive },
  ]));
}

function normalizeAndSarif(findings: Finding[]): { findings: Finding[]; tags: string[][] } {
  const normalized = runRegisteredNormalizationEngines({
    findings: findings.map((finding) => ({ ...finding })),
    scanDir: process.cwd(),
    directDeps: new Set(),
  }).findings;
  const sarif = toSarif(normalized, { coverageAbsent: "#2227 exercises the normal CWE-to-SARIF seam." }) as {
    runs: { tool: { driver: { rules: { properties: { tags: string[] } }[] } } }[];
  };
  return { findings: normalized, tags: sarif.runs[0]!.tool.driver.rules.map((rule) => rule.properties.tags) };
}

describe("#975: every detector taxonomy has a CWE decision (fail loud on an unclassified one)", () => {
  const discovery = detectorTaxonomies();
  const taxonomies = discovery.taxonomies;

  it("harvested a non-trivial set of detector taxonomies", () => {
    // Guards the harvester itself: a zero/tiny count would make the coverage assertion vacuously pass.
    expect(taxonomies.length).toBeGreaterThan(100);
  });

  it("discovers constant and conditional taxonomy expressions beyond quoted assignments", () => {
    expect(taxonomies).toContain("M1 — Hardcoded tenant identifier at client/request boundary");
    expect(taxonomies).toContain("M1 — Client-supplied owner id trusted by authenticated action");
    expect(taxonomies).toContain("M1 — Client-supplied owner id trusted by unauthenticated service-role action");
  });

  it("binds unresolved live producer expressions to a registry contract", () => {
    const implementations = new Set(MECHANICAL_DETECTORS.map((definition) => definition.implementation.file));
    for (const location of discovery.dynamicLocations) {
      const file = location.slice(0, location.lastIndexOf(":"));
      if (!implementations.has(file)) continue;
      const contracts = MECHANICAL_DETECTORS.filter((definition) => definition.implementation.file === file);
      expect(contracts, `${location} has no live producer contract`).not.toEqual([]);
      expect(contracts.some((definition) => definition.taxonomies.length > 0), `${location} has no declared taxonomy contract`).toBe(true);
    }
  });

  it("classifies every exact live producer contract and exercises every non-prefix wildcard", () => {
    const emitted = dynamicPgResponseExposureFindings();
    for (const definition of MECHANICAL_DETECTORS) {
      for (const taxonomy of definition.taxonomies) {
        if (!taxonomy.includes("*")) {
          expect(classifyTaxonomyCwe(taxonomy), `${definition.id} declares an unclassified taxonomy`).toBeDefined();
          continue;
        }
        const expression = new RegExp(`^${taxonomy.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
        const matched = emitted.filter((finding) => expression.test(finding.taxonomy));
        if (matched.length > 0) {
          for (const finding of matched) expect(classifyTaxonomyCwe(finding.taxonomy), `${definition.id} emits an unclassified wildcard taxonomy`).toBeDefined();
        } else {
          const representative = taxonomy.replace("*", "taxonomy discovery probe");
          expect(classifyTaxonomyCwe(representative), `${definition.id} wildcard needs an exercised producer control or a prefix classification`).toBeDefined();
        }
      }
    }
  });

  it.each(taxonomies)("%s is classified (cwe or explicit no-cwe-with-reason)", (taxonomy) => {
    const c = classifyTaxonomyCwe(taxonomy);
    expect(c, `taxonomy "${taxonomy}" is unclassified — add it to SECURITY (with a CWE) or NO_CWE (with a reason) in src/cwe-map.ts`).toBeDefined();
    if (c?.kind === "cwe") {
      expect(c.cwe.length).toBeGreaterThan(0);
      // #1661: every entry, not just the first — the field is a list and a second entry that was
      // never shape-checked would reach the report and SARIF unvalidated.
      for (const id of c.cwe) expect(id).toMatch(/^CWE-\d+:/);
    } else {
      expect(c?.kind).toBe("none");
      expect((c as { reason: string }).reason.length).toBeGreaterThan(0);
    }
  });
});

describe("#2227: dynamic pg response-exposure taxonomy coverage", () => {
  const findings = dynamicPgResponseExposureFindings();
  const taxonomyKind = (taxonomy: string): string | undefined => taxonomy.match(/\(pg-resjson-exposure-([^)]*)\)$/)?.[1];

  it("enumerates every finite producer kind from emitted findings", () => {
    // This deliberately invokes the production detector. A quoted-assignment grep cannot see these
    // template-built taxonomies, and skipping any producer makes this cardinality assertion fail.
    expect(findings).toHaveLength(pgResponseExposureCases.length);
    expect(findings.map((finding) => taxonomyKind(finding.taxonomy)).sort()).toEqual(pgResponseExposureCases.map((entry) => entry.kind).sort());
    for (const { kind, safe } of pgResponseExposureCases) {
      expect(detectPgResponseExposureFindings([{ path: `pg-response-${kind}-safe.ts`, text: safe }])).toEqual([]);
    }
  });

  it("preserves the detector's severity, review boundary, and stable IDs", () => {
    expect(findings.map(({ id, severity, precisionTier }) => ({ id: /^SEC-PG-RESJSON-pg-response-(?:direct|spread|select-star)-\d+-ts-\d+$/.test(id), severity, precisionTier }))).toEqual(
      pgResponseExposureCases.map(({ kind }) => ({ id: true, severity: kind === "select-star" ? "Medium" : "High", precisionTier: "review" })),
    );
  });

  it.each(findings)("classifies emitted %s taxonomy as CWE-200/A01", (finding) => {
    expect(classifyTaxonomyCwe(finding.taxonomy)).toEqual({
      kind: "cwe",
      cwe: ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"],
      owasp: ["A01:2021 - Broken Access Control"],
    });
  });

  it("carries each emitted decision through normal enrichment into SARIF CWE tags", () => {
    const normalized = normalizeAndSarif(findings);
    expect(normalized.findings.map((finding) => finding.cwe)).toEqual(Array.from({ length: pgResponseExposureCases.length }, () => ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"]));
    for (const tags of normalized.tags) expect(tags).toContain("external/cwe/cwe-200");
  });
});

describe("#2227: constant producer taxonomy coverage", () => {
  it("normalizes and exports the hardcoded tenant producer with CWE-639", () => {
    const findings = detectM1HardcodedTenantFindings([{
      path: "src/components/tenant-client.tsx",
      text: `"use client"; export const tenant = new TenantClient({ tenantId: "tenant_example-4821" });`,
    }]);
    expect(findings).toHaveLength(1);
    const normalized = normalizeAndSarif(findings);
    expect(normalized.findings[0]).toMatchObject({
      taxonomy: "M1 — Hardcoded tenant identifier at client/request boundary",
      cwe: ["CWE-639: Authorization Bypass Through User-Controlled Key"],
      owasp: ["A01:2021 - Broken Access Control"],
    });
    expect(normalized.tags[0]).toContain("external/cwe/cwe-639");
  });
});

describe("#975: enrichFindingsCwe", () => {
  it("declares the CWE for a security taxonomy that lacks one", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "Object-level authorization gap: client-supplied owner id scopes the query" })]);
    expect(f!.cwe).toEqual(["CWE-639: Authorization Bypass Through User-Controlled Key"]);
    expect(f!.owasp).toEqual(["A01:2021 - Broken Access Control"]);
  });

  it("carries the CWE without an OWASP category when OWASP does not categorize it", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "Non-atomic read-modify-write race condition" })]);
    expect(f!.cwe).toEqual(["CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"]);
    expect(f!.owasp).toBeUndefined();
  });

  it("leaves a non-security (quality) taxonomy without a CWE", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "M6 — Indicator: manual date formatting" })]);
    expect(f!.cwe).toBeUndefined();
  });

  it("does not overwrite a CWE the finding already carries (semgrep/OSV-sourced)", () => {
    const [f] = enrichFindingsCwe([finding({ taxonomy: "SQL injection", cwe: ["CWE-943: something else"] })]);
    expect(f!.cwe).toEqual(["CWE-943: something else"]);
  });
});
