import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  MECHANICAL_DETECTORS,
  discoverMechanicalDetectorExports,
  validateMechanicalDetectorRegistry,
  type MechanicalDetectorDefinition,
} from "./mechanical-detector-registry.js";
import {
  MECHANICAL_REGISTRY,
  discoverMechanicalRegistryImplementations,
  operatorMechanicalScopeRows,
  validateMechanicalEngineRegistry,
  validateMechanicalOrchestrationSource,
  type MechanicalRegistryEntry,
} from "./mechanical-engine-registry.js";
import { assertProducerTaxonomyOwnership } from "./mechanical-registry-contract.js";

const repoRoot = fileURLToPath(new URL("../../", import.meta.url));

function replace(id: string, update: (definition: MechanicalDetectorDefinition) => MechanicalDetectorDefinition): MechanicalDetectorDefinition[] {
  return MECHANICAL_DETECTORS.map((definition) => definition.id === id ? update(definition) : definition);
}

describe("#1851 discovery-backed mechanical detector registry", () => {
  it("registers every discovered scan export with live ownership and required assurance evidence", () => {
    expect(discoverMechanicalDetectorExports(repoRoot).length).toBeGreaterThan(25);
    expect(MECHANICAL_DETECTORS.length).toBeGreaterThan(25);
    expect(validateMechanicalDetectorRegistry(repoRoot)).toEqual([]);
  });

  it("fails when an implemented detector is unregistered", () => {
    const registry = MECHANICAL_DETECTORS.filter((definition) => definition.id !== "counter-race");
    expect(validateMechanicalDetectorRegistry(repoRoot, registry)).toContain("detectCounterRaceFindings: implemented detector is not registered");
  });

  it.each(["leftover-auth", "path-scope-disclosure", "handrolled-indicators"])(
    "fails when non-standard export ownership is removed: %s",
    (id) => {
      const registry = MECHANICAL_DETECTORS.filter((definition) => definition.id !== id);
      expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("implemented detector is not registered");
    },
  );

  it("fails when a registration goes stale", () => {
    const registry = replace("counter-race", (definition) => ({ ...definition, implementation: { ...definition.implementation, exportName: "goneCounterRace" } }));
    expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("stale registration cannot find export goneCounterRace");
  });

  it("fails when detector source owns a taxonomy the registration does not declare", () => {
    const registry = replace("counter-race", (definition) => ({ ...definition, taxonomies: ["different taxonomy"] }));
    expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("unknown taxonomy Non-atomic read-modify-write race condition");
  });

  it("fails invented computed-taxonomy ownership", () => {
    const registry = replace("path-scope-disclosure", (definition) => ({ ...definition, taxonomies: ["Invented taxonomy"] }));
    expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("taxonomy ownership differs");
  });

  it("fails a wildcard that broadens finding ownership beyond the canonical implementation", () => {
    const registry = replace("counter-race", (definition) => ({ ...definition, findingIds: ["*"] }));
    expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("finding-id ownership differs");
  });

  it("fails duplicate implementation ownership", () => {
    const registry = [...MECHANICAL_DETECTORS, { ...MECHANICAL_DETECTORS[0]!, id: "leftover-auth-copy", order: 999 }];
    expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("duplicate implementation ownership: src/scan/leftover-auth.ts#classifyLeftoverAuth");
  });

  it("fails missing fixture/evidence links", () => {
    const registry = replace("counter-race", (definition) => ({ ...definition, positiveFixture: { status: "covered", path: "missing-positive.test.ts", detail: "This deliberately missing path proves the discovery gate fails." } }));
    expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("positiveFixture points to missing evidence missing-positive.test.ts");
  });

  it("fails a covered fixture link that exists but never consumes the detector", () => {
    const registry = replace("path-scope-disclosure", (definition) => ({
      ...definition,
      positiveFixture: { status: "covered", path: "src/scan/counter-race.test.ts", detail: "An existing but unrelated file must not pass as detector-specific fixture evidence." },
    }));
    expect(validateMechanicalDetectorRegistry(repoRoot, registry).join("\n")).toContain("positiveFixture does not consume pathScopeNotAssessedRows");
  });

});

function replaceEngine(
  phase: MechanicalRegistryEntry["phase"],
  id: string,
  update: (entry: MechanicalRegistryEntry) => MechanicalRegistryEntry,
): MechanicalRegistryEntry[] {
  return MECHANICAL_REGISTRY.map((entry) => entry.phase === phase && entry.id === id ? update(entry) : entry);
}

describe("#1851 complete mechanical producer ownership", () => {
  it("validates every phase registry and derives the complete operator scope from it", () => {
    expect(MECHANICAL_REGISTRY.length).toBeGreaterThan(MECHANICAL_DETECTORS.length);
    expect(validateMechanicalEngineRegistry(repoRoot)).toEqual([]);
    expect(operatorMechanicalScopeRows().map((row) => [row.phase, row.id, row.taxonomies])).toEqual(
      MECHANICAL_REGISTRY.map((entry) => [entry.phase, entry.id, entry.taxonomies]),
    );
  });

  it.each(MECHANICAL_REGISTRY
    .filter((entry) => entry.phase !== "structural-ast")
    .map((entry) => [`${entry.phase}:${entry.id}`, entry.phase, entry.id] as const))(
    "fails when any non-structural mechanical producer is removed: %s",
    (_label, phase, id) => {
      const registry = MECHANICAL_REGISTRY.filter((entry) => entry.phase !== phase || entry.id !== id);
      expect(validateMechanicalEngineRegistry(repoRoot, registry)).toContain(`${phase}:${id}: registered mechanical producer is missing`);
    },
  );

  it("fails stale implementation ownership and canonical metadata drift", () => {
    const registry = replaceEngine("configuration", "workflow-permissions", (entry) => ({
      ...entry,
      implementations: [{ ...entry.implementations[0]!, exportName: "goneWorkflowPermissions" }],
    }));
    const problems = validateMechanicalEngineRegistry(repoRoot, registry).join("\n");
    expect(problems).toContain("registry metadata differs from canonical invocation ownership");
    expect(problems).toContain("stale implementation export src/scan/gha-permissions.ts#goneWorkflowPermissions");
  });

  it("fails duplicate phase order, producer id, and implementation ownership", () => {
    const first = MECHANICAL_REGISTRY[0]!;
    const second = MECHANICAL_REGISTRY.find((entry) => entry.phase === "dependency-advisory")!;
    const duplicate = { ...second, id: first.id, order: first.order, implementations: first.implementations };
    const problems = validateMechanicalEngineRegistry(repoRoot, [...MECHANICAL_REGISTRY, duplicate]).join("\n");
    expect(problems).toContain("duplicate producer id across mechanical phases");
    expect(problems).toContain("duplicate implementation ownership");
    expect(problems).toContain("duplicate execution order");
  });

  it("fails missing metadata and assurance evidence even when the row still exists", () => {
    const registry = replaceEngine("dependency-advisory", "lockfile-presence", (entry) => ({
      ...entry,
      taxonomies: [],
      fallback: "",
      corpus: { status: "covered", path: "src/scan/counter-race.test.ts", detail: "An unrelated existing test cannot substantiate corpus execution evidence." },
    }));
    const problems = validateMechanicalEngineRegistry(repoRoot, registry).join("\n");
    expect(problems).toContain("required implementation/taxonomy/executable-applicability/examined-unit/fallback metadata is missing");
    expect(problems).toContain("corpus evidence does not execute the mechanical registry and retain its execution census");
  });

  it("rejects generic evidence and missing executable selector ownership", () => {
    const registry = replaceEngine("configuration", "workflow-permissions", (entry) => ({
      ...entry,
      select: undefined as unknown as MechanicalRegistryEntry["select"],
      conservation: { status: "structured-exception", detail: "A generic module plant exists but says nothing producer-specific." },
    }));
    const problems = validateMechanicalEngineRegistry(repoRoot, registry).join("\n");
    expect(problems).toContain("required implementation/taxonomy/executable-applicability/examined-unit/fallback metadata is missing");
    expect(problems).toContain("conservation is generic rather than producer-specific");
  });

  it.each([
    "mechanical-configuration-registry.ts",
    "mechanical-dependency-registry.ts",
    "mechanical-secrets-registry.ts",
    "mechanical-semgrep-registry.ts",
    "mechanical-normalization-registry.ts",
  ])("discovers a live but unregistered producer call in %s", (registryName) => {
    const root = mkdtempSync(join(tmpdir(), "harvey-registry-discovery-"));
    try {
      mkdirSync(join(root, "src", "scan"), { recursive: true });
      for (const name of [
        "mechanical-configuration-registry.ts", "mechanical-dependency-registry.ts", "mechanical-secrets-registry.ts",
        "mechanical-semgrep-registry.ts", "mechanical-normalization-registry.ts", "mechanical-detector-registry.ts",
      ]) writeFileSync(join(root, "src", "scan", name), readFileSync(join(repoRoot, "src", "scan", name), "utf8"));
      const path = join(root, "src", "scan", registryName);
      writeFileSync(path, `${readFileSync(path, "utf8")}\nimport { brandNewProducer } from "./brand-new-producer.js";\nbrandNewProducer();\n`);
      expect(discoverMechanicalRegistryImplementations(root)).toContainEqual({
        file: "src/scan/brand-new-producer.ts", exportName: "brandNewProducer", registryFile: `src/scan/${registryName}`,
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails when a non-standard mechanical producer is implemented outside every registry", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-unregistered-producer-"));
    try {
      mkdirSync(join(root, "src", "scan"), { recursive: true });
      // Exact adversarial class from criterion 3: a fully implemented producer copied under a new
      // path, with no detect*Findings naming convention and no call added to a registry file.
      writeFileSync(
        join(root, "src", "scan", "adversarial-unregistered.ts"),
        readFileSync(join(repoRoot, "src", "scan", "gha-permissions.ts"), "utf8"),
      );
      expect(validateMechanicalEngineRegistry(repoRoot, MECHANICAL_REGISTRY, root)).toContain(
        "src/scan/adversarial-unregistered.ts#checkWorkflowPermissions: implemented mechanical finding producer is not registered",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("discovers an inferred-return producer without flagging an ordinary exported helper", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-inferred-producer-"));
    try {
      mkdirSync(join(root, "src", "scan"), { recursive: true });
      writeFileSync(join(root, "src", "scan", "inferred.ts"), `import { mechanicalFinding as emit } from "./common.js";
export const ordinaryHelper = (value: string) => value.trim();
export function inferredProducer() {
  return [emit({ id: "X", title: "x", severity: "Low", category: "x", taxonomy: "x", location: "x", evidence: "x", impact: "x", fix: "x" })];
}
`);
      const problems = validateMechanicalEngineRegistry(repoRoot, MECHANICAL_REGISTRY, root).join("\n");
      expect(problems).toContain("src/scan/inferred.ts#inferredProducer: implemented mechanical finding producer is not registered");
      expect(problems).not.toContain("ordinaryHelper");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("follows wrapper, exported-alias, and re-export chains to an implemented producer", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-transitive-producer-"));
    try {
      mkdirSync(join(root, "src", "scan"), { recursive: true });
      writeFileSync(join(root, "src", "scan", "producer.ts"), `import { mechanicalFinding as emit } from "./common.js";
function localProducer() {
  return [emit({ id: "X", title: "x", severity: "Low", category: "x", taxonomy: "x", location: "x", evidence: "x", impact: "x", fix: "x" })];
}
export function wrappedProducer() { return localProducer(); }
export const aliasedProducer = localProducer;
export const ordinaryHelper = (value: string) => value.trim();
`);
      writeFileSync(join(root, "src", "scan", "forwarded.ts"), `export { wrappedProducer as reexportedProducer } from "./producer.js";\n`);
      const problems = validateMechanicalEngineRegistry(repoRoot, MECHANICAL_REGISTRY, root).join("\n");
      for (const name of ["wrappedProducer", "aliasedProducer"]) {
        expect(problems).toContain(`src/scan/producer.ts#${name}: implemented mechanical finding producer is not registered`);
      }
      expect(problems).toContain("src/scan/forwarded.ts#reexportedProducer: implemented mechanical finding producer is not registered");
      expect(problems).not.toContain("ordinaryHelper");
      expect(problems).not.toContain("localProducer: implemented mechanical finding producer is not registered");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("resolves imported helpers, star/re-export cycles, direct rows, and shadowed seed names", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-symbol-producer-"));
    try {
      mkdirSync(join(root, "src", "scan"), { recursive: true });
      writeFileSync(join(root, "src", "scan", "common.ts"), `export const mechanicalFinding = <T>(value: T): T => value;\n`);
      writeFileSync(join(root, "src", "scan", "helper.ts"), `import { mechanicalFinding } from "./common.js";
export function helperProducer() { return [mechanicalFinding({ id: "X", title: "x", severity: "Low", category: "x", taxonomy: "x", location: "x", evidence: "x", impact: "x", fix: "x" })]; }
`);
      writeFileSync(join(root, "src", "scan", "entry.ts"), `import { helperProducer } from "./helper.js";
export function importedWrapper() { return helperProducer(); }
export function directFinding() { return [{ id: "Y", title: "y", severity: "Low", category: "y", taxonomy: "y", location: "y", evidence: "y", impact: "y", fix: "y" }]; }
export function shadowedSeed(mechanicalFinding: (value: string) => string) { return mechanicalFinding("ordinary"); }
`);
      writeFileSync(join(root, "src", "scan", "forwarded.ts"), `export * from "./entry.js";\n`);
      writeFileSync(join(root, "src", "scan", "cycle-a.ts"), `export * from "./forwarded.js"; export * from "./cycle-b.js";\n`);
      writeFileSync(join(root, "src", "scan", "cycle-b.ts"), `export * from "./cycle-a.js";\n`);
      const problems = validateMechanicalEngineRegistry(repoRoot, MECHANICAL_REGISTRY, root).join("\n");
      for (const key of [
        "src/scan/helper.ts#helperProducer",
        "src/scan/entry.ts#importedWrapper",
        "src/scan/entry.ts#directFinding",
        "src/scan/forwarded.ts#importedWrapper",
        "src/scan/cycle-a.ts#importedWrapper",
        "src/scan/cycle-b.ts#importedWrapper",
      ]) expect(problems).toContain(`${key}: implemented mechanical finding producer is not registered`);
      expect(problems).not.toContain("shadowedSeed");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails closed on ambiguous star exports, dynamic dispatch, and stale helper aliases", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-ambiguous-producer-"));
    try {
      mkdirSync(join(root, "src", "scan"), { recursive: true });
      writeFileSync(join(root, "src", "scan", "common.ts"), `export const mechanicalFinding = <T>(value: T): T => value;\n`);
      for (const name of ["one", "two"]) writeFileSync(join(root, "src", "scan", `${name}.ts`), `import { mechanicalFinding } from "./common.js";
export function sameName() { return [mechanicalFinding({ id: "${name}", title: "x", severity: "Low", category: "x", taxonomy: "x", location: "x", evidence: "x", impact: "x", fix: "x" })]; }
`);
      writeFileSync(join(root, "src", "scan", "barrel.ts"), `export * from "./one.js"; export * from "./two.js";\n`);
      writeFileSync(join(root, "src", "scan", "dynamic.ts"), `import { sameName } from "./one.js";
const producers = [sameName];
export function dynamicProducer(index: number) { return producers[index]!(); }
`);
      writeFileSync(join(root, "src", "scan", "stale.ts"), `export const staleProducer = missingHelper;\n`);
      const problems = validateMechanicalEngineRegistry(repoRoot, MECHANICAL_REGISTRY, root).join("\n");
      expect(problems).toContain("src/scan/barrel.ts#sameName: ambiguous export-star mechanical producer ownership");
      expect(problems).toContain("ambiguous dynamic mechanical producer dispatch is not registry-auditable");
      expect(problems).toContain("src/scan/stale.ts#staleProducer: stale exported helper alias cannot be resolved");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("rejects a live producer taxonomy outside its declared ownership", () => {
    expect(() => assertProducerTaxonomyOwnership(
      { id: "fixture-producer", phase: "configuration", taxonomies: ["Owned taxonomy"] },
      [{ id: "F-1", title: "fixture", severity: "Low", confidence: "Likely", category: "test", taxonomy: "Unowned taxonomy", location: "fixture.ts:1", status: "Open", evidence: "e", impact: "i", fix: "f", value: 1, ease: 1, safety: 1 }],
    )).toThrow("configuration:fixture-producer: emitted unknown taxonomies [Unowned taxonomy]");
  });

  it("passes the shared import graph and alias inventory to service-role-literal", () => {
    const source = readFileSync(join(repoRoot, "src/scan/mechanical-detector-registry.ts"), "utf8");
    expect(source).toContain("detectServiceRoleLiteralFindings([...selected], context.importGraph, context.pathAliases)");
  });

  it("fails a direct producer call or a missing registered phase runner in the orchestrator", () => {
    const source = readFileSync(fileURLToPath(new URL("./mechanical.ts", import.meta.url)), "utf8");
    const mutated = source
      .replace('import type { Finding } from "../findings.js";', 'import type { Finding } from "../findings.js";\nimport { checkWorkflowPermissions } from "./gha-permissions.js";')
      .replace("findings.push(...configuration.findings);", "findings.push(...checkWorkflowPermissions(scanDir));")
      .replace("runRegisteredSemgrepEngines(", "removedSemgrepRegistryRunner(");
    const problems = validateMechanicalOrchestrationSource(mutated).join("\n");
    expect(problems).toContain("semgrep: mechanical orchestrator does not invoke runRegisteredSemgrepEngines");
    expect(problems).toContain("directly imports registered producer src/scan/gha-permissions.ts#checkWorkflowPermissions");
    expect(problems).toContain("unregistered direct finding composition");
    expect(problems).toContain("missing registered phase composition: findings.push(...configuration.findings)");
  });
});
