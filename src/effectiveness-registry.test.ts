import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CALIBRATION_PLANTS } from "./audit-conservation.js";
import { AUDIT_RUNNERS } from "./audit-runners.js";
import {
  buildEffectivenessInventory,
  discoverProductionProducerCalls,
  EFFECTIVENESS_INVENTORY,
  EFFECTIVENESS_INVENTORY_JSON,
  serializeEffectivenessInventory,
  validateEffectivenessInventory,
} from "./effectiveness-registry.js";
import type { EffectivenessInventory, EffectivenessProducer } from "./effectiveness-schema.js";
import { SCORED_GATES } from "./scored-gates.js";
import { MECHANICAL_DETECTORS } from "./scan/mechanical-detector-registry.js";
import { MECHANICAL_REGISTRY } from "./scan/mechanical-engine-registry.js";
import { REGISTRY_PACKS } from "./scan/semgrep.js";

const freshInventory = (): EffectivenessInventory =>
  JSON.parse(EFFECTIVENESS_INVENTORY_JSON) as EffectivenessInventory;

function producer(inventory: EffectivenessInventory, id: string): EffectivenessProducer {
  const row = inventory.producers.find((candidate) => candidate.id === id);
  expect(row, `missing producer ${id}`).toBeDefined();
  return row!;
}

function withProducer(
  inventory: EffectivenessInventory,
  id: string,
  update: (row: EffectivenessProducer) => EffectivenessProducer,
): EffectivenessInventory {
  return {
    ...inventory,
    producers: inventory.producers.map((row) => (row.id === id ? update(row) : row)),
  };
}

const expectRestoredBaseline = (): void => {
  expect(validateEffectivenessInventory(freshInventory())).toEqual([]);
};

describe("effectiveness producer inventory (#1910)", () => {
  it("closes the production registries and preserves the current exact populations", () => {
    const inventory = freshInventory();
    expect(validateEffectivenessInventory(inventory)).toEqual([]);
    expect(inventory.receipt).toMatchObject({
      mechanicalDefinitions: 65,
      localSemgrepFamilies: 10,
      localSemgrepRuleIds: 118,
      registrySemgrepPacks: 6,
    });
    expect(inventory.receipt.mechanicalProducerIds).toHaveLength(65);
    expect(inventory.receipt.localSemgrepFamilyIds).toHaveLength(10);
    expect(inventory.receipt.localSemgrepRules).toHaveLength(118);
    expect(inventory.receipt.registrySemgrepPackIds).toEqual([
      "p/nextjs",
      "p/owasp-top-ten",
      "p/react",
      "p/secrets",
      "p/security-audit",
      "p/typescript",
    ]);
  });

  it("keeps each producer class disjoint and excludes controls from the true-family count", () => {
    const inventory = freshInventory();
    const summary = inventory.summary;
    expect(
      summary.trueFindingProducers
        + summary.disclosureOnly
        + summary.typedNotAssessed
        + summary.conservationPlants
        + summary.adapters
        + summary.synthesizers,
    ).toBe(summary.producers);
    expect(summary.denominatorConserved).toBe(true);

    const trueFindingFamilies = inventory.producers
      .filter((row) => row.populationClass === "true-finding-producer")
      .flatMap((row) => row.findingFamilies)
      .filter((row) => row.kind === "finding");
    const allFindingShapedFamilies = inventory.producers
      .flatMap((row) => row.findingFamilies)
      .filter((row) => row.kind === "finding");
    expect(summary.findingFamilies).toBe(trueFindingFamilies.length);
    expect(allFindingShapedFamilies.length).toBeGreaterThan(summary.findingFamilies);
  });

  it("derives deterministic JSON even when every live registry input is reversed", () => {
    const reversed = buildEffectivenessInventory({
      auditRunners: [...AUDIT_RUNNERS].reverse(),
      mechanicalRegistry: [...MECHANICAL_REGISTRY].reverse(),
      mechanicalDetectors: [...MECHANICAL_DETECTORS].reverse(),
      scoredGates: [...SCORED_GATES].reverse(),
      plants: [...CALIBRATION_PLANTS].reverse(),
      registryPacks: [...REGISTRY_PACKS].reverse(),
    });
    expect(serializeEffectivenessInventory(reversed)).toBe(EFFECTIVENESS_INVENTORY_JSON);
    expect(JSON.parse(EFFECTIVENESS_INVENTORY_JSON)).toEqual(EFFECTIVENESS_INVENTORY);
    expect(Object.isFrozen(EFFECTIVENESS_INVENTORY)).toBe(true);
  });

  it("retains one handrolled and one SFC producer across their multiple consumers", () => {
    const inventory = freshInventory();
    const owners = (symbol: string): EffectivenessProducer[] => inventory.producers.filter((row) =>
      row.implementations.some((item) => item.symbol === symbol));
    expect(owners("detectHandrolledFindings").map((row) => row.id)).toEqual([
      "mechanical:structural-ast:handrolled-indicators",
    ]);
    expect(owners("checkUnassessedSfcFiles").map((row) => row.id)).toEqual([
      "mechanical:configuration:sfc-coverage",
    ]);
    expect(inventory.receipt.composedCalls.filter((row) => row.symbol === "detectHandrolledFindings")).toHaveLength(1);
    expect(producer(inventory, "mechanical:structural-ast:handrolled-indicators").consumerPath)
      .toEqual(expect.arrayContaining([expect.objectContaining({ file: "src/cli/static-detect.ts" })]));
  });

  it("expands App Router into M1/M9 finding, disclosure, and not-assessed families", () => {
    const appRouter = producer(freshInventory(), "detector:app-router");
    expect(appRouter.modules).toEqual(["M1", "M9"]);
    expect(new Set(appRouter.findingFamilies.map((row) => row.module))).toEqual(new Set(["M1", "M9"]));
    expect(new Set(appRouter.findingFamilies.map((row) => row.kind))).toEqual(
      new Set(["finding", "coverage-disclosure", "not-assessed"]),
    );
  });

  it("gives the current M2 true population one empirical no-cadence exemption", () => {
    const inventory = freshInventory();
    const expected = inventory.producers
      .filter((row) => row.populationClass === "true-finding-producer" && row.modules.includes("M2") && row.venueIds.length === 0)
      .map((row) => row.id)
      .sort();
    const exemption = inventory.exemptions.find((row) => row.id === "exemption:m2-live-score");
    expect(exemption).toMatchObject({
      kind: "empirical",
      provenance: "src/scored-gates.ts#validate-connected; tracked by #1491",
      cadence: "none",
    });
    expect(exemption?.applicableProducerIds).toEqual(expected);
    expect(expected).not.toHaveLength(0);
    for (const id of expected) expect(producer(inventory, id).exemptionId).toBe(exemption?.id);
  });

  it("keeps normalization and applyVerifyResults outside the true-producer denominator", () => {
    const inventory = freshInventory();
    const normalization = inventory.producers.filter((row) => row.id.startsWith("mechanical:normalization:"));
    expect(normalization).toHaveLength(1);
    expect(normalization.every((row) => row.populationClass === "synthesizer")).toBe(true);
    const applyOwner = inventory.producers.find((row) =>
      row.implementations.some((item) => item.symbol === "applyVerifyResults"));
    expect(applyOwner).toMatchObject({
      id: "synthesizer:m2-apply-verify-results",
      populationClass: "synthesizer",
    });
  });

  it("discovers an unregistered finding call and fails until the receipt is restored", () => {
    const root = mkdtempSync(join(tmpdir(), "harvey-effectiveness-discovery-"));
    try {
      mkdirSync(join(root, "src", "cli"), { recursive: true });
      writeFileSync(
        join(root, "src", "cli", "static-detect.ts"),
        'import { detectGhostFindings } from "../ghost.js";\nexport const findings = detectGhostFindings();\n',
      );
      writeFileSync(
        join(root, "src", "ghost.ts"),
        "export function detectGhostFindings(): unknown[] { return []; }\n",
      );
      const discovered = discoverProductionProducerCalls(root, new Set(), ["src/cli/static-detect.ts"]);
      expect(discovered).toEqual([{ file: "src/ghost.ts", symbol: "detectGhostFindings" }]);

      const baseline = freshInventory();
      const composedCalls = [...baseline.receipt.composedCalls, ...discovered]
        .sort((a, b) => `${a.file}#${a.symbol}`.localeCompare(`${b.file}#${b.symbol}`));
      const planted: EffectivenessInventory = {
        ...baseline,
        receipt: {
          ...baseline.receipt,
          composedCalls,
          discoveredComposedCalls: composedCalls.length,
        },
      };
      expect(validateEffectivenessInventory(planted)).toContain(
        "src/ghost.ts#detectGhostFindings: discovered production producer call is unregistered",
      );
      expectRestoredBaseline();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("fails a deleted scored venue and passes when it is restored", () => {
    const baseline = freshInventory();
    const planted: EffectivenessInventory = {
      ...baseline,
      venues: baseline.venues.filter((row) => row.id !== "validate-calibration"),
    };
    expect(validateEffectivenessInventory(planted)).toContain(
      "mechanical:structural-ast:handrolled-indicators: scored venue validate-calibration no longer exists",
    );
    expectRestoredBaseline();
  });

  it("fails a module-mismatched venue and passes when it is restored", () => {
    const baseline = freshInventory();
    const planted: EffectivenessInventory = {
      ...baseline,
      venues: baseline.venues.map((row) => row.id === "validate-precision"
        ? { ...row, modules: ["M2"] as const }
        : row),
    };
    expect(validateEffectivenessInventory(planted)).toContain(
      "validate-precision: module claims do not match the live venue population",
    );
    expectRestoredBaseline();
  });

  it("fails a duplicate producer id and passes when the duplicate is removed", () => {
    const baseline = freshInventory();
    const duplicate = producer(baseline, "detector:app-router");
    const planted: EffectivenessInventory = {
      ...baseline,
      producers: [...baseline.producers, duplicate],
    };
    expect(validateEffectivenessInventory(planted)).toContain("detector:app-router: duplicate producer id");
    expectRestoredBaseline();
  });

  it("fails an orphaned implementation identity and passes when it is restored", () => {
    const baseline = freshInventory();
    const id = "detector:app-router";
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      implementations: row.implementations.map((item, index) => index === 0
        ? { ...item, symbol: "removedAppRouterProducer" }
        : item),
    }));
    expect(validateEffectivenessInventory(planted)).toContain(
      `${id}: orphaned implementation symbol src/detectors/app-router.ts#removedAppRouterProducer`,
    );
    expectRestoredBaseline();
  });

  it("fails a broken real-consumer proof and passes when it is restored", () => {
    const baseline = freshInventory();
    const id = "detector:app-router";
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      consumerPath: row.consumerPath.map((hop, index) => index === 0
        ? { ...hop, contains: "removedAppRouterConsumer" }
        : hop),
    }));
    expect(validateEffectivenessInventory(planted)).toContain(
      `${id}: consumer proof src/cli/static-detect.ts no longer contains "removedAppRouterConsumer"`,
    );
    expectRestoredBaseline();
  });

  it("fails a stale exemption after a real venue is assigned and passes when restored", () => {
    const baseline = freshInventory();
    const id = "detector:hook-deps";
    expect(producer(baseline, id)).toMatchObject({ venueIds: [], exemptionId: expect.any(String) });
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      venueIds: ["validate-precision"],
    }));
    expect(validateEffectivenessInventory(planted)).toContain(
      `${id}: stale exemption ${producer(baseline, id).exemptionId} remains after a scored venue was assigned`,
    );
    expectRestoredBaseline();
  });

  it("fails an incomplete structured exemption and passes when restored", () => {
    const baseline = freshInventory();
    const id = "exemption:m2-live-score";
    const planted: EffectivenessInventory = {
      ...baseline,
      exemptions: baseline.exemptions.map((row) => row.id === id ? { ...row, owner: "" } : row),
    };
    expect(validateEffectivenessInventory(planted)).toContain(`${id}: exemption metadata is incomplete`);
    expectRestoredBaseline();
  });

  it("fails a wrongly classified synthesizer and passes when it is restored", () => {
    const baseline = freshInventory();
    const id = "synthesizer:m2-apply-verify-results";
    const planted = withProducer(baseline, id, (row) => ({
      ...row,
      populationClass: "true-finding-producer",
    }));
    expect(validateEffectivenessInventory(planted)).toContain(
      `${id}: synthesizer implementation is wrongly classified as true-finding-producer`,
    );
    expectRestoredBaseline();
  });
});
