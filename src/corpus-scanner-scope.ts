import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import type { CorpusCacheableScanner, CorpusScannerObservation, CorpusScannerScope } from "./corpus-scanner-cache.js";

interface CorpusScannerScopeReceipt extends CorpusScannerScope {
  schema: 1;
  scanner: CorpusCacheableScanner;
  observation: CorpusScannerObservation;
}

export type CorpusScannerOwnedScope = CorpusScannerScope & { observation: CorpusScannerObservation };

export function digestObservedPaths(paths: readonly string[]): string {
  return createHash("sha256").update([...paths].sort().join("\0")).digest("hex");
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

export function isCorpusScannerOwnedScope(scope: Partial<CorpusScannerOwnedScope>, scanner: CorpusCacheableScanner): scope is CorpusScannerOwnedScope {
  const units = scope.unitsExamined;
  const observation = scope.observation;
  if (!Number.isInteger(units) || units! < 0 || typeof scope.description !== "string" || scope.description.length === 0 || !observation || observation.scanner !== scanner) return false;
  if (scanner !== "mutation-detect-only" && units === 0) return false;
  if (observation.scanner === "detect-static") {
    return observation.loadedSources.count === units
      && observation.loadedSources.pathsDigest.length > 0
      && observation.ancillary.productSources + observation.ancillary.configSources + observation.ancillary.testStorySources === units;
  }
  if (observation.scanner === "quality-scan") {
    return observation.productSources.count === units
      && observation.productSources.pathsDigest.length > 0
      && Number.isInteger(observation.jscpd.comparedLines)
      && observation.jscpd.comparedLines >= 0
      && stringArray(observation.knip.discovered)
      && stringArray(observation.knip.completed)
      && stringArray(observation.knip.reduced)
      && stringArray(observation.knip.incomplete);
  }
  return observation.testSources.count === units
    && observation.testSources.pathsDigest.length > 0
    && typeof observation.suiteSignals.packageManifest === "boolean"
    && typeof observation.suiteSignals.strykerConfig === "boolean"
    && (observation.suiteSignals.ancestorWorkspaceSuite === null || typeof observation.suiteSignals.ancestorWorkspaceSuite === "string")
    && stringArray(observation.suiteSignals.childWorkspaceSuites);
}

/** Write the examined scope from inside the scanner process that performed the work. */
export function writeCorpusScannerScope(
  path: string | undefined,
  scanner: CorpusCacheableScanner,
  scope: CorpusScannerOwnedScope,
): void {
  if (!path) return;
  if (!isCorpusScannerOwnedScope(scope, scanner)) {
    throw new Error(`${scanner}: cannot emit an incomplete or zero examined-scope receipt`);
  }
  if (scope.observation.scanner !== scanner) throw new Error(`${scanner}: examined-scope observation belongs to ${scope.observation.scanner}`);
  const receipt: CorpusScannerScopeReceipt = { schema: 1, scanner, ...scope };
  writeFileSync(path, `${JSON.stringify(receipt, null, 2)}\n`);
}

/** Read a scanner-owned receipt; a shared target census is deliberately not accepted. */
export function readCorpusScannerScope(path: string, scanner: CorpusCacheableScanner): CorpusScannerOwnedScope {
  const value = JSON.parse(readFileSync(path, "utf8")) as Partial<CorpusScannerScopeReceipt>;
  if (
    value.schema !== 1
    || value.scanner !== scanner
    || !Number.isInteger(value.unitsExamined)
    || value.unitsExamined! < 0
    || typeof value.description !== "string"
    || value.description.length === 0
    || !isCorpusScannerOwnedScope(value, scanner)
  ) {
    throw new Error(`${scanner}: scanner-owned examined-scope receipt is missing, mismatched, zero, or malformed`);
  }
  return { unitsExamined: value.unitsExamined, description: value.description, observation: value.observation } as CorpusScannerOwnedScope;
}
