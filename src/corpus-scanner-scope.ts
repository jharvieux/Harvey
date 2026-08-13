import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import type { CorpusCacheableScanner, CorpusScannerObservation, CorpusScannerScope } from "./corpus-scanner-cache.js";

interface CorpusScannerScopeReceipt extends CorpusScannerScope {
  schema: 1;
  scanner: CorpusCacheableScanner;
  observation: CorpusScannerObservation;
}

type CorpusScannerOwnedScope = CorpusScannerScope & { observation: CorpusScannerObservation };

export function digestObservedPaths(paths: readonly string[]): string {
  return createHash("sha256").update([...paths].sort().join("\0")).digest("hex");
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function canonicalStringSet(value: unknown): value is string[] {
  return stringArray(value)
    && new Set(value).size === value.length
    && value.every((item, index) => index === 0 || value[index - 1]! < item);
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function sha256Digest(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function completeExplanation(value: unknown): value is string {
  return typeof value === "string" && value.trim().length >= 20;
}

export function isCorpusScannerOwnedScope(scope: Partial<CorpusScannerOwnedScope>, scanner: CorpusCacheableScanner): scope is CorpusScannerOwnedScope {
  const units = scope.unitsExamined;
  const observation = scope.observation;
  if (!Number.isInteger(units) || units! < 0 || typeof scope.description !== "string" || scope.description.length === 0 || !observation || observation.scanner !== scanner) return false;
  if (scanner !== "mutation-detect-only" && units === 0) return false;
  if (observation.scanner === "detect-static") {
    return nonNegativeInteger(observation.loadedSources?.count)
      && observation.loadedSources.count === units
      && sha256Digest(observation.loadedSources.pathsDigest)
      && nonNegativeInteger(observation.ancillary?.productSources)
      && nonNegativeInteger(observation.ancillary?.configSources)
      && nonNegativeInteger(observation.ancillary?.testStorySources)
      && observation.ancillary.productSources + observation.ancillary.configSources + observation.ancillary.testStorySources === units;
  }
  if (observation.scanner === "quality-scan") {
    if (!nonNegativeInteger(observation.productSources?.count)
      || observation.productSources.count !== units
      || !sha256Digest(observation.productSources.pathsDigest)
      || (observation.jscpd?.status !== "completed" && observation.jscpd?.status !== "incomplete")
      || !nonNegativeInteger(observation.jscpd.comparedLines)
      || !canonicalStringSet(observation.knip?.discovered)
      || !canonicalStringSet(observation.knip.completed)
      || !canonicalStringSet(observation.knip.reduced)
      || !canonicalStringSet(observation.knip.incomplete)
      || !nonNegativeInteger(observation.divergedClones?.securityPathSources)
      || typeof observation.divergedClones.wholeRepoEnabled !== "boolean"
      || !nonNegativeInteger(observation.divergedClones.complementSources)
      || observation.divergedClones.securityPathSources > units!) return false;
    const discovered = new Set(observation.knip.discovered);
    const completed = new Set(observation.knip.completed);
    const incomplete = new Set(observation.knip.incomplete);
    if (observation.knip.completed.some((scope) => incomplete.has(scope))
      || observation.knip.reduced.some((scope) => !completed.has(scope))
      || observation.knip.incomplete.some((scope) => !discovered.has(scope))
      || observation.knip.completed.some((scope) => !discovered.has(scope))
      || discovered.size !== completed.size + incomplete.size) return false;
    return observation.divergedClones.complementSources === (observation.divergedClones.wholeRepoEnabled
      ? units! - observation.divergedClones.securityPathSources
      : 0);
  }
  const mutationShapeIsComplete = nonNegativeInteger(observation.testSources?.count)
    && observation.testSources.count === units
    && sha256Digest(observation.testSources.pathsDigest)
    && typeof observation.suiteSignals?.packageManifest === "boolean"
    && typeof observation.suiteSignals.strykerConfig === "boolean"
    && (observation.suiteSignals.ancestorWorkspaceSuite === null || typeof observation.suiteSignals.ancestorWorkspaceSuite === "string")
    && canonicalStringSet(observation.suiteSignals.childWorkspaceSuites);
  if (!mutationShapeIsComplete) return false;
  if (units! > 0) return observation.zeroTestDisposition === undefined;
  const disposition = observation.zeroTestDisposition;
  return observation.testSources.pathsDigest === digestObservedPaths([])
    && observation.suiteSignals.strykerConfig === false
    && observation.suiteSignals.ancestorWorkspaceSuite === null
    && observation.suiteSignals.childWorkspaceSuites.length === 0
    && (disposition?.status === "no-suite" || disposition?.status === "not-applicable")
    && completeExplanation(disposition.reason)
    && completeExplanation(disposition.provenance)
    && completeExplanation(disposition.falsifier);
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
