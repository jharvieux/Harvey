import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { readEntriesSafe } from "./fs-walk.js";

export interface CorpusCacheSeedReadiness {
  component: string;
  status: "ready" | "missing" | "incompatible" | "invalid" | "unavailable";
  key?: string;
  path?: string;
  reason: string;
}

function identityComponents(value: unknown, prefix = "identity"): Map<string, string> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return new Map(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
      .flatMap(([name, item]) => [...identityComponents(item, `${prefix}.${name}`)]));
  }
  return new Map([[prefix, JSON.stringify(value)]]);
}

/** Readiness uses the consumer's exact address and validator; nearby artifacts explain misses only. */
export function inspectCorpusCacheSeed(options: {
  component: string;
  key: string;
  path: string;
  identity: unknown;
  acceptsCandidate: (value: Record<string, unknown>) => boolean;
  validate: (text: string) => unknown;
}): CorpusCacheSeedReadiness {
  const { component, key, path } = options;
  if (existsSync(path)) {
    try {
      options.validate(readFileSync(path, "utf8"));
      return { component, key, path, status: "ready", reason: "complete matching artifact validated by its execution consumer" };
    } catch (error) {
      return { component, key, path, status: "invalid", reason: error instanceof Error ? error.message : String(error) };
    }
  }

  const current = identityComponents(options.identity);
  let closest: { changed: string[]; matches: number } | undefined;
  const entries = existsSync(dirname(path)) ? readEntriesSafe(dirname(path)).entries : [];
  for (const entry of entries.filter((entry) => !entry.isDirectory && entry.name.endsWith(".json"))) {
    try {
      const value: unknown = JSON.parse(readFileSync(join(dirname(path), entry.name), "utf8"));
      if (!value || typeof value !== "object" || Array.isArray(value) || !options.acceptsCandidate(value as Record<string, unknown>)) continue;
      const prior = identityComponents((value as Record<string, unknown>).identity);
      const names = [...new Set([...current.keys(), ...prior.keys()])].sort();
      const changed = names.filter((name) => current.get(name) !== prior.get(name));
      const matches = names.length - changed.length;
      if (changed.length > 0 && (!closest || matches > closest.matches)) closest = { changed, matches };
    } catch {
      // A malformed nearby file is not a candidate seed. An exact-address file is checked above.
    }
  }
  return {
    component, key, path,
    status: closest ? "incompatible" : "missing",
    reason: closest
      ? `no matching artifact; closest prior identity differs in ${closest.changed.join(", ")}`
      : "no complete artifact at the required content address",
  };
}

/** A successful preflight binds addresses, never observations or freshly written cache misses. */
export function assertCorpusCachePreflight(target: string, seeds: readonly CorpusCacheSeedReadiness[]): string {
  const failures = seeds.filter((seed) => seed.status !== "ready");
  if (failures.length > 0 || seeds.length === 0) {
    throw new Error([
      `${target}: forced-cold cache preflight rejected before scan execution`,
      ...failures.map((seed) => `  ${seed.component}: ${seed.status}: ${seed.reason}${seed.path ? `; required artifact ${seed.path}` : ""}`),
      ...(seeds.length === 0 ? ["  no eligible cache comparisons were planned"] : []),
      "Seed locally by running the same corpus-drift invocation without --force-cold-cache, then rerun with --force-cold-cache using the same cache directory, immutable Harvey source, target pins/tree, runtime/tools, configuration and external-state mode. Keep the same registry snapshot in reuse mode for both commands.",
      "A trusted-main snapshot-mode transport is not a matching live-verify seed. Another manual run's artifacts are not an accepted hosted transport. Live provider checks and dependency installation are not cache-equivalence proof.",
    ].join("\n"));
  }
  return createHash("sha256").update(JSON.stringify(seeds.map(({ component, key }) => ({ component, key })))).digest("hex");
}
