import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CORPUS_CACHE_MAX_PAYLOAD_BYTES,
  corpusCacheOwnershipScope,
  corpusCacheScopeSha256,
  corpusCacheTransportKey,
  decideCorpusCacheRestore,
  rejectCorpusCacheTransport,
  validateCorpusCacheTransport,
  writeCorpusCacheTransport,
  type CorpusCacheOwnershipScope,
  type CorpusCacheTransportManifest,
} from "./corpus-cache-transport.js";
import { EXTERNAL_CORPUS } from "./scan/external-corpus.js";
import { compareUtf8Bytes, TARGET_SCAN_SECONDS } from "./scan/corpus-shards.js";

const targets = EXTERNAL_CORPUS.map((target) => ({
  slug: target.slug,
  repo: target.repo,
  commit: target.commit,
  vendoredSubtrees: target.vendoredSubtrees,
  scanRoots: target.scanRoots,
  installFlags: target.m8?.installFlags,
}));
const scope = (
  namespace = 1,
  input: Parameters<typeof corpusCacheOwnershipScope>[0] = targets,
  weights: Readonly<Record<string, number>> = TARGET_SCAN_SECONDS,
): CorpusCacheOwnershipScope => corpusCacheOwnershipScope(input, namespace, weights);
const EMPTY_INVENTORY_SHA = createHash("sha256").update("[]").digest("hex");

function stableUtf8(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableUtf8).join(",")}]`;
  if (value && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort(compareUtf8Bytes).map((key) => `${JSON.stringify(key)}:${stableUtf8(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

const source = (overrides: Partial<CorpusCacheTransportManifest> = {}, namespace = 1): CorpusCacheTransportManifest => {
  const ownership = overrides.scope ?? scope(namespace);
  const scopeSha256 = overrides.scopeSha256 ?? corpusCacheScopeSha256(ownership);
  const manifest = {
    schema: 4 as const,
    family: (overrides.family ?? "main") as "run" | "main",
    event: "push",
    ref: "refs/heads/main",
    runId: "100",
    runAttempt: "1",
    headSha: "a".repeat(40),
    writtenAt: "2026-08-22T01:00:00.000Z",
    scope: ownership,
    scopeSha256,
    payload: { bytes: 0, files: 0, inventorySha256: EMPTY_INVENTORY_SHA, classes: [], maxBytes: CORPUS_CACHE_MAX_PAYLOAD_BYTES, symlinks: 0 as const },
    ...overrides,
  };
  return {
    ...manifest,
    key: overrides.key ?? corpusCacheTransportKey({ family: manifest.family, platform: "Linux", namespace: String(namespace), scopeSha256: manifest.scopeSha256, runId: manifest.runId, runAttempt: manifest.runAttempt, headSha: manifest.headSha }),
  };
};

const current = (manifest: CorpusCacheTransportManifest, overrides: Partial<Parameters<typeof decideCorpusCacheRestore>[1]> = {}): Parameters<typeof decideCorpusCacheRestore>[1] => ({
  matchedKey: manifest.key,
  event: "pull_request",
  ref: "refs/pull/200/merge",
  runId: "2000",
  defaultRef: "refs/heads/main",
  platform: "Linux",
  namespace: String(manifest.scope.namespace),
  headSha: "b".repeat(40),
  scope: manifest.scope,
  ...overrides,
});

describe("ownership-bound corpus cache transport", () => {
  const dirs: string[] = [];
  const temporary = (label: string): string => {
    const dir = mkdtempSync(join(tmpdir(), `harvey-${label}-`));
    dirs.push(dir);
    return dir;
  };
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("accepts only a same-scope trusted-main seed or exact current-run retry", () => {
    const main = source();
    expect(decideCorpusCacheRestore(main, current(main))).toMatchObject({ accepted: true, reason: expect.stringContaining("trusted default-branch") });

    const retry = source({ family: "run", event: "pull_request", ref: "refs/pull/200/merge", runId: "2000" });
    expect(decideCorpusCacheRestore(retry, current(retry, { ref: retry.ref, runId: retry.runId, headSha: retry.headSha })).accepted).toBe(true);

    const otherPr = source({ family: "run", event: "pull_request", ref: "refs/pull/199/merge", runId: "1990" });
    expect(decideCorpusCacheRestore(otherPr, current(otherPr)).reason).toContain("untrusted cache scope");
    const nonDefault = source({ event: "push", ref: "refs/heads/feature" });
    expect(decideCorpusCacheRestore(nonDefault, current(nonDefault)).accepted).toBe(false);
  });

  it("rejects the old/shared ownership class even when platform and numeric namespace match", () => {
    const oldOwners = targets.map((target) => target.slug === "tanstack-com" ? { ...target, commit: "f".repeat(40) } : target);
    const stale = source({}, 3);
    const expected = scope(3, oldOwners);
    expect(corpusCacheScopeSha256(stale.scope)).not.toBe(corpusCacheScopeSha256(expected));
    expect(decideCorpusCacheRestore(stale, current(stale, { scope: expected })).reason).toContain("is not current scope");
  });

  it("rotates every owner scope when the complete weight table changes without moving membership", () => {
    const changedWeights = { ...TARGET_SCAN_SECONDS, carbon: 1410 };
    const before = [1, 2, 3, 4].map((namespace) => scope(namespace));
    const after = [1, 2, 3, 4].map((namespace) => scope(namespace, targets, changedWeights));
    expect(after.map((ownership) => ownership.partitions)).toEqual(before.map((ownership) => ownership.partitions));
    after.forEach((ownership, index) => {
      expect(corpusCacheScopeSha256(ownership)).not.toBe(corpusCacheScopeSha256(before[index]!));
      expect(ownership.weights.find((row) => row.slug === "carbon")?.seconds).toBe(1410);
    });

    const stale = source({}, 4);
    expect(decideCorpusCacheRestore(stale, current(stale, { scope: after[3]! })).reason).toContain("is not current scope");
  });

  it("uses one POSIX UTF-8 order for scope construction and scope hashing", () => {
    const trapTargets = [
      { slug: "path/a.ts", repo: "owner/a", commit: "a".repeat(40), scanRoots: { "path/a.ts": "a", "path/\u{10000}.ts": "astral", "path/\uE000.ts": "private", "path/A.ts": "A" } },
      { slug: "path/\u{10000}.ts", repo: "owner/astral", commit: "b".repeat(40) },
      { slug: "path/\uE000.ts", repo: "owner/private", commit: "c".repeat(40) },
      { slug: "path/A.ts", repo: "owner/A", commit: "d".repeat(40) },
    ];
    const trapWeights = Object.fromEntries(trapTargets.map((target) => [target.slug, 1]));
    const ownership = scope(1, trapTargets, trapWeights);
    const expectedOrder = ["path/A.ts", "path/a.ts", "path/\uE000.ts", "path/\u{10000}.ts"];
    expect(ownership.population.map((target) => target.slug)).toEqual(expectedOrder);
    expect(ownership.weights.map((row) => row.slug)).toEqual(expectedOrder);
    expect(Object.keys(ownership.population.find((target) => target.slug === "path/a.ts")!.scanRoots)).toEqual(expectedOrder);
    expect(corpusCacheScopeSha256(ownership)).toBe(createHash("sha256").update(stableUtf8(ownership)).digest("hex"));
  });

  it("fails closed on incomplete, duplicate, unknown, or repartitioned ownership", () => {
    expect(() => corpusCacheOwnershipScope([...targets, targets[0]!], 1)).toThrow("duplicate target slug");
    const canonical = source({}, 2);
    const variants = [
      corpusCacheOwnershipScope(targets.slice(1), 2),
      corpusCacheOwnershipScope([...targets, { slug: "unknown", repo: "owner/unknown", commit: "f".repeat(40) }], 2),
      { ...canonical.scope, partitions: canonical.scope.partitions.map((row, index) => index === 0 ? { ...row, targets: row.targets.slice(1) } : row) },
      { ...canonical.scope, owners: [...canonical.scope.owners, canonical.scope.partitions[0]!.targets[0]!] },
    ];
    for (const ownership of variants) {
      const stale = source({ scope: ownership, scopeSha256: corpusCacheScopeSha256(ownership) }, 2);
      expect(decideCorpusCacheRestore(stale, current(stale, { scope: canonical.scope })).accepted).toBe(false);
    }
  });

  it("rejects cross-shard namespace use and forged matched keys", () => {
    const shard1 = source({}, 1);
    expect(decideCorpusCacheRestore(shard1, current(shard1, { namespace: "2", scope: scope(2) })).reason).toContain("shard2");
    expect(decideCorpusCacheRestore(shard1, current(shard1, { matchedKey: "different-key" })).reason).toContain("disagrees with provenance key");
  });

  it("round-trips every regular byte with a file/content/class inventory", () => {
    const dir = temporary("cache-transport-roundtrip");
    mkdirSync(join(dir, "semgrep-family-timeout-telemetry"), { recursive: true });
    mkdirSync(join(dir, "dependency-preparation", "receipts"), { recursive: true });
    writeFileSync(join(dir, "semgrep-family-timeout-telemetry", "raw.json"), "raw evidence\n");
    writeFileSync(join(dir, "dependency-preparation", "receipts", "one.json"), "{}\n");
    const written = writeCorpusCacheTransport(dir, source());
    expect(written.payload).toMatchObject({ bytes: 16, files: 2, symlinks: 0 });
    expect(written.payload.classes.map((row) => row.name)).toEqual(["dependency-preparation", "semgrep-family-timeout-telemetry"]);
    expect(validateCorpusCacheTransport(dir, current(written))).toMatchObject({ accepted: true });
  });

  it("detects undercount, omission, rename, and same-size content mutation", () => {
    const dir = temporary("cache-transport-inventory");
    writeFileSync(join(dir, "artifact.json"), "alpha\n");
    const written = writeCorpusCacheTransport(dir, source());
    writeFileSync(join(dir, "artifact.json"), "bravo\n");
    expect(validateCorpusCacheTransport(dir, current(written)).reason).toContain("inventory");

    writeFileSync(join(dir, "artifact.json"), "alpha\n");
    const fresh = writeCorpusCacheTransport(dir, source());
    renameSync(join(dir, "artifact.json"), join(dir, "renamed.json"));
    expect(validateCorpusCacheTransport(dir, current(fresh)).reason).toContain("inventory");

    const forged = { ...fresh, payload: { ...fresh.payload, bytes: fresh.payload.bytes - 1 } };
    writeFileSync(join(dir, "transport-provenance.json"), `${JSON.stringify(forged)}\n`);
    expect(validateCorpusCacheTransport(dir, current(forged)).reason).toMatch(/class census|inventory/);
  });

  it("refuses oversize, symlink, special-file, and pnpm path-bound payloads", () => {
    const oversized = temporary("cache-transport-oversized");
    writeFileSync(join(oversized, "sparse"), "");
    truncateSync(join(oversized, "sparse"), CORPUS_CACHE_MAX_PAYLOAD_BYTES + 1);
    expect(() => writeCorpusCacheTransport(oversized, source())).toThrow(`${CORPUS_CACHE_MAX_PAYLOAD_BYTES}-byte ceiling`);

    const linked = temporary("cache-transport-linked");
    writeFileSync(join(linked, "content"), "portable\n");
    symlinkSync(join(linked, "content"), join(linked, "link"));
    expect(() => writeCorpusCacheTransport(linked, source())).toThrow("path-bound link");

    const special = temporary("cache-transport-special");
    execFileSync("mkfifo", [join(special, "pipe")]);
    expect(() => writeCorpusCacheTransport(special, source())).toThrow("special file");

    const pnpm = temporary("cache-transport-pnpm");
    mkdirSync(join(pnpm, "dependency-preparation", "stores", "linux-x64", "pnpm", "v10", "projects"), { recursive: true });
    writeFileSync(join(pnpm, "dependency-preparation", "stores", "linux-x64", "pnpm", "v10", "projects", "root"), "/tmp/checkout\n");
    expect(() => writeCorpusCacheTransport(pnpm, source())).toThrow("path-bound pnpm data");
  });

  it("rejects legacy schema/key, corrupt provenance, and a changed scope claim", () => {
    const dir = temporary("cache-transport-corrupt");
    writeFileSync(join(dir, "transport-provenance.json"), JSON.stringify({ ...source(), schema: 3, key: source().key.replace("-v6-", "-v5-") }));
    expect(validateCorpusCacheTransport(dir, current(source())).reason).toContain("unsupported transport provenance schema");
    writeFileSync(join(dir, "transport-provenance.json"), "{not-json");
    expect(validateCorpusCacheTransport(dir, current(source())).reason).toContain("invalid transport provenance");

    const changed = source();
    changed.scope.population[0]!.commit = "e".repeat(40);
    writeFileSync(join(dir, "transport-provenance.json"), `${JSON.stringify(changed)}\n`);
    expect(validateCorpusCacheTransport(dir, current(source())).reason).toContain("scope digest disagrees");
  });

  it("treats a miss as recomputable and clears only the rejected namespace", () => {
    const parent = temporary("cache-transport-local-reject");
    const shard1 = join(parent, "shard1");
    const shard2 = join(parent, "shard2");
    mkdirSync(shard1);
    mkdirSync(shard2);
    writeFileSync(join(shard1, "untrusted"), "bad\n");
    writeFileSync(join(shard2, "trusted"), "good\n");
    expect(validateCorpusCacheTransport(shard1, current(source(), { matchedKey: "" }))).toMatchObject({ accepted: true, reason: expect.stringContaining("miss") });
    rejectCorpusCacheTransport(shard1);
    expect(existsSync(join(shard1, "untrusted"))).toBe(false);
    expect(existsSync(join(shard2, "trusted"))).toBe(true);
  });

  it("fails key construction on invalid identity fields", () => {
    const valid = source();
    expect(() => corpusCacheTransportKey({ family: "main", platform: "Linux", namespace: "1", scopeSha256: "bad", runId: "1", runAttempt: "1", headSha: valid.headSha })).toThrow("scopeSha256");
    expect(() => corpusCacheTransportKey({ family: "main", platform: "Linux", namespace: "1", scopeSha256: valid.scopeSha256, runId: "1", runAttempt: "1", headSha: "forged" })).toThrow("headSha");
  });
});
