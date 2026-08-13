import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CORPUS_CACHE_MAX_PAYLOAD_BYTES,
  corpusCacheTransportKey,
  decideCorpusCacheRestore,
  mergeCorpusCacheTransports,
  rejectCorpusCacheTransport,
  validateCorpusCacheTransport,
  writeCorpusCacheTransport,
  type CorpusCacheTransportManifest,
} from "./corpus-cache-transport.js";

const source = (overrides: Partial<CorpusCacheTransportManifest> = {}): CorpusCacheTransportManifest => {
  const manifest = {
    schema: 4 as const,
    family: overrides.family ?? "main",
    event: "push",
    ref: "refs/heads/main",
    runId: "100",
    runAttempt: "1",
    headSha: "a".repeat(40),
    writtenAt: "2026-08-12T01:00:00.000Z",
    payload: { bytes: 0, maxBytes: CORPUS_CACHE_MAX_PAYLOAD_BYTES, symlinks: 0 as const },
    ...overrides,
  };
  return {
    ...manifest,
    key: overrides.key ?? corpusCacheTransportKey({ family: manifest.family, platform: "Linux", namespace: "1", runId: manifest.runId, runAttempt: manifest.runAttempt, headSha: manifest.headSha, ...(manifest.benchmarkSeed === undefined ? {} : { benchmarkSeed: manifest.benchmarkSeed }) }),
  };
};

describe("corpus cache transport scope across refs (#1867)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  it("accepts a main-visible seed in a different PR ref and records its exact provenance", () => {
    const decision = decideCorpusCacheRestore(source(), {
      matchedKey: source().key,
      event: "pull_request",
      ref: "refs/pull/200/merge",
      runId: "2000",
    defaultRef: "refs/heads/main",
    platform: "Linux",
    namespace: "1",
    headSha: "b".repeat(40),
    });
    expect(decision).toMatchObject({ accepted: true, reason: expect.stringContaining("trusted default-branch seed") });
    expect(decision.source).toMatchObject({ event: "push", ref: "refs/heads/main", runId: "100" });
  });

  it("rejects a cache written by a separate PR even when its key prefix and scanner inputs match", () => {
    const otherPr = source({ family: "run", event: "pull_request", ref: "refs/pull/199/merge", runId: "1990" });
    const decision = decideCorpusCacheRestore(otherPr, {
      matchedKey: otherPr.key,
      event: "pull_request",
      ref: "refs/pull/200/merge",
      runId: "2000",
      defaultRef: "refs/heads/main",
      platform: "Linux",
      namespace: "1",
      headSha: "b".repeat(40),
    });
    expect(decision.accepted).toBe(false);
    expect(decision.reason).toContain("untrusted cache scope");
  });

  it("accepts only the current run's PR cache on a retry and rejects a forged matched key", () => {
    const retry = source({ family: "run", event: "pull_request", ref: "refs/pull/200/merge", runId: "2000" });
    expect(decideCorpusCacheRestore(retry, {
      matchedKey: retry.key,
      event: "pull_request",
      ref: retry.ref,
      runId: retry.runId,
      defaultRef: "refs/heads/main",
      platform: "Linux",
      namespace: "1",
      headSha: retry.headSha,
    }).accepted).toBe(true);
    expect(decideCorpusCacheRestore(retry, {
      matchedKey: "different-key",
      event: "pull_request",
      ref: retry.ref,
      runId: retry.runId,
      defaultRef: "refs/heads/main",
      platform: "Linux",
      namespace: "1",
      headSha: retry.headSha,
    }).reason).toContain("disagrees with provenance key");
  });

  it("visibly rejects missing/corrupt provenance and removes every restored artifact", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-cache-transport-"));
    dirs.push(dir);
    mkdirSync(join(dir, "semgrep"));
    writeFileSync(join(dir, "semgrep", "artifact.json"), "untrusted");
    const current = { matchedKey: source().key, event: "pull_request", ref: "refs/pull/200/merge", runId: "2000", defaultRef: "refs/heads/main", platform: "Linux", namespace: "1", headSha: "b".repeat(40) };
    expect(validateCorpusCacheTransport(dir, current).reason).toContain("has no transport-provenance.json");
    writeFileSync(join(dir, "transport-provenance.json"), "{not-json");
    expect(validateCorpusCacheTransport(dir, current).reason).toContain("invalid transport provenance");
    rejectCorpusCacheTransport(dir);
    expect(existsSync(join(dir, "semgrep", "artifact.json"))).toBe(false);
  });

  it("round-trips a provenance manifest before accepting transported artifacts", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-cache-transport-roundtrip-"));
    dirs.push(dir);
    writeCorpusCacheTransport(dir, source());
    expect(validateCorpusCacheTransport(dir, {
      matchedKey: source().key,
      event: "pull_request",
      ref: "refs/pull/200/merge",
      runId: "2000",
      defaultRef: "refs/heads/main",
      platform: "Linux",
      namespace: "1",
      headSha: "b".repeat(40),
    })).toMatchObject({ accepted: true, source: source() });
  });

  it("refuses to author a transport containing links or exceeding the payload ceiling", () => {
    const linked = mkdtempSync(join(tmpdir(), "harvey-cache-transport-linked-"));
    const oversized = mkdtempSync(join(tmpdir(), "harvey-cache-transport-oversized-"));
    dirs.push(linked, oversized);
    writeFileSync(join(linked, "content"), "portable bytes\n");
    symlinkSync(join(linked, "content"), join(linked, "path-bound-link"));
    expect(() => writeCorpusCacheTransport(linked, source())).toThrow("path-bound link");

    const sparse = join(oversized, "sparse-payload");
    writeFileSync(sparse, "");
    truncateSync(sparse, CORPUS_CACHE_MAX_PAYLOAD_BYTES + 1);
    expect(() => writeCorpusCacheTransport(oversized, source())).toThrow(`${CORPUS_CACHE_MAX_PAYLOAD_BYTES}-byte ceiling`);
  });

  it("rejects a shard2/3 namespace absence instead of falling back to shard1", () => {
    for (const namespace of ["2", "3"]) {
      const decision = decideCorpusCacheRestore(source(), {
        matchedKey: source().key,
        event: "pull_request",
        ref: "refs/pull/200/merge",
        runId: "2000",
        defaultRef: "refs/heads/main",
        platform: "Linux",
        namespace,
        headSha: "b".repeat(40),
      });
      expect(decision).toMatchObject({ accepted: false, reason: expect.stringContaining(`shard${namespace}`) });
    }
  });

  it("rejects forged and mismatched head SHA claims", () => {
    expect(() => corpusCacheTransportKey({ family: "main", platform: "Linux", namespace: "1", runId: "100", runAttempt: "1", headSha: "forged" })).toThrow("headSha");
    const forged = source({ headSha: "b".repeat(40), key: source().key });
    const dir = mkdtempSync(join(tmpdir(), "harvey-cache-transport-forged-"));
    dirs.push(dir);
    writeFileSync(join(dir, "transport-provenance.json"), `${JSON.stringify(forged)}\n`);
    expect(validateCorpusCacheTransport(dir, {
      matchedKey: forged.key,
      event: "pull_request",
      ref: "refs/pull/200/merge",
      runId: "2000",
      defaultRef: "refs/heads/main",
      platform: "Linux",
      namespace: "1",
      headSha: "c".repeat(40),
    }).reason).toContain("key disagrees");

    const retry = source({
      event: "pull_request",
      ref: "refs/pull/200/merge",
      runId: "2000",
      family: "run",
      key: corpusCacheTransportKey({ family: "run", platform: "Linux", namespace: "1", runId: "2000", runAttempt: "1", headSha: "a".repeat(40) }),
    });
    expect(decideCorpusCacheRestore(retry, {
      matchedKey: retry.key,
      event: "pull_request",
      ref: retry.ref,
      runId: retry.runId,
      defaultRef: "refs/heads/main",
      platform: "Linux",
      namespace: "1",
      headSha: "c".repeat(40),
    }).accepted).toBe(false);
  });

  it("accepts a cross-run benchmark transport only for the exact seed, ref, and head", () => {
    const benchmark = source({
      family: "benchmark",
      event: "workflow_dispatch",
      ref: "refs/heads/feature/benchmark",
      runId: "3000",
      headSha: "b".repeat(40),
      benchmarkSeed: "cohort-2026-08-12",
    });
    const current = {
      matchedKey: benchmark.key,
      event: "workflow_dispatch",
      ref: benchmark.ref,
      runId: "3001",
      defaultRef: "refs/heads/main",
      platform: "Linux",
      namespace: "1",
      headSha: benchmark.headSha,
      benchmarkSeed: benchmark.benchmarkSeed,
    };
    expect(decideCorpusCacheRestore(benchmark, current)).toMatchObject({ accepted: true, reason: expect.stringContaining("exact benchmark seed") });
    expect(decideCorpusCacheRestore(benchmark, { ...current, benchmarkSeed: "other" }).accepted).toBe(false);
    expect(decideCorpusCacheRestore(benchmark, { ...current, headSha: "c".repeat(40) }).accepted).toBe(false);
    expect(decideCorpusCacheRestore(benchmark, { ...current, ref: "refs/heads/other" }).accepted).toBe(false);
  });

  it("merges all old shard namespaces by content address so a target moving into a fourth shard retains identical evidence", () => {
    const seed = "three-to-four-seed";
    const headSha = "d".repeat(40);
    const artifactPath = `corpus-scanners/detect-static/${"1".repeat(64)}.json`;
    const artifact = `${JSON.stringify({ findings: [{ id: "moved-target" }], scope: { unitsExamined: 7 } })}\n`;
    const sources = ["1", "2", "3"].map((namespace) => {
      const dir = mkdtempSync(join(tmpdir(), `harvey-cache-seed-${namespace}-`));
      dirs.push(dir);
      if (namespace === "2") {
        mkdirSync(join(dir, "corpus-scanners", "detect-static"), { recursive: true });
        writeFileSync(join(dir, artifactPath), artifact);
      }
      const manifest = source({
        family: "benchmark",
        event: "workflow_dispatch",
        ref: "refs/heads/feature/benchmark",
        runId: `40${namespace}`,
        headSha,
        benchmarkSeed: seed,
        key: corpusCacheTransportKey({ family: "benchmark", platform: "Linux", namespace, runId: `40${namespace}`, runAttempt: "1", headSha, benchmarkSeed: seed }),
      });
      const written = writeCorpusCacheTransport(dir, manifest);
      return { dir, namespace, matchedKey: written.key };
    });
    const destination = mkdtempSync(join(tmpdir(), "harvey-cache-merged-"));
    dirs.push(destination);
    const receipt = mergeCorpusCacheTransports({
      sources,
      destination,
      current: {
        event: "workflow_dispatch",
        ref: "refs/heads/feature/benchmark",
        runId: "5000",
        defaultRef: "refs/heads/main",
        platform: "Linux",
        headSha,
        benchmarkSeed: seed,
      },
      requiredNamespaces: ["1", "2", "3"],
    });
    expect(receipt.sources.map((row) => row.namespace)).toEqual(["1", "2", "3"]);
    expect(receipt.files.map((row) => row.path)).toContain(artifactPath);
    expect(readFileSync(join(destination, artifactPath), "utf8")).toBe(artifact);
    expect(JSON.parse(readFileSync(join(destination, artifactPath), "utf8"))).toEqual({ findings: [{ id: "moved-target" }], scope: { unitsExamined: 7 } });
    expect(receipt.conflicts).toBe(0);
  });

  it("fails loud on missing namespaces, conflicting duplicate bytes, and non-content-addressed paths", () => {
    const seed = "falsifier-seed";
    const headSha = "e".repeat(40);
    const artifactPath = `corpus-scanners/detect-static/${"2".repeat(64)}.json`;
    const make = (namespace: string, body: string, path = artifactPath) => {
      const dir = mkdtempSync(join(tmpdir(), `harvey-cache-falsifier-${namespace}-`));
      dirs.push(dir);
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), body);
      const manifest = source({
        family: "benchmark",
        event: "workflow_dispatch",
        ref: "refs/heads/feature/benchmark",
        runId: `60${namespace}`,
        headSha,
        benchmarkSeed: seed,
        key: corpusCacheTransportKey({ family: "benchmark", platform: "Linux", namespace, runId: `60${namespace}`, runAttempt: "1", headSha, benchmarkSeed: seed }),
      });
      return { dir, namespace, matchedKey: writeCorpusCacheTransport(dir, manifest).key };
    };
    const current = { event: "workflow_dispatch", ref: "refs/heads/feature/benchmark", runId: "7000", defaultRef: "refs/heads/main", platform: "Linux", headSha, benchmarkSeed: seed };
    const one = make("1", "one");
    expect(() => mergeCorpusCacheTransports({ sources: [one], destination: temporaryDestination(), current, requiredNamespaces: ["1", "2"] })).toThrow(/missing 2/);

    const two = make("2", "two");
    expect(() => mergeCorpusCacheTransports({ sources: [one, two], destination: temporaryDestination(), current, requiredNamespaces: ["1", "2"] })).toThrow(/conflict/);

    const unknown = make("3", "unknown", "mutable-pointer.json");
    expect(() => mergeCorpusCacheTransports({ sources: [unknown], destination: temporaryDestination(), current, requiredNamespaces: ["3"] })).toThrow(/non-content-addressed path/);
  });

  function temporaryDestination(): string {
    const dir = mkdtempSync(join(tmpdir(), "harvey-cache-merge-destination-"));
    dirs.push(dir);
    return dir;
  }
});
