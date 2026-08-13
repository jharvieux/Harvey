import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CORPUS_CACHE_MAX_PAYLOAD_BYTES,
  corpusCacheTransportKey,
  decideCorpusCacheRestore,
  rejectCorpusCacheTransport,
  validateCorpusCacheTransport,
  writeCorpusCacheTransport,
  type CorpusCacheTransportManifest,
} from "./corpus-cache-transport.js";

const source = (overrides: Partial<CorpusCacheTransportManifest> = {}): CorpusCacheTransportManifest => {
  const manifest = {
    schema: 3 as const,
    family: (overrides.family ?? "main") as "run" | "main",
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
    key: overrides.key ?? corpusCacheTransportKey({ family: manifest.family, platform: "Linux", namespace: "1", runId: manifest.runId, runAttempt: manifest.runAttempt, headSha: manifest.headSha }),
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
});
