import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  decideCorpusCacheRestore,
  rejectCorpusCacheTransport,
  validateCorpusCacheTransport,
  writeCorpusCacheTransport,
  type CorpusCacheTransportManifest,
} from "./corpus-cache-transport.js";

const source = (overrides: Partial<CorpusCacheTransportManifest> = {}): CorpusCacheTransportManifest => ({
  schema: 1,
  key: "corpus-phase-v3-Linux-shard1-100-1",
  event: "push",
  ref: "refs/heads/main",
  runId: "100",
  runAttempt: "1",
  headSha: "a".repeat(40),
  writtenAt: "2026-08-12T01:00:00.000Z",
  ...overrides,
});

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
    });
    expect(decision).toMatchObject({ accepted: true, reason: expect.stringContaining("trusted default-branch seed") });
    expect(decision.source).toMatchObject({ event: "push", ref: "refs/heads/main", runId: "100" });
  });

  it("rejects a cache written by a separate PR even when its key prefix and scanner inputs match", () => {
    const decision = decideCorpusCacheRestore(source({ event: "pull_request", ref: "refs/pull/199/merge", runId: "1990" }), {
      matchedKey: source().key,
      event: "pull_request",
      ref: "refs/pull/200/merge",
      runId: "2000",
      defaultRef: "refs/heads/main",
    });
    expect(decision.accepted).toBe(false);
    expect(decision.reason).toContain("untrusted cache scope");
  });

  it("accepts only the current run's PR cache on a retry and rejects a forged matched key", () => {
    const retry = source({ event: "pull_request", ref: "refs/pull/200/merge", runId: "2000" });
    expect(decideCorpusCacheRestore(retry, {
      matchedKey: retry.key,
      event: "pull_request",
      ref: retry.ref,
      runId: retry.runId,
      defaultRef: "refs/heads/main",
    }).accepted).toBe(true);
    expect(decideCorpusCacheRestore(retry, {
      matchedKey: "different-key",
      event: "pull_request",
      ref: retry.ref,
      runId: retry.runId,
      defaultRef: "refs/heads/main",
    }).reason).toContain("disagrees with provenance key");
  });

  it("visibly rejects missing/corrupt provenance and removes every restored artifact", () => {
    const dir = mkdtempSync(join(tmpdir(), "harvey-cache-transport-"));
    dirs.push(dir);
    mkdirSync(join(dir, "semgrep"));
    writeFileSync(join(dir, "semgrep", "artifact.json"), "untrusted");
    const current = { matchedKey: source().key, event: "pull_request", ref: "refs/pull/200/merge", runId: "2000", defaultRef: "refs/heads/main" };
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
    })).toMatchObject({ accepted: true, source: source() });
  });
});
