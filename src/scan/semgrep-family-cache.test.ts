import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertSemgrepFamilyPlan,
  assertSemgrepFamilyVerification,
  buildSemgrepCommandSemanticReceipt,
  canonicalizeOwnedSemgrepOutput,
  canonicalizeSemgrepOutput,
  discoverLocalSemgrepFamilies,
  executeSemgrepFamily,
  mergeSemgrepFamilyOutputs,
  localSemgrepConfigYardstick,
  rejectUnregisteredSemgrepFamilyArtifacts,
  type SemgrepFamily,
  type SemgrepFamilyCacheOptions,
  type SemgrepFamilyRecord,
  type SemgrepFamilyExecutionReceipt,
  type SemgrepCommandSemanticReceipt,
} from "./semgrep-family-cache.js";
import type { SemgrepOutput } from "./semgrep.js";
import { canonicalizeSemgrepTime, SemgrepTimeoutTelemetryError } from "./semgrep-time.js";

const output = (id: string, path = "src/route.ts"): SemgrepOutput => ({
  results: [{ check_id: id, path, start: { line: 1 }, extra: { message: id, severity: "WARNING" } }],
  errors: [],
  paths: { scanned: [path], skipped: [] },
  time: { rules: [id], fixpoint_timeouts: [] },
});

function semanticTimeout() {
  return {
    error_type: "Fixpoint timeout", severity: "warn",
    message: "Fixpoint timeout while performing taint analysis at src/route.ts:7:3 [rules: 1, first: auth]",
    location: { path: "src/route.ts", start: { line: 7, col: 4, offset: 90 }, end: { line: 7, col: 8, offset: 94 } },
  };
}

function stableFixture(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableFixture).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stableFixture(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function executed(family: SemgrepFamily, value: SemgrepOutput): { output: SemgrepOutput; execution: SemgrepFamilyExecutionReceipt } {
  const loadedRuleIds = [...new Set((value.time?.rules ?? []) as string[])].sort();
  const rawTimeouts = canonicalizeSemgrepTime(value.time, loadedRuleIds).fixpoint_timeouts;
  const configured = parseYaml(readFileSync(family.configPath, "utf8")) as { rules?: Array<{ id?: string; mode?: string }> };
  const ownedTaintRuleIds = (configured.rules ?? []).filter((rule) => rule.mode === "taint" && typeof rule.id === "string").map((rule) => rule.id!);
  const loadedTaintRuleIds = loadedRuleIds.filter((id) => ownedTaintRuleIds.includes(id));
  const taintCoverage = rawTimeouts.length > 0 ? "not-assessed" as const : "no-timeout-observed" as const;
  const semantic = {
    argv: ["semgrep", "--config", family.configPath], loadedRuleIds,
    resultCount: value.results?.length ?? 0,
    resultsSha256: createHash("sha256").update(stableFixture(value.results ?? [])).digest("hex"),
    scanned: value.paths?.scanned ?? [], skipped: value.paths?.skipped ?? [], skippedRules: value.skipped_rules ?? [],
    errors: value.errors ?? [], loadedTaintRuleIds, taintCoverage,
  };
  const attempt = { status: "succeeded" as const, attempt: 1, ...semantic, semanticSha256: createHash("sha256").update(stableFixture(semantic)).digest("hex") };
  const configSha256 = createHash("sha256").update(readFileSync(family.configPath)).digest("hex");
  const ownedRuleIds = [...new Set([family.id, ...loadedRuleIds])].sort();
  return { output: value, execution: {
    ordinal: 0, id: family.id, familyId: family.id, sourceKind: "local-config", sourceId: family.id,
    configSha256, sourceConfigSha256: configSha256, ruleIds: ownedRuleIds, ownedRuleIds, ownedTaintRuleIds,
    loadedRuleIds, loadedTaintRuleIds, taintCoverage, excludedRuleIds: [], argv: semantic.argv, topology: "single-command-v1",
    mergeAlgorithm: "single-command-v1", partitions: [], verification: "single", status: "succeeded", attempts: [attempt],
  } };
}

describe("Semgrep family cache and reassembly (#1869)", () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((dir) => rmSync(dir, { recursive: true, force: true })));

  const fixture = (): { root: string; families: SemgrepFamily[]; options: SemgrepFamilyCacheOptions } => {
    const root = mkdtempSync(join(tmpdir(), "harvey-semgrep-family-"));
    dirs.push(root);
    const rules = join(root, "rules");
    mkdirSync(rules);
    const families = ["auth", "xss", "registry"].map((id) => {
      const configPath = join(rules, `${id}.yml`);
      writeFileSync(configPath, `rules:\n  - id: ${id}\n    mode: taint\n    languages: [typescript]\n    message: ${id}\n    pattern-sources: [{ pattern: $SOURCE }]\n    pattern-sinks: [{ pattern: $SINK }]\n    severity: WARNING\n`);
      return { id, configPath };
    });
    return {
      root,
      families,
      options: {
        dir: join(root, "cache"),
        mode: "read-write",
        targetRevision: "commit-a",
        targetTree: "tree-a",
        implementation: "semgrep-wrapper-v1",
        externalInputs: { semgrep: "1.173.0", node: "v24.18.0", toolchain: "lock", options: "pinned" },
      },
    };
  };

  it("requires a stable exhaustive disjoint partition in both directions", () => {
    const { families } = fixture();
    const expected = families.map((family) => family.configPath);
    expect(() => assertSemgrepFamilyPlan(families, expected)).not.toThrow();
    expect(() => assertSemgrepFamilyPlan(families.slice(1), expected)).toThrow("omitted");
    expect(() => assertSemgrepFamilyPlan([...families, families[0]!], expected)).toThrow("duplicate ids");
    expect(() => assertSemgrepFamilyPlan([...families, { id: "unknown", configPath: "/unknown.yml" }], expected)).toThrow("unregistered");
  });

  it("discovers .yml and .yaml through an execution loader independent of the expected-set yardstick", () => {
    const { root } = fixture();
    const rules = join(root, "extension-rules");
    mkdirSync(join(rules, "nested"), { recursive: true });
    writeFileSync(join(rules, "legacy.yml"), "rules: []\n");
    writeFileSync(join(rules, "nested", "new-family.yaml"), "rules: []\n");
    writeFileSync(join(rules, "not-a-rule.txt"), "rules: []\n");
    const discovered = discoverLocalSemgrepFamilies(rules);
    const expected = localSemgrepConfigYardstick(rules);
    expect(discovered.map((family) => family.configPath)).toEqual(expected);
    expect(discovered.map((family) => family.configPath)).toContain(join(rules, "nested", "new-family.yaml"));
    expect(() => assertSemgrepFamilyPlan(discovered.filter((family) => family.configPath.endsWith(".yml")), expected)).toThrow("omitted");
  });

  it("changing one local rule invalidates only its family", async () => {
    const { families, options } = fixture();
    for (const family of families) expect((await executeSemgrepFamily(family, options, () => executed(family, output(family.id)))).cache).toBe("miss");
    writeFileSync(families[0]!.configPath, "rules: [] # auth-v2\n");
    for (const [index, family] of families.entries()) {
      expect((await executeSemgrepFamily(family, options, () => executed(family, output(`${family.id}-fresh`)))).cache).toBe(index === 0 ? "miss" : "hit");
    }
  });

  it("binds YAML taint mode into family identity and ownership", async () => {
    const { families, options } = fixture();
    const family = families[0]!;
    const first = await executeSemgrepFamily(family, options, () => executed(family, output(family.id)));
    expect(first.execution?.ownedTaintRuleIds).toEqual([family.id]);
    writeFileSync(family.configPath, readFileSync(family.configPath, "utf8").replace("mode: taint", "mode: search"));
    const second = await executeSemgrepFamily(family, options, () => executed(family, output(family.id)));
    expect(second.cache).toBe("miss");
    expect(second.key).not.toBe(first.key);
    expect(second.execution?.ownedTaintRuleIds).toEqual([]);
  });

  it("caches a complete zero-applicable-rule family and continues the exhaustive plan", async () => {
    const { families, options } = fixture();
    const empty: SemgrepOutput = { results: [], errors: [], paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } };
    const cold = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, empty));
    const warm = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, output("must-not-run")));
    const reusable = { ...empty, time: { rules: [] } };
    expect(cold).toMatchObject({ cache: "miss", unitsExamined: 1, output: reusable });
    expect(warm).toMatchObject({ cache: "hit", unitsExamined: 1, output: reusable });
  });

  it("stores a production callback's explicitly canonical timeout output without raw-parsing it again", async () => {
    const { families, options } = fixture();
    const family = families[0]!;
    const raw: SemgrepOutput = { ...output("auth"), time: { rules: ["auth"], fixpoint_timeouts: [semanticTimeout()] } };
    const execution = executed(family, raw).execution;
    const canonical = canonicalizeSemgrepOutput(raw, "raw", ["auth"]);
    const cold = await executeSemgrepFamily(family, options, () => ({ output: canonical, execution, telemetry: [{ attempt: 1, components: [{ id: family.id, fixpointTimeouts: [semanticTimeout()] }] }], outputMode: "canonical" }));
    const warm = await executeSemgrepFamily(family, options, () => { throw new Error("canonical cache hit re-executed"); });
    expect(cold.cache).toBe("miss");
    expect(cold.output.time?.fixpoint_timeouts).toEqual(canonical.time?.fixpoint_timeouts);
    expect(warm.cache).toBe("hit");
  });

  it("physically rejects both raw/canonical boundary reversions", async () => {
    const canonicalCase = fixture();
    const canonicalFamily = canonicalCase.families[0]!;
    const raw: SemgrepOutput = { ...output("auth"), time: { rules: ["auth"], fixpoint_timeouts: [semanticTimeout()] } };
    const execution = executed(canonicalFamily, raw).execution;
    const canonical = canonicalizeSemgrepOutput(raw, "raw", ["auth"]);
    await expect(executeSemgrepFamily(canonicalFamily, canonicalCase.options, () => ({ output: canonical, execution })))
      .rejects.toThrow(/fixpoint_timeouts population is missing/i);

    const rawCase = fixture();
    const rawFamily = rawCase.families[0]!;
    await expect(executeSemgrepFamily(rawFamily, rawCase.options, () => ({ output: raw, execution: executed(rawFamily, raw).execution, outputMode: "canonical" })))
      .rejects.toThrow(/canonical Semgrep output contains raw timeout telemetry/);
  });

  it("fails closed when timeout telemetry has no owned and loaded taint-mode candidate", () => {
    const raw: SemgrepOutput = {
      ...output("search-only"),
      time: { rules: ["search-only"], fixpoint_timeouts: [semanticTimeout()] },
    };
    expect(() => buildSemgrepCommandSemanticReceipt(
      raw, "/target", ["semgrep"], 1, ["search-only"], undefined, "raw", [],
    )).toThrow(/without any bound loaded taint-mode rule/i);
  });

  it("canonicalizes scratch-checkout roots and materializes the current root on a hit", async () => {
    const { root, families, options } = fixture();
    const rootA = join(root, "checkout-a");
    const rootB = join(root, "checkout-b");
    mkdirSync(rootA);
    mkdirSync(rootB);
    const cold = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootA }, () => executed(families[0]!, output("auth", join(rootA, "src/route.ts"))));
    const warm = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB }, () => executed(families[0]!, output("must-not-run")));
    expect(cold.cache).toBe("miss");
    expect(warm.cache).toBe("hit");
    expect(warm.output.results?.[0]?.path).toBe(join(rootB, "src/route.ts"));
    expect((await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB, mode: "verify" }, () => executed(families[0]!, output("auth", join(rootB, "src/route.ts"))))).cache).toBe("recomputed");
  });

  it("target and runtime identities invalidate every affected family", async () => {
    const { families, options } = fixture();
    for (const family of families) await executeSemgrepFamily(family, options, () => executed(family, output(family.id)));
    const changed = { ...options, targetTree: "tree-b", externalInputs: { ...options.externalInputs, semgrep: "1.165.0" } };
    for (const family of families) expect((await executeSemgrepFamily(family, changed, () => executed(family, output(`${family.id}-moved`)))).cache).toBe("miss");
  });

  it("rejects corrupt, incomplete, and unregistered artifacts visibly before recompute", async () => {
    const { families, options } = fixture();
    const events: string[] = [];
    options.onEvent = (message) => events.push(message);
    const cold = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, output("auth")));
    const artifact = join(options.dir, "semgrep-families", "auth", `${cold.key}.json`);
    const parsed = JSON.parse(readFileSync(artifact, "utf8")) as { output: { paths: unknown }; payloadDigest: string };
    parsed.output.paths = undefined;
    writeFileSync(artifact, JSON.stringify(parsed));
    expect((await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, output("auth-fresh")))).cache).toBe("miss");
    expect(events).toContainEqual(expect.stringContaining("examined-path scope is incomplete"));

    const unknown = join(options.dir, "semgrep-families", "unknown", "artifact.json");
    mkdirSync(join(options.dir, "semgrep-families", "unknown"), { recursive: true });
    writeFileSync(unknown, JSON.stringify({ schema: 1, family: "not-registered" }));
    rejectUnregisteredSemgrepFamilyArtifacts(options, new Set(families.map((family) => family.id)));
    expect(events).toContainEqual(expect.stringContaining("artifact is unregistered"));
  });

  it("rejects legacy, failed, and self-checksummed semantic-receipt tampering before reuse", async () => {
    type MutableArtifact = { schema: number; output: unknown; unitsExamined: number; payloadDigest: string; execution: { status: string; attempts: SemgrepCommandSemanticReceipt[] } };
    const cases: Array<[string, (artifact: MutableArtifact) => void, RegExp]> = [
      ["schema-5 downgrade", (artifact) => { artifact.schema = 5; }, /identity\/schema mismatch/],
      ["schema-6 downgrade", (artifact) => { artifact.schema = 6; }, /identity\/schema mismatch/],
      ["schema-7 downgrade", (artifact) => { artifact.schema = 7; }, /identity\/schema mismatch/],
      ["failed execution", (artifact) => { artifact.execution.status = "failed"; }, /successful semantic execution receipt/],
      ["swapped scanned population", (artifact) => {
        artifact.execution.attempts[0]!.scanned = ["different.ts"];
        const attempt = artifact.execution.attempts[0]!;
        const semantic = Object.fromEntries(Object.entries(attempt).filter(([key]) => !["status", "attempt", "semanticSha256"].includes(key)));
        attempt.semanticSha256 = createHash("sha256").update(stableFixture(semantic)).digest("hex");
      }, /differs from its stored output/],
    ];
    for (const [name, mutate, reason] of cases) {
      const { families, options } = fixture();
      const events: string[] = [];
      options.onEvent = (message) => events.push(message);
      const cold = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, output("auth")));
      const path = join(options.dir, "semgrep-families", "auth", `${cold.key}.json`);
      const artifact = JSON.parse(readFileSync(path, "utf8")) as MutableArtifact;
      mutate(artifact);
      artifact.payloadDigest = createHash("sha256").update(stableFixture({ output: artifact.output, unitsExamined: artifact.unitsExamined, execution: artifact.execution })).digest("hex");
      writeFileSync(path, JSON.stringify(artifact));
      expect((await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, output(`fresh-${name}`)))).cache).toBe("miss");
      expect(events.some((event) => reason.test(event))).toBe(true);
    }
  });

  it("binds routed manifest identity into the family cache key", async () => {
    const { families, options } = fixture();
    const family = { ...families[0]!, cacheIdentity: "manifest-a" };
    expect((await executeSemgrepFamily(family, options, () => executed(family, output("auth")))).cache).toBe("miss");
    expect((await executeSemgrepFamily(family, options, () => executed(family, output("must-not-run")))).cache).toBe("hit");
    const moved = { ...family, cacheIdentity: "manifest-b" };
    expect((await executeSemgrepFamily(moved, options, () => executed(moved, output("auth-moved")))).cache).toBe("miss");
  });

  it("reassembles deterministic monolithic shape with exact deduplication", () => {
    const duplicate = output("tmp.cache-a.registry-packs.digest.javascript.react.same").results![0]!;
    const sameRegistryRule = { ...duplicate, check_id: "tmp.cache-b.registry-packs.digest.javascript.react.same" };
    const merged = mergeSemgrepFamilyOutputs([
      { family: "b", output: { ...output("b"), results: [duplicate, output("b").results![0]!], time: { rules: ["same", "b"], fixpoint_timeouts: [] } }, cache: "hit", key: "b", unitsExamined: 1 },
      { family: "a", output: { ...output("a"), results: [sameRegistryRule, output("a").results![0]!], time: { rules: ["same", "a"], fixpoint_timeouts: [] } }, cache: "hit", key: "a", unitsExamined: 1 },
    ]);
    expect(merged.results?.map((result) => result.check_id)).toEqual(["a", "b", "javascript.react.same"]);
    expect(merged.paths?.scanned).toEqual(["src/route.ts"]);
    expect(merged.time?.rules).toEqual(["a", "b", "same"]);
  });

  it("canonicalizes generated partition rule namespaces across cache roots", () => {
    const generated = (cache: string): SemgrepOutput => ({
      results: [{
        check_id: `${cache}.semgrep-owned-configs.harvey-log-injection`, path: "src/route.ts",
        start: { line: 1 }, extra: { message: "match", severity: "WARNING" },
      }],
      errors: [{ message: `first: ${cache}.semgrep-owned-configs.harvey-log-injection` }],
      paths: { scanned: ["src/route.ts"], skipped: [] },
      time: {
        rules: [`${cache}.semgrep-owned-configs.harvey-log-injection`],
        fixpoint_timeouts: [{
          error_type: "Fixpoint timeout", severity: "warn",
          message: `Fixpoint timeout while performing taint analysis at src/route.ts:1:0 [rules: 1, first: ${cache}.semgrep-owned-configs.harvey-log-injection]`,
          location: { path: "src/route.ts", start: { line: 1, col: 1, offset: 0 }, end: { line: 1, col: 2, offset: 1 } },
        }],
      },
    });
    const first = canonicalizeSemgrepOutput(generated("private.tmp.cache-one"));
    const second = canonicalizeSemgrepOutput(generated("private.tmp.cache-two"));
    expect(first).toEqual(second);
    expect(first.results?.[0]?.check_id).toBe("src.scan.rules.semgrep.harvey-log-injection");
    expect(first.time?.rules).toEqual(["src.scan.rules.semgrep.harvey-log-injection"]);
    expect(JSON.stringify(first)).not.toContain("semgrep-owned-configs");

    const firstReceipt = buildSemgrepCommandSemanticReceipt(generated("private.tmp.cache-one"), "/target", ["semgrep"], 1, ["harvey-log-injection"], undefined, "raw", ["harvey-log-injection"]);
    const renamedReceipt = buildSemgrepCommandSemanticReceipt(generated("private.tmp.cache-two"), "/target", ["semgrep"], 1, ["harvey-log-injection"], undefined, "raw", ["harvey-log-injection"]);
    expect(firstReceipt).toEqual(renamedReceipt);

    const unknown = generated("private.tmp.cache-one");
    unknown.results![0]!.check_id = "private.tmp.unknown.harvey-log-injection";
    unknown.time!.rules = ["private.tmp.unknown.harvey-log-injection"];
    (unknown.time!.fixpoint_timeouts![0]! as Record<string, unknown>).message = "Fixpoint timeout while performing taint analysis at src/route.ts:1:0 [rules: 1, first: private.tmp.unknown.harvey-log-injection]";
    const unknownReceipt = buildSemgrepCommandSemanticReceipt(unknown, "/target", ["semgrep"], 1, ["private.tmp.unknown.harvey-log-injection"], undefined, "raw", ["private.tmp.unknown.harvey-log-injection"]);
    expect(unknownReceipt.semanticSha256).not.toBe(firstReceipt.semanticSha256);

    const semanticMutation = generated("private.tmp.cache-one");
    semanticMutation.results![0]!.check_id = "private.tmp.cache-one.semgrep-owned-configs.harvey-path-traversal";
    semanticMutation.time!.rules = ["private.tmp.cache-one.semgrep-owned-configs.harvey-path-traversal"];
    (semanticMutation.time!.fixpoint_timeouts![0]! as Record<string, unknown>).message = "Fixpoint timeout while performing taint analysis at src/route.ts:1:0 [rules: 1, first: private.tmp.cache-one.semgrep-owned-configs.harvey-path-traversal]";
    const mutatedReceipt = buildSemgrepCommandSemanticReceipt(semanticMutation, "/target", ["semgrep"], 1, ["harvey-path-traversal"], undefined, "raw", ["harvey-path-traversal"]);
    expect(mutatedReceipt.semanticSha256).not.toBe(firstReceipt.semanticSha256);

    const arbitraryFirst = JSON.parse(JSON.stringify(generated("private.tmp.harvey-semgrep-monolithic-owned-a1b2")).replaceAll(".semgrep-owned-configs", "")) as SemgrepOutput;
    const arbitrarySecond = JSON.parse(JSON.stringify(generated("private.tmp.harvey-semgrep-monolithic-owned-c3d4")).replaceAll(".semgrep-owned-configs", "")) as SemgrepOutput;
    expect(canonicalizeOwnedSemgrepOutput(arbitraryFirst, ["harvey-log-injection"]))
      .toEqual(canonicalizeOwnedSemgrepOutput(arbitrarySecond, ["harvey-log-injection"]));
    expect(canonicalizeOwnedSemgrepOutput(arbitraryFirst, ["harvey-path-traversal"]))
      .not.toEqual(canonicalizeOwnedSemgrepOutput(arbitraryFirst, ["harvey-log-injection"]));
  });

  it("keeps raw timeout multiplicity only in a non-reusable content-addressed sidecar", async () => {
    const { root, families, options } = fixture();
    const rootA = join(root, "checkout-a");
    const rootB = join(root, "checkout-b");
    mkdirSync(rootA);
    mkdirSync(rootB);
    const rawTimeout = (pathRoot: string, rule = "auth", count = 1) => ({
      error_type: "Fixpoint timeout", severity: "warn",
      message: `Fixpoint timeout while performing taint analysis at ${join(pathRoot, "src/route.ts")}:1:0 [rules: ${count}, first: ${rule}]`,
      location: { path: join(pathRoot, "src/route.ts"), start: { line: 1, col: 1, offset: 0 }, end: { line: 1, col: 2, offset: 1 } },
    });
    const raw = rawTimeout(rootA);
    const execution = executed(families[0]!, {
      ...output("auth", join(rootA, "src/route.ts")),
      time: { rules: ["auth"], fixpoint_timeouts: [raw, raw] },
    });
    const cold = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootA }, () => ({
      ...execution,
      telemetry: [{ attempt: 1, components: [{ id: families[0]!.id, fixpointTimeouts: [raw, raw] }] }],
    }));
    const warm = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB }, () => executed(families[0]!, output("must-not-run")));
    expect(cold.output.time).not.toHaveProperty("fixpoint_timeouts");
    expect(warm.output.time).not.toHaveProperty("fixpoint_timeouts");
    const relativeFiles = (await import("../fs-walk.js")).readRecursiveSafe(join(options.dir, "semgrep-family-timeout-telemetry", "auth", cold.key));
    expect(relativeFiles).toHaveLength(1);
    const sidecar = JSON.parse(readFileSync(join(options.dir, "semgrep-family-timeout-telemetry", "auth", cold.key, relativeFiles[0]!), "utf8"));
    expect(sidecar).toMatchObject({ schema: 8, reusable: false, telemetry: { attempt: 1 } });
    expect(sidecar.telemetry.components[0].fixpointTimeouts).toHaveLength(2);
    const success = JSON.parse(readFileSync(join(options.dir, "semgrep-families", "auth", `${cold.key}.json`), "utf8"));
    expect(JSON.stringify(success)).not.toContain("Fixpoint timeout while performing taint analysis at");
    rmSync(join(options.dir, "semgrep-family-timeout-telemetry", "auth", cold.key), { recursive: true, force: true });
    const afterSidecarDeletion = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB }, () => {
      throw new Error("a reusable success receipt must not depend on its non-reusable telemetry sidecar");
    });
    expect(afterSidecarDeletion.cache).toBe("hit");
    expect(afterSidecarDeletion.output).toEqual(warm.output);
    expect(afterSidecarDeletion.execution?.taintCoverage).toBe("not-assessed");
  });

  it("accepts both-nonempty raw timeout drift while retaining two distinct sidecars", async () => {
    const { root, families, options } = fixture();
    const family = families[0]!;
    const path = join(root, "src/route.ts");
    const row = (message: string, line: number) => ({
      error_type: "Fixpoint timeout", severity: "warn", message,
      location: { path, start: { line, col: 1, offset: line }, end: { line, col: 2, offset: line + 1 } },
    });
    const firstRaw = { ...output("auth", path), time: { rules: ["auth"], fixpoint_timeouts: [row("first volatile suffix", 1)] } };
    const secondRaw = { ...output("auth", path), time: { rules: ["auth"], fixpoint_timeouts: [row("second volatile suffix", 9), row("second volatile suffix", 9)] } };
    const firstReceipt = buildSemgrepCommandSemanticReceipt(firstRaw, root, ["semgrep"], 1, ["auth"], undefined, "raw", ["auth"]);
    const secondReceipt = buildSemgrepCommandSemanticReceipt(secondRaw, root, ["semgrep"], 2, ["auth"], undefined, "raw", ["auth"]);
    expect({ ...firstReceipt, attempt: 0 }).toEqual({ ...secondReceipt, attempt: 0 });
    const base = executed(family, firstRaw).execution;
    const execution: SemgrepFamilyExecutionReceipt = {
      ...base,
      argv: firstReceipt.argv,
      loadedRuleIds: firstReceipt.loadedRuleIds,
      loadedTaintRuleIds: firstReceipt.loadedTaintRuleIds,
      taintCoverage: firstReceipt.taintCoverage,
      verification: "paired-cold-exact",
      attempts: [firstReceipt, secondReceipt],
    };
    const record = await executeSemgrepFamily(family, { ...options, pathRoot: root }, () => ({
      output: canonicalizeSemgrepOutput(firstRaw), execution, outputMode: "canonical",
      telemetry: [
        { attempt: 1, components: [{ id: family.id, fixpointTimeouts: canonicalizeSemgrepTime(firstRaw.time).fixpoint_timeouts }] },
        { attempt: 2, components: [{ id: family.id, fixpointTimeouts: canonicalizeSemgrepTime(secondRaw.time).fixpoint_timeouts }] },
      ],
    }));
    const sidecars = (await import("../fs-walk.js")).readRecursiveSafe(join(options.dir, "semgrep-family-timeout-telemetry", "auth", record.key));
    expect(sidecars).toHaveLength(2);
    expect(record.execution?.taintCoverage).toBe("not-assessed");
  });

  it("retains raw timeout row text, order, and multiplicity without suffix parsing", () => {
    const path = "src/route.ts";
    const row = (count: number, first: string) => ({
      error_type: "Fixpoint timeout", severity: "warn",
      message: `Fixpoint timeout while performing taint analysis at ${path}:7:3 [rules: ${count}, first: ${first}]`,
      location: { path, start: { line: 7, col: 4, offset: 90 }, end: { line: 7, col: 8, offset: 94 } },
    });
    const first = canonicalizeSemgrepTime({ rules: ["auth", "xss"], fixpoint_timeouts: [row(1, "auth"), row(2, "xss")] }, ["auth", "xss"]);
    const second = canonicalizeSemgrepTime({ rules: ["xss", "auth"], fixpoint_timeouts: [row(2, "auth"), row(1, "xss")] }, ["auth", "xss"]);
    expect(first).not.toEqual(second);
    expect(first.fixpoint_timeouts).toHaveLength(2);
    expect(first.fixpoint_timeouts[0]).not.toEqual(first.fixpoint_timeouts[1]);
    expect(canonicalizeSemgrepTime({ rules: ["auth", "xss"], fixpoint_timeouts: [row(1, "auth")] }, ["auth", "xss"]).fixpoint_timeouts)
      .not.toEqual(first.fixpoint_timeouts);
  });

  it.each([
    ["path", (row: ReturnType<typeof semanticTimeout>, time: { rules: string[] }) => {
      row.location.path = "src/other.ts";
      row.message = `Fixpoint timeout while performing taint analysis at src/other.ts:7:3 [rules: 1, first: ${time.rules[0]!}]`;
    }],
    ["span", (row: ReturnType<typeof semanticTimeout>) => { row.location.end.col = 9; }],
    ["error type", (row: ReturnType<typeof semanticTimeout>) => { row.error_type = "Different timeout"; }],
    ["severity", (row: ReturnType<typeof semanticTimeout>) => { row.severity = "error"; }],
    ["loaded rules", (_row: ReturnType<typeof semanticTimeout>, time: { rules: string[] }) => { time.rules.push("xss"); }],
  ])("retains semantic timeout %s mutations", (_name, mutate) => {
    const baseTime = { rules: ["auth"], fixpoint_timeouts: [semanticTimeout()] };
    const changedTime = structuredClone(baseTime);
    mutate(changedTime.fixpoint_timeouts[0]!, changedTime);
    expect(canonicalizeSemgrepTime(changedTime, changedTime.rules)).not.toEqual(canonicalizeSemgrepTime(baseTime, baseTime.rules));
  });

  it.each([
    "Fixpoint timeout while performing taint analysis at src/route.ts:7:3 [rules: 0, first: auth]",
    "some other timeout",
  ])("does not interpret volatile raw timeout message %s", (message) => {
    const raw = { error_type: "Fixpoint timeout", severity: "warn", message, location: {
      path: "src/route.ts", start: { line: 7, col: 4, offset: 90 }, end: { line: 7, col: 8, offset: 94 },
    } };
    expect(canonicalizeSemgrepTime({ rules: ["auth"], fixpoint_timeouts: [raw] }, ["auth"]).fixpoint_timeouts).toEqual([raw]);
  });

  it.each([
    ["unknown row key", (row: ReturnType<typeof semanticTimeout>) => { (row as unknown as Record<string, unknown>).future = true; }],
    ["unknown nested key", (row: ReturnType<typeof semanticTimeout>) => { (row.location.start as unknown as Record<string, unknown>).future = true; }],
  ])("rejects timeout %s shape expansion", (_name, mutate) => {
    const row = { error_type: "Fixpoint timeout", severity: "warn",
      message: "Fixpoint timeout while performing taint analysis at src/route.ts:7:3 [rules: 1, first: auth]",
      location: { path: "src/route.ts", start: { line: 7, col: 4, offset: 90 }, end: { line: 7, col: 8, offset: 94 } } };
    mutate(row);
    expect(() => canonicalizeSemgrepTime({ rules: ["auth"], fixpoint_timeouts: [row] }, ["auth"]))
      .toThrow(SemgrepTimeoutTelemetryError);
  });

  it("rejects legacy or unknown time evidence before cache storage", async () => {
    const { families, options } = fixture();
    await expect(executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, {
      ...output("auth"), time: { rules: ["auth"] },
    }))).rejects.toThrow(/fixpoint_timeouts population is missing/);
    await expect(executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, {
      ...output("auth"), time: { rules: ["auth"], fixpoint_timeouts: [], future: [] },
    }))).rejects.toThrow(/unclassified child evidence.*future/);
  });

  it("conserves distinct same-path errors and removes only exact cross-family duplicates", () => {
    const first = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 42 }]], message: "first partial parse" };
    const second = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 47 }]], message: "second partial parse" };
    const merged = mergeSemgrepFamilyOutputs([
      { family: "a", output: { ...output("a"), errors: [first, second] }, cache: "miss", key: "a", unitsExamined: 1 },
      { family: "b", output: { ...output("b"), errors: [first] }, cache: "miss", key: "b", unitsExamined: 1 },
    ]);
    expect(merged.errors).toEqual([first, second]);
  });

  it("does not erase an exact duplicate emitted twice by one family", () => {
    const repeated = { path: "/target/src/broken.ts", type: "ParseError", message: "same engine record twice" };
    const merged = mergeSemgrepFamilyOutputs([
      { family: "a", output: { ...output("a"), errors: [repeated, repeated] }, cache: "miss", key: "a", unitsExamined: 1 },
      { family: "b", output: { ...output("b"), errors: [repeated] }, cache: "miss", key: "b", unitsExamined: 1 },
    ]);
    expect(merged.errors).toEqual([repeated, repeated]);
  });

  it("stores and rereads every same-path diagnostic without collapsing its structure", async () => {
    const { families, options } = fixture();
    const first = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 42 }]], message: "first partial parse" };
    const second = { path: "/target/src/broken.ts", type: ["PartialParsing", [{ line: 47 }]], message: "second partial parse" };
    const complete: SemgrepOutput = { ...output("auth"), errors: [first, second] };
    const cold = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, complete));
    const warm = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, output("must-not-run")));
    expect(cold.output.errors).toEqual([first, second]);
    expect(warm.output.errors).toEqual([first, second]);
  });

  it("preserves the monolithic namespace for a local Harvey rule loaded as one family", () => {
    const merged = mergeSemgrepFamilyOutputs([
      { family: "local", output: output("harvey-route-noauth"), cache: "miss", key: "local", unitsExamined: 1 },
    ]);
    expect(merged.results?.map((result) => result.check_id)).toEqual(["src.scan.rules.semgrep.harvey-route-noauth"]);
  });

  it("forced-cold verification passes only when every family re-executed against a hit", async () => {
    const { families, options } = fixture();
    for (const family of families) await executeSemgrepFamily(family, options, () => executed(family, output(family.id)));
    const verified: SemgrepFamilyRecord[] = [];
    for (const family of families) verified.push(await executeSemgrepFamily(family, { ...options, mode: "verify" }, () => executed(family, output(family.id))));
    expect(() => assertSemgrepFamilyVerification(verified, families, "verify")).not.toThrow();
    expect(verified.every((record) => record.cache === "recomputed")).toBe(true);

    const empty = fixture();
    const misses: SemgrepFamilyRecord[] = [];
    for (const family of empty.families) misses.push(await executeSemgrepFamily(family, { ...empty.options, mode: "verify" }, () => executed(family, output(family.id))));
    expect(() => assertSemgrepFamilyVerification(misses, empty.families, "verify")).toThrow("forced-cold Semgrep family verification incomplete");
  });
});
