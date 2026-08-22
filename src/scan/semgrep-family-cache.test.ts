import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

const output = (id: string, path = "src/route.ts"): SemgrepOutput => ({
  results: [{ check_id: id, path, start: { line: 1 }, extra: { message: id, severity: "WARNING" } }],
  errors: [],
  paths: { scanned: [path], skipped: [] },
  time: { rules: [id], fixpoint_timeouts: [] },
});

function stableFixture(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableFixture).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stableFixture(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function executed(family: SemgrepFamily, value: SemgrepOutput): { output: SemgrepOutput; execution: SemgrepFamilyExecutionReceipt } {
  const loadedRuleIds = [...new Set((value.time?.rules ?? []) as string[])].sort();
  const semantic = {
    argv: ["semgrep", "--config", family.configPath], loadedRuleIds,
    resultCount: value.results?.length ?? 0,
    resultsSha256: createHash("sha256").update(stableFixture(value.results ?? [])).digest("hex"),
    scanned: value.paths?.scanned ?? [], skipped: value.paths?.skipped ?? [], skippedRules: value.skipped_rules ?? [],
    errors: value.errors ?? [], fixpointTimeouts: value.time?.fixpoint_timeouts ?? [],
  };
  const attempt = { status: "succeeded" as const, attempt: 1, ...semantic, semanticSha256: createHash("sha256").update(stableFixture(semantic)).digest("hex") };
  const configSha256 = createHash("sha256").update(readFileSync(family.configPath)).digest("hex");
  return { output: value, execution: {
    ordinal: 0, id: family.id, familyId: family.id, sourceKind: "local-config", sourceId: family.id,
    configSha256, sourceConfigSha256: configSha256, ruleIds: loadedRuleIds, ownedRuleIds: loadedRuleIds,
    loadedRuleIds, excludedRuleIds: [], argv: semantic.argv, topology: "single-command-v1",
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
      writeFileSync(configPath, `rules: [] # ${id}\n`);
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

  it("caches a complete zero-applicable-rule family and continues the exhaustive plan", async () => {
    const { families, options } = fixture();
    const empty: SemgrepOutput = { results: [], errors: [], paths: { scanned: [], skipped: [] }, time: { rules: [], fixpoint_timeouts: [] } };
    const cold = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, empty));
    const warm = await executeSemgrepFamily(families[0]!, options, () => executed(families[0]!, output("must-not-run")));
    expect(cold).toMatchObject({ cache: "miss", unitsExamined: 1, output: empty });
    expect(warm).toMatchObject({ cache: "hit", unitsExamined: 1, output: empty });
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
      ["legacy schema", (artifact) => { artifact.schema = 4; }, /identity\/schema mismatch/],
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
        fixpoint_timeouts: [{ message: `first: ${cache}.semgrep-owned-configs.harvey-log-injection` }],
      },
    });
    const first = canonicalizeSemgrepOutput(generated("private.tmp.cache-one"));
    const second = canonicalizeSemgrepOutput(generated("private.tmp.cache-two"));
    expect(first).toEqual(second);
    expect(first.results?.[0]?.check_id).toBe("src.scan.rules.semgrep.harvey-log-injection");
    expect(first.time?.rules).toEqual(["src.scan.rules.semgrep.harvey-log-injection"]);
    expect(JSON.stringify(first)).not.toContain("semgrep-owned-configs");

    const firstReceipt = buildSemgrepCommandSemanticReceipt(generated("private.tmp.cache-one"), "/target", ["semgrep"], 1);
    const renamedReceipt = buildSemgrepCommandSemanticReceipt(generated("private.tmp.cache-two"), "/target", ["semgrep"], 1);
    expect(firstReceipt).toEqual(renamedReceipt);

    const unknown = generated("private.tmp.cache-one");
    unknown.results![0]!.check_id = "private.tmp.unknown.harvey-log-injection";
    unknown.time!.rules = ["private.tmp.unknown.harvey-log-injection"];
    const unknownReceipt = buildSemgrepCommandSemanticReceipt(unknown, "/target", ["semgrep"], 1);
    expect(unknownReceipt.semanticSha256).not.toBe(firstReceipt.semanticSha256);

    const semanticMutation = generated("private.tmp.cache-one");
    semanticMutation.results![0]!.check_id = "private.tmp.cache-one.semgrep-owned-configs.harvey-path-traversal";
    semanticMutation.time!.rules = ["private.tmp.cache-one.semgrep-owned-configs.harvey-path-traversal"];
    const mutatedReceipt = buildSemgrepCommandSemanticReceipt(semanticMutation, "/target", ["semgrep"], 1);
    expect(mutatedReceipt.semanticSha256).not.toBe(firstReceipt.semanticSha256);

    const arbitraryFirst = JSON.parse(JSON.stringify(generated("private.tmp.harvey-semgrep-monolithic-owned-a1b2")).replaceAll(".semgrep-owned-configs", "")) as SemgrepOutput;
    const arbitrarySecond = JSON.parse(JSON.stringify(generated("private.tmp.harvey-semgrep-monolithic-owned-c3d4")).replaceAll(".semgrep-owned-configs", "")) as SemgrepOutput;
    expect(canonicalizeOwnedSemgrepOutput(arbitraryFirst, ["harvey-log-injection"]))
      .toEqual(canonicalizeOwnedSemgrepOutput(arbitrarySecond, ["harvey-log-injection"]));
    expect(canonicalizeOwnedSemgrepOutput(arbitraryFirst, ["harvey-path-traversal"]))
      .not.toEqual(canonicalizeOwnedSemgrepOutput(arbitrarySecond, ["harvey-path-traversal"]));
  });

  it("conserves, deduplicates, and root-materializes fixpoint timeout evidence", async () => {
    const { root, families, options } = fixture();
    const rootA = join(root, "checkout-a");
    const rootB = join(root, "checkout-b");
    mkdirSync(rootA);
    mkdirSync(rootB);
    const timeout = (pathRoot: string) => ({
      error_type: "Fixpoint timeout", severity: "warn",
      message: `Fixpoint timeout at ${join(pathRoot, "src/route.ts")}:1:0`,
      location: { path: join(pathRoot, "src/route.ts"), start: { line: 1 }, end: { line: 1 } },
    });
    const cold = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootA }, () => executed(families[0]!, {
      ...output("auth", join(rootA, "src/route.ts")),
      time: { rules: ["auth"], fixpoint_timeouts: [timeout(rootA)] },
    }));
    const warm = await executeSemgrepFamily(families[0]!, { ...options, pathRoot: rootB }, () => executed(families[0]!, output("must-not-run")));
    expect(cold.output.time?.fixpoint_timeouts).toHaveLength(1);
    expect(warm.output.time?.fixpoint_timeouts).toEqual([timeout(rootB)]);

    const merged = mergeSemgrepFamilyOutputs([
      { ...cold, output: { ...cold.output, time: { rules: ["auth"], fixpoint_timeouts: [timeout(rootA)] } } },
      { family: "duplicate", output: { ...cold.output, time: { rules: ["other"], fixpoint_timeouts: [timeout(rootA)] } }, cache: "miss", key: "duplicate", unitsExamined: 1 },
    ]);
    expect(merged.time?.fixpoint_timeouts).toEqual([timeout(rootA)]);
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
